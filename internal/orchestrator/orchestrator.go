// Package orchestrator drives each run's lifecycle timers.
//
// Two engines implement Engine:
//
//   - Builtin: the tenant plane's own reaper and drift scheduler, backed by
//     PostgreSQL. No extra infrastructure.
//   - Temporal: one durable workflow per run ("run-<id>") that follows the run
//     through signals (planned, approved, finished) and owns its timers: a
//     runner that stops reporting fails the run, a plan nobody approves in time
//     is discarded, an apply that never finishes fails. Drift checks are queued
//     Runs are visible in the Temporal UI. Drift checks are only ever started
//     by people; nothing is scheduled.
//
// Either way the database stays the source of truth: workflow activities apply
// guarded, idempotent status changes, so a late signal or a duplicate timer
// can never move a run backwards.
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Engine receives run lifecycle events from the tenant plane.
type Engine interface {
	RunCreated(ctx context.Context, runID string)
	Planned(ctx context.Context, runID string, awaitingApproval bool)
	Approved(ctx context.Context, runID string)
	Finished(ctx context.Context, runID string)
	Name() string
}

// Builtin does nothing per event: the reaper and scheduler poll the database.
type Builtin struct{}

func (Builtin) RunCreated(context.Context, string)    {}
func (Builtin) Planned(context.Context, string, bool) {}
func (Builtin) Approved(context.Context, string)      {}
func (Builtin) Finished(context.Context, string)      {}
func (Builtin) Name() string                          { return "builtin" }

// Timeouts for a run's phases.
type Timeouts struct {
	Planning time.Duration // runner silent while planning
	Approval time.Duration // plan waiting for approvals
	Applying time.Duration // apply never finishing
}

var DefaultTimeouts = Timeouts{Planning: 30 * time.Minute, Approval: 24 * time.Hour, Applying: 2 * time.Hour}

// Store is what activities need from the tenant database.
type Store interface {
	// Expire moves a run out of one of the given statuses; false if it had already moved on.
	Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error)
}

// ---- workflows ----

const (
	SignalPlanned  = "planned"
	SignalApproved = "approved"
	SignalFinished = "finished"
)

// RunInput starts a run's workflow. RunID and Timeouts drive it; Run and
// Deadlines are there so the Temporal UI shows what the run is (Timeouts are
// nanoseconds on the wire, Deadlines the same as text).
type RunInput struct {
	RunID     string
	Timeouts  Timeouts
	Run       *RunInfo          `json:"run,omitempty"`
	Deadlines map[string]string `json:"deadlines,omitempty"`
}

// RunInfo describes a run for people reading Temporal.
type RunInfo struct {
	RunID       string `json:"run_id"`
	Tenant      string `json:"tenant"`
	Stack       string `json:"stack"`
	BU          string `json:"business_unit"`
	Environment string `json:"environment"`
	Operation   string `json:"operation"`
	Status      string `json:"status,omitempty"`
	RequestedBy string `json:"requested_by,omitempty"`
	Origin      string `json:"origin,omitempty"` // pull request, live -> code from run ...
	Link        string `json:"link,omitempty"`
}

// Signal is the payload of planned, approved and finished: the run's status
// at that moment. (Workflows started before it carried a bare boolean.)
type Signal struct {
	Status           string `json:"status"`
	AwaitingApproval *bool  `json:"awaiting_approval,omitempty"`
}

// readSignal decodes a signal payload: a Signal, or the boolean older
// workflows were sent (awaiting approval for planned).
func readSignal(raw json.RawMessage) (status string, awaiting bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return "", b
	}
	var sg Signal
	json.Unmarshal(raw, &sg)
	return sg.Status, sg.AwaitingApproval != nil && *sg.AwaitingApproval
}

var statusText = map[string]string{
	"no_changes": "no changes", "policy_failed": "blocked by policy", "planned": "planned", "apply_queued": "approved",
	"applied": "applied", "failed": "failed", "discarded": "discarded", "no_drift": "no drift", "drifted": "drift found", "cancelled": "cancelled",
}

func describeStatus(st string) string {
	if t, ok := statusText[st]; ok {
		return t
	}
	return strings.ReplaceAll(st, "_", " ")
}

// RunLifecycle follows one run from queued to a terminal status.
func RunLifecycle(ctx workflow.Context, in RunInput) (string, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 10},
	})
	planned := workflow.GetSignalChannel(ctx, SignalPlanned)
	approved := workflow.GetSignalChannel(ctx, SignalApproved)
	finished := workflow.GetSignalChannel(ctx, SignalFinished)

	// wait blocks for one of the given signals or a timer; it returns the name
	// of what fired ("timeout" for the timer).
	status := ""
	wait := func(d time.Duration, chans map[string]workflow.ReceiveChannel) (string, bool) {
		tctx, cancel := workflow.WithCancel(ctx)
		defer cancel()
		got, payload := "timeout", false
		sel := workflow.NewSelector(ctx)
		for name, ch := range chans {
			name, ch := name, ch
			sel.AddReceive(ch, func(c workflow.ReceiveChannel, _ bool) {
				var raw json.RawMessage
				c.Receive(ctx, &raw)
				var st string
				st, payload = readSignal(raw)
				got = name
				if st != "" {
					status = st
				}
			})
		}
		sel.AddFuture(workflow.NewTimer(tctx, d), func(workflow.Future) {})
		sel.Select(ctx)
		return got, payload
	}
	done := func(fallback string) string {
		if status == "" {
			return fallback
		}
		return describeStatus(status)
	}
	expire := func(from []string, to, reason string) (string, error) {
		var moved bool
		err := workflow.ExecuteActivity(ctx, (*Activities).Expire, in.RunID, from, to, reason).Get(ctx, &moved)
		if err != nil {
			return "", err
		}
		return to + ": " + reason, nil
	}

	got, awaiting := wait(in.Timeouts.Planning, map[string]workflow.ReceiveChannel{SignalPlanned: planned, SignalFinished: finished})
	switch got {
	case "timeout":
		return expire([]string{"queued", "planning"}, "failed", "runner stopped reporting while planning")
	case SignalFinished:
		return done("finished"), nil
	}
	if !awaiting {
		return "plan finished: " + done("nothing to approve"), nil
	}
	got, _ = wait(in.Timeouts.Approval, map[string]workflow.ReceiveChannel{SignalApproved: approved, SignalFinished: finished})
	switch got {
	case "timeout":
		return expire([]string{"planned"}, "discarded", "plan expired before approval")
	case SignalFinished:
		return done("discarded"), nil
	}
	got, _ = wait(in.Timeouts.Applying, map[string]workflow.ReceiveChannel{SignalFinished: finished})
	if got == "timeout" {
		return expire([]string{"apply_queued", "applying"}, "failed", "apply did not finish in time")
	}
	return done("applied or failed"), nil
}

// ---- activities ----

type Activities struct {
	Store   Store
	OnQueue func(ctx context.Context, runIDs []string) // e.g. wake runners, start workflows
}

func (a *Activities) Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error) {
	activity.GetLogger(ctx).Info("expiring run", "run", runID, "to", to, "reason", reason)
	return a.Store.Expire(ctx, runID, from, to, reason)
}

// ---- the Temporal engine ----

type Temporal struct {
	c         client.Client
	w         worker.Worker
	taskQueue string
	timeouts  Timeouts
	log       func(msg string, args ...any)
	// Describe looks a run up so workflows and signals carry readable details.
	Describe func(ctx context.Context, runID string) (RunInfo, bool)
}

type TemporalConfig struct {
	Address   string
	Namespace string
	TaskQueue string
	Timeouts  Timeouts
}

// NewTemporal connects to Temporal, registers the workflows and activities,
// and starts a worker on the tenant's task queue.
func NewTemporal(cfg TemporalConfig, acts *Activities, logf func(string, ...any)) (*Temporal, error) {
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	// Temporal may still be starting (e.g. in Compose, the namespace can lag
	// the frontend): retry connecting and starting the worker for a while.
	var c client.Client
	var w worker.Worker
	var err error
	for deadline := time.Now().Add(90 * time.Second); ; {
		if c, err = client.Dial(client.Options{HostPort: cfg.Address, Namespace: cfg.Namespace}); err == nil {
			w = worker.New(c, cfg.TaskQueue, worker.Options{})
			w.RegisterWorkflow(RunLifecycle)
			w.RegisterActivity(acts)
			if err = w.Start(); err == nil {
				break
			}
			c.Close()
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		if logf != nil {
			logf("waiting for Temporal", "address", cfg.Address, "err", err)
		}
		time.Sleep(3 * time.Second)
	}
	t := &Temporal{c: c, w: w, taskQueue: cfg.TaskQueue, timeouts: cfg.Timeouts, log: logf}
	// Drift checks are started by people, never on a schedule. Stop the cron
	// workflow earlier versions started, so it no longer fires every minute.
	tctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.TerminateWorkflow(tctx, "drift-sweep-"+cfg.TaskQueue, "", "drift checks are manual")
	return t, nil
}

func isAlreadyStarted(err error) bool { return temporal.IsWorkflowExecutionAlreadyStartedError(err) }

func (t *Temporal) Name() string { return "temporal" }

func (t *Temporal) Close() {
	t.w.Stop()
	t.c.Close()
}

func workflowID(runID string) string { return "run-" + runID }

func (t *Temporal) describe(ctx context.Context, runID string) (RunInfo, bool) {
	if t.Describe == nil {
		return RunInfo{}, false
	}
	return t.Describe(ctx, runID)
}

func (t *Temporal) RunCreated(ctx context.Context, runID string) {
	in := RunInput{RunID: runID, Timeouts: t.timeouts, Deadlines: map[string]string{
		"planning": t.timeouts.Planning.String(), "approval": t.timeouts.Approval.String(), "applying": t.timeouts.Applying.String()}}
	opts := client.StartWorkflowOptions{ID: workflowID(runID), TaskQueue: t.taskQueue}
	if info, ok := t.describe(ctx, runID); ok {
		in.Run = &info
		opts.Memo = map[string]any{"tenant": info.Tenant, "stack": info.Stack, "business_unit": info.BU, "environment": info.Environment, "operation": info.Operation, "requested_by": info.RequestedBy}
		opts.StaticSummary = fmt.Sprintf("%s %s in %s (%s)", info.Operation, info.Stack, info.Environment, info.Tenant)
		details := fmt.Sprintf("**Run** `%s`\n\n- Stack: `%s` (business unit `%s`)\n- Environment: `%s`\n- Operation: `%s`\n- Requested by: %s", info.RunID, info.Stack, info.BU, info.Environment, info.Operation, info.RequestedBy)
		if info.Origin != "" {
			details += "\n- Origin: " + info.Origin
		}
		if info.Link != "" {
			details += "\n\n[Open in SrustiOps](" + info.Link + ")"
		}
		opts.StaticDetails = details
	}
	_, err := t.c.ExecuteWorkflow(context.WithoutCancel(ctx), opts, RunLifecycle, in)
	if err != nil && !isAlreadyStarted(err) {
		t.log("starting run workflow failed", "run", runID, "err", err)
	}
}

func (t *Temporal) signal(ctx context.Context, runID, name string, arg any) {
	if err := t.c.SignalWorkflow(context.WithoutCancel(ctx), workflowID(runID), "", name, arg); err != nil {
		t.log("signalling run workflow failed", "run", runID, "signal", name, "err", err)
	}
}

// statusSignal carries the run's current status with a signal.
func (t *Temporal) statusSignal(ctx context.Context, runID, fallback string, awaiting *bool) Signal {
	sg := Signal{Status: fallback, AwaitingApproval: awaiting}
	if info, ok := t.describe(ctx, runID); ok && info.Status != "" {
		sg.Status = info.Status
	}
	return sg
}

func (t *Temporal) Planned(ctx context.Context, runID string, awaiting bool) {
	t.signal(ctx, runID, SignalPlanned, t.statusSignal(ctx, runID, "planned", &awaiting))
}
func (t *Temporal) Approved(ctx context.Context, runID string) {
	t.signal(ctx, runID, SignalApproved, t.statusSignal(ctx, runID, "apply_queued", nil))
}
func (t *Temporal) Finished(ctx context.Context, runID string) {
	t.signal(ctx, runID, SignalFinished, t.statusSignal(ctx, runID, "finished", nil))
}
