package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/api"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// runUpdater runs beside a tenant plane and applies the version central's
// fleet rollout gives it (kept in the tenant database, setting fleet_target):
//
//	-mode k8s      rolls the Deployments (SRUSTIOPS_UPDATER_DEPLOYMENTS,
//	               default srustiops-tenant,srustiops-runner) to the new image
//	               tag and waits until every replica is available; with more
//	               than one replica and maxUnavailable 0 nothing goes down.
//	-mode compose  writes SRUSTIOPS_VERSION into the Compose project's .env
//	               (-dir) and runs `docker compose pull` and `up -d`.
//
// It records what happened (setting fleet_status), which tenant admins and
// central see. -once checks once and exits (for cron, and tests).
func runUpdater(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("updater", flag.ExitOnError)
	mode := fs.String("mode", "k8s", "k8s | compose")
	dir := fs.String("dir", ".", "compose: the project directory holding docker-compose.yml and .env")
	every := fs.Duration("every", time.Minute, "how often to check")
	once := fs.Bool("once", false, "check once and exit")
	dry := fs.Bool("dry-run", false, "report what would change, change nothing")
	fs.Parse(args)
	dbURL := os.Getenv("SRUSTIOPS_DATABASE_URL")
	if f := os.Getenv("SRUSTIOPS_DATABASE_URL_FILE"); dbURL == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		dbURL = strings.TrimSpace(string(b))
	}
	if dbURL == "" {
		return errors.New("SRUSTIOPS_DATABASE_URL (the tenant database) is required")
	}
	st, err := store.Open(ctx, dbURL)
	if err != nil {
		return err
	}
	defer st.Close()
	var u upgrader
	switch *mode {
	case "k8s":
		k, err := newKubeSink("")
		if err != nil {
			return err
		}
		deps := os.Getenv("SRUSTIOPS_UPDATER_DEPLOYMENTS")
		if deps == "" {
			deps = "srustiops-tenant,srustiops-runner"
		}
		u = &kubeUpgrader{k: k, deployments: strings.Split(deps, ",")}
	case "compose":
		u = &composeUpgrader{dir: *dir}
	default:
		return errors.New("mode must be k8s or compose")
	}
	for {
		if err := updateOnce(ctx, log, st, u, *dry); err != nil {
			log.Warn("update check failed", "err", err)
		}
		if *once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

type upgrader interface {
	Running(ctx context.Context) (string, error)
	Upgrade(ctx context.Context, version string) error
}

func updateOnce(ctx context.Context, log *slog.Logger, st *store.Store, u upgrader, dry bool) error {
	var t api.FleetTarget
	if ok, err := st.Setting(ctx, "fleet_target", &t); err != nil || !ok || t.Version == "" {
		return err
	}
	running, err := u.Running(ctx)
	if err != nil {
		return err
	}
	report := func(state, detail string) {
		st.PutSetting(ctx, "fleet_status", api.FleetStatus{Running: running, Target: t.Version, State: state, Detail: detail, UpdatedAt: time.Now().UTC()}, "system:updater")
	}
	if running == t.Version {
		report("done", "running the target version")
		return nil
	}
	if dry {
		log.Info("would upgrade", "from", running, "to", t.Version)
		report("idle", fmt.Sprintf("would upgrade %s → %s (dry run)", running, t.Version))
		return nil
	}
	log.Info("upgrading", "from", running, "to", t.Version, "rollout", t.Rollout)
	report("upgrading", fmt.Sprintf("%s → %s", running, t.Version))
	if err := u.Upgrade(ctx, t.Version); err != nil {
		report("failed", err.Error())
		return err
	}
	running = t.Version
	report("done", "upgraded to "+t.Version)
	return nil
}

// ---- Kubernetes ----

type kubeUpgrader struct {
	k           *kubeSink
	deployments []string
}

var tagRe = regexp.MustCompile(`:([^:/@]+)$`)

func (u *kubeUpgrader) call(ctx context.Context, method, name string, body []byte, ct string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, method, u.k.api+"/apis/apps/v1/namespaces/"+u.k.ns+"/deployments/"+name, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+u.k.token)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := u.k.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("deployment %s: %s: %s", name, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

type deployment struct {
	Metadata struct {
		Generation int64 `json:"generation"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int `json:"replicas"`
		Template struct {
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		ObservedGeneration int64 `json:"observedGeneration"`
		UpdatedReplicas    int   `json:"updatedReplicas"`
		AvailableReplicas  int   `json:"availableReplicas"`
		Replicas           int   `json:"replicas"`
	} `json:"status"`
}

func (u *kubeUpgrader) Running(ctx context.Context) (string, error) {
	var d deployment
	if err := u.call(ctx, http.MethodGet, u.deployments[0], nil, "", &d); err != nil {
		return "", err
	}
	for _, c := range d.Spec.Template.Spec.Containers {
		if m := tagRe.FindStringSubmatch(c.Image); m != nil && strings.Contains(c.Image, "srustiops") {
			return m[1], nil
		}
	}
	return "", errors.New("no SrustiOps container in deployment " + u.deployments[0])
}

func (u *kubeUpgrader) Upgrade(ctx context.Context, version string) error {
	for _, name := range u.deployments {
		var d deployment
		if err := u.call(ctx, http.MethodGet, name, nil, "", &d); err != nil {
			return err
		}
		var containers []map[string]string
		for _, c := range d.Spec.Template.Spec.Containers {
			if strings.Contains(c.Image, "srustiops") {
				containers = append(containers, map[string]string{"name": c.Name, "image": tagRe.ReplaceAllString(c.Image, ":"+version)})
			}
		}
		patch, _ := json.Marshal(map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"containers": containers}}}})
		if err := u.call(ctx, http.MethodPatch, name, patch, "application/strategic-merge-patch+json", nil); err != nil {
			return err
		}
		// Wait until the rollout finished: every replica updated and available.
		deadline := time.Now().Add(15 * time.Minute)
		for {
			var cur deployment
			if err := u.call(ctx, http.MethodGet, name, nil, "", &cur); err != nil {
				return err
			}
			want := 1
			if cur.Spec.Replicas != nil {
				want = *cur.Spec.Replicas
			}
			if cur.Status.ObservedGeneration >= cur.Metadata.Generation && cur.Status.UpdatedReplicas == want && cur.Status.AvailableReplicas == want && cur.Status.Replicas == want {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("deployment %s did not become ready on %s within 15 minutes; Kubernetes keeps the old pods serving", name, version)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
	return nil
}

// ---- Docker Compose ----

type composeUpgrader struct{ dir string }

var envVersionRe = regexp.MustCompile(`(?m)^SRUSTIOPS_VERSION=(.*)$`)

func (u *composeUpgrader) Running(ctx context.Context) (string, error) {
	b, err := os.ReadFile(filepath.Join(u.dir, ".env"))
	if err != nil {
		return "", err
	}
	m := envVersionRe.FindSubmatch(b)
	if m == nil {
		return "", errors.New("SRUSTIOPS_VERSION is not set in " + filepath.Join(u.dir, ".env"))
	}
	return strings.Trim(strings.TrimSpace(string(m[1])), `"`), nil
}

func (u *composeUpgrader) Upgrade(ctx context.Context, version string) error {
	p := filepath.Join(u.dir, ".env")
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	prev := b
	b = envVersionRe.ReplaceAll(b, []byte("SRUSTIOPS_VERSION="+version))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	for _, args := range [][]string{{"compose", "pull"}, {"compose", "up", "-d", "--remove-orphans"}} {
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Dir = u.dir
		if out, err := cmd.CombinedOutput(); err != nil {
			os.WriteFile(p, prev, 0o600) // back to the version that ran
			return fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, lastLines(string(out), 5))
		}
	}
	return nil
}

func lastLines(s string, n int) string {
	ls := strings.Split(strings.TrimSpace(s), "\n")
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return strings.Join(ls, " | ")
}
