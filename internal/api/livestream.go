package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- live streams ----
//
// Database triggers notify channel srustiops_events with "<kind>:<id>:<bu>"
// on every log chunk, run change, approval and stack change (migration 026).
// One connection per tenant plane listens and fans the events out to open
// server-sent-event streams, so the console updates the moment something
// changes instead of polling every few seconds.

// change is one notification.
type change struct{ Kind, ID, BU string }

type changeHub struct {
	mu   sync.Mutex
	subs map[chan change]struct{}
}

func newChangeHub() *changeHub { return &changeHub{subs: map[chan change]struct{}{}} }

func (h *changeHub) subscribe() (chan change, func()) {
	ch := make(chan change, 64)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
}

func (h *changeHub) publish(c change) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- c:
		default: // a slow reader misses events, never blocks the hub; it re-reads on reconnect
		}
	}
}

func (h *changeHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// listenChanges holds one connection listening for change events, and
// reconnects after errors.
func (s *Server) listenChanges(ctx context.Context) {
	for ctx.Err() == nil {
		if err := s.listenOnce(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("change stream listener stopped; retrying", "err", err)
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (s *Server) listenOnce(ctx context.Context) error {
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN srustiops_events`); err != nil {
		return err
	}
	// Anything missed while disconnected: tell every stream to re-read.
	s.changes.publish(change{Kind: "resync"})
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		p := strings.SplitN(n.Payload, ":", 3)
		if len(p) == 3 {
			s.changes.publish(change{Kind: p[0], ID: p[1], BU: p[2]})
		}
	}
}

// sse starts a server-sent-event response that may outlive the server's
// write timeout; streams end after streamMax and clients reconnect.
const streamMax = 30 * time.Minute

func sse(w http.ResponseWriter) (func(event, id string, data any) error, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming is not supported here")
		return nil, false
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(streamMax + time.Minute))
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // proxies must not buffer the stream
	w.WriteHeader(200)
	f.Flush()
	return func(event, id string, data any) error {
		b, _ := json.Marshal(data)
		var sb strings.Builder
		if id != "" {
			sb.WriteString("id: " + id + "\n")
		}
		if event != "" {
			sb.WriteString("event: " + event + "\n")
		}
		sb.WriteString("data: " + string(b) + "\n\n")
		if _, err := w.Write([]byte(sb.String())); err != nil {
			return err
		}
		f.Flush()
		return nil
	}, true
}

// streamRunLogs streams a run's log: what is there after ?after= (or the
// Last-Event-ID a reconnecting client sends), then each chunk as it is
// written, and an "end" event once the run has finished.
func (s *Server) streamRunLogs(w http.ResponseWriter, r *http.Request) {
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		after, _ = strconv.ParseInt(v, 10, 64)
	}
	ch, done := s.changes.subscribe()
	defer done()
	send, ok := sse(w)
	if !ok {
		return
	}
	flush := func() error {
		for {
			logs, err := s.runLogs(r.Context(), run, after)
			if err != nil {
				return err
			}
			for _, c := range logs {
				if err := send("log", strconv.FormatInt(c.Seq, 10), c); err != nil {
					return err
				}
				after = c.Seq
			}
			if len(logs) < 1000 {
				return nil
			}
		}
	}
	finished := func() bool {
		cur, err := s.store.GetRun(r.Context(), run.ID)
		return err != nil || slices.Contains(store.Terminal, cur.Status)
	}
	if flush() != nil {
		return
	}
	if finished() {
		send("end", "", map[string]string{"run": run.ID})
		return
	}
	deadline := time.After(streamMax)
	beat := time.NewTicker(20 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return // the client reconnects with Last-Event-ID
		case <-beat.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		case c := <-ch:
			if c.Kind == "resync" || (c.ID == run.ID && (c.Kind == "log" || c.Kind == "run")) {
				if flush() != nil {
					return
				}
				if c.Kind != "log" && finished() {
					flush()
					send("end", "", map[string]string{"run": run.ID})
					return
				}
			}
		}
	}
}

// streamChanges streams which runs and stacks the caller can see changed, so
// open lists refresh at once. Events carry only the kind and ID; the console
// re-reads through the ordinary, permission-checked API.
func (s *Server) streamChanges(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	ch, done := s.changes.subscribe()
	defer done()
	send, ok := sse(w)
	if !ok {
		return
	}
	if send("ready", "", map[string]int{"listeners": s.changes.count()}) != nil {
		return
	}
	deadline := time.After(streamMax)
	beat := time.NewTicker(20 * time.Second)
	defer beat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return
		case <-beat.C:
			if _, err := w.Write([]byte(": keep-alive\n\n")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		case c := <-ch:
			if c.Kind == "log" {
				continue // log chunks go to the run's own stream
			}
			if c.Kind != "resync" && !p.CanView(c.BU) {
				continue
			}
			if send(c.Kind, "", map[string]string{"id": c.ID}) != nil {
				return
			}
		}
	}
}

// runLogs reads a run's log chunks after seq: from the bucket once archived,
// otherwise from the database.
func (s *Server) runLogs(ctx context.Context, run *store.Run, after int64) ([]store.LogChunk, error) {
	if s.objects != nil && s.store.LogsArchived(ctx, run.ID) {
		b, err := s.objects.Get(ctx, logKey(run.ID))
		if err != nil {
			return nil, fmt.Errorf("reading the archived log: %w", err)
		}
		var all []store.LogChunk
		if err := json.Unmarshal(b, &all); err != nil {
			return nil, err
		}
		out := []store.LogChunk{}
		for _, c := range all {
			if c.Seq > after && len(out) < 1000 {
				out = append(out, c)
			}
		}
		return out, nil
	}
	return s.store.Logs(ctx, run.ID, after)
}

func logKey(runID string) string { return "logs/" + runID + ".json" }

// archiveLogs moves a finished run's log to the tenant bucket, so the
// database keeps only live logs. Without a bucket, logs stay in PostgreSQL.
func (s *Server) archiveLogs(ctx context.Context, runID string) {
	if s.objects == nil {
		return
	}
	var all []store.LogChunk
	for after := int64(0); ; {
		page, err := s.store.Logs(ctx, runID, after)
		if err != nil {
			s.log.Warn("archiving run log failed", "run", runID, "err", err)
			return
		}
		all = append(all, page...)
		if len(page) < 1000 {
			break
		}
		after = page[len(page)-1].Seq
	}
	if len(all) == 0 {
		return
	}
	b, _ := json.Marshal(all)
	if err := s.objects.Put(ctx, logKey(runID), b); err != nil {
		s.log.Warn("archiving run log failed", "run", runID, "err", err)
		return
	}
	if err := s.store.MarkLogsArchived(ctx, runID); err != nil {
		s.log.Warn("archiving run log failed", "run", runID, "err", err)
	}
}

// logArchiver moves finished runs' logs to the bucket a few at a time,
// SRUSTIOPS_LOG_ARCHIVE_AFTER (five minutes) after they finish, when late
// chunks have landed.
func (s *Server) logArchiver(ctx context.Context) {
	if s.objects == nil {
		return
	}
	after := s.cfg.LogArchiveAfter
	t := time.NewTicker(min(time.Minute, after))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.store.TryLock(ctx, 7315, func(ctx context.Context) { // one replica archives
			ids, err := s.store.RunsToArchive(ctx, after, 50)
			if err != nil {
				return
			}
			for _, id := range ids {
				s.archiveLogs(ctx, id)
			}
		})
	}
}
