package auditexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
)

type memSource []audit.Event

func (m memSource) AuditAfter(ctx context.Context, after int64, limit int) ([]audit.Event, error) {
	var out []audit.Event
	for _, e := range m {
		if e.ID > after && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func events(n int) memSource {
	var m memSource
	for i := 1; i <= n; i++ {
		m = append(m, audit.Event{ID: int64(i), TS: time.Date(2026, 11, 12, 10, 0, i%60, 0, time.UTC), Actor: "alice", Action: "run.create", Target: "run/x", Payload: json.RawMessage(`{"n":1}`)})
	}
	return m
}

func TestWebhookSplunkAndS3(t *testing.T) {
	var mu sync.Mutex
	got := map[string][][]byte{}
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/hook":
			if !Verify([]byte("a-long-signing-secret"), b, r.Header.Get("X-SrustiOps-Signature")) {
				w.WriteHeader(401)
				return
			}
			if fail { // the first delivery fails: the batch is retried from the same cursor
				fail = false
				w.WriteHeader(503)
				return
			}
		case r.URL.Path == "/services/collector/event":
			if r.Header.Get("Authorization") != "Splunk hec-token" {
				w.WriteHeader(403)
				return
			}
		case r.Method == http.MethodPut: // S3
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
				w.WriteHeader(403)
				return
			}
		}
		got[r.URL.Path] = append(got[r.URL.Path], b)
	}))
	defer srv.Close()
	ctx := context.Background()
	src := events(1200)
	x := &Exporter{Plane: "tenant:acme"}

	hook := Config{Kind: "webhook", URL: srv.URL + "/hook", Secret: "a-long-signing-secret"}
	if p := hook.Validate(); len(p) > 0 {
		t.Fatal(p)
	}
	st := x.Run(ctx, hook, src, Status{}, 10)
	if st.Cursor != 0 || st.LastError == "" {
		t.Fatalf("a failed delivery must not move the cursor: %+v", st)
	}
	st = x.Run(ctx, hook, src, st, 10)
	if st.Cursor != 1200 || st.Sent != 1200 || st.LastError != "" || len(got["/hook"]) != 3 {
		t.Fatalf("webhook: %+v, %d deliveries", st, len(got["/hook"]))
	}
	var first struct {
		Plane  string        `json:"plane"`
		Events []audit.Event `json:"events"`
	}
	json.Unmarshal(got["/hook"][0], &first)
	if first.Plane != "tenant:acme" || len(first.Events) != 500 || first.Events[0].ID != 1 {
		t.Fatalf("first batch: %s %d", first.Plane, len(first.Events))
	}
	if st2 := x.Run(ctx, hook, src, st, 10); st2.Cursor != 1200 || len(got["/hook"]) != 3 {
		t.Fatal("caught up: nothing more is sent")
	}

	splunk := Config{Kind: "splunk", URL: srv.URL, Secret: "hec-token", Index: "infra"}
	if st := x.Run(ctx, splunk, events(3), Status{}, 1); st.Cursor != 3 {
		t.Fatalf("splunk: %+v", st)
	}
	sc := bufio.NewScanner(bytes.NewReader(got["/services/collector/event"][0]))
	lines := 0
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil || m["sourcetype"] != "srustiops:audit" || m["index"] != "infra" {
			t.Fatalf("splunk line: %s", sc.Bytes())
		}
		lines++
	}
	if lines != 3 {
		t.Fatalf("splunk lines: %d", lines)
	}

	s3 := Config{Kind: "s3", URL: "s3://audit-bucket/srustiops?endpoint=" + url.QueryEscape(srv.URL) + "&region=eu-west-1", AccessKey: "AKIAEXAMPLE", Secret: "secretsecret"}
	if p := s3.Validate(); len(p) > 0 {
		t.Fatal(p)
	}
	if st := x.Run(ctx, s3, events(2), Status{}, 1); st.Cursor != 2 || st.LastError != "" {
		t.Fatalf("s3: %+v", st)
	}
	found := false
	for p := range got {
		if strings.Contains(p, "tenant-acme/2026/11/12/000000000001-000000000002.jsonl") {
			found = true
		}
	}
	if !found {
		t.Fatalf("s3 key: %v", got)
	}
	if p := (&Config{Kind: "webhook", URL: "http://example.com/x", Secret: "short"}).Validate(); len(p) != 2 {
		t.Fatalf("validation: %v", p)
	}
}

func TestRangeAndCSV(t *testing.T) {
	s, u, err := ParseRange(url.Values{"since": {"2026-11-01"}, "until": {"2026-11-02"}})
	if err != nil || s.Day() != 1 || u.Day() != 3 {
		t.Fatalf("range: %v %v %v", s, u, err)
	}
	if _, _, err := ParseRange(url.Values{"since": {"2026-11-05"}, "until": {"2026-11-01"}}); err == nil {
		t.Fatal("a reversed range was accepted")
	}
	rec := httptest.NewRecorder()
	evs := events(3)
	evs[0].Actor = "=cmd()"
	calls := 0
	ServeCSV(rec, "audit.csv", func(before int64) ([]audit.Event, error) {
		calls++
		if before == 0 {
			return []audit.Event{evs[2], evs[1], evs[0]}, nil
		}
		return nil, nil
	})
	out := rec.Body.String()
	if !strings.HasPrefix(out, "id,time,actor") || strings.Count(out, "\n") != 4 || !strings.Contains(out, "'=cmd()") {
		t.Fatalf("csv: %s", out)
	}
}
