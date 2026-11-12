// Package auditexport gets audit events out of SrustiOps: date-range
// filters and CSV downloads for people, and a continuous export to a SIEM —
// a signed webhook, a Splunk HTTP Event Collector, or JSON lines in an S3
// bucket. The export keeps a cursor (the last event id sent), so it resumes
// where it stopped and every event is sent at least once, in order.
package auditexport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
	"github.com/itsPavanFeed/srustiops-backend/internal/blob"
)

// ---- date ranges and CSV ----

// ParseRange reads ?since= and ?until= as RFC 3339 times or YYYY-MM-DD dates
// (an until date includes that whole day).
func ParseRange(q url.Values) (since, until time.Time, err error) {
	parse := func(v string, end bool) (time.Time, error) {
		if v == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t, nil
		}
		t, err := time.Parse("2006-01-02", v)
		if err != nil {
			return time.Time{}, fmt.Errorf("%q is not a date (YYYY-MM-DD) or an RFC 3339 time", v)
		}
		if end {
			t = t.AddDate(0, 0, 1)
		}
		return t, nil
	}
	if since, err = parse(q.Get("since"), false); err != nil {
		return
	}
	if until, err = parse(q.Get("until"), true); err != nil {
		return
	}
	if !since.IsZero() && !until.IsZero() && !until.After(since) {
		err = errors.New("until must be after since")
	}
	return
}

// MaxCSVRows bounds one download.
const MaxCSVRows = 100000

// ServeCSV streams events newest first as CSV, paging with page(before).
func ServeCSV(w http.ResponseWriter, filename string, page func(before int64) ([]audit.Event, error)) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"id", "time", "actor", "action", "target", "scope", "payload", "hash"})
	var before int64
	rows := 0
	for rows < MaxCSVRows {
		evs, err := page(before)
		if err != nil || len(evs) == 0 {
			break
		}
		for _, e := range evs {
			cw.Write([]string{strconv.FormatInt(e.ID, 10), e.TS.UTC().Format(time.RFC3339Nano), csvSafe(e.Actor), csvSafe(e.Action), csvSafe(e.Target), csvSafe(e.Scope), string(e.Payload), e.Hash})
			rows++
		}
		before = evs[len(evs)-1].ID
		cw.Flush()
	}
	cw.Flush()
}

// csvSafe stops spreadsheet formula injection: a cell starting with = + - @
// is prefixed with a quote.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// ---- continuous export ----

// Config is where events go. Secret is the webhook's signing key, the
// Splunk HEC token, or the S3 secret key; it is stored sealed.
type Config struct {
	Enabled   bool   `json:"enabled"`
	Kind      string `json:"kind"` // webhook | splunk | s3
	URL       string `json:"url"`  // webhook URL | HEC base URL | s3://bucket/prefix?region=…&endpoint=…
	Secret    string `json:"secret,omitempty"`
	AccessKey string `json:"access_key,omitempty"` // S3
	Index     string `json:"index,omitempty"`      // Splunk index (optional)
}

// Status is the export's progress.
type Status struct {
	Cursor    int64      `json:"cursor"` // last event id delivered
	Sent      int64      `json:"sent"`
	LastSent  *time.Time `json:"last_sent,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	FailedAt  *time.Time `json:"failed_at,omitempty"`
}

func loopback(h string) bool {
	ip := net.ParseIP(h)
	return h == "localhost" || (ip != nil && ip.IsLoopback())
}

// Validate checks a configuration (with the secret already filled in).
func (c *Config) Validate() []string {
	var probs []string
	u, err := url.Parse(c.URL)
	switch c.Kind {
	case "webhook", "splunk":
		if err != nil || u.Host == "" || !(u.Scheme == "https" || (u.Scheme == "http" && loopback(u.Hostname()))) {
			probs = append(probs, "url must be an https URL")
		}
		if c.Kind == "webhook" && len(c.Secret) < 16 {
			probs = append(probs, "a webhook needs a signing secret of at least 16 characters")
		}
		if c.Kind == "splunk" && c.Secret == "" {
			probs = append(probs, "Splunk needs the HEC token")
		}
	case "s3":
		if _, err := blob.ParseURL(c.URL, c.AccessKey, c.Secret); err != nil {
			probs = append(probs, "url: "+err.Error())
		}
		if c.AccessKey == "" || c.Secret == "" {
			probs = append(probs, "S3 needs an access key and a secret key")
		}
	default:
		probs = append(probs, `kind must be "webhook", "splunk" or "s3"`)
	}
	if len(c.Index) > 80 {
		probs = append(probs, "index is too long")
	}
	return probs
}

// Source reads audit events after an id.
type Source interface {
	AuditAfter(ctx context.Context, after int64, limit int) ([]audit.Event, error)
}

const batch = 500

// Exporter sends events for one plane ("tenant:acme", "central").
type Exporter struct {
	Plane string
	HC    *http.Client
}

// Run sends everything after st.Cursor, a batch at a time (at most
// maxBatches per call), and returns the updated status. A failed batch
// stops the run; it is retried from the same cursor next time.
func (x *Exporter) Run(ctx context.Context, c Config, src Source, st Status, maxBatches int) Status {
	for i := 0; i < maxBatches; i++ {
		evs, err := src.AuditAfter(ctx, st.Cursor, batch)
		if err != nil {
			return x.fail(st, err)
		}
		if len(evs) == 0 {
			return st
		}
		if err := x.Send(ctx, c, evs); err != nil {
			return x.fail(st, err)
		}
		now := time.Now()
		st.Cursor, st.Sent, st.LastSent, st.LastError, st.FailedAt = evs[len(evs)-1].ID, st.Sent+int64(len(evs)), &now, "", nil
	}
	return st
}

func (x *Exporter) fail(st Status, err error) Status {
	now := time.Now()
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	st.LastError, st.FailedAt = msg, &now
	return st
}

func (x *Exporter) client() *http.Client {
	if x.HC != nil {
		return x.HC
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Send delivers one batch.
func (x *Exporter) Send(ctx context.Context, c Config, evs []audit.Event) error {
	switch c.Kind {
	case "webhook":
		body, _ := json.Marshal(map[string]any{"source": "srustiops", "plane": x.Plane, "events": evs})
		mac := hmac.New(sha256.New, []byte(c.Secret))
		mac.Write(body)
		return x.post(ctx, c.URL, body, map[string]string{"Content-Type": "application/json", "X-SrustiOps-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil)),
			"X-SrustiOps-Events": fmt.Sprintf("%d-%d", evs[0].ID, evs[len(evs)-1].ID)})
	case "splunk":
		var buf bytes.Buffer
		for _, e := range evs {
			m := map[string]any{"time": float64(e.TS.UnixMilli()) / 1000, "source": "srustiops:" + x.Plane, "sourcetype": "srustiops:audit", "event": e}
			if c.Index != "" {
				m["index"] = c.Index
			}
			b, _ := json.Marshal(m)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		return x.post(ctx, strings.TrimRight(c.URL, "/")+"/services/collector/event", buf.Bytes(),
			map[string]string{"Content-Type": "application/json", "Authorization": "Splunk " + c.Secret})
	case "s3":
		cfg, err := blob.ParseURL(c.URL, c.AccessKey, c.Secret)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		for _, e := range evs {
			b, _ := json.Marshal(e)
			buf.Write(b)
			buf.WriteByte('\n')
		}
		t := evs[0].TS.UTC()
		key := fmt.Sprintf("%s/%04d/%02d/%02d/%012d-%012d.jsonl", strings.ReplaceAll(x.Plane, ":", "-"), t.Year(), t.Month(), t.Day(), evs[0].ID, evs[len(evs)-1].ID)
		return blob.New(cfg, x.client()).Put(ctx, key, buf.Bytes())
	}
	return fmt.Errorf("unknown export kind %q", c.Kind)
}

func (x *Exporter) post(ctx context.Context, u string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "SrustiOps-AuditExport")
	resp, err := x.client().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s answered %s", hostOf(u), resp.Status)
	}
	return nil
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return "the destination"
}

// Verify checks a webhook delivery's signature (for receivers, and tests).
func Verify(secret, body []byte, header string) bool {
	h, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	want, err := hex.DecodeString(h)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), want)
}
