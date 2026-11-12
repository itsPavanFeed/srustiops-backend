package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"regexp"
	"time"
)

// Request tracing across planes with W3C Trace Context: each request keeps
// the caller's trace (traceparent) or starts one, answers with it (and its
// trace ID as X-Request-Id), and central passes it on to the workspace it
// calls, so one trace ID follows a request through central, the link and
// the tenant plane. Slow and failed requests are logged with it.

var traceparentRe = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$`)

type traceKey struct{}

type traceCtx struct{ traceID, spanID, flags string }

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TraceID is the request's trace ID ("" outside a traced request).
func TraceID(ctx context.Context) string {
	if t, ok := ctx.Value(traceKey{}).(*traceCtx); ok {
		return t.traceID
	}
	return ""
}

// Traceparent is the header for an outgoing call made while handling ctx: the
// same trace, a new span.
func Traceparent(ctx context.Context) string {
	t, ok := ctx.Value(traceKey{}).(*traceCtx)
	if !ok {
		return ""
	}
	return "00-" + t.traceID + "-" + randHex(8) + "-" + t.flags
}

// SetTrace adds the traceparent of ctx to an outgoing request.
func SetTrace(ctx context.Context, req *http.Request) {
	if tp := Traceparent(ctx); tp != "" {
		req.Header.Set("traceparent", tp)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int)           { w.status = c; w.ResponseWriter.WriteHeader(c) }
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Trace wraps a plane's handler. plane names it in the logs; slow is the
// duration after which a request is logged (streams are not).
func Trace(log *slog.Logger, plane string, slow time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := &traceCtx{spanID: randHex(8), flags: "01"}
		if m := traceparentRe.FindStringSubmatch(r.Header.Get("traceparent")); m != nil && m[1] != "00000000000000000000000000000000" {
			t.traceID, t.flags = m[1], m[3]
		} else {
			t.traceID = randHex(16)
		}
		w.Header().Set("traceparent", "00-"+t.traceID+"-"+t.spanID+"-"+t.flags)
		w.Header().Set("X-Request-Id", t.traceID)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		start := time.Now()
		next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), traceKey{}, t)))
		d := time.Since(start)
		stream := r.Header.Get("Accept") == "text/event-stream"
		if log != nil && (sw.status >= 500 || (d > slow && !stream)) {
			lvl := slog.LevelWarn
			if sw.status >= 500 {
				lvl = slog.LevelError
			}
			log.Log(r.Context(), lvl, "request", "plane", plane, "method", r.Method, "path", r.URL.Path, "status", sw.status,
				"ms", d.Milliseconds(), "trace", t.traceID)
		}
	})
}
