// Package metrics exposes counters, gauges and histograms in the Prometheus
// text format, without a client library: the planes need a handful of
// series, and every dependency is one more thing to vet.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds a process's series.
type Registry struct {
	mu     sync.Mutex
	series map[string]*family
	// Collect runs before every scrape, to set gauges read from elsewhere.
	collectors []func()
}

type family struct {
	name, help, kind string
	buckets          []float64
	mu               sync.Mutex
	values           map[string]*value // by rendered label set
}

type value struct {
	n      atomic.Uint64 // float64 bits for counters and gauges
	counts []atomic.Uint64
	sum    atomic.Uint64
	labels string
}

func New() *Registry { return &Registry{series: map[string]*family{}} }

// Default is the process-wide registry.
var Default = New()

func (r *Registry) family(name, help, kind string, buckets []float64) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.series[name]
	if f == nil {
		f = &family{name: name, help: help, kind: kind, buckets: buckets, values: map[string]*value{}}
		r.series[name] = f
	}
	return f
}

// OnCollect registers a function run before each scrape.
func (r *Registry) OnCollect(fn func()) {
	r.mu.Lock()
	r.collectors = append(r.collectors, fn)
	r.mu.Unlock()
}

// labelString renders label pairs sorted by name, so one series has one
// spelling however callers order its labels.
func labelString(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	idx := make([]int, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		idx = append(idx, i)
	}
	sort.Slice(idx, func(a, b int) bool { return kv[idx[a]] < kv[idx[b]] })
	var b strings.Builder
	b.WriteByte('{')
	for n, i := range idx {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i])
		b.WriteString(`="`)
		b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(kv[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func (f *family) get(kv []string) *value {
	key := labelString(kv)
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.values[key]
	if v == nil {
		v = &value{labels: key}
		if f.kind == "histogram" {
			v.counts = make([]atomic.Uint64, len(f.buckets)+1)
		}
		f.values[key] = v
	}
	return v
}

func addFloat(a *atomic.Uint64, d float64) {
	for {
		old := a.Load()
		if a.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+d)) {
			return
		}
	}
}

// Counter only goes up.
type Counter struct{ f *family }

func (r *Registry) Counter(name, help string) Counter {
	return Counter{r.family(name, help, "counter", nil)}
}

// Add adds d to the series with these label pairs ("code", "2xx", ...).
func (c Counter) Add(d float64, labels ...string) { addFloat(&c.f.get(labels).n, d) }
func (c Counter) Inc(labels ...string)            { c.Add(1, labels...) }

// Gauge is set to the current value.
type Gauge struct{ f *family }

func (r *Registry) Gauge(name, help string) Gauge { return Gauge{r.family(name, help, "gauge", nil)} }

func (g Gauge) Set(v float64, labels ...string) { g.f.get(labels).n.Store(math.Float64bits(v)) }

// Reset drops every series of the gauge (before re-setting the current ones).
func (g Gauge) Reset() {
	g.f.mu.Lock()
	g.f.values = map[string]*value{}
	g.f.mu.Unlock()
}

// Histogram counts observations into buckets.
type Histogram struct{ f *family }

// DurationBuckets suit HTTP request times, in seconds.
var DurationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

func (r *Registry) Histogram(name, help string, buckets []float64) Histogram {
	return Histogram{r.family(name, help, "histogram", buckets)}
}

func (h Histogram) Observe(v float64, labels ...string) {
	x := h.f.get(labels)
	i := sort.SearchFloat64s(h.f.buckets, v)
	x.counts[i].Add(1)
	addFloat(&x.sum, v)
}

// Write renders every series.
func (r *Registry) Write(w http.ResponseWriter) {
	r.mu.Lock()
	cols := append([]func(){}, r.collectors...)
	names := make([]string, 0, len(r.series))
	for n := range r.series {
		names = append(names, n)
	}
	r.mu.Unlock()
	for _, c := range cols {
		c()
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	for _, n := range names {
		r.mu.Lock()
		f := r.series[n]
		r.mu.Unlock()
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		f.mu.Lock()
		keys := make([]string, 0, len(f.values))
		for k := range f.values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := f.values[k]
			if f.kind != "histogram" {
				fmt.Fprintf(w, "%s%s %s\n", f.name, k, num(math.Float64frombits(v.n.Load())))
				continue
			}
			var cum uint64
			for i, b := range f.buckets {
				cum += v.counts[i].Load()
				fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, withLE(k, num(b)), cum)
			}
			cum += v.counts[len(f.buckets)].Load()
			fmt.Fprintf(w, "%s_bucket%s %d\n%s_sum%s %s\n%s_count%s %d\n", f.name, withLE(k, "+Inf"), cum,
				f.name, k, num(math.Float64frombits(v.sum.Load())), f.name, k, cum)
		}
		f.mu.Unlock()
	}
}

func withLE(labels, le string) string {
	if labels == "" {
		return `{le="` + le + `"}`
	}
	return labels[:len(labels)-1] + `,le="` + le + `"}`
}

func num(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// Handler serves the registry.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { r.Write(w) })
}

// Serve runs a metrics listener (SRUSTIOPS_METRICS_LISTEN) until ctx ends.
// It is a separate port so it never shares the public listener.
func Serve(ctx context.Context, log *slog.Logger, addr string, r *Registry) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", r.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Info("metrics serving", "listen", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("metrics listener stopped", "err", err)
	}
}

// Requests wraps a handler, counting requests by method class and status
// class and timing them. route names the series ("central", "tenant").
func (r *Registry) Requests(route string, next http.Handler) http.Handler {
	total := r.Counter("srustiops_http_requests_total", "HTTP requests served, by plane and status class.")
	dur := r.Histogram("srustiops_http_request_duration_seconds", "HTTP request time, by plane.", DurationBuckets)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		sw := &codeWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, req)
		if strings.HasSuffix(req.URL.Path, "/stream") {
			return // streams last minutes; they would swamp the timings
		}
		total.Inc("plane", route, "code", strconv.Itoa(sw.code/100)+"xx")
		dur.Observe(time.Since(start).Seconds(), "plane", route)
	})
}

type codeWriter struct {
	http.ResponseWriter
	code int
}

func (w *codeWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }
func (w *codeWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *codeWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
