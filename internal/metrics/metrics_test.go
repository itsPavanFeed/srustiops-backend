package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	c := r.Counter("x_total", "x")
	c.Inc("code", "2xx")
	c.Add(2, "code", "2xx")
	g := r.Gauge("y", "y")
	r.OnCollect(func() { g.Set(7, "pool", `de"fault`) })
	h := r.Histogram("z_seconds", "z", []float64{1, 5})
	h.Observe(0.5)
	h.Observe(3)
	h.Observe(9)
	w := httptest.NewRecorder()
	r.Write(w)
	out := w.Body.String()
	for _, want := range []string{
		`x_total{code="2xx"} 3`,
		`y{pool="de\"fault"} 7`,
		`z_seconds_bucket{le="1"} 1`,
		`z_seconds_bucket{le="5"} 2`,
		`z_seconds_bucket{le="+Inf"} 3`,
		`z_seconds_count 3`,
		"# TYPE z_seconds histogram",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestLabelsAreSorted(t *testing.T) {
	if got := labelString([]string{"plane", "central", "code", "2xx"}); got != `{code="2xx",plane="central"}` {
		t.Fatalf("labels: %s", got)
	}
}
