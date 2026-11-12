package httpx

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBucketsAllowBurstThenRefill(t *testing.T) {
	b := NewBuckets()
	r := Rate{PerSecond: 10, Burst: 3}
	for i := 0; i < 3; i++ {
		if !b.Take("k", r).OK {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	v := b.Take("k", r)
	if v.OK || v.Retry <= 0 || v.Retry > 110*time.Millisecond {
		t.Fatalf("over the burst: %+v", v)
	}
	if !b.Take("other", r).OK {
		t.Fatal("keys share a bucket")
	}
	time.Sleep(120 * time.Millisecond)
	if !b.Take("k", r).OK {
		t.Fatal("the bucket did not refill")
	}
	if !b.Take("k", Rate{}).OK {
		t.Fatal("a zero rate must not limit")
	}
}

func TestGateQueuesThenSheds(t *testing.T) {
	g := NewGate()
	ctx := context.Background()
	a := g.Acquire(ctx, "w", 1, 0)
	if a == nil {
		t.Fatal("first slot refused")
	}
	if g.Acquire(ctx, "w", 1, 0) != nil {
		t.Fatal("second request got a slot over the cap")
	}
	go func() { time.Sleep(50 * time.Millisecond); a() }()
	b := g.Acquire(ctx, "w", 1, time.Second)
	if b == nil {
		t.Fatal("a queued request did not get the freed slot")
	}
	if now, peak := g.InFlight("w"); now != 1 || peak != 1 {
		t.Fatalf("in flight %d, peak %d", now, peak)
	}
	b()
	b() // releasing twice is harmless
	if now, _ := g.InFlight("w"); now != 0 {
		t.Fatalf("in flight after release: %d", now)
	}
}

func TestClientIPTrustsOnlyNamedProxies(t *testing.T) {
	defer SetTrustedProxies(nil)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:4000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.9")
	if ip := ClientIP(r); ip != "10.0.0.5" {
		t.Fatalf("an untrusted peer's header was believed: %s", ip)
	}
	nets, err := ParseCIDRs("10.0.0.0/24, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	SetTrustedProxies(nets)
	if ip := ClientIP(r); ip != "198.51.100.7" {
		t.Fatalf("client behind trusted proxies: %s", ip)
	}
	r.Header.Set("X-Forwarded-For", "garbage, 203.0.113.4")
	if ip := ClientIP(r); ip != "203.0.113.4" {
		t.Fatalf("spoofed left-most entry: %s", ip)
	}
}
