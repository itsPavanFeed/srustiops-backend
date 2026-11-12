package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// runLoadTest drives a workspace's busiest read paths through central with
// many concurrent clients, then reports throughput, latency percentiles and
// errors per path. Read-only: nothing is changed. Use a token of a test
// workspace; rate limits apply (turned-away requests are counted).
func runLoadTest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("loadtest", flag.ExitOnError)
	base := fs.String("url", "", "central's URL, e.g. https://srustiops.example.com")
	tenant := fs.String("tenant", "", "the workspace to load")
	tokenFile := fs.String("token-file", "", "file holding a SrustiOps API token for that workspace")
	caFile := fs.String("ca", "", "CA certificate to trust (optional)")
	conc := fs.Int("c", 20, "concurrent clients")
	dur := fs.Duration("d", 30*time.Second, "how long")
	paths := fs.String("paths", "/stacks?limit=50,/runs?limit=50,/inventory/summary,/notifications?limit=20,/costs,/me", "workspace paths to request, comma-separated")
	fs.Parse(args)
	if *base == "" || *tenant == "" || *tokenFile == "" {
		return errors.New("usage: srustiops loadtest -url URL -tenant T -token-file F [-c 20] [-d 30s] [-paths P,...]")
	}
	tok, err := os.ReadFile(*tokenFile)
	if err != nil {
		return err
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tc.RootCAs = pool
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: *conc}}
	ps := strings.Split(*paths, ",")
	type stat struct {
		lat           []time.Duration
		errs, limited int
		statuses      map[int]int
	}
	stats := map[string]*stat{}
	for _, p := range ps {
		stats[p] = &stat{statuses: map[int]int{}}
	}
	var mu sync.Mutex
	ctx, cancel := context.WithTimeout(ctx, *dur)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := i; ctx.Err() == nil; n++ {
				p := ps[n%len(ps)]
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(*base, "/")+"/api/v1/t/"+*tenant+p, nil)
				req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
				t0 := time.Now()
				resp, err := hc.Do(req)
				d := time.Since(t0)
				if ctx.Err() != nil {
					return
				}
				mu.Lock()
				st := stats[p]
				if err != nil {
					st.errs++
				} else {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					st.statuses[resp.StatusCode]++
					switch {
					case resp.StatusCode == http.StatusTooManyRequests:
						st.limited++
					case resp.StatusCode >= 400:
						st.errs++
					default:
						st.lat = append(st.lat, d)
					}
				}
				mu.Unlock()
				if err == nil && resp.StatusCode == http.StatusTooManyRequests {
					time.Sleep(time.Second)
				}
			}
		}(i)
	}
	wg.Wait()
	el := time.Since(start).Seconds()
	pct := func(l []time.Duration, q float64) string {
		if len(l) == 0 {
			return "-"
		}
		return l[int(float64(len(l)-1)*q)].Round(time.Millisecond).String()
	}
	fmt.Printf("%d clients for %s against %s\n\n%-28s %8s %8s %8s %8s %8s %8s\n", *conc, *dur, *tenant, "path", "ok/s", "p50", "p95", "p99", "errors", "429s")
	total, failed := 0, 0
	for _, p := range ps {
		st := stats[p]
		sort.Slice(st.lat, func(i, j int) bool { return st.lat[i] < st.lat[j] })
		total += len(st.lat)
		failed += st.errs
		fmt.Printf("%-28s %8.1f %8s %8s %8s %8d %8d\n", p, float64(len(st.lat))/el, pct(st.lat, .5), pct(st.lat, .95), pct(st.lat, .99), st.errs, st.limited)
	}
	fmt.Printf("\n%.1f successful requests/s, %d errors\n", float64(total)/el, failed)
	if failed > 0 {
		return fmt.Errorf("%d requests failed", failed)
	}
	return nil
}
