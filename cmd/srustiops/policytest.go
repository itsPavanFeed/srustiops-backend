package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/opapolicy"
	"github.com/open-policy-agent/opa/v1/tester"
)

// runPolicy: `srustiops policy test` checks a policy repository in CI, the
// way SrustiOps will run it:
//
//   - every policy (*.rego, not *_test.rego) must compile as a SrustiOps
//     policy (package srustiops.policy, deny rules);
//   - Rego unit tests (*_test.rego, test_* rules) must pass;
//   - each fixture (-fixtures, *.json: {"input": <plan input>, "expect":
//     ["words of a denial", ...]}) must be denied with every expected
//     message, or pass when expect is empty.
//
// The input is what policies see on a real run: run, summary, cost and
// budget (copy one from a plan with Policies → Test against a run).
func runPolicy(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "test" {
		return errors.New("usage: srustiops policy test [-dir DIR] [-fixtures DIR]")
	}
	fl := flag.NewFlagSet("policy test", flag.ExitOnError)
	dir := fl.String("dir", ".", "the policies: *.rego files, with *_test.rego unit tests")
	fixtures := fl.String("fixtures", "", "fixture plans (*.json); default DIR/fixtures when it exists")
	fl.Parse(args[1:])
	if *fixtures == "" {
		if st, err := os.Stat(filepath.Join(*dir, "fixtures")); err == nil && st.IsDir() {
			*fixtures = filepath.Join(*dir, "fixtures")
		}
	}
	failed := 0
	report := func(ok bool, what string, detail ...string) {
		mark := "PASS"
		if !ok {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("%s  %s\n", mark, what)
		for _, d := range detail {
			fmt.Printf("      %s\n", d)
		}
	}

	// 1. Every policy compiles as SrustiOps runs it.
	var sets []opapolicy.Set
	var regoFiles []string // only Rego reaches the unit tests (fixtures are not data)
	err := filepath.WalkDir(*dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".rego") {
			regoFiles = append(regoFiles, p)
		}
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rego") || strings.HasSuffix(p, "_test.rego") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(filepath.Base(p), ".rego")
		if cerr := opapolicy.Compile(string(b)); cerr != nil {
			report(false, "compile "+p, cerr.Error())
			return nil
		}
		report(true, "compile "+p)
		sets = append(sets, opapolicy.Set{Name: name, Level: "hard", Module: string(b)})
		return nil
	})
	if err != nil {
		return err
	}
	if len(sets) == 0 {
		return fmt.Errorf("no policies (*.rego) under %s", *dir)
	}

	// 2. Rego unit tests.
	results, err := tester.Run(ctx, regoFiles...)
	if err != nil {
		return fmt.Errorf("loading the unit tests: %w", err)
	}
	for _, r := range results {
		name := r.Package + "." + r.Name
		switch {
		case r.Skip:
			fmt.Printf("SKIP  %s\n", name)
		case r.Error != nil:
			report(false, "test "+name, r.Error.Error())
		default:
			report(!r.Fail, "test "+name)
		}
	}

	// 3. Fixtures: real-shaped plan inputs and the denials they must get.
	if *fixtures != "" {
		var files []string
		filepath.WalkDir(*fixtures, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".json") {
				files = append(files, p)
			}
			return nil
		})
		sort.Strings(files)
		for _, f := range files {
			b, err := os.ReadFile(f)
			var fx struct {
				Input  map[string]any `json:"input"`
				Expect []string       `json:"expect"`
			}
			if err == nil {
				err = json.Unmarshal(b, &fx)
			}
			if err != nil || fx.Input == nil {
				report(false, "fixture "+f, "a fixture is {\"input\": {...}, \"expect\": [...]}")
				continue
			}
			vs := opapolicy.Evaluate(ctx, sets, fx.Input)
			var got []string
			for _, v := range vs {
				got = append(got, v.Rule+": "+v.Message)
			}
			all := strings.Join(got, "\n")
			var missing []string
			for _, e := range fx.Expect {
				if !strings.Contains(all, e) {
					missing = append(missing, "expected a denial with: "+e)
				}
			}
			if len(fx.Expect) == 0 && len(got) > 0 {
				missing = append(missing, "expected no denials, got:")
				missing = append(missing, got...)
			}
			report(len(missing) == 0, "fixture "+f, missing...)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("all policy checks passed")
	return nil
}
