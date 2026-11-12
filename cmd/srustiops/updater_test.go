package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/api"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

func TestComposeUpdater(t *testing.T) {
	url := os.Getenv("SRUSTIOPS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("SRUSTIOPS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	db := fmt.Sprintf("updater_%d", time.Now().UnixNano())
	admin.Exec(ctx, "CREATE DATABASE "+db)
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
		admin.Close(context.Background())
	})
	i := strings.LastIndex(url, "/")
	q := url[i:]
	if j := strings.Index(q, "?"); j >= 0 {
		q = q[j:]
	} else {
		q = ""
	}
	st, err := store.Open(ctx, url[:i+1]+db+q)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	dir, bin := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SRUSTIOPS_TENANT=acme\nSRUSTIOPS_VERSION=0.3.0\n"), 0o600)
	// A stand-in docker that records what it was asked; FAIL makes "up" fail.
	os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho \"$@\" >> \"$LOG\"\n[ \"$2\" = up ] && [ -n \"$FAIL\" ] && { echo boom; exit 1; }\nexit 0\n"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	logf := filepath.Join(dir, "docker.log")
	t.Setenv("LOG", logf)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u := &composeUpgrader{dir: dir}
	st.PutSetting(ctx, "fleet_status", api.FleetStatus{}, "t")
	st.PutSetting(ctx, "fleet_target", api.FleetTarget{Version: "0.4.0", Rollout: "r1"}, "t")
	if err := updateOnce(ctx, log, st, u, true); err != nil {
		t.Fatal(err)
	}
	if v, _ := u.Running(ctx); v != "0.3.0" {
		t.Fatal("a dry run changed the version")
	}
	t.Setenv("FAIL", "1")
	if err := updateOnce(ctx, log, st, u, false); err == nil {
		t.Fatal("a failed `up` was reported as success")
	}
	var fs api.FleetStatus
	st.Setting(ctx, "fleet_status", &fs)
	if v, _ := u.Running(ctx); v != "0.3.0" || fs.State != "failed" || !strings.Contains(fs.Detail, "boom") {
		t.Fatalf("after a failure the old version stays: %s %+v", v, fs)
	}
	t.Setenv("FAIL", "")
	if err := updateOnce(ctx, log, st, u, false); err != nil {
		t.Fatal(err)
	}
	st.Setting(ctx, "fleet_status", &fs)
	calls, _ := os.ReadFile(logf)
	if v, _ := u.Running(ctx); v != "0.4.0" || fs.State != "done" || !strings.Contains(string(calls), "compose pull") || !strings.Contains(string(calls), "compose up -d") {
		t.Fatalf("upgrade: %s %+v %s", v, fs, calls)
	}
	env, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(env), "SRUSTIOPS_TENANT=acme") {
		t.Fatal("the rest of .env was lost")
	}
	st.PutSetting(ctx, "fleet_target", api.FleetTarget{}, "t")
}
