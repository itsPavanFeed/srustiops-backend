package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// freshDB makes a new, empty database next to SRUSTIOPS_TEST_DATABASE_URL's.
func freshDB(t *testing.T, name string) string {
	base := os.Getenv("SRUSTIOPS_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("SRUSTIOPS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	db := fmt.Sprintf("%s_%d", name, time.Now().UnixNano())
	if _, err := c.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err == nil {
			c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
			c.Close(context.Background())
		}
	})
	i := strings.LastIndex(base, "/")
	q := ""
	if j := strings.Index(base[i:], "?"); j >= 0 {
		q = base[i+j:]
	}
	return base[:i+1] + db + q
}

func open(t *testing.T, url string) *Store {
	st, err := Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestBackupDrillRestore(t *testing.T) {
	ctx := context.Background()
	src := open(t, freshDB(t, "bk_src"))
	// Some of everything: an environment, a stack, a run with logs and a
	// self-referencing run, two state versions (one inline, one in a
	// "bucket"), audit events, notifications, settings and keys.
	env, err := src.CreateEnvironment(ctx, &Environment{Name: "dev", Entity: "retail", Tier: "nonprod", RunnerPool: "default", CreatedBy: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := src.CreateStack(ctx, "naming", "payments", "retail", env.ID, nil, []byte(`{"modules":[{"name":"n","kind":"X"}]}`), "alice@x.test")
	if err != nil {
		t.Fatal(err)
	}
	run, err := src.CreateRun(ctx, st.ID, "apply", "alice@x.test", "h1")
	if err != nil {
		t.Fatal(err)
	}
	src.AppendLog(ctx, run.ID, "line one\nwith a tab\there and a backslash \\ too\n")
	src.db.Exec(ctx, `UPDATE runs SET status = 'applied', finished_at = now() WHERE id = $1`, run.ID)
	run2, _ := src.CreateCandidateRun(ctx, st.ID, "alice@x.test", "h2", []byte(`{}`), run.ID)
	src.db.Exec(ctx, `UPDATE runs SET status = 'no_changes', finished_at = now() WHERE id = $1`, run2.ID)
	inline := []byte("ciphertext-state-1")
	sum := sha256.Sum256(inline)
	if _, err := src.PutState(ctx, st.ID, run.ID, inline, "", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	obj := []byte("ciphertext-state-2-in-bucket")
	osum := sha256.Sum256(obj)
	src.PutState(ctx, st.ID, run.ID, nil, "state/naming/2", hex.EncodeToString(osum[:]))
	for i := 0; i < 30; i++ {
		if err := src.AppendAudit(ctx, "alice@x.test", "run.create", "run/x", "payments", map[string]int{"i": i}); err != nil {
			t.Fatal(err)
		}
	}
	src.AddNotification(ctx, &Notification{Kind: "run.applied", Severity: "success", Title: "Applied", BU: "payments"})
	src.PutSetting(ctx, "risk", map[string]string{"x": "y"}, "t")
	src.PutMetaIfAbsent(ctx, "oidc_signing_key", []byte("sealed-key-bytes"))

	// Back up (objects added as makeBackup does).
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	m, err := src.DumpDatabase(ctx, tw, "acme")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := src.BackupObjectKeys(ctx)
	if len(keys) != 1 || keys[0] != "state/naming/2" {
		t.Fatalf("object keys: %v", keys)
	}
	m.Objects["state/naming/2"] = ObjectDump{Size: len(obj), SHA256: hex.EncodeToString(osum[:])}
	tw.WriteHeader(&tar.Header{Name: "objects/state/naming/2", Mode: 0o600, Size: int64(len(obj))})
	tw.Write(obj)
	mb, _ := json.Marshal(m)
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(mb))})
	tw.Write(mb)
	tw.Close()
	zw.Close()
	if m.Tables["audit_events"].Rows < 30 || m.Tables["state_versions"].Rows != 2 || m.Tables["schema_meta"].Rows < 1 {
		t.Fatalf("manifest: %+v", m.Tables)
	}
	a, err := ReadArchive(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// The drill loads it beside the live data and checks it.
	rep, err := src.Drill(ctx, a)
	if err != nil || !rep.OK || rep.States != 2 || rep.Audit < 30 || rep.Objects != 1 {
		t.Fatalf("drill: %+v %v", rep, err)
	}
	var schemas int
	src.db.QueryRow(ctx, `SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'restore_drill_%'`).Scan(&schemas)
	if schemas != 0 {
		t.Fatal("the drill left its scratch schema behind")
	}
	// A damaged backup fails the drill.
	bad := *a
	bad.Tables = map[string][]byte{}
	for k, v := range a.Tables {
		bad.Tables[k] = v
	}
	bad.Tables["audit_events"] = bytes.Replace(a.Tables["audit_events"], []byte("run.create"), []byte("run.delete"), 1)
	if rep, _ := src.Drill(ctx, &bad); rep.OK {
		t.Fatal("an altered audit event passed the drill")
	}
	bad.Tables = a.Tables
	bad.Objects = map[string][]byte{}
	if rep, _ := src.Drill(ctx, &bad); rep.OK {
		t.Fatal("a missing state object passed the drill")
	}

	// A real restore into a new database, then the restored data is checked.
	dst := open(t, freshDB(t, "bk_dst"))
	dst.PutSetting(ctx, "made_at_startup", true, "t")
	if err := dst.RestoreInto(ctx, a); err != nil {
		t.Fatal(err)
	}
	if probs := dst.CheckLive(ctx, a); len(probs) > 0 {
		t.Fatalf("restored data differs: %v", probs)
	}
	if n, broken, err := dst.VerifyAudit(ctx); err != nil || broken != 0 || n < 30 {
		t.Fatalf("restored audit: %d %d %v", n, broken, err)
	}
	// It keeps working: new rows get new ids, foreign keys hold again.
	if err := dst.AppendAudit(ctx, "bob@x.test", "run.create", "run/y", "payments", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dst.VerifyAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.db.Exec(ctx, `INSERT INTO runs (stack_id, operation, status, created_by, config_hash) VALUES (gen_random_uuid(), 'apply', 'failed', 'x', 'h')`); err == nil {
		t.Fatal("foreign keys were left deferrable or off after the restore")
	}
	var deferrable int
	dst.db.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND condeferrable`).Scan(&deferrable)
	if deferrable != 0 {
		t.Fatalf("%d foreign keys stayed deferrable", deferrable)
	}
	// A database with data is refused.
	if err := dst.RestoreInto(ctx, a); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("restoring over data: %v", err)
	}
}
