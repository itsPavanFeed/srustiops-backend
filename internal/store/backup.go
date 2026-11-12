package store

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/srustiops-backend/internal/audit"
)

// ---- backups of a tenant plane's database ----
//
// A backup is a gzipped tar: manifest.json, one COPY (text format) per table
// taken in one consistent snapshot, and the bucket objects the database
// points at (state versions, archived logs), which the caller adds. Each
// table has an order-independent digest, so a restore drill can check what
// it loaded without depending on row order.

// BackupManifest describes a backup.
type BackupManifest struct {
	Format     int                   `json:"format"` // 1
	Tenant     string                `json:"tenant"`
	CreatedAt  time.Time             `json:"created_at"`
	Migrations []string              `json:"migrations"` // applied migrations: a restore needs the same schema
	Tables     map[string]TableDump  `json:"tables"`
	Objects    map[string]ObjectDump `json:"objects"`
	AuditLast  int64                 `json:"audit_last_id"`
}

type TableDump struct {
	Columns []string `json:"columns"`
	Rows    int64    `json:"rows"`
	Digest  string   `json:"digest"` // order-independent: sum of the rows' SHA-256 prefixes
}

type ObjectDump struct {
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// digest accumulates an order-independent digest of COPY lines.
type digest struct {
	sum  uint64
	rows int64
}

func (d *digest) add(line []byte) {
	h := sha256.Sum256(line)
	d.sum += binary.BigEndian.Uint64(h[:8])
	d.rows++
}

func (d *digest) String() string { return fmt.Sprintf("%016x", d.sum) }

// lineDigest reads COPY text output (one row per line) into a digest.
func lineDigest(b []byte) *digest {
	d := &digest{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		d.add(sc.Bytes())
	}
	return d
}

// backupTables lists the tables a backup holds (all of schema public but the
// migration bookkeeping) with their columns, in a stable order. schema_meta
// is included: it holds the sealed signing keys clouds trust.
func (s *Store) backupTables(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, schema string) (map[string][]string, error) {
	rows, err := q.Query(ctx, `SELECT c.table_name, c.column_name FROM information_schema.columns c
		JOIN information_schema.tables t ON t.table_schema = c.table_schema AND t.table_name = c.table_name AND t.table_type = 'BASE TABLE'
		WHERE c.table_schema = $1 AND c.table_name <> 'schema_migrations' AND c.is_generated = 'NEVER' ORDER BY c.table_name, c.ordinal_position`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		out[t] = append(out[t], c)
	}
	return out, rows.Err()
}

func quoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = pgx.Identifier{c}.Sanitize()
	}
	return strings.Join(q, ", ")
}

// Migrations lists the applied migrations.
func (s *Store) Migrations(ctx context.Context) []string {
	rows, err := s.db.Query(ctx, `SELECT name FROM schema_migrations ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out
}

// DumpDatabase writes every table, in one snapshot, into tw, and returns
// the manifest (objects are the caller's to add).
func (s *Store) DumpDatabase(ctx context.Context, tw *tar.Writer, tenant string) (*BackupManifest, error) {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	tables, err := s.backupTables(ctx, tx, "public")
	if err != nil {
		return nil, err
	}
	m := &BackupManifest{Format: 1, Tenant: tenant, CreatedAt: time.Now().UTC(), Migrations: s.Migrations(ctx), Tables: map[string]TableDump{}, Objects: map[string]ObjectDump{}}
	tx.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM audit_events`).Scan(&m.AuditLast)
	names := make([]string, 0, len(tables))
	for t := range tables {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		var buf bytes.Buffer
		sql := fmt.Sprintf(`COPY (SELECT %s FROM %s) TO STDOUT`, quoteCols(tables[t]), pgx.Identifier{t}.Sanitize())
		if _, err := tx.Conn().PgConn().CopyTo(ctx, &buf, sql); err != nil {
			return nil, fmt.Errorf("copying %s: %w", t, err)
		}
		d := lineDigest(buf.Bytes())
		m.Tables[t] = TableDump{Columns: tables[t], Rows: d.rows, Digest: d.String()}
		if err := tw.WriteHeader(&tar.Header{Name: "tables/" + t + ".copy", Mode: 0o600, Size: int64(buf.Len()), ModTime: m.CreatedAt}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(buf.Bytes()); err != nil {
			return nil, err
		}
	}
	return m, tx.Commit(ctx)
}

// BackupObjectKeys lists the bucket objects the database points at.
func (s *Store) BackupObjectKeys(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `SELECT object_key FROM state_versions WHERE object_key IS NOT NULL
		UNION SELECT 'logs/' || id || '.json' FROM runs WHERE logs_archived ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// Archive is a backup read into memory.
type Archive struct {
	Manifest BackupManifest
	Tables   map[string][]byte
	Objects  map[string][]byte
}

// ReadArchive parses a backup's gzipped tar.
func ReadArchive(gz []byte) (*Archive, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(zr)
	a := &Archive{Tables: map[string][]byte{}, Objects: map[string][]byte{}}
	seenManifest := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(tr, 2<<30))
		if err != nil {
			return nil, err
		}
		switch {
		case h.Name == "manifest.json":
			if err := json.Unmarshal(b, &a.Manifest); err != nil {
				return nil, fmt.Errorf("manifest: %w", err)
			}
			seenManifest = true
		case strings.HasPrefix(h.Name, "tables/") && strings.HasSuffix(h.Name, ".copy"):
			a.Tables[strings.TrimSuffix(strings.TrimPrefix(h.Name, "tables/"), ".copy")] = b
		case strings.HasPrefix(h.Name, "objects/"):
			a.Objects[strings.TrimPrefix(h.Name, "objects/")] = b
		}
	}
	if !seenManifest || a.Manifest.Format != 1 {
		return nil, errors.New("not a SrustiOps backup (no manifest)")
	}
	return a, nil
}

// DrillReport is what a restore drill found.
type DrillReport struct {
	OK       bool              `json:"ok"`
	Tables   int               `json:"tables"`
	Rows     int64             `json:"rows"`
	Objects  int               `json:"objects"`
	States   int               `json:"state_versions"`
	Audit    int               `json:"audit_events"`
	Problems []string          `json:"problems"`
	Seconds  float64           `json:"seconds"`
	Details  map[string]string `json:"details,omitempty"`
}

// Drill loads a backup into a scratch schema next to the live data (never
// touching it), checks every table's rows and digest, the audit chain and
// every state version's hash, then drops the scratch schema.
func (s *Store) Drill(ctx context.Context, a *Archive) (*DrillReport, error) {
	start := time.Now()
	rep := &DrillReport{Problems: []string{}}
	schema := fmt.Sprintf("restore_drill_%d", time.Now().UnixNano())
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `DROP SCHEMA `+schema+` CASCADE`)
	live, err := s.backupTables(ctx, conn, "public")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(a.Manifest.Tables))
	for t := range a.Manifest.Tables {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		td := a.Manifest.Tables[t]
		if _, ok := live[t]; !ok {
			rep.Problems = append(rep.Problems, "table "+t+" is not in this database's schema")
			continue
		}
		data, ok := a.Tables[t]
		if !ok {
			rep.Problems = append(rep.Problems, "table "+t+" is missing from the archive")
			continue
		}
		// LIKE copies columns and defaults, not foreign keys or triggers.
		if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE TABLE %s.%s (LIKE public.%s INCLUDING DEFAULTS)`, schema, pgx.Identifier{t}.Sanitize(), pgx.Identifier{t}.Sanitize())); err != nil {
			return nil, err
		}
		target := schema + "." + pgx.Identifier{t}.Sanitize()
		if _, err := conn.Conn().PgConn().CopyFrom(ctx, bytes.NewReader(data), fmt.Sprintf(`COPY %s (%s) FROM STDIN`, target, quoteCols(td.Columns))); err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("table %s does not load: %v", t, err))
			continue
		}
		var back bytes.Buffer
		if _, err := conn.Conn().PgConn().CopyTo(ctx, &back, fmt.Sprintf(`COPY (SELECT %s FROM %s) TO STDOUT`, quoteCols(td.Columns), target)); err != nil {
			return nil, err
		}
		d := lineDigest(back.Bytes())
		if d.rows != td.Rows || d.String() != td.Digest {
			rep.Problems = append(rep.Problems, fmt.Sprintf("table %s: %d rows (digest %s), the manifest says %d (%s)", t, d.rows, d, td.Rows, td.Digest))
		}
		rep.Tables++
		rep.Rows += d.rows
	}
	// The audit chain, as loaded.
	if _, ok := a.Manifest.Tables["audit_events"]; ok {
		prev, after := audit.Genesis, int64(0)
		for {
			rows, err := conn.Query(ctx, `SELECT id, ts, actor, action, target, bu, payload::text, prev_hash, hash FROM `+schema+`.audit_events WHERE id > $1 ORDER BY id LIMIT 5000`, after)
			if err != nil {
				return nil, err
			}
			evs, err := scanAudit(rows)
			if err != nil {
				return nil, err
			}
			if len(evs) == 0 {
				break
			}
			if b := audit.Verify(evs, prev); b != 0 {
				rep.Problems = append(rep.Problems, fmt.Sprintf("the audit chain breaks at event %d", b))
				break
			}
			rep.Audit += len(evs)
			prev, after = evs[len(evs)-1].Hash, evs[len(evs)-1].ID
		}
	}
	// Every state version: inline data or a bucket object, both by hash.
	rows, err := conn.Query(ctx, `SELECT stack_id::text, serial, data, object_key, sha256 FROM `+schema+`.state_versions`)
	if err == nil {
		for rows.Next() {
			var stack, sha string
			var serial int64
			var data []byte
			var obj *string
			if rows.Scan(&stack, &serial, &data, &obj, &sha) != nil {
				continue
			}
			if obj != nil {
				data = a.Objects[*obj]
				if data == nil {
					rep.Problems = append(rep.Problems, fmt.Sprintf("state %s#%d: object %s is missing", stack[:8], serial, *obj))
					continue
				}
			}
			if h := sha256.Sum256(data); hex.EncodeToString(h[:]) != sha {
				rep.Problems = append(rep.Problems, fmt.Sprintf("state %s#%d does not match its hash", stack[:8], serial))
			}
			rep.States++
		}
		rows.Close()
	}
	for k, o := range a.Manifest.Objects {
		b := a.Objects[k]
		if h := sha256.Sum256(b); b == nil || hex.EncodeToString(h[:]) != o.SHA256 {
			rep.Problems = append(rep.Problems, "object "+k+" is missing or altered")
		}
		rep.Objects++
	}
	rep.OK = len(rep.Problems) == 0
	rep.Seconds = time.Since(start).Seconds()
	return rep, nil
}

// RestoreInto loads a backup into this (freshly migrated, empty) database.
// Foreign keys are made deferrable for the load, so rows can arrive in any
// order and are checked once at commit; then they are set back.
func (s *Store) RestoreInto(ctx context.Context, a *Archive) error {
	have := s.Migrations(ctx)
	if strings.Join(have, ",") != strings.Join(a.Manifest.Migrations, ",") {
		return fmt.Errorf("the backup was made at schema %d migration(s), this database is at %d: restore with the matching SrustiOps version", len(a.Manifest.Migrations), len(have))
	}
	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	live, err := s.backupTables(ctx, conn, "public")
	if err != nil {
		return err
	}
	for t := range live {
		var n int64
		conn.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{t}.Sanitize()).Scan(&n)
		if n > 0 && t != "tenant_settings" && t != "schema_meta" {
			return fmt.Errorf("the database is not empty (table %s has %d rows): restore into a new database", t, n)
		}
	}
	type fk struct{ table, name string }
	var fks []fk
	rows, err := conn.Query(ctx, `SELECT conrelid::regclass::text, conname FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace AND NOT condeferrable`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var f fk
		if rows.Scan(&f.table, &f.name) == nil {
			fks = append(fks, f)
		}
	}
	rows.Close()
	alter := func(mode string) error {
		for _, f := range fks {
			if _, err := conn.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ALTER CONSTRAINT %s %s`, f.table, pgx.Identifier{f.name}.Sanitize(), mode)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := alter("DEFERRABLE INITIALLY DEFERRED"); err != nil {
		return fmt.Errorf("making foreign keys deferrable: %w", err)
	}
	defer alter("NOT DEFERRABLE")
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// Rows a start-up may have made (keys, settings): the backup's win.
	for _, q := range []string{`SET CONSTRAINTS ALL DEFERRED`, `DELETE FROM tenant_settings`, `DELETE FROM schema_meta`} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	names := make([]string, 0, len(a.Manifest.Tables))
	for t := range a.Manifest.Tables {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		td := a.Manifest.Tables[t]
		if _, err := tx.Conn().PgConn().CopyFrom(ctx, bytes.NewReader(a.Tables[t]), fmt.Sprintf(`COPY %s (%s) FROM STDIN`, pgx.Identifier{t}.Sanitize(), quoteCols(td.Columns))); err != nil {
			return fmt.Errorf("loading %s: %w", t, err)
		}
	}
	// Sequences continue after the restored rows.
	seqs, err := tx.Query(ctx, `SELECT c.relname, a.attname, pg_get_serial_sequence(quote_ident(c.relname), a.attname) FROM pg_class c
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
		AND pg_get_serial_sequence(quote_ident(c.relname), a.attname) IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("listing sequences: %w", err)
	}
	type seq struct{ table, col, seq string }
	var ss []seq
	for seqs.Next() {
		var x seq
		if seqs.Scan(&x.table, &x.col, &x.seq) == nil {
			ss = append(ss, x)
		}
	}
	seqs.Close()
	if err := seqs.Err(); err != nil {
		return fmt.Errorf("listing sequences: %w", err)
	}
	for _, x := range ss {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`SELECT setval('%s', GREATEST((SELECT COALESCE(max(%s), 0) FROM %s), 1))`, x.seq, pgx.Identifier{x.col}.Sanitize(), pgx.Identifier{x.table}.Sanitize())); err != nil {
			return fmt.Errorf("setting %s: %w", x.seq, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing the restore: %w", err)
	}
	return nil
}

// CheckLive compares this database's tables with a backup's manifest (after
// a restore): every table's rows and digest must match.
func (s *Store) CheckLive(ctx context.Context, a *Archive) []string {
	var probs []string
	for t, td := range a.Manifest.Tables {
		var buf bytes.Buffer
		if _, err := s.db.Exec(ctx, `SELECT 1`); err != nil {
			return []string{err.Error()}
		}
		conn, err := s.db.Acquire(ctx)
		if err != nil {
			return []string{err.Error()}
		}
		_, err = conn.Conn().PgConn().CopyTo(ctx, &buf, fmt.Sprintf(`COPY (SELECT %s FROM %s) TO STDOUT`, quoteCols(td.Columns), pgx.Identifier{t}.Sanitize()))
		conn.Release()
		if err != nil {
			probs = append(probs, t+": "+err.Error())
			continue
		}
		if d := lineDigest(buf.Bytes()); d.rows != td.Rows || d.String() != td.Digest {
			probs = append(probs, fmt.Sprintf("%s: %d rows, the backup has %d", t, d.rows, td.Rows))
		}
	}
	sort.Strings(probs)
	return probs
}
