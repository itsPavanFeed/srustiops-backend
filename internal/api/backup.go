package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- backups and restore drills (Tenant settings → Backups) ----
//
// A backup is this plane's whole database (one consistent snapshot) and the
// bucket objects it points at (state versions, archived logs), gzipped and
// sealed with the master key, written to the tenant bucket — or to
// SRUSTIOPS_BACKUP_DIR when there is no bucket. Backups run on a schedule
// (daily by default) and keep the newest N. A restore drill loads a backup
// into a scratch schema beside the live data and verifies it; a real restore
// is `srustiops tenant restore` into a new database.

const (
	backupSchedule = "backup_schedule"
	backupLock     = 7306
)

type backupSettings struct {
	Enabled    bool `json:"enabled"`
	EveryHours int  `json:"every_hours"`
	Keep       int  `json:"keep"`
	DrillAfter bool `json:"drill_after"` // drill every scheduled backup
}

func (s *Server) backupSettings(ctx context.Context) backupSettings {
	b := backupSettings{Enabled: true, EveryHours: 24, Keep: 7, DrillAfter: true}
	s.store.Setting(ctx, backupSchedule, &b)
	return b
}

// backupDest is where backups are kept.
type backupDest interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

type dirDest struct{ dir string }

func (d dirDest) path(key string) string { return filepath.Join(d.dir, filepath.Base(key)) }
func (d dirDest) Put(_ context.Context, key string, data []byte) error {
	return os.WriteFile(d.path(key), data, 0o600)
}
func (d dirDest) Get(_ context.Context, key string) ([]byte, error) { return os.ReadFile(d.path(key)) }
func (d dirDest) Delete(_ context.Context, key string) error        { return os.Remove(d.path(key)) }

func (s *Server) backupDest() (backupDest, string) {
	if s.objects != nil {
		return s.objects, "bucket"
	}
	if s.cfg.BackupDir != "" {
		return dirDest{s.cfg.BackupDir}, "directory"
	}
	return nil, ""
}

func backupAAD(tenant string) []byte { return []byte("srustiops-backup:" + tenant) }

// A backup is sealed in parts of backupPart bytes, each bound to the tenant,
// its place and the number of parts, so parts cannot be dropped, reordered
// or mixed between backups of the same size unnoticed.
const backupPart = 64 << 20

func partAAD(tenant string, i, n int) []byte {
	return []byte(fmt.Sprintf("srustiops-backup:%s:part:%d/%d", tenant, i+1, n))
}

func partKey(key string, i int) string { return fmt.Sprintf("%s.part-%04d", key, i+1) }

// The downloaded file of a backup in parts: a header, the number of parts,
// then each sealed part with its length.
var backupFileMagic = []byte("SOPBAK2\n")

// makeBackup writes a backup and records it.
func (s *Server) makeBackup(ctx context.Context, by string) (*store.BackupRow, error) {
	dest, _ := s.backupDest()
	if dest == nil {
		return nil, errors.New("there is nowhere to keep backups: configure the tenant bucket or SRUSTIOPS_BACKUP_DIR")
	}
	// The archive is spooled to a temporary file, then sealed and uploaded a
	// part at a time: memory stays at one part, whatever the workspace's size.
	spool, err := os.CreateTemp(s.cfg.BackupDir, "srustiops-backup-*.tar.gz")
	if err != nil {
		return nil, fmt.Errorf("spooling the backup: %w", err)
	}
	defer os.Remove(spool.Name())
	defer spool.Close()
	zw := gzip.NewWriter(spool)
	tw := tar.NewWriter(zw)
	m, err := s.store.DumpDatabase(ctx, tw, s.cfg.Tenant)
	if err != nil {
		return nil, err
	}
	keys, err := s.store.BackupObjectKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if s.objects == nil {
			break
		}
		b, err := s.objects.Get(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("reading object %s: %w", k, err)
		}
		h := sha256.Sum256(b)
		m.Objects[k] = store.ObjectDump{Size: len(b), SHA256: hex.EncodeToString(h[:])}
		tw.WriteHeader(&tar.Header{Name: "objects/" + k, Mode: 0o600, Size: int64(len(b)), ModTime: m.CreatedAt})
		tw.Write(b)
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(mb)), ModTime: m.CreatedAt})
	tw.Write(mb)
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	fi, err := spool.Stat()
	if err != nil {
		return nil, err
	}
	rnd := make([]byte, 4)
	rand.Read(rnd)
	key := fmt.Sprintf("backups/%s-%s-%s.sopbak", s.cfg.Tenant, m.CreatedAt.Format("20060102T150405Z"), hex.EncodeToString(rnd))
	parts := max(1, int((fi.Size()+backupPart-1)/backupPart))
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var size int64
	var copyErr error // the second copy failing does not fail the backup; it is reported
	chunk := make([]byte, backupPart)
	for i := 0; i < parts; i++ {
		n, err := io.ReadFull(spool, chunk)
		if err != nil && err != io.ErrUnexpectedEOF && !(err == io.EOF && i == parts-1) {
			return nil, err
		}
		sealed, err := s.sealer.Seal(chunk[:n], partAAD(s.cfg.Tenant, i, parts))
		if err != nil {
			return nil, err
		}
		if err := dest.Put(ctx, partKey(key, i), sealed); err != nil {
			for j := 0; j < i; j++ {
				dest.Delete(ctx, partKey(key, j))
			}
			return nil, fmt.Errorf("writing the backup: %w", err)
		}
		if s.backupCopy != nil && copyErr == nil {
			if copyErr = s.backupCopy.Put(ctx, partKey(key, i), sealed); copyErr != nil {
				copyErr = fmt.Errorf("writing the copy to %s: %w", s.backupCopy, copyErr)
			}
		}
		size += int64(len(sealed))
	}
	var rows int64
	for _, t := range m.Tables {
		rows += t.Rows
	}
	row, err := s.store.AddBackup(ctx, &store.BackupRow{Key: key, Size: size, Tables: len(m.Tables), Rows: rows, Objects: len(m.Objects), Parts: parts, CreatedBy: by})
	if err != nil {
		return nil, err
	}
	if copyErr != nil {
		s.notifyEvent(ctx, store.Notification{Kind: "backup.failed", Severity: "error", Title: "A backup's second copy failed", Body: copyErr.Error(), Link: "settings/backups"})
	}
	s.audit(ctx, by, "backup.create", "backup/"+row.ID, "", map[string]any{"key": key, "size": size, "parts": parts, "copied": s.backupCopy != nil && copyErr == nil, "tables": len(m.Tables), "rows": rows, "objects": len(m.Objects), "audit_last_id": m.AuditLast})
	return row, nil
}

// openBackup reads and unseals a backup.
func (s *Server) openBackup(ctx context.Context, row *store.BackupRow) (*store.Archive, error) {
	dest, _ := s.backupDest()
	if dest == nil {
		return nil, errors.New("there is nowhere backups are kept")
	}
	if row.Parts == 0 { // one object (backups from before parts)
		sealed, err := dest.Get(ctx, row.Key)
		if err != nil {
			return nil, fmt.Errorf("reading the backup: %w", err)
		}
		return OpenBackup(sealed, s.sealer, s.cfg.Tenant)
	}
	var gz bytes.Buffer
	for i := 0; i < row.Parts; i++ {
		sealed, err := dest.Get(ctx, partKey(row.Key, i))
		if err != nil {
			return nil, fmt.Errorf("reading part %d of %d of the backup: %w", i+1, row.Parts, err)
		}
		plain, err := s.sealer.Open(sealed, partAAD(s.cfg.Tenant, i, row.Parts))
		if err != nil {
			return nil, fmt.Errorf("part %d of %d of the backup cannot be opened: it is damaged, or belongs to another tenant or master key", i+1, row.Parts)
		}
		gz.Write(plain)
	}
	return readBackupArchive(gz.Bytes(), s.cfg.Tenant)
}

func readBackupArchive(gz []byte, tenant string) (*store.Archive, error) {
	a, err := store.ReadArchive(gz)
	if err != nil {
		return nil, err
	}
	if a.Manifest.Tenant != tenant {
		return nil, fmt.Errorf("the backup is of tenant %s", a.Manifest.Tenant)
	}
	return a, nil
}

// OpenBackup unseals and parses a backup file (also used by `srustiops tenant restore`).
func OpenBackup(sealed []byte, sealer *secure.Sealer, tenant string) (*store.Archive, error) {
	if bytes.HasPrefix(sealed, backupFileMagic) { // a downloaded backup in parts
		r := bytes.NewReader(sealed[len(backupFileMagic):])
		var n uint32
		if binary.Read(r, binary.BigEndian, &n) != nil || n == 0 || n > 1<<16 {
			return nil, errors.New("the backup file is damaged")
		}
		var gz bytes.Buffer
		for i := 0; i < int(n); i++ {
			var l uint64
			if binary.Read(r, binary.BigEndian, &l) != nil || l > uint64(r.Len()) {
				return nil, errors.New("the backup file is truncated")
			}
			part := make([]byte, l)
			io.ReadFull(r, part)
			plain, err := sealer.Open(part, partAAD(tenant, i, int(n)))
			if err != nil {
				return nil, errors.New("the backup cannot be opened: it is damaged, or belongs to another tenant or master key")
			}
			gz.Write(plain)
		}
		return readBackupArchive(gz.Bytes(), tenant)
	}
	gz, err := sealer.Open(sealed, backupAAD(tenant))
	if err != nil {
		return nil, errors.New("the backup cannot be opened: it belongs to another tenant or another master key")
	}
	a, err := store.ReadArchive(gz)
	if err != nil {
		return nil, err
	}
	if a.Manifest.Tenant != tenant {
		return nil, fmt.Errorf("the backup is of tenant %s", a.Manifest.Tenant)
	}
	return a, nil
}

func (s *Server) drillBackup(ctx context.Context, row *store.BackupRow, by string) (*store.DrillReport, error) {
	a, err := s.openBackup(ctx, row)
	var rep *store.DrillReport
	if err == nil {
		rep, err = s.store.Drill(ctx, a)
	}
	if err != nil {
		rep = &store.DrillReport{OK: false, Problems: []string{err.Error()}}
	}
	s.store.SetDrill(ctx, row.ID, rep)
	s.audit(ctx, by, "backup.drill", "backup/"+row.ID, "", rep)
	if !rep.OK {
		s.notifyEvent(ctx, store.Notification{Kind: "backup.drill_failed", Severity: "error", Title: "A restore drill failed",
			Body: strings.Join(firstN(rep.Problems, 3), "; "), Link: "settings/backups"})
	}
	return rep, nil
}

// pruneBackups keeps the newest keep backups.
func (s *Server) pruneBackups(ctx context.Context, keep int) {
	rows, err := s.store.ListBackups(ctx)
	if err != nil || len(rows) <= keep {
		return
	}
	dest, _ := s.backupDest()
	for _, r := range rows[keep:] {
		if dest != nil {
			dest.Delete(ctx, r.Key)
			for i := 0; i < r.Parts; i++ {
				dest.Delete(ctx, partKey(r.Key, i))
				if s.backupCopy != nil {
					s.backupCopy.Delete(ctx, partKey(r.Key, i))
				}
			}
		}
		s.store.DeleteBackupRow(ctx, r.ID)
		s.audit(ctx, "system:backups", "backup.expired", "backup/"+r.ID, "", map[string]string{"key": r.Key})
	}
}

// backupLoop takes scheduled backups (and drills them) on one replica.
func (s *Server) backupLoop(ctx context.Context) {
	every := min(s.cfg.ScheduleEvery, time.Minute)
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		bs := s.backupSettings(ctx)
		if dest, _ := s.backupDest(); !bs.Enabled || dest == nil {
			continue
		}
		s.store.TryLock(ctx, backupLock, func(ctx context.Context) {
			rows, _ := s.store.ListBackups(ctx)
			s.backupHealth(ctx, bs, rows)
			if len(rows) > 0 && time.Since(rows[0].CreatedAt) < time.Duration(bs.EveryHours)*time.Hour {
				return
			}
			row, err := s.makeBackup(ctx, "system:backups")
			if err != nil {
				s.log.Error("scheduled backup failed", "err", err)
				s.notifyEvent(ctx, store.Notification{Kind: "backup.failed", Severity: "error", Title: "A scheduled backup failed", Body: err.Error(), Link: "settings/backups"})
				return
			}
			if bs.DrillAfter {
				s.drillBackup(ctx, row, "system:backups")
			}
			s.pruneBackups(ctx, bs.Keep)
		})
	}
}

// ---- API ----

func (s *Server) listBackups(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	rows, err := s.store.ListBackups(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	_, where := s.backupDest()
	out := map[string]any{"backups": rows, "schedule": s.backupSettings(r.Context()), "destination": where}
	if s.backupCopy != nil {
		out["copy"] = s.backupCopy.String()
	}
	writeJSON(w, 200, out)
}

func (s *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var row *store.BackupRow
	err := errors.New("another backup is running; try again in a moment")
	s.store.TryLock(r.Context(), backupLock, func(ctx context.Context) { row, err = s.makeBackup(ctx, user(r).Subject) })
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, 201, row)
}

func (s *Server) drillBackupHandler(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	row, err := s.store.GetBackup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	rep, _ := s.drillBackup(r.Context(), row, user(r).Subject)
	writeJSON(w, 200, rep)
}

func (s *Server) putBackupSchedule(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b backupSettings
	if !decode(w, r, &b) {
		return
	}
	if b.EveryHours < 1 || b.EveryHours > 24*30 || b.Keep < 1 || b.Keep > 365 {
		writeErr(w, 422, "every_hours must be 1-720 and keep 1-365")
		return
	}
	if err := s.store.PutSetting(r.Context(), backupSchedule, b, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "backup.schedule", "backups", "", b)
	s.listBackups(w, r)
}

// downloadBackup hands the sealed file to a tenant admin: it can only be
// restored with this tenant's master key.
func (s *Server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	row, err := s.store.GetBackup(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	dest, _ := s.backupDest()
	if row.Parts == 0 {
		data, err := dest.Get(r.Context(), row.Key)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "reading the backup failed: "+err.Error())
			return
		}
		s.audit(r.Context(), user(r).Actor(), "backup.download", "backup/"+row.ID, "", map[string]string{"key": row.Key})
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(row.Key)+`"`)
		w.Write(data)
		return
	}
	// Parts are read and sent one at a time.
	first, err := dest.Get(r.Context(), partKey(row.Key, 0))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "reading the backup failed: "+err.Error())
		return
	}
	s.audit(r.Context(), user(r).Actor(), "backup.download", "backup/"+row.ID, "", map[string]any{"key": row.Key, "parts": row.Parts})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(row.Key)+`"`)
	w.Write(backupFileMagic)
	binary.Write(w, binary.BigEndian, uint32(row.Parts))
	for i := 0; i < row.Parts; i++ {
		part := first
		if i > 0 {
			if part, err = dest.Get(r.Context(), partKey(row.Key, i)); err != nil {
				s.log.Error("backup download cut short", "backup", row.ID, "part", i+1, "err", err)
				return // the file is then truncated, which the restore detects
			}
		}
		binary.Write(w, binary.BigEndian, uint64(len(part)))
		w.Write(part)
	}
}

// backupHealth warns, once a day each, when the newest backup is older than
// twice the schedule (backups keep failing) or its restore drill failed.
func (s *Server) backupHealth(ctx context.Context, bs backupSettings, rows []*store.BackupRow) {
	warn := func(kind, title, body string) {
		day := time.Now().UTC().Format("2006-01-02")
		var last string
		if s.store.Setting(ctx, "backup_warned_"+kind, &last); last == day {
			return
		}
		s.store.PutSetting(ctx, "backup_warned_"+kind, day, "system:backups")
		s.notifyEvent(ctx, store.Notification{Kind: "backup.failed", Severity: "error", Title: title, Body: body, Link: "settings/backups"})
	}
	late := time.Duration(2*bs.EveryHours) * time.Hour
	switch {
	case len(rows) == 0:
	case time.Since(rows[0].CreatedAt) > late:
		warn("late", "Backups are overdue", fmt.Sprintf("The newest backup is from %s, more than twice the %dh schedule ago.", rows[0].CreatedAt.UTC().Format(time.RFC3339), bs.EveryHours))
	}
	if len(rows) > 0 && rows[0].Drill != nil {
		var d store.DrillReport
		if json.Unmarshal(rows[0].Drill, &d) == nil && !d.OK {
			warn("drill", "The newest backup failed its restore drill", strings.Join(firstN(d.Problems, 3), "; "))
		}
	}
}
