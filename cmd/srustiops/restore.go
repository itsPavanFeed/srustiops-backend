package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/itsPavanFeed/srustiops-backend/internal/api"
	"github.com/itsPavanFeed/srustiops-backend/internal/blob"
	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// runTenantRestore loads a backup (a .sopbak file, downloaded from Tenant
// settings → Backups or taken from the bucket) into a new, empty database,
// with the tenant's usual settings (SRUSTIOPS_DATABASE_URL, the same
// SRUSTIOPS_MASTER_KEY and SRUSTIOPS_TENANT, and its bucket). The tenant
// plane must not be running against that database.
func runTenantRestore(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tenant restore", flag.ExitOnError)
	file := fs.String("file", "", "the backup file (.sopbak)")
	fs.Parse(args)
	if *file == "" {
		return errors.New("usage: srustiops tenant restore -file backup.sopbak")
	}
	cfg, err := config.LoadServer()
	if err != nil {
		return err
	}
	sealer, err := sealerFrom(cfg.MasterKey)
	if err != nil {
		return err
	}
	sealed, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	a, err := api.OpenBackup(sealed, sealer, cfg.Tenant)
	if err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if len(a.Objects) > 0 {
		if cfg.BucketURL == "" {
			return errors.New("the backup holds bucket objects (state, logs): set SRUSTIOPS_BUCKET_URL to the bucket to restore them into")
		}
		b, err := blob.Open(cfg.BucketURL, cfg.BucketAccessKey, cfg.BucketSecretKey, nil)
		if err != nil {
			return err
		}
		if cfg.BucketCreate {
			b.EnsureBucket(ctx)
		}
		for k, data := range a.Objects {
			if err := b.Put(ctx, k, data); err != nil {
				return fmt.Errorf("restoring object %s: %w", k, err)
			}
		}
	}
	if err := st.RestoreInto(ctx, a); err != nil {
		return err
	}
	if probs := st.CheckLive(ctx, a); len(probs) > 0 {
		return fmt.Errorf("restored, but the check found differences: %v", probs)
	}
	if n, broken, err := st.VerifyAudit(ctx); err != nil || broken != 0 {
		return fmt.Errorf("restored, but the audit chain does not verify (first broken event %d): %v", broken, err)
	} else {
		fmt.Printf("restored tenant %s from %s: %d tables, %d objects; audit chain of %d events verified\n",
			a.Manifest.Tenant, a.Manifest.CreatedAt.Format("2006-01-02 15:04 UTC"), len(a.Manifest.Tables), len(a.Objects), n)
	}
	return nil
}
