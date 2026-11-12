package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/release"
)

// Air-gapped tenants get everything from the outside on media: these
// commands run on a connected machine and write directories to copy in.
//
//	srustiops modules mirror    registry module packages, signed (SRUSTIOPS_MODULE_MIRROR on the tenant)
//	srustiops providers mirror  OpenTofu providers at their pins (SRUSTIOPS_PROVIDER_MIRROR on runners)

func runModules(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "mirror" {
		return errors.New("usage: srustiops modules mirror -catalog DIR -out DIR -key FILE")
	}
	fs := flag.NewFlagSet("modules mirror", flag.ExitOnError)
	dir := fs.String("catalog", "../srustiops-modules/catalog", "the module catalog to mirror packages for")
	out := fs.String("out", "module-mirror", "output directory")
	keyFile := fs.String("key", "module-mirror.key", "Ed25519 signing key (created with a .pub next to it when missing)")
	registry := fs.String("registry", "", "registry base URL (default registry.opentofu.org)")
	fs.Parse(args[1:])
	cat, err := catalog.Load(*dir)
	if err != nil {
		return err
	}
	key, pub, err := mirrorKey(*keyFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	wants := release.WantsFromCatalog(cat)
	fmt.Printf("mirroring %d module package versions into %s\n", len(wants), *out)
	if err := release.BuildMirror(ctx, &release.Registry{Base: *registry}, wants, *out, key, func(s string) { fmt.Println("  " + s) }); err != nil {
		return err
	}
	fmt.Printf("\nsigned with %s. On the tenant plane set:\n  SRUSTIOPS_MODULE_MIRROR=<where you copy %s>\n  SRUSTIOPS_MODULE_MIRROR_KEY=%s\n", *keyFile, *out, base64.StdEncoding.EncodeToString(pub))
	return nil
}

// mirrorKey loads a base64 Ed25519 private key, or creates one.
func mirrorKey(file string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if b, err := os.ReadFile(file); err == nil {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("%s is not a base64 Ed25519 private key", file)
		}
		k := ed25519.PrivateKey(raw)
		return k, k.Public().(ed25519.PublicKey), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(file+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return nil, nil, err
	}
	fmt.Printf("created signing key %s (keep it offline) and %s.pub\n", file, file)
	return priv, pub, nil
}

func runProviders(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "mirror" {
		return errors.New("usage: srustiops providers mirror -catalog DIR -out DIR [-platforms linux_amd64,linux_arm64]")
	}
	fs := flag.NewFlagSet("providers mirror", flag.ExitOnError)
	dir := fs.String("catalog", "../srustiops-modules/catalog", "the module catalog whose pinned providers to mirror")
	out := fs.String("out", "provider-mirror", "output directory (an OpenTofu filesystem mirror)")
	platforms := fs.String("platforms", "linux_amd64,linux_arm64", "comma-separated platforms the runners use")
	tofu := fs.String("tofu", "tofu", "OpenTofu binary")
	cloud := fs.String("cloud", "", "only providers for this cloud (aws, gcp, azure); default all")
	fs.Parse(args[1:])
	cat, err := catalog.Load(*dir)
	if err != nil {
		return err
	}
	work, err := os.MkdirTemp("", "srustiops-providers-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	var b strings.Builder
	b.WriteString("terraform {\n  required_providers {\n")
	n := 0
	for _, p := range cat.Providers {
		if *cloud != "" && p.Cloud != *cloud && p.Cloud != "" {
			continue
		}
		fmt.Fprintf(&b, "    p%d = { source = %q, version = %q }\n", n, catalog.Registry+"/"+p.Source, "= "+p.Version)
		n++
	}
	b.WriteString("  }\n}\n")
	if n == 0 {
		return errors.New("no providers to mirror")
	}
	if err := os.WriteFile(filepath.Join(work, "versions.tf"), []byte(b.String()), 0o644); err != nil {
		return err
	}
	abs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	cmdArgs := []string{"providers", "mirror"}
	for _, p := range strings.Split(*platforms, ",") {
		if p = strings.TrimSpace(p); p != "" {
			cmdArgs = append(cmdArgs, "-platform="+p)
		}
	}
	cmdArgs = append(cmdArgs, abs)
	fmt.Printf("mirroring %d pinned providers for %s into %s\n", n, *platforms, abs)
	cmd := exec.CommandContext(ctx, *tofu, cmdArgs...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = work, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tofu providers mirror: %w", err)
	}
	fmt.Printf("\nOn runners set SRUSTIOPS_PROVIDER_MIRROR=<where you copy %s>. Lock file hashes still verify every provider.\n", *out)
	return nil
}
