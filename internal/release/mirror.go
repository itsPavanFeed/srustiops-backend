package release

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
)

// A module mirror carries registry module packages to tenants without
// internet access. It is built on a connected machine (srustiops modules
// mirror), copied in, and read instead of the registry for release builds:
//
//	index.json   {"packages": {"<source>@<version>": {"dir", "origin", "sha256"}}}
//	index.sig    base64 Ed25519 signature of index.json
//	pkgs/<sha256>/...   each package's files
//
// The tenant trusts only the public key it was configured with; every
// package's files are checked against the signed index when read.

const (
	mirrorIndex = "index.json"
	mirrorSig   = "index.sig"
)

type mirrorEntry struct {
	Dir    string `json:"dir"`
	Origin string `json:"origin"`
	SHA256 string `json:"sha256"`
}

type mirrorIndexDoc struct {
	Version  int                    `json:"version"`
	Packages map[string]mirrorEntry `json:"packages"`
}

// filesSum is a package's checksum: every file's path and content, in order.
func filesSum(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Mirror fetches packages from a signed module mirror.
type Mirror struct {
	Dir string
	Key ed25519.PublicKey

	once sync.Once
	idx  *mirrorIndexDoc
	err  error
}

// ParseMirrorKey reads a base64 Ed25519 public key.
func ParseMirrorKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("module mirror key must be a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

func (m *Mirror) index() (*mirrorIndexDoc, error) {
	m.once.Do(func() {
		raw, err := os.ReadFile(filepath.Join(m.Dir, mirrorIndex))
		if err != nil {
			m.err = fmt.Errorf("module mirror: %w", err)
			return
		}
		sig, err := os.ReadFile(filepath.Join(m.Dir, mirrorSig))
		if err != nil {
			m.err = fmt.Errorf("module mirror is not signed: %w", err)
			return
		}
		s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
		if err != nil || !ed25519.Verify(m.Key, raw, s) {
			m.err = errors.New("module mirror signature does not match the configured key")
			return
		}
		var d mirrorIndexDoc
		if err := json.Unmarshal(raw, &d); err != nil {
			m.err = fmt.Errorf("module mirror index: %w", err)
			return
		}
		m.idx = &d
	})
	return m.idx, m.err
}

func (m *Mirror) Fetch(_ context.Context, source, version string) (map[string][]byte, string, error) {
	idx, err := m.index()
	if err != nil {
		return nil, "", err
	}
	key := catalog.BaseSource(source) + "@" + version
	e, ok := idx.Packages[key]
	if !ok {
		return nil, "", fmt.Errorf("the module mirror has no %s; rebuild it with this catalog", key)
	}
	root := filepath.Join(m.Dir, filepath.FromSlash(e.Dir))
	if rel, err := filepath.Rel(m.Dir, root); err != nil || strings.HasPrefix(rel, "..") {
		return nil, "", errors.New("module mirror entry points outside the mirror")
	}
	files := map[string][]byte{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("module mirror contains a link: %s", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files[filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if filesSum(files) != e.SHA256 {
		return nil, "", fmt.Errorf("module mirror package %s does not match its signed checksum", key)
	}
	return files, "mirror: " + e.Origin, nil
}

// MirrorWant is one package version to put in a mirror.
type MirrorWant struct{ Source, Version string }

// WantsFromCatalog lists every registry package a catalog can use: each
// module version and each dependency version (first-party modules travel
// with the catalog and need no mirror).
func WantsFromCatalog(c *catalog.Catalog) []MirrorWant {
	seen := map[string]bool{}
	var out []MirrorWant
	add := func(src, ver string) {
		src = catalog.BaseSource(src)
		if catalog.IsFirstParty(src) || seen[src+"@"+ver] {
			return
		}
		seen[src+"@"+ver] = true
		out = append(out, MirrorWant{src, ver})
	}
	for _, m := range c.Modules {
		for _, v := range m.Versions {
			add(m.Source, v)
		}
		for _, d := range m.Dependencies {
			for _, v := range d.Versions {
				add(d.Source, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Source+out[i].Version < out[j].Source+out[j].Version })
	return out
}

// BuildMirror fetches packages and writes a signed mirror into dir.
func BuildMirror(ctx context.Context, f Fetcher, wants []MirrorWant, dir string, key ed25519.PrivateKey, progress func(string)) error {
	idx := mirrorIndexDoc{Version: 1, Packages: map[string]mirrorEntry{}}
	for _, w := range wants {
		files, origin, err := f.Fetch(ctx, w.Source, w.Version)
		if err != nil {
			return fmt.Errorf("%s@%s: %w", w.Source, w.Version, err)
		}
		sum := filesSum(files)
		rel := "pkgs/" + sum
		for name, b := range files {
			p := filepath.Join(dir, filepath.FromSlash(rel), filepath.FromSlash(name))
			if r, err := filepath.Rel(filepath.Join(dir, rel), p); err != nil || strings.HasPrefix(r, "..") {
				return fmt.Errorf("%s@%s: file %q escapes the package", w.Source, w.Version, name)
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				return err
			}
		}
		idx.Packages[w.Source+"@"+w.Version] = mirrorEntry{Dir: rel, Origin: origin, SHA256: sum}
		if progress != nil {
			progress(fmt.Sprintf("%s@%s (%d files)", w.Source, w.Version, len(files)))
		}
	}
	raw, _ := json.MarshalIndent(idx, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, mirrorIndex), raw, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, mirrorSig), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw))+"\n"), 0o644)
}
