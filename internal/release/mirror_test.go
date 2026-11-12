package release

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mirrorFetch map[string]map[string][]byte

func (f mirrorFetch) Fetch(_ context.Context, source, version string) (map[string][]byte, string, error) {
	return f[source+"@"+version], "github.com/x/" + source + "@deadbeef", nil
}

func TestModuleMirror(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	dir := t.TempDir()
	f := mirrorFetch{
		"terraform-aws-modules/vpc/aws@6.0.1":       {"main.tf": []byte("# vpc"), "modules/x/main.tf": []byte("# sub")},
		"terraform-aws-modules/s3-bucket/aws@5.0.0": {"main.tf": []byte("# s3")},
	}
	wants := []MirrorWant{{"terraform-aws-modules/vpc/aws", "6.0.1"}, {"terraform-aws-modules/s3-bucket/aws", "5.0.0"}}
	if err := BuildMirror(context.Background(), f, wants, dir, priv, nil); err != nil {
		t.Fatal(err)
	}
	m := &Mirror{Dir: dir, Key: pub}
	files, origin, err := m.Fetch(context.Background(), "terraform-aws-modules/vpc/aws//modules/x", "6.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if string(files["modules/x/main.tf"]) != "# sub" || !strings.HasPrefix(origin, "mirror: ") {
		t.Fatalf("files %v origin %q", files, origin)
	}
	if _, _, err := m.Fetch(context.Background(), "terraform-aws-modules/eks/aws", "1.0.0"); err == nil {
		t.Fatal("a package missing from the mirror must fail")
	}

	// A changed file is caught by the signed checksum.
	var pkg string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, _ error) error {
		if !d.IsDir() && strings.HasSuffix(p, "main.tf") && strings.Contains(string(must(os.ReadFile(p))), "# s3") {
			pkg = p
		}
		return nil
	})
	os.WriteFile(pkg, []byte("# s3 with a backdoor"), 0o644)
	if _, _, err := (&Mirror{Dir: dir, Key: pub}).Fetch(context.Background(), "terraform-aws-modules/s3-bucket/aws", "5.0.0"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("tampered package: %v", err)
	}

	// Another key, or a changed index, is refused.
	other, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := (&Mirror{Dir: dir, Key: other}).Fetch(context.Background(), "terraform-aws-modules/vpc/aws", "6.0.1"); err == nil {
		t.Fatal("a mirror signed with another key must be refused")
	}
	idx := filepath.Join(dir, "index.json")
	os.WriteFile(idx, append(must(os.ReadFile(idx)), ' '), 0o644)
	if _, _, err := (&Mirror{Dir: dir, Key: pub}).Fetch(context.Background(), "terraform-aws-modules/vpc/aws", "6.0.1"); err == nil {
		t.Fatal("an edited index must be refused")
	}
	if _, err := ParseMirrorKey("nope"); err == nil {
		t.Fatal("bad key accepted")
	}
}

func must(b []byte, _ error) []byte { return b }
