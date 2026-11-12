package depcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
)

// A first-party module in a run must be byte-for-byte the catalog's code;
// anything else (a changed file, an extra file, an unknown module) is refused.
func TestFirstPartyModulesMatchTheCatalog(t *testing.T) {
	cat := &catalog.Catalog{FirstParty: map[string]map[string][]byte{
		"first-party/aws/subnet@1.0.0": {"main.tf": []byte(`resource "aws_subnet" "this" {}`), "variables.tf": []byte(`variable "vpc_id" {}`)},
	}}
	dir := filepath.Join(t.TempDir(), catalog.FirstPartyDir("first-party/aws/subnet", "1.0.0"))
	os.MkdirAll(dir, 0o700)
	write := func(n, s string) { os.WriteFile(filepath.Join(dir, n), []byte(s), 0o600) }
	write("main.tf", `resource "aws_subnet" "this" {}`)
	write("variables.tf", `variable "vpc_id" {}`)
	if err := checkFirstParty(dir, cat); err != nil {
		t.Fatalf("identical code refused: %v", err)
	}
	write("main.tf", `resource "aws_subnet" "this" {}
resource "null_resource" "x" { provisioner "local-exec" { command = "id" } }`)
	if err := checkFirstParty(dir, cat); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed code accepted: %v", err)
	}
	write("main.tf", `resource "aws_subnet" "this" {}`)
	write("extra.tf", `output "x" { value = 1 }`)
	if err := checkFirstParty(dir, cat); err == nil {
		t.Fatal("an extra file was accepted")
	}
	other := filepath.Join(t.TempDir(), "first-party-aws-unknown-1.0.0")
	os.MkdirAll(other, 0o700)
	if err := checkFirstParty(other, cat); err == nil || !strings.Contains(err.Error(), "not in this runner's catalog") {
		t.Fatalf("unknown module accepted: %v", err)
	}
}

// The whole check, as a run does it after `tofu init`: the root module
// loads a first-party module from .srustiops/modules.
func TestCheckAcceptsFirstPartyModulesInARun(t *testing.T) {
	cat, err := catalog.Load("../../../srustiops-modules/catalog")
	if err != nil {
		t.Skipf("modules repo not available: %v", err)
	}
	code := cat.FirstParty["first-party/aws/subnet@1.0.0"]
	if code == nil {
		t.Skip("no first-party subnet module")
	}
	root := t.TempDir()
	dir := ".srustiops/modules/" + catalog.FirstPartyDir("first-party/aws/subnet", "1.0.0")
	os.MkdirAll(filepath.Join(root, dir), 0o700)
	for n, b := range code {
		os.WriteFile(filepath.Join(root, dir, n), b, 0o600)
	}
	os.MkdirAll(filepath.Join(root, ".terraform", "modules"), 0o700)
	os.WriteFile(filepath.Join(root, ".terraform", "modules", "modules.json"), []byte(`{"Modules":[
		{"Key":"","Source":"","Dir":"."},
		{"Key":"net","Source":"./`+dir+`","Dir":"`+dir+`"}]}`), 0o600)
	p, _ := cat.Provider("hashicorp/aws")
	os.WriteFile(filepath.Join(root, ".terraform.lock.hcl"), []byte(`provider "registry.opentofu.org/hashicorp/aws" {
  version = "`+p.Version+`"
}
`), 0o600)
	if err := Check(root, cat); err != nil {
		t.Fatalf("first-party module refused: %v", err)
	}
	// Changed code in the run is refused.
	os.WriteFile(filepath.Join(root, dir, "main.tf"), []byte(`resource "aws_subnet" "this" { cidr_block = "0.0.0.0/0" }`), 0o600)
	if err := Check(root, cat); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed first-party code accepted: %v", err)
	}
}
