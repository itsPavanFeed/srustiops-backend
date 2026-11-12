package catalog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestKindsMatchModuleSources checks every terraform-aws-modules kind against
// the module's real source: inputs, enforced settings and every baseline gap
// must be module variables, outputs must exist and adopt imports must name
// resources of the module. Point SRUSTIOPS_MODULE_SOURCES at a folder with one
// sub-folder per module (vpc/, sqs/, …) holding its variables.tf, outputs.tf
// and main.tf at the catalog's version.
func TestKindsMatchModuleSources(t *testing.T) {
	dir := os.Getenv("SRUSTIOPS_MODULE_SOURCES")
	if dir == "" {
		t.Skip("SRUSTIOPS_MODULE_SOURCES not set")
	}
	cat, err := Load("../../../srustiops-modules/catalog")
	if err != nil {
		t.Fatal(err)
	}
	srcRe := regexp.MustCompile(`^terraform-aws-modules/([a-z0-9-]+)/aws(?://modules/([a-z0-9_-]+))?`)
	read := func(mod, file string) string {
		b, _ := os.ReadFile(filepath.Join(dir, mod, file))
		return string(b)
	}
	// A submodule's sources sit in a folder named after it (iam-policy/),
	// else in the package's folder.
	folder := func(p []string) string {
		if p[2] != "" {
			if _, err := os.Stat(filepath.Join(dir, p[2], "variables.tf")); err == nil {
				return p[2]
			}
		}
		return p[1]
	}
	set := func(src, kind string) map[string]bool {
		out := map[string]bool{}
		for _, m := range regexp.MustCompile(`(?m)^`+kind+` "([a-z0-9_]+)"`).FindAllStringSubmatch(src, -1) {
			out[m[1]] = true
		}
		return out
	}
	checked := 0
	for _, m := range cat.Modules {
		var vars, outs map[string]bool
		var mainTF string
		if IsFirstParty(m.Source) {
			// First-party code is in the catalog itself.
			code := cat.FirstParty[m.Source+"@"+m.Versions[0]]
			all := ""
			for _, b := range code {
				all += string(b) + "\n"
			}
			vars, outs, mainTF = set(all, "variable"), set(all, "output"), all
		} else {
			p := srcRe.FindStringSubmatch(m.Source)
			if p == nil {
				continue
			}
			mod := folder(p)
			vars, outs, mainTF = set(read(mod, "variables.tf"), "variable"), set(read(mod, "outputs.tf"), "output"), read(mod, "main.tf")
		}
		if len(vars) == 0 {
			t.Errorf("%s: no sources for %s", m.Kind, m.Source)
			continue
		}
		res := map[string]bool{}
		for _, r := range regexp.MustCompile(`(?m)^resource "([a-z0-9_]+)" "([a-z0-9_]+)"`).FindAllStringSubmatch(mainTF, -1) {
			res[r[1]+"."+r[2]] = true
		}
		need := func(name, what string) {
			if !vars[name] {
				t.Errorf("%s: %s %q is not a variable of %s", m.Kind, what, name, m.Source)
			}
		}
		for _, in := range m.Inputs {
			need(in.Name, "input")
		}
		for k := range m.Enforced {
			need(k, "enforced setting")
		}
		for _, o := range m.Outputs {
			if !outs[o] {
				t.Errorf("%s: output %q is not an output of %s", m.Kind, o, m.Source)
			}
		}
		if a := m.Adopt; a != nil {
			for k := range a.Gaps {
				need(k, "adopt gap")
			}
			for _, im := range a.Imports {
				addr := strings.SplitN(im.To, "[", 2)[0]
				if strings.HasPrefix(addr, "module.") {
					continue // inside one of the module's own submodules
				}
				if !res[addr] {
					t.Errorf("%s: import %q is not a resource of %s", m.Kind, im.To, m.Source)
				}
				for k := range im.Absent {
					need(k, "absent gap")
				}
			}
			for _, r := range a.Live {
				for k := range r.Gaps {
					need(k, "live gap")
				}
			}
			for _, d := range a.Dependencies {
				if d.Gap != "" {
					need(strings.SplitN(d.Gap, ".", 2)[0], "dependency gap")
				}
			}
		}
		checked++
	}
	t.Logf("checked %d kinds against their module sources", checked)
}
