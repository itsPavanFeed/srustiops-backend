// Package catalog loads the approved-module catalog from srustiops-modules.
//
// The catalog is the only source of modules a stack may use: every entry is a
// public OpenTofu registry module pinned to exact versions, plus the provider
// versions those modules may pull in. Nothing outside the catalog can be run.
package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/yamlx"
)

// Registry is the only module and provider registry the platform trusts.
const Registry = "registry.opentofu.org"

var (
	idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	// KindRe: the name contracts use for a catalog entry, e.g. S3Bucket.
	KindRe = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{1,62}$`)
	// namespace/name/provider, optionally //modules/<sub> for a registry package's submodule
	sourceRe  = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[a-z0-9]{1,32}(//modules/[a-z0-9_-]{1,64})?|first-party/[a-z0-9-]{1,32}/[a-z0-9-]{1,64})$`)
	provRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[a-z0-9][a-z0-9-]{0,63}$`)
	semverRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	inputRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	inputType = map[string]bool{
		"string": true, "number": true, "bool": true,
		"list(string)": true, "list(number)": true,
		"map(string)": true, "map(bool)": true, "json": true,
	}
)

type Provider struct {
	Source  string `json:"source"`  // e.g. hashicorp/aws
	Version string `json:"version"` // exact pin
	Cloud   string `json:"cloud"`   // aws | gcp | azure | ""
}

type Dependency struct {
	Source   string   `json:"source"`
	Versions []string `json:"versions"`
}

type Input struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	ItemPattern string   `json:"item_pattern,omitempty"`
	Allowed     []any    `json:"allowed,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	MaxItems    int      `json:"max_items,omitempty"`
	// Sensitive inputs never take a literal value: contracts must pass a
	// secret reference, so the value stays in the secret store and out of Git.
	Sensitive bool `json:"sensitive,omitempty"`
	// OneTimeToken inputs take the platform's one-time install token
	// (sop_i_…) as a literal and nothing else: it works once and expires
	// within an hour. Only the provisioner's install modules use it.
	OneTimeToken bool `json:"one_time_token,omitempty"`
	// Into places the value as a key inside an enforced object instead of as a
	// module argument, so a baseline can lock an object's other keys.
	Into string `json:"into,omitempty"`

	pattern     *regexp.Regexp
	itemPattern *regexp.Regexp
}

func (i *Input) PatternRe() *regexp.Regexp     { return i.pattern }
func (i *Input) ItemPatternRe() *regexp.Regexp { return i.itemPattern }

// Module is one catalog entry. Contracts call it by its Kind.
type Module struct {
	ID           string         `json:"id"`
	Kind         string         `json:"kind"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Source       string         `json:"source"` // namespace/name/provider
	Versions     []string       `json:"versions"`
	Cloud        string         `json:"cloud"`
	Providers    []string       `json:"providers"`
	Dependencies []Dependency   `json:"dependencies,omitempty"`
	Inputs       []*Input       `json:"inputs"`
	Enforced     map[string]any `json:"enforced,omitempty"`
	Outputs      []string       `json:"outputs"`
	// Adopt describes how existing cloud resources become this kind (import
	// and backporting); nil means the kind cannot adopt resources yet.
	Adopt *Adopt `json:"adopt,omitempty"`
	// Platform marks a kind only the provisioner uses (the SrustiOps services
	// themselves): workspaces neither list it nor build stacks from it.
	Platform bool `json:"platform,omitempty"`
	// File is where the kind is defined, relative to the catalog folder
	// (modules/aws/s3-bucket.yaml); set by the loader, used by the console editor.
	File string `json:"file,omitempty"`
}

// Adopt maps an existing cloud resource onto a kind. Templates may use
// {{id}}, {{name}}, {{arn}}, {{region}}, {{project}}, {{account}} and, as a
// whole value, {{tags}} from the inventory item.
type Adopt struct {
	// Resource is the OpenTofu type of the primary resource, e.g. aws_s3_bucket.
	Resource string `json:"resource"`
	// Match lists the inventory types this kind adopts, per cloud
	// (AWS Resource Explorer "s3:bucket", GCP asset "storage.googleapis.com/Bucket", ...).
	Match map[string][]string `json:"match"`
	// Inputs are contract inputs filled from the live resource.
	Inputs map[string]string `json:"inputs,omitempty"`
	// Imports adopt every resource the module manages for one live resource,
	// so the plan after import can show zero changes.
	Imports []AdoptImport `json:"imports"`
	// Attributes map inputs to live attributes (resource address inside the
	// module and top-level attribute), so live values can flow back into the
	// contract (live -> code).
	Attributes map[string]AttrRef `json:"attributes,omitempty"`
	// Live rules make the adopted contract match live settings that differ
	// from the enforced baseline (a bucket encrypted with AES256): when an
	// imported resource differs, its live values become baseline gaps.
	Live []LiveRule `json:"live,omitempty"`
	// Properties says how to read a live resource's full properties, per
	// cloud (aws: a Cloud Control type and identifier template). Inputs,
	// gaps and dependencies may use {{prop:<path>}} (the value) and
	// {{propjson:<path>}} (the value as JSON text).
	Properties map[string]PropSource `json:"properties,omitempty"`
	// Gaps are baseline gaps set when adopting, from the live properties
	// (a key's own policy, its rotation setting).
	Gaps map[string]any `json:"gaps,omitempty"`
	// Dependencies are properties that name other resources: adoption
	// references them (stack/<stack>/<resource>.<output>) when they are
	// managed, adopts them first when their kind can, and otherwise keeps
	// the literal ID.
	Dependencies []AdoptDependency `json:"dependencies,omitempty"`
}

// PropSource reads one live resource's properties.
type PropSource struct {
	Type string `json:"type"` // e.g. AWS::EC2::SecurityGroup
	ID   string `json:"id"`   // identifier template, e.g. {{id_tail}}
	// Related adds the properties of a resource of another type that points
	// at this one (an internet gateway's VPC attachment), under As.
	Related *RelatedSource `json:"related,omitempty"`
}

// RelatedSource finds the resource of Type whose property Key equals this
// resource's identifier, and adds its properties as As.
type RelatedSource struct {
	Type string `json:"type"` // e.g. AWS::EC2::VPCGatewayAttachment
	Key  string `json:"key"`  // e.g. InternetGatewayId
	As   string `json:"as"`   // e.g. Attachment
}

// AdoptDependency: the property at Path (a value or a list) holds IDs of
// resources of Kind, equal to that kind's Output; they fill Input (or the
// baseline gap at Gap, a dotted path).
type AdoptDependency struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Output string `json:"output"`
	Input  string `json:"input,omitempty"`
	Gap    string `json:"gap,omitempty"`
}

// LiveRule maps one imported resource's live settings to baseline gaps. It
// applies when the resource differs from the code and every When condition
// holds. Gap values may be "{{live:<attr>.<index or key>...}}", replaced by
// the live value there (dropped when the live value is null); DropImport
// removes the resource's import too (the module cannot express the live
// state, e.g. versioning that was never enabled, so it must not manage it).
type LiveRule struct {
	Resource   string         `json:"resource"`
	When       map[string]any `json:"when,omitempty"`
	DropImport bool           `json:"drop_import,omitempty"`
	Gaps       map[string]any `json:"gaps,omitempty"`
	// ClearGaps removes baseline gaps the live resource no longer has (the
	// baseline applies again), and AddImport adopts the object that now
	// exists; its id may use {{input:<name>}} (an input of the resource).
	ClearGaps []string     `json:"clear_gaps,omitempty"`
	AddImport *AdoptImport `json:"add_import,omitempty"`
}

type AdoptImport struct {
	To string `json:"to"` // address inside the module, e.g. aws_s3_bucket.this[0]
	ID string `json:"id"` // template for the cloud ID
	// Optional imports may not exist in the cloud (a bucket without a
	// policy). When the plan finds nothing to import there, the import is
	// dropped and Absent becomes a baseline gap of the adopted resource:
	// module arguments that stop the module from creating the missing
	// object, so the adopted code matches what exists (zero diff).
	Optional bool           `json:"optional,omitempty"`
	Absent   map[string]any `json:"absent,omitempty"`
	// IfProp: import only when the live resource has this property (a
	// redrive policy, a lifecycle rule); the module creates the object only
	// then, so an import without it would target nothing.
	IfProp string `json:"if_prop,omitempty"`
}

// GapsFor returns the baseline gaps allowed when the optional import at
// address (inside the module) does not exist, or false.
func (a *Adopt) GapsFor(address string) (map[string]any, bool) {
	for _, im := range a.Imports {
		if im.To == address && im.Optional {
			return im.Absent, true
		}
	}
	return nil, false
}

// GapAllowed reports whether value may be set for name as a baseline gap:
// some optional import of the kind declares exactly that value, or a live
// rule takes that argument from the live resource.
func (a *Adopt) GapAllowed(name string, value any) bool {
	if a == nil {
		return false
	}
	for _, r := range a.Live {
		if _, ok := r.Gaps[name]; ok {
			return true
		}
	}
	if _, ok := a.Gaps[name]; ok {
		return true
	}
	want, _ := json.Marshal(value)
	for _, im := range a.Imports {
		if v, ok := im.Absent[name]; ok && im.Optional {
			if got, _ := json.Marshal(v); string(got) == string(want) {
				return true
			}
		}
	}
	return false
}

type AttrRef struct {
	Resource string `json:"resource"` // e.g. aws_s3_bucket.this[0]
	Path     string `json:"path"`     // top-level attribute, e.g. tags
}

var (
	adoptPlaceholderRe = regexp.MustCompile(`\{\{([a-z_]+)(:[A-Za-z0-9_.,=:/-]+)?\}\}`)
	adoptPlaceholders  = map[string]bool{"id": true, "id_tail": true, "arn_path": true, "name": true, "arn": true, "region": true, "project": true, "account": true, "tags": true,
		"prop": true, "propjson": true, "propmap": true, "propfind": true, "live": true, "input": true}
	moduleAddrRe = regexp.MustCompile(`^([a-z][a-z0-9_]{0,63}\.)?[a-z][a-z0-9_]{0,63}\.[A-Za-z_][A-Za-z0-9_-]{0,63}(\[(\d{1,4}|"[^"\\]{1,128}")\])?$`)
	attrPathRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	tfTypeRe     = regexp.MustCompile(`^[a-z][a-z0-9]*_[a-z0-9_]{1,80}$`)
)

func (a *Adopt) check(m *Module) []error {
	var errs []error
	where := "module " + m.ID + " adopt"
	if !tfTypeRe.MatchString(a.Resource) {
		errs = append(errs, fmt.Errorf("%s: resource %q is not an OpenTofu type", where, a.Resource))
	}
	if len(a.Match) == 0 || len(a.Imports) == 0 {
		errs = append(errs, fmt.Errorf("%s: match and imports are required", where))
	}
	tmpl := func(what, t string, whole bool) {
		for _, p := range adoptPlaceholderRe.FindAllStringSubmatch(t, -1) {
			if !adoptPlaceholders[p[1]] {
				errs = append(errs, fmt.Errorf("%s: %s uses unknown placeholder {{%s}}", where, what, p[1]))
			}
			if p[1] == "tags" && t != "{{tags}}" {
				errs = append(errs, fmt.Errorf("%s: %s: {{tags}} must be the whole value", where, what))
			}
		}
		_ = whole
	}
	for in, t := range a.Inputs {
		if m.Input(in) == nil {
			errs = append(errs, fmt.Errorf("%s: %s is not an input of the kind", where, in))
		}
		tmpl("input "+in, t, true)
	}
	for _, im := range a.Imports {
		if !moduleAddrRe.MatchString(im.To) && !strings.HasPrefix(im.To, "module.") {
			errs = append(errs, fmt.Errorf("%s: import address %q is not an address inside the module", where, im.To))
		}
		tmpl("import "+im.To, im.ID, false)
		if len(im.Absent) > 0 && !im.Optional {
			errs = append(errs, fmt.Errorf("%s: import %q: absent applies only to optional imports", where, im.To))
		}
		for k := range im.Absent {
			if !attrPathRe.MatchString(k) {
				errs = append(errs, fmt.Errorf("%s: import %q: absent sets %q, which is not a module argument", where, im.To, k))
			}
		}
	}
	for _, lr := range a.Live {
		if !moduleAddrRe.MatchString(lr.Resource) || len(lr.Gaps) == 0 && len(lr.ClearGaps) == 0 && lr.AddImport == nil && !lr.DropImport {
			errs = append(errs, fmt.Errorf("%s: live rule for %q needs a resource address and something to do (gaps, clear_gaps, add_import or drop_import)", where, lr.Resource))
		}
		if lr.AddImport != nil && !moduleAddrRe.MatchString(lr.AddImport.To) {
			errs = append(errs, fmt.Errorf("%s: live rule for %q: add_import needs an address inside the module", where, lr.Resource))
		}
		for k := range lr.Gaps {
			if !attrPathRe.MatchString(k) {
				errs = append(errs, fmt.Errorf("%s: live rule for %q sets %q, which is not a module argument", where, lr.Resource, k))
			}
		}
	}
	for cloud, ps := range a.Properties {
		if cloud != "aws" && cloud != "gcp" && cloud != "azure" || ps.Type == "" || ps.ID == "" {
			errs = append(errs, fmt.Errorf("%s: properties for %q need a cloud (aws, gcp, azure), a type and an id", where, cloud))
		}
	}
	for _, d := range a.Dependencies {
		if d.Path == "" || d.Kind == "" || d.Output == "" || (d.Input == "") == (d.Gap == "") {
			errs = append(errs, fmt.Errorf("%s: dependency at %q needs path, kind, output and exactly one of input or gap", where, d.Path))
		}
		if d.Input != "" && m.Input(d.Input) == nil {
			errs = append(errs, fmt.Errorf("%s: dependency fills %s, which is not an input of the kind", where, d.Input))
		}
	}
	for in, ref := range a.Attributes {
		if m.Input(in) == nil {
			errs = append(errs, fmt.Errorf("%s: attribute mapping for %s, which is not an input", where, in))
		}
		if !attrPathRe.MatchString(ref.Path) || ref.Resource == "" {
			errs = append(errs, fmt.Errorf("%s: attribute mapping for %s needs a resource and a top-level attribute", where, in))
		}
	}
	return errs
}

func (m *Module) Input(name string) *Input {
	for _, in := range m.Inputs {
		if in.Name == name {
			return in
		}
	}
	return nil
}

func (m *Module) HasVersion(v string) bool { return contains(m.Versions, v) }

func (m *Module) HasOutput(o string) bool { return contains(m.Outputs, o) }

// LatestVersion is the last listed version; catalogs list versions oldest first.
func (m *Module) LatestVersion() string { return m.Versions[len(m.Versions)-1] }

type Catalog struct {
	Modules   []*Module  `json:"modules"`
	Providers []Provider `json:"providers"`
	// FirstParty holds the code of first-party modules, by "<source>@<version>"
	// (first-party/aws/subnet@1.0.0): thin single-resource modules kept with
	// the catalog for resource types no public module manages on their own.
	FirstParty map[string]map[string][]byte `json:"first_party,omitempty"`

	byID     map[string]*Module
	byKind   map[string]*Module
	bySource map[string]*Module
	provider map[string]Provider
}

func (c *Catalog) Module(id string) *Module { return c.byID[id] }

// Kind finds a catalog entry by the kind contracts use, e.g. "S3Bucket".
func (c *Catalog) Kind(kind string) *Module { return c.byKind[kind] }

// BaseSource strips a //modules/<sub> suffix: the registry package address.
func BaseSource(src string) string {
	if i := strings.Index(src, "//"); i >= 0 {
		return src[:i]
	}
	return src
}

func (c *Catalog) ModuleBySource(src string) *Module { return c.bySource[strings.ToLower(src)] }

func (c *Catalog) Provider(src string) (Provider, bool) {
	p, ok := c.provider[strings.ToLower(src)]
	return p, ok
}

// ModuleVersionAllowed reports whether a registry module address (with or without
// the registry host) at a version is approved, either as a catalog module or as a
// declared dependency of one.
func (c *Catalog) ModuleVersionAllowed(source, version string) bool {
	source = strings.TrimPrefix(strings.ToLower(source), Registry+"/")
	if i := strings.Index(source, "//"); i >= 0 {
		source = source[:i]
	}
	for _, m := range c.Modules {
		if strings.EqualFold(BaseSource(m.Source), source) && m.HasVersion(version) {
			return true
		}
	}
	for _, m := range c.Modules {
		for _, d := range m.Dependencies {
			if strings.EqualFold(d.Source, source) && contains(d.Versions, version) {
				return true
			}
		}
	}
	return false
}

// New builds a catalog from already-decoded parts (for example, the copy a
// runner receives with a job) and validates it exactly as Load does.
//
// A module built in code without a kind gets one derived from its id
// (aws-vpc -> AwsVpc); catalog files must always name their kind.
func New(mods []*Module, provs []Provider) (*Catalog, error) {
	for _, m := range mods {
		if m.Kind == "" {
			m.Kind = KindFromID(m.ID)
		}
	}
	c := &Catalog{Modules: mods, Providers: provs}
	if err := c.index(); err != nil {
		return nil, err
	}
	return c, nil
}

// Catalog layout, segregated by cloud provider:
//
//	providers/<cloud>.yaml      providers for that cloud (exact pins)
//	modules/<cloud>/<name>.yaml one kind per file, wrapping one public module
//
// <cloud> is aws, gcp, azure, or "common" for modules and providers that need
// no cloud credentials. The folder is the single source of truth for a
// module's cloud, and a module may only use its own cloud's providers plus
// common ones, so an AWS module can never pull in a GCP provider. Files may be
// YAML (.yaml, .yml) or JSON (.json).
const CommonFolder = "common"

// Clouds lists the supported cloud folders (besides common).
var Clouds = []string{"aws", "gcp", "azure"}

func folderCloud(folder string) (string, bool) {
	if folder == CommonFolder {
		return "", true
	}
	for _, c := range Clouds {
		if folder == c {
			return c, true
		}
	}
	return "", false
}

// Load reads a catalog directory laid out as described above and validates it.
func Load(dir string) (*Catalog, error) {
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	return LoadFS(os.DirFS(dir))
}

// LoadFS is Load for any file system, e.g. a snapshot of the modules repository.
func LoadFS(fsys fs.FS) (*Catalog, error) {
	var errs []error
	if _, err := fs.Stat(fsys, "providers.json"); err == nil {
		errs = append(errs, errors.New("providers.json is the old flat layout; split it into providers/<cloud>.yaml"))
	}
	c := &Catalog{}
	pfiles := dataFiles(fsys, "providers")
	if len(pfiles) == 0 {
		errs = append(errs, errors.New("no providers/<cloud>.yaml files"))
	}
	for _, f := range pfiles {
		cloud, ok := folderCloud(stem(f))
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unknown cloud; use one of %s or %s", f, strings.Join(Clouds, ", "), CommonFolder))
			continue
		}
		var pf struct {
			Registry  string     `json:"registry"`
			Providers []Provider `json:"providers"`
		}
		if err := readData(fsys, f, &pf); err != nil {
			errs = append(errs, err)
			continue
		}
		if pf.Registry != Registry {
			errs = append(errs, fmt.Errorf("%s: registry must be %q", f, Registry))
		}
		for _, p := range pf.Providers {
			if p.Cloud != "" {
				errs = append(errs, fmt.Errorf("%s: provider %s must not set cloud; the file name decides it", f, p.Source))
			}
			p.Cloud = cloud
			c.Providers = append(c.Providers, p)
		}
	}
	if flat := dataFiles(fsys, "modules"); len(flat) > 0 {
		errs = append(errs, fmt.Errorf("modules must live in modules/<cloud>/, found %s", flat[0]))
	}
	entries, err := fs.ReadDir(fsys, "modules")
	if err != nil {
		return nil, errors.Join(append(errs, err)...)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cloud, ok := folderCloud(e.Name())
		if !ok {
			errs = append(errs, fmt.Errorf("modules/%s: unknown cloud folder; use one of %s or %s", e.Name(), strings.Join(Clouds, ", "), CommonFolder))
			continue
		}
		for _, f := range dataFiles(fsys, path.Join("modules", e.Name())) {
			var m Module
			if err := readData(fsys, f, &m); err != nil {
				errs = append(errs, err)
				continue
			}
			if m.Cloud != "" {
				errs = append(errs, fmt.Errorf("%s: must not set cloud; the folder decides it", f))
			}
			if m.File != "" {
				errs = append(errs, fmt.Errorf("%s: must not set file", f))
			}
			m.Cloud, m.File = cloud, f
			c.Modules = append(c.Modules, &m)
		}
	}
	fp, fpErrs := loadFirstParty(fsys)
	c.FirstParty = fp
	errs = append(errs, fpErrs...)
	// Every first-party kind has its code here. (A release's catalog does
	// not carry the code: it is vendored into the release bundle.)
	for _, m := range c.Modules {
		if IsFirstParty(m.Source) {
			for _, v := range m.Versions {
				if fp[m.Source+"@"+v] == nil {
					errs = append(errs, fmt.Errorf("%s: first-party code for %s %s is missing (first-party/…/%s/)", m.File, m.Source, v, v))
				}
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if err := c.index(); err != nil {
		return nil, err
	}
	return c, nil
}

// FirstPartyPrefix starts the sources of first-party modules.
const FirstPartyPrefix = "first-party/"

// IsFirstParty reports a first-party module source.
func IsFirstParty(source string) bool { return strings.HasPrefix(source, FirstPartyPrefix) }

// FirstPartyDir names the folder a first-party module version is written to
// in a run: first-party-aws-subnet-1.0.0.
func FirstPartyDir(source, version string) string {
	return strings.ReplaceAll(strings.TrimSuffix(source, "/"), "/", "-") + "-" + version
}

// FirstPartySum is a checksum over a module version's files.
func FirstPartySum(files map[string][]byte) string {
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

var firstPartyFileRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}\.tf$`)

// loadFirstParty reads first-party/<cloud>/<name>/<version>/*.tf. Only .tf
// files directly in a version folder are code; anything else is refused, so
// what is reviewed in the repository is exactly what runs.
func loadFirstParty(fsys fs.FS) (map[string]map[string][]byte, []error) {
	out := map[string]map[string][]byte{}
	var errs []error
	clouds, err := fs.ReadDir(fsys, "first-party")
	if err != nil {
		return out, nil // no first-party modules
	}
	for _, c := range clouds {
		if !c.IsDir() {
			continue
		}
		names, _ := fs.ReadDir(fsys, path.Join("first-party", c.Name()))
		for _, n := range names {
			if !n.IsDir() {
				continue
			}
			versions, _ := fs.ReadDir(fsys, path.Join("first-party", c.Name(), n.Name()))
			for _, v := range versions {
				dir := path.Join("first-party", c.Name(), n.Name(), v.Name())
				if !v.IsDir() || !semverRe.MatchString(v.Name()) {
					errs = append(errs, fmt.Errorf("%s: first-party modules are first-party/<cloud>/<name>/<x.y.z>/", dir))
					continue
				}
				files := map[string][]byte{}
				entries, _ := fs.ReadDir(fsys, dir)
				for _, e := range entries {
					if e.IsDir() || !firstPartyFileRe.MatchString(e.Name()) {
						errs = append(errs, fmt.Errorf("%s/%s: only .tf files directly in the version folder are allowed", dir, e.Name()))
						continue
					}
					b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
					if err != nil || len(b) > 256<<10 {
						errs = append(errs, fmt.Errorf("%s/%s: unreadable or larger than 256 KiB", dir, e.Name()))
						continue
					}
					files[e.Name()] = b
				}
				if len(files) == 0 {
					errs = append(errs, fmt.Errorf("%s: no .tf files", dir))
					continue
				}
				out[FirstPartyPrefix+c.Name()+"/"+n.Name()+"@"+v.Name()] = files
			}
		}
	}
	return out, errs
}

// dataFiles lists the YAML and JSON files directly inside dir, sorted.
func dataFiles(fsys fs.FS, dir string) []string {
	entries, _ := fs.ReadDir(fsys, dir)
	var out []string
	for _, e := range entries {
		if !e.IsDir() && isData(e.Name()) {
			out = append(out, path.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

func isData(name string) bool {
	switch path.Ext(name) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

func stem(f string) string { return strings.TrimSuffix(path.Base(f), path.Ext(f)) }

func (c *Catalog) index() error {
	c.byID = map[string]*Module{}
	c.byKind = map[string]*Module{}
	c.bySource = map[string]*Module{}
	c.provider = map[string]Provider{}
	var errs []error
	for _, p := range c.Providers {
		if !provRe.MatchString(p.Source) || !semverRe.MatchString(p.Version) {
			errs = append(errs, fmt.Errorf("provider %q: source must be namespace/type and version an exact x.y.z pin", p.Source))
		}
		if _, dup := c.provider[strings.ToLower(p.Source)]; dup {
			errs = append(errs, fmt.Errorf("provider %q is listed more than once", p.Source))
		}
		if _, ok := folderCloud(cloudFolder(p.Cloud)); !ok {
			errs = append(errs, fmt.Errorf("provider %q: unknown cloud %q", p.Source, p.Cloud))
		}
		c.provider[strings.ToLower(p.Source)] = p
	}
	for _, m := range c.Modules {
		where := "module " + m.ID
		if !idRe.MatchString(m.ID) {
			errs = append(errs, fmt.Errorf("%s: invalid id", where))
		}
		if c.byID[m.ID] != nil {
			errs = append(errs, fmt.Errorf("%s: duplicate id", where))
		}
		switch {
		case !KindRe.MatchString(m.Kind):
			errs = append(errs, fmt.Errorf("%s: kind %q must be a name like S3Bucket", where, m.Kind))
		case m.Kind == "Defaults" || m.Kind == "Stack":
			errs = append(errs, fmt.Errorf("%s: kind %q is reserved", where, m.Kind))
		case c.byKind[m.Kind] != nil:
			errs = append(errs, fmt.Errorf("%s: kind %q is already used by %s", where, m.Kind, c.byKind[m.Kind].ID))
		}
		if !sourceRe.MatchString(m.Source) {
			errs = append(errs, fmt.Errorf("%s: source %q must be a public registry address namespace/name/provider", where, m.Source))
		}
		if len(m.Versions) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one pinned version required", where))
		}
		for _, v := range m.Versions {
			if !semverRe.MatchString(v) {
				errs = append(errs, fmt.Errorf("%s: version %q must be an exact x.y.z pin", where, v))
			}
		}
		for _, d := range m.Dependencies {
			if !sourceRe.MatchString(d.Source) || len(d.Versions) == 0 {
				errs = append(errs, fmt.Errorf("%s: dependency %q needs a registry source and pinned versions", where, d.Source))
			}
			for _, v := range d.Versions {
				if !semverRe.MatchString(v) {
					errs = append(errs, fmt.Errorf("%s: dependency version %q must be exact", where, v))
				}
			}
		}
		if _, ok := folderCloud(cloudFolder(m.Cloud)); !ok {
			errs = append(errs, fmt.Errorf("%s: unknown cloud %q", where, m.Cloud))
		}
		for _, p := range m.Providers {
			pv, ok := c.provider[strings.ToLower(p)]
			switch {
			case !ok:
				errs = append(errs, fmt.Errorf("%s: provider %q is not allowlisted in providers/", where, p))
			case pv.Cloud != "" && pv.Cloud != m.Cloud:
				errs = append(errs, fmt.Errorf("%s: a %s module cannot use the %s provider %q", where, cloudFolder(m.Cloud), pv.Cloud, p))
			}
		}
		seen := map[string]bool{}
		for _, in := range m.Inputs {
			if !inputRe.MatchString(in.Name) || !inputType[in.Type] || seen[in.Name] {
				errs = append(errs, fmt.Errorf("%s: input %q has an invalid name, type %q or is duplicated", where, in.Name, in.Type))
			}
			if _, enforced := m.Enforced[in.Name]; enforced {
				errs = append(errs, fmt.Errorf("%s: input %q is both user-settable and enforced", where, in.Name))
			}
			if in.Sensitive && in.Type != "string" {
				errs = append(errs, fmt.Errorf("%s: sensitive input %q must be a string", where, in.Name))
			}
			if in.Sensitive && in.Default != nil {
				errs = append(errs, fmt.Errorf("%s: sensitive input %q cannot have a default", where, in.Name))
			}
			if in.OneTimeToken && (in.Type != "string" || in.Default != nil || in.Sensitive || !strings.HasPrefix(m.Source, FirstPartyPrefix)) {
				errs = append(errs, fmt.Errorf("%s: one_time_token input %q must be a string with no default, not sensitive, in a first-party module", where, in.Name))
			}
			if in.Into != "" {
				obj, ok := m.Enforced[in.Into].(map[string]any)
				if !ok {
					errs = append(errs, fmt.Errorf("%s: input %q goes into %q, which is not an enforced object", where, in.Name, in.Into))
				} else if _, locked := obj[in.Name]; locked {
					errs = append(errs, fmt.Errorf("%s: input %q would override the enforced %s.%s", where, in.Name, in.Into, in.Name))
				}
			}
			seen[in.Name] = true
			var err error
			if in.Pattern != "" {
				if in.pattern, err = regexp.Compile(in.Pattern); err != nil {
					errs = append(errs, fmt.Errorf("%s: input %q pattern: %w", where, in.Name, err))
				}
			}
			if in.ItemPattern != "" {
				if in.itemPattern, err = regexp.Compile(in.ItemPattern); err != nil {
					errs = append(errs, fmt.Errorf("%s: input %q item_pattern: %w", where, in.Name, err))
				}
			}
		}
		if m.Adopt != nil {
			errs = append(errs, m.Adopt.check(m)...)
		}
		c.byID[m.ID] = m
		if m.Kind != "" && c.byKind[m.Kind] == nil {
			c.byKind[m.Kind] = m
		}
		c.bySource[strings.ToLower(m.Source)] = m
	}
	return errors.Join(errs...)
}

// KindFromID derives a kind name from a module id: aws-s3-bucket -> AwsS3Bucket.
func KindFromID(id string) string {
	var b strings.Builder
	for _, part := range strings.Split(id, "-") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]) + part[1:])
		}
	}
	return b.String()
}

func cloudFolder(cloud string) string {
	if cloud == "" {
		return CommonFolder
	}
	return cloud
}

func readData(fsys fs.FS, name string, v any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return err
	}
	if path.Ext(name) == ".json" {
		err = yamlx.DecodeJSON(b, v)
	} else {
		err = yamlx.Decode(b, v)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
