// Package policy evaluates a plan before anyone can approve it.
//
// The runner sends a redacted summary of `tofu show -json` (addresses, types,
// actions and non-sensitive planned values). Hard violations block the run;
// advisory ones are shown to the approver.
package policy

import (
	"fmt"
	"strings"
)

type ResourceChange struct {
	Address   string         `json:"address"`
	Type      string         `json:"type"`
	Actions   []string       `json:"actions"`
	Importing bool           `json:"importing,omitempty"` // adopted from an existing cloud resource
	After     map[string]any `json:"after,omitempty"`     // sensitive and unknown values removed
	// Diff lists the top-level attributes whose live value differs from the
	// code (for updates, replacements, imports that would change, and drift).
	Diff []AttrDiff `json:"diff,omitempty"`
}

// AttrDiff is one attribute that differs between the live resource and the
// code. Sensitive values are shown as "(sensitive)".
type AttrDiff struct {
	Path string `json:"path"`
	Live any    `json:"live"`
	Code any    `json:"code"`
}

type Summary struct {
	Add       int              `json:"add"`
	Change    int              `json:"change"`
	Destroy   int              `json:"destroy"`
	Replace   int              `json:"replace"`
	Imports   int              `json:"imports,omitempty"` // existing resources adopted into state
	Resources []ResourceChange `json:"resources"`
	Outputs   []string         `json:"outputs,omitempty"`
	// Drift lists resources changed outside OpenTofu since the last apply
	// (from a refresh-only plan's resource_drift).
	Drift []ResourceChange `json:"drift,omitempty"`
	// State lists the managed resources in state before this run (after
	// refresh), Planned those the state holds once the plan is applied.
	// Addresses, types and IDs only; the stack page shows them.
	State   []StateResource `json:"state,omitempty"`
	Planned []StateResource `json:"planned,omitempty"`
}

// StateResource is one managed resource instance.
type StateResource struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	ID      string `json:"id,omitempty"`
}

func (s *Summary) HasChanges() bool { return s.Add+s.Change+s.Destroy+s.Replace+s.Imports > 0 }

type Violation struct {
	Rule    string `json:"rule"`
	Level   string `json:"level"` // hard | advisory
	Address string `json:"address,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Passed     bool        `json:"passed"`
	Violations []Violation `json:"violations"`
}

// Limits come from the environment.
type Limits struct {
	MaxDestroys  int  // deletes (including replacements) allowed in one run
	MaxCreates   int  // resources one run may create (0 = no limit)
	MaxImports   int  // resources one run may import (0 = no limit)
	AllowDestroy bool // whether destroy runs are allowed at all
	Destroying   bool // this run is a destroy run
	// ZeroDiff: the run plans a contract matched to the live resources
	// (live -> code); like an import, it must change nothing.
	ZeroDiff bool
}

// Resource types that create long-lived credentials or public exposure.
var forbiddenTypes = map[string]string{
	"aws_iam_access_key":          "creates a static AWS access key",
	"aws_iam_user_login_profile":  "creates a console password",
	"aws_iam_user":                "IAM users are not allowed; use roles",
	"google_service_account_key":  "creates a static GCP service account key",
	"google_storage_bucket_acl":   "legacy ACLs can make buckets public",
	"google_storage_hmac_key":     "creates a static HMAC key",
	"azurerm_storage_account_sas": "creates a shared access signature",
}

func Evaluate(s Summary, l Limits) Result {
	var v []Violation
	deletes := s.Destroy + s.Replace
	if l.Destroying && !l.AllowDestroy {
		v = append(v, Violation{Rule: "destroy-disabled", Level: "hard", Message: "destroy runs are disabled for this environment"})
	}
	if !l.Destroying && deletes > l.MaxDestroys {
		v = append(v, Violation{Rule: "destroy-limit", Level: "hard",
			Message: fmt.Sprintf("plan deletes %d resources; this environment allows at most %d per run", deletes, l.MaxDestroys)})
	}
	if l.MaxCreates > 0 && s.Add > l.MaxCreates {
		v = append(v, Violation{Rule: "create-limit", Level: "hard",
			Message: fmt.Sprintf("plan creates %d resources; this environment allows at most %d per run", s.Add, l.MaxCreates)})
	}
	if l.MaxImports > 0 && s.Imports > l.MaxImports {
		v = append(v, Violation{Rule: "import-limit", Level: "hard",
			Message: fmt.Sprintf("plan imports %d resources; this environment allows at most %d per run", s.Imports, l.MaxImports)})
	}
	// The zero-diff gate: a plan that imports existing resources, or that
	// tests a contract matched to the live resources (live -> code), must
	// change nothing at all. The contract has to describe the live
	// infrastructure exactly; only then are the resources adopted or the
	// contract saved. The one exception is the platform's ownership labels,
	// which every managed resource carries; the plan still lists them.
	if s.Imports > 0 || l.ZeroDiff {
		for _, r := range s.Resources {
			if len(r.Actions) == 1 && r.Actions[0] == "import" || OwnershipLabelsOnly(r) {
				continue
			}
			what := strings.Join(r.Actions, " and ")
			msg := fmt.Sprintf("zero-diff gate: the plan would %s this resource; the contract must match the live resource before it is adopted", what)
			if len(r.Diff) > 0 {
				var paths []string
				for _, d := range r.Diff {
					paths = append(paths, d.Path)
				}
				msg += " (differs: " + strings.Join(paths, ", ") + ")"
			} else if has(r.Actions, "create") && !r.Importing {
				msg = "zero-diff gate: the plan would create this resource, which does not exist in the cloud; adopt it with an import or remove it from the contract"
			}
			v = append(v, Violation{Rule: "import-zero-diff", Level: "hard", Address: r.Address, Message: msg})
		}
	}
	for _, r := range s.Resources {
		creating := has(r.Actions, "create") || has(r.Actions, "update")
		if why, bad := forbiddenTypes[r.Type]; bad && creating {
			v = append(v, Violation{Rule: "forbidden-resource", Level: "hard", Address: r.Address, Message: r.Type + ": " + why})
		}
		if !creating || r.After == nil {
			continue
		}
		switch r.Type {
		case "aws_vpc_security_group_ingress_rule":
			if r.After["cidr_ipv4"] == "0.0.0.0/0" || r.After["cidr_ipv6"] == "::/0" {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "ingress from the whole internet is not allowed"})
			}
		case "aws_security_group_rule":
			if r.After["type"] == "ingress" && containsAny(r.After["cidr_blocks"], "0.0.0.0/0") {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "ingress from the whole internet is not allowed"})
			}
		case "aws_s3_bucket_public_access_block":
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if b, ok := r.After[k].(bool); ok && !b {
					v = append(v, Violation{Rule: "s3-public-access", Level: "hard", Address: r.Address, Message: k + " must be true"})
				}
			}
		case "google_storage_bucket":
			if p, ok := r.After["public_access_prevention"].(string); ok && p != "enforced" {
				v = append(v, Violation{Rule: "gcs-public-access", Level: "hard", Address: r.Address, Message: "public_access_prevention must be enforced"})
			}
		case "google_compute_firewall":
			if containsAny(r.After["source_ranges"], "0.0.0.0/0") && r.After["direction"] != "EGRESS" {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "firewall ingress from 0.0.0.0/0 is not allowed"})
			}
		}
		if strings.HasPrefix(r.Type, "aws_") && r.After["tags_all"] == nil && r.After["tags"] == nil && taggable(r.Type) {
			v = append(v, Violation{Rule: "tags", Level: "advisory", Address: r.Address, Message: "resource has no tags"})
		}
	}
	passed := true
	for _, x := range v {
		if x.Level == "hard" {
			passed = false
		}
	}
	return Result{Passed: passed, Violations: v}
}

func taggable(t string) bool {
	switch t {
	case "aws_vpc", "aws_subnet", "aws_s3_bucket", "aws_security_group", "aws_instance", "aws_nat_gateway", "aws_internet_gateway":
		return true
	}
	return false
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsAny(v any, want string) bool {
	xs, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range xs {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

// labelAttrs hold resource tags or labels, as each provider reports them.
var labelAttrs = map[string]bool{"tags": true, "tags_all": true, "labels": true, "effective_labels": true, "terraform_labels": true}

// OwnershipLabel reports the keys the platform puts on every resource it
// manages (and the Google provider's own attribution label).
func OwnershipLabel(k string) bool {
	return k == "managed-by" || k == "goog-terraform-provisioned" || strings.HasPrefix(k, "srustiops-")
}

// localOnlyAttrs change only how OpenTofu treats a resource (never the cloud
// object), so an imported resource may differ in them.
// deletion_window_in_days only applies when a KMS key is scheduled for
// deletion; AWS does not report it, so an imported key never has it in state.
// The RDS settings below only apply when a database is deleted or modified
// and are not reported by AWS either.
var localOnlyAttrs = map[string]bool{"skip_destroy": true, "deletion_window_in_days": true,
	"skip_final_snapshot": true, "final_snapshot_identifier": true, "delete_automated_backups": true, "apply_immediately": true}

// LocalOnly reports an attribute that only affects OpenTofu, never the cloud.
func LocalOnly(attr string) bool { return localOnlyAttrs[attr] }

// OwnershipLabelsOnly reports an imported resource whose only change is
// adding (or correcting) the platform's ownership labels: every differing
// attribute is a label map, and only ownership keys differ in it. Attributes
// that only affect OpenTofu (skip_destroy) are ignored.
func OwnershipLabelsOnly(r ResourceChange) bool {
	if !r.Importing || len(r.Diff) == 0 || len(r.Actions) == 0 {
		return false
	}
	for _, a := range r.Actions {
		if a != "update" && a != "import" {
			return false
		}
	}
	for _, d := range r.Diff {
		if localOnlyAttrs[d.Path] {
			continue
		}
		if !labelAttrs[d.Path] {
			return false
		}
		live, ok1 := labelMap(d.Live)
		code, ok2 := labelMap(d.Code)
		if !ok1 || !ok2 {
			return false // unknown or sensitive
		}
		for k := range union(live, code) {
			if live[k] != code[k] && !OwnershipLabel(k) {
				return false
			}
			_, inLive := live[k]
			_, inCode := code[k]
			if inLive != inCode && !OwnershipLabel(k) {
				return false
			}
		}
	}
	return true
}

func labelMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case nil:
		return map[string]any{}, true
	case map[string]any:
		return t, true
	}
	return nil, false
}

func union(a, b map[string]any) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}
