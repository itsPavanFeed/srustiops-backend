package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/opapolicy"
	"github.com/itsPavanFeed/srustiops-backend/internal/policy"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- the policy library ----
//
// Ready-made Rego policy sets for the checks most tenants want, each with a
// few parameters. The console fills the parameters in, shows the Rego, and
// backtests it against recent plans before it is saved as an ordinary
// policy set (which the tenant then owns and may edit).

type libParam struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Type    string   `json:"type"` // list | string
	Default []string `json:"default"`
}

type libPolicy struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Category    string     `json:"category"`
	Level       string     `json:"level"` // suggested
	Params      []libParam `json:"params"`
	Rego        string     `json:"rego"` // uses `params`, filled in from the parameters
}

// Every set reads the planned resources (input.summary.resources: address,
// type, actions and the planned attributes in after) and the run.
const regoHeader = "package srustiops.policy\n\n"

var policyLibrary = []libPolicy{
	{
		ID: "required-tags", Title: "Required tags", Category: "Tagging", Level: "hard",
		Description: "Every created or updated resource that takes tags (AWS tags, GCP and Azure labels or tags) must carry these keys. Tags SrustiOps adds itself (default tags) count.",
		Params:      []libParam{{Name: "keys", Label: "Tag keys", Type: "list", Default: []string{"owner", "cost-center"}}},
		Rego: `# Resources that take tags must have every required key.
taggable(after) if after.tags_all != null
taggable(after) if after.tags != null
taggable(after) if after.labels != null

tag_keys(after) := {k | some k, _ in object.union(object.union(object.get(after, "tags", {}) , object.get(after, "tags_all", {})), object.get(after, "labels", {}))}

deny contains {"msg": sprintf("%s is missing tag(s) %v", [r.address, missing]), "address": r.address} if {
	some r in input.summary.resources
	r.actions[_] in {"create", "update"}
	r.after != null
	taggable(r.after)
	missing := {k | some k in params.keys} - tag_keys(r.after)
	count(missing) > 0
}
`,
	},
	{
		ID: "encryption-at-rest", Title: "Encryption at rest", Category: "Security", Level: "hard",
		Description: "Storage must be encrypted: EBS volumes, RDS instances and clusters, EFS file systems, EC2 root and EBS block devices, and DynamoDB tables with encryption turned off.",
		Params:      []libParam{},
		Rego: `checks := {
	"aws_ebs_volume": "encrypted",
	"aws_db_instance": "storage_encrypted",
	"aws_rds_cluster": "storage_encrypted",
	"aws_efs_file_system": "encrypted",
}

deny contains {"msg": sprintf("%s must be encrypted (%s = true)", [r.address, attr]), "address": r.address} if {
	some r in input.summary.resources
	r.actions[_] in {"create", "update"}
	attr := checks[r.type]
	object.get(r.after, attr, false) != true
}

deny contains {"msg": sprintf("%s: every block device must be encrypted", [r.address]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_instance"
	r.actions[_] in {"create", "update"}
	some dev in array.concat(object.get(r.after, "root_block_device", []), object.get(r.after, "ebs_block_device", []))
	object.get(dev, "encrypted", false) != true
}

deny contains {"msg": sprintf("%s must keep server-side encryption on", [r.address]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_dynamodb_table"
	r.actions[_] in {"create", "update"}
	some sse in object.get(r.after, "server_side_encryption", [])
	sse.enabled == false
}
`,
	},
	{
		ID: "no-public-access", Title: "No public access", Category: "Security", Level: "hard",
		Description: "No public buckets, databases or wide-open ingress: S3 public-access blocks must block everything, RDS instances must not be publicly accessible, security groups may open only the listed ports to the internet, and GCS buckets must prevent public access.",
		Params:      []libParam{{Name: "public_ports", Label: "Ports allowed from the internet", Type: "list", Default: []string{"80", "443"}}},
		Rego: `open_to_world(rule) if "0.0.0.0/0" in object.get(rule, "cidr_blocks", [])
open_to_world(rule) if "::/0" in object.get(rule, "ipv6_cidr_blocks", [])

allowed_port(rule) if {
	rule.from_port == rule.to_port
	sprintf("%d", [rule.from_port]) in {p | some p in params.public_ports}
}

deny contains {"msg": sprintf("%s opens ports %d-%d to the internet", [r.address, rule.from_port, rule.to_port]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_security_group"
	r.actions[_] in {"create", "update"}
	some rule in object.get(r.after, "ingress", [])
	open_to_world(rule)
	not allowed_port(rule)
}

deny contains {"msg": sprintf("%s opens ports %d-%d to the internet", [r.address, r.after.from_port, r.after.to_port]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_security_group_rule"
	r.actions[_] in {"create", "update"}
	r.after.type == "ingress"
	open_to_world(r.after)
	not allowed_port(r.after)
}

deny contains {"msg": sprintf("%s must block all public access (%s)", [r.address, k]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_s3_bucket_public_access_block"
	r.actions[_] in {"create", "update"}
	some k in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	object.get(r.after, k, false) != true
}

deny contains {"msg": sprintf("%s must not be publicly accessible", [r.address]), "address": r.address} if {
	some r in input.summary.resources
	r.type in {"aws_db_instance", "aws_rds_cluster_instance"}
	r.actions[_] in {"create", "update"}
	r.after.publicly_accessible == true
}

deny contains {"msg": sprintf("%s must enforce public access prevention", [r.address]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "google_storage_bucket"
	r.actions[_] in {"create", "update"}
	object.get(r.after, "public_access_prevention", "") != "enforced"
}
`,
	},
	{
		ID: "allowed-regions", Title: "Allowed regions", Category: "Compliance", Level: "hard",
		Description: "Deploy only to these regions: the environment's cloud region, and any resource that names its own region or location.",
		Params:      []libParam{{Name: "regions", Label: "Regions", Type: "list", Default: []string{"eu-west-1", "eu-central-1"}}},
		Rego: `allowed := {lower(x) | some x in params.regions}

deny contains sprintf("environment %s deploys to region %s, which is not allowed", [input.run.environment, input.run.region]) if {
	input.run.region != ""
	not lower(input.run.region) in allowed
}

deny contains {"msg": sprintf("%s is in %s, which is not an allowed region", [r.address, loc]), "address": r.address} if {
	some r in input.summary.resources
	r.actions[_] == "create"
	some key in ["region", "location"]
	loc := object.get(r.after, key, "")
	is_string(loc)
	loc != ""
	not lower(loc) in allowed
}
`,
	},
	{
		ID: "allowed-instance-types", Title: "Allowed instance sizes", Category: "Cost", Level: "advisory",
		Description: "EC2 instances, launch templates, RDS instances and GCE machines must use one of these sizes.",
		Params:      []libParam{{Name: "types", Label: "Instance types", Type: "list", Default: []string{"t3.micro", "t3.small", "t3.medium", "db.t3.micro", "db.t3.small", "e2-small", "e2-medium"}}},
		Rego: `attr := {"aws_instance": "instance_type", "aws_launch_template": "instance_type", "aws_db_instance": "instance_class", "google_compute_instance": "machine_type"}

deny contains {"msg": sprintf("%s uses %s, which is not an allowed size", [r.address, size]), "address": r.address} if {
	some r in input.summary.resources
	r.actions[_] in {"create", "update"}
	size := object.get(r.after, attr[r.type], "")
	is_string(size)
	size != ""
	not size in {t | some t in params.types}
}
`,
	},
	{
		ID: "no-destroy-in-prod", Title: "No deletes in production", Category: "Change safety", Level: "hard",
		Description: "Plans in production environments may not delete or replace resources, except of the listed types. Destroy runs are refused too.",
		Params:      []libParam{{Name: "except_types", Label: "Resource types that may be replaced", Type: "list", Default: []string{}}},
		Rego: `deny contains {"msg": sprintf("%s would be deleted in production", [r.address]), "address": r.address} if {
	input.run.tier == "prod"
	some r in input.summary.resources
	"delete" in r.actions
	not r.type in {t | some t in params.except_types}
}
`,
	},
	{
		ID: "monthly-cost-limit", Title: "Monthly cost limit", Category: "Cost", Level: "advisory",
		Description: "A plan may not raise the stack's estimated monthly cost by more than this amount (USD).",
		Params:      []libParam{{Name: "max_increase", Label: "Largest monthly increase (USD)", Type: "string", Default: []string{"500"}}},
		Rego: `deny contains sprintf("this plan adds about $%v a month, above the $%s limit", [round(input.cost.monthly_delta_usd), params.max_increase]) if {
	input.cost.monthly_delta_usd > to_number(params.max_increase)
}
`,
	},
	{
		ID: "bu-budget", Title: "Stay within the BU's budget", Category: "Cost", Level: "advisory",
		Description: "Holds a plan that adds cost when the BU's month-end forecast (actual spend so far at its current pace, from Costs) plus the plan's monthly increase would pass this share of its budget. BUs without a budget are not affected.",
		Params:      []libParam{{Name: "max_used_pct", Label: "Hold new cost above this % of the budget", Type: "string", Default: []string{"100"}}},
		Rego: `deny contains sprintf("%s is heading for %v%% of its %v budget this month (%v spent so far); this plan adds about $%v a month", [input.run.bu, round(projected_pct), round(input.budget.monthly), round(input.budget.spent), round(input.cost.monthly_delta_usd)]) if {
	input.budget != null
	input.cost.monthly_delta_usd > 0
	projected_pct >= to_number(params.max_used_pct)
}

projected_pct := (object.get(input.budget, "forecast", input.budget.spent) + input.cost.monthly_delta_usd) / input.budget.monthly * 100 if input.budget != null
`,
	},
}

// renderLibPolicy fills a library policy's parameters in.
func renderLibPolicy(p libPolicy, values map[string][]string) (string, []string) {
	params := map[string]any{}
	var probs []string
	for _, prm := range p.Params {
		v, ok := values[prm.Name]
		if !ok {
			v = prm.Default
		}
		clean := []string{}
		for _, x := range v {
			x = strings.TrimSpace(x)
			if x == "" {
				continue
			}
			if len(x) > 200 || strings.Contains(x, "`") {
				probs = append(probs, prm.Label+": a value is too long or has a backtick")
				continue
			}
			clean = append(clean, x)
		}
		if len(clean) > 200 {
			probs = append(probs, prm.Label+": too many values")
		}
		if prm.Type == "string" {
			if len(clean) != 1 {
				probs = append(probs, prm.Label+" needs one value")
				continue
			}
			params[prm.Name] = clean[0]
		} else {
			params[prm.Name] = clean
		}
	}
	// Parsed at evaluation, so an empty list type-checks like a full one.
	b, _ := json.MarshalIndent(params, "", "\t")
	return regoHeader + "# " + p.Title + " (from the SrustiOps policy library)\n\nparams := json.unmarshal(`" + string(b) + "`)\n\n" + p.Rego, probs
}

func (s *Server) policyLibrary(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		libPolicy
		Example string `json:"example"` // rendered with the defaults
	}
	out := []entry{}
	for _, p := range policyLibrary {
		m, _ := renderLibPolicy(p, nil)
		out = append(out, entry{libPolicy: p, Example: m})
	}
	writeJSON(w, 200, out)
}

// backtestPolicy evaluates a policy set (written or from the library) against
// the most recent plans in its scope, to show what it would have stopped.
func (s *Server) backtestPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Module  string              `json:"module"`
		Library string              `json:"library"`
		Params  map[string][]string `json:"params"`
		Scope   string              `json:"scope"`
		Limit   int                 `json:"limit"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Library != "" {
		var lp *libPolicy
		for i := range policyLibrary {
			if policyLibrary[i].ID == b.Library {
				lp = &policyLibrary[i]
			}
		}
		if lp == nil {
			writeErr(w, 422, "unknown library policy "+b.Library)
			return
		}
		m, probs := renderLibPolicy(*lp, b.Params)
		if len(probs) > 0 {
			writeErr(w, 422, "invalid parameters", probs...)
			return
		}
		b.Module = m
	}
	if err := opapolicy.Compile(b.Module); err != nil {
		writeErr(w, 422, "rego: "+err.Error())
		return
	}
	if b.Scope == "" {
		b.Scope = "tenant"
	}
	if !psScopeRe.MatchString(b.Scope) {
		writeErr(w, 422, `scope must be "tenant", "entity:<slug>" or "bu:<slug>"`)
		return
	}
	if b.Limit <= 0 || b.Limit > 100 {
		b.Limit = 25
	}
	runs, err := s.store.QueryRuns(r.Context(), store.RunQuery{BUs: visible(r), Limit: 200, Operations: []string{"apply", "destroy"},
		Statuses: []string{"planned", "apply_queued", "applying", "applied", "policy_failed", "no_changes", "failed", "discarded"}})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	type result struct {
		RunID      string             `json:"run_id"`
		Stack      string             `json:"stack"`
		BU         string             `json:"bu"`
		Env        string             `json:"environment"`
		Status     string             `json:"status"`
		CreatedAt  string             `json:"created_at"`
		Violations []policy.Violation `json:"violations"`
	}
	envs := map[string]*store.Environment{}
	out := []result{}
	failing := 0
	set := []opapolicy.Set{{Name: "backtest", Level: "hard", Module: b.Module}}
	for _, run := range runs {
		if len(out) >= b.Limit {
			break
		}
		if len(run.PlanSummary) == 0 || (b.Scope != "tenant" && b.Scope != "entity:"+run.Entity && b.Scope != "bu:"+run.BU) {
			continue
		}
		var sum policy.Summary
		if json.Unmarshal(run.PlanSummary, &sum) != nil {
			continue
		}
		key := run.Entity + ":" + run.Environment
		env, ok := envs[key]
		if !ok {
			env, _ = s.store.EntityEnvironment(r.Context(), run.Entity, run.Environment)
			envs[key] = env
		}
		vs := opapolicy.Evaluate(r.Context(), set, s.policyInput(r.Context(), run, env, sum))
		if vs == nil {
			vs = []policy.Violation{}
		}
		if len(vs) > 0 {
			failing++
		}
		out = append(out, result{RunID: run.ID, Stack: run.StackName, BU: run.BU, Env: run.Environment, Status: run.Status,
			CreatedAt: run.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), Violations: vs})
	}
	writeJSON(w, 200, map[string]any{"module": b.Module, "plans": len(out), "would_fail": failing, "results": out})
}

// cloudRegion is the region an environment's connection deploys to.
func cloudRegion(env *store.Environment) string {
	if env == nil {
		return ""
	}
	cl, err := spec.DecodeCloud(env.Cloud)
	if err != nil {
		return ""
	}
	switch {
	case cl.AWS != nil:
		return cl.AWS.Region
	case cl.GCP != nil:
		return cl.GCP.Region
	}
	return ""
}
