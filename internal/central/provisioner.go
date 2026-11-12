package central

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/httpx"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
	"github.com/itsPavanFeed/srustiops-backend/internal/yamlx"
	"github.com/jackc/pgx/v5"
)

// The provisioner builds a workspace's infrastructure in the client's own
// cloud account and installs the tenant plane there, for clients who would
// rather not run the install command. It is no new engine: every piece is a
// stack in the platform's own tenant (SRUSTIOPS_PROVISIONER_TENANT), with that
// tenant's plans, cost estimates, policies, approvals, state and audit, run
// by its dedicated runner pool. The connection still comes first: the client
// creates a role in their account that trusts only this workspace's stacks.
//
// Approvals stay real. The plan's manager step is signed in the client
// admin's name once they approve the plan and its cost. Two guards sign the
// other steps, each only when its rule holds, and are audited as themselves:
// the budget guard (FinOps) while the estimated monthly cost stays within the
// cap the client accepted, and the blueprint guard (Security) while no plan
// destroys or replaces what holds the tenant's data. Anything else waits for
// a person.

//go:embed blueprints/*.yaml
var builtinBlueprints embed.FS

const (
	provisionerEntity = "provisioner"
	provisionerUser   = "provisioner@srustiops.internal"
	budgetGuard       = "budget-guard@srustiops.internal"
	blueprintGuard    = "blueprint-guard@srustiops.internal"
)

// Stack roles: data holds the tenant's data (and the network it lives in)
// and is never destroyed; service is compute for SrustiOps alone; install puts
// the tenant plane on it and carries the install token.
const (
	roleData    = "data"
	roleService = "service"
	roleInstall = "install"
)

type BlueprintInput struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	List     bool   `json:"list,omitempty"`
}

type BlueprintStack struct {
	Name string `json:"name"`
	Role string `json:"role"`
	Spec string `json:"-"`
	// Uninstall says how removing the workspace takes SrustiOps off the install
	// piece: "destroy" when the piece is only SrustiOps (a Helm release), or
	// "input:<name>" to apply the piece with that input set to true (a VM,
	// where the machine stays and only the services go).
	Uninstall string `json:"uninstall,omitempty"`
}

type Blueprint struct {
	ID     string           `json:"id"`
	Title  string           `json:"title"`
	Cloud  string           `json:"cloud"`
	Mode   string           `json:"mode"`
	Target string           `json:"target"`
	Inputs []BlueprintInput `json:"inputs"`
	Stacks []BlueprintStack `json:"stacks"`
}

// Sizes are what the client picks from; budget_usd is the default cap.
type Size map[string]any

func (s *Server) blueprints() (map[string]*Blueprint, map[string]Size, error) {
	var fsys fs.FS
	if dir := s.cfg.ProvisionerBlueprints; dir != "" {
		fsys = os.DirFS(dir)
	} else {
		sub, _ := fs.Sub(builtinBlueprints, "blueprints")
		fsys = sub
	}
	files, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, nil, err
	}
	bps, sizes := map[string]*Blueprint{}, map[string]Size{}
	for _, f := range files {
		b, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, nil, err
		}
		if f == "sizes.yaml" {
			if err := yamlx.Decode(b, &sizes); err != nil {
				return nil, nil, fmt.Errorf("%s: %w", f, err)
			}
			continue
		}
		var raw struct {
			ID     string           `json:"id"`
			Title  string           `json:"title"`
			Cloud  string           `json:"cloud"`
			Mode   string           `json:"mode"`
			Target string           `json:"target"`
			Inputs []BlueprintInput `json:"inputs"`
			Stacks []struct {
				Name      string `json:"name"`
				Role      string `json:"role"`
				Spec      string `json:"spec"`
				Uninstall string `json:"uninstall"`
			} `json:"stacks"`
		}
		if err := yamlx.Decode(b, &raw); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", f, err)
		}
		bp := &Blueprint{ID: raw.ID, Title: raw.Title, Cloud: raw.Cloud, Mode: raw.Mode, Target: raw.Target, Inputs: raw.Inputs}
		for _, st := range raw.Stacks {
			if st.Role != roleData && st.Role != roleService && st.Role != roleInstall {
				return nil, nil, fmt.Errorf("%s: stack %s: role must be data, service or install", f, st.Name)
			}
			if st.Uninstall == "" && st.Role == roleInstall {
				st.Uninstall = "destroy"
			}
			if st.Uninstall != "" && (st.Role != roleInstall || (st.Uninstall != "destroy" && !strings.HasPrefix(st.Uninstall, "input:"))) {
				return nil, nil, fmt.Errorf("%s: stack %s: uninstall is \"destroy\" or \"input:<name>\", and only on the install stack", f, st.Name)
			}
			bp.Stacks = append(bp.Stacks, BlueprintStack{Name: st.Name, Role: st.Role, Spec: st.Spec, Uninstall: st.Uninstall})
		}
		if bp.ID == "" || len(bp.Stacks) == 0 || bp.Stacks[len(bp.Stacks)-1].Role != roleInstall {
			return nil, nil, fmt.Errorf("%s: a blueprint needs an id and stacks ending with its install stack", f)
		}
		if bp.Inputs == nil {
			bp.Inputs = []BlueprintInput{}
		}
		bps[bp.ID] = bp
	}
	if len(sizes) == 0 {
		return nil, nil, errors.New("blueprints: sizes.yaml is missing")
	}
	return bps, sizes, nil
}

// ---- rendering ----

type renderData struct {
	Slug, Name, Region string
	Account            string // AWS account, GCP project or Azure subscription
	Inputs             map[string]any
	Size               Size
	Platform           platformRefs
	InstallToken       string
}

type platformRefs struct {
	GatewayURL, CentralURL, GatewayCA, ImageRepo, ImageTag, ChartRepository, ChartVersion string
}

func (s *Server) platformRefs() platformRefs {
	ca := ""
	if s.cfg.LinkServerCA != "" {
		if b, err := os.ReadFile(s.cfg.LinkServerCA); err == nil {
			ca = string(b)
		}
	}
	repo := s.cfg.ChartRepository
	if repo == "" {
		repo = "oci://" + strings.TrimPrefix(s.cfg.ImageRepo, "oci://") + "/charts"
	}
	ver := s.cfg.ChartVersion
	if ver == "" {
		ver = "0.1.0"
	}
	return platformRefs{GatewayURL: s.cfg.LinkPublicURL, CentralURL: s.cfg.PublicURL, GatewayCA: ca,
		ImageRepo: s.cfg.ImageRepo, ImageTag: s.cfg.ImageTag, ChartRepository: repo, ChartVersion: ver}
}

func stackName(slug, name string) string { return "pv-" + slug + "-" + name }

// render turns one blueprint stack into the spec the platform tenant takes.
func render(slug string, st BlueprintStack, d renderData) (json.RawMessage, error) {
	funcs := template.FuncMap{
		"json":  func(v any) string { b, _ := json.Marshal(v); return string(b) },
		"stack": func(n string) string { return stackName(slug, n) },
		"azs": func(region string, n int) []string {
			out := []string{}
			for _, z := range []string{"a", "b", "c", "d"}[:n] {
				out = append(out, region+z)
			}
			return out
		},
		// subnet carves the netnum-th block of newbits extra bits out of cidr
		// (like OpenTofu's cidrsubnet).
		"subnet": func(cidr any, newbits, netnum int) (string, error) {
			_, n, err := net.ParseCIDR(fmt.Sprint(cidr))
			if err != nil || n.IP.To4() == nil {
				return "", fmt.Errorf("%v is not an IPv4 CIDR", cidr)
			}
			ones, _ := n.Mask.Size()
			if ones+newbits > 30 {
				return "", fmt.Errorf("%v is too small", cidr)
			}
			ip := n.IP.To4()
			v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
			v |= uint32(netnum) << (32 - ones - newbits)
			return fmt.Sprintf("%d.%d.%d.%d/%d", v>>24, v>>16&255, v>>8&255, v&255, ones+newbits), nil
		},
	}
	t, err := template.New(st.Name).Funcs(funcs).Option("missingkey=error").Parse(st.Spec)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	var spec any
	if err := yamlx.Decode(buf.Bytes(), &spec); err != nil {
		return nil, fmt.Errorf("stack %s: %w", st.Name, err)
	}
	return json.Marshal(spec)
}

// ---- records ----

type ProvStack struct {
	Name     string   `json:"name"`  // in the blueprint
	Stack    string   `json:"stack"` // in the platform tenant
	Role     string   `json:"role"`
	Created  bool     `json:"created"`
	RunID    string   `json:"run_id,omitempty"`
	Op       string   `json:"operation,omitempty"`
	Status   string   `json:"status"` // the latest run's status, or waiting/not_started
	WaitsOn  []string `json:"waits_on,omitempty"`
	Add      int      `json:"add"`
	Change   int      `json:"change"`
	Destroy  int      `json:"destroy"`
	Replace  int      `json:"replace"`
	CostUSD  float64  `json:"monthly_cost_usd"`
	Required []string `json:"required_approvals,omitempty"`
	Signed   []string `json:"signed,omitempty"`
	Error    string   `json:"error,omitempty"`
	// Uninstalling: the workspace was removed and this install piece is being
	// applied without SrustiOps (see BlueprintStack.Uninstall).
	Uninstalling bool `json:"uninstalling,omitempty"`
}

type Provisioning struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"-"`
	Tenant      string         `json:"tenant"`
	Blueprint   string         `json:"blueprint"`
	Cloud       string         `json:"cloud"`
	Mode        string         `json:"mode"`
	Target      string         `json:"target"`
	Size        string         `json:"size"`
	Region      string         `json:"region"`
	Account     string         `json:"account"`
	Inputs      map[string]any `json:"inputs"`
	BudgetUSD   float64        `json:"budget_usd"`
	Status      string         `json:"status"`
	Detail      string         `json:"detail"`
	Stacks      []*ProvStack   `json:"stacks"`
	ApprovedBy  string         `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time     `json:"approved_at,omitempty"`
	DecomBy     string         `json:"decommissioned_by,omitempty"`
	HandedOver  *time.Time     `json:"handed_over_at,omitempty"`
	CreatedBy   string         `json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	Trust       *trustSetup    `json:"trust,omitempty"`
	Install     *installState  `json:"install,omitempty"`
	CostUSD     float64        `json:"monthly_cost_usd"`
	PlatformBU  string         `json:"platform_bu"`
	PlatformEnv string         `json:"platform_environment"`
	// TrustIssuer is the issuer the trust role was verified against;
	// TrustCheck the latest re-check of it.
	TrustIssuer string      `json:"trust_issuer,omitempty"`
	TrustCheck  *trustCheck `json:"trust_check,omitempty"`
}

// trustCheck is the outcome of re-checking the client's trust role.
type trustCheck struct {
	OK            bool                                    `json:"ok"`
	CheckedAt     time.Time                               `json:"checked_at"`
	CheckedBy     string                                  `json:"checked_by"`
	Checks        []struct{ Name, Status, Detail string } `json:"checks"`
	Issuer        string                                  `json:"issuer"`
	IssuerChanged bool                                    `json:"issuer_changed"`
	Detail        string                                  `json:"detail"`
}

const provCols = `p.id, p.tenant_id, t.slug, p.blueprint, p.cloud, p.mode, p.target, p.size, p.region, p.account, p.inputs, p.budget_usd, p.status, p.detail,
	p.stacks, p.approved_by, p.approved_at, p.decommissioned_by, p.handed_over_at, p.created_by, p.created_at, p.updated_at, p.trust_issuer, p.trust_check`

func scanProv(r pgx.Row) (*Provisioning, error) {
	var p Provisioning
	var inputs, stacks, check []byte
	err := r.Scan(&p.ID, &p.TenantID, &p.Tenant, &p.Blueprint, &p.Cloud, &p.Mode, &p.Target, &p.Size, &p.Region, &p.Account, &inputs, &p.BudgetUSD,
		&p.Status, &p.Detail, &stacks, &p.ApprovedBy, &p.ApprovedAt, &p.DecomBy, &p.HandedOver, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.TrustIssuer, &check)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(inputs, &p.Inputs)
	json.Unmarshal(stacks, &p.Stacks)
	if len(check) > 0 {
		json.Unmarshal(check, &p.TrustCheck)
	}
	if p.Stacks == nil {
		p.Stacks = []*ProvStack{}
	}
	p.PlatformBU, p.PlatformEnv = "pv-"+p.Tenant, p.Tenant
	for _, st := range p.Stacks {
		p.CostUSD += st.CostUSD
	}
	return &p, nil
}

func (s *Store) provisioningFor(ctx context.Context, tenantID string) (*Provisioning, error) {
	return scanProv(s.Pool().QueryRow(ctx, `SELECT `+provCols+` FROM provisionings p JOIN tenants t ON t.id = p.tenant_id
		WHERE p.tenant_id = $1 ORDER BY p.created_at DESC LIMIT 1`, tenantID))
}

func (s *Store) saveProvisioning(ctx context.Context, p *Provisioning) error {
	stacks, _ := json.Marshal(p.Stacks)
	inputs, _ := json.Marshal(p.Inputs)
	_, err := s.Pool().Exec(ctx, `UPDATE provisionings SET status = $2, detail = $3, stacks = $4, approved_by = $5, approved_at = $6,
		decommissioned_by = $7, handed_over_at = $8, budget_usd = $9, trust_issuer = $10, trust_check = $11, inputs = $12, updated_at = now() WHERE id = $1`,
		p.ID, p.Status, trim(p.Detail, 1000), stacks, p.ApprovedBy, p.ApprovedAt, p.DecomBy, p.HandedOver, p.BudgetUSD, p.TrustIssuer, nullJSON(p.TrustCheck), inputs)
	return err
}

// ---- trust ----

type trustSetup struct {
	RoleARN           string `json:"role_arn,omitempty"`
	Issuer            string `json:"issuer"`
	Subject           string `json:"subject"`
	Audience          string `json:"audience"`
	CloudFormation    string `json:"cloudformation,omitempty"`
	CloudFormationURL string `json:"cloudformation_console_url,omitempty"`
	Script            string `json:"script,omitempty"`
	Revoke            string `json:"revoke"`
	// Problem says why the cloud cannot use the issuer (it is not public
	// https), so no template is offered that would only fail there.
	Problem string `json:"problem,omitempty"`
}

// issuerProblem: AWS fetches the issuer's keys over the internet, so it
// must be https on a public host; loopback, private and link-local
// addresses, and names like localhost, can never be trusted from AWS.
func issuerProblem(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Sprintf("The platform tenant's OIDC issuer is %q; AWS needs a public https address to fetch its keys.", issuer)
	}
	h := u.Hostname()
	ip := net.ParseIP(h)
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".local") ||
		(ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())) {
		return fmt.Sprintf("The platform tenant's OIDC issuer is %s, which AWS cannot reach. Give the platform tenant a public https address (SRUSTIOPS_PUBLIC_URL; locally DEV_ACME_PUBLIC_URL with a tunnel) and reload this page.", issuer)
	}
	return ""
}

// installState is what the console shows while the tenant plane comes up:
// the install token's life, when bootstrap used it, and the link.
type installState struct {
	TokenIssuedAt  *time.Time `json:"token_issued_at,omitempty"`
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
	TokenUsedAt    *time.Time `json:"token_used_at,omitempty"`
	Tunnels        int        `json:"tunnels"`
	Online         bool       `json:"online"`
	GatewayURL     string     `json:"gateway_url"`
}

var awsAccountRe = regexp.MustCompile(`^\d{12}$`)

// cloudChecks: what a region and an account (AWS account, GCP project,
// Azure subscription) look like in each cloud.
var cloudChecks = map[string]struct {
	region, account            *regexp.Regexp
	regionExample, accountHint string
}{
	"aws":   {regexp.MustCompile(`^[a-z]{2}-[a-z]+-\d$`), awsAccountRe, "eu-west-1", "the 12-digit AWS account ID"},
	"gcp":   {regexp.MustCompile(`^[a-z]+-[a-z]+\d$`), regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`), "europe-west1", "the GCP project ID"},
	"azure": {regexp.MustCompile(`^[a-z]+[a-z0-9]*$`), guidRe, "westeurope", "the Azure subscription ID"},
}

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// gcpIDs are the workload identity pool, its provider and the service
// account a GCP workspace's trust uses (GCP's ID length limits applied).
func gcpIDs(tenant string) (pool, provider, sa string) {
	pool = strings.TrimRight(trim("sop-"+tenant, 32), "-")
	sa = strings.TrimRight(trim("sop-prov-"+tenant, 30), "-")
	return pool, "srustiops", sa
}

// trustSubjects are the exact OIDC subjects of a workspace's provisioning
// stacks (both phases) and its connection check, for clouds that match
// subjects exactly (Azure federated credentials).
func (s *Server) trustSubjects(p *Provisioning) []string {
	var out []string
	if bps, _, err := s.blueprints(); err == nil && bps[p.Blueprint] != nil {
		for _, st := range bps[p.Blueprint].Stacks {
			for _, ph := range []string{"plan", "apply"} {
				out = append(out, "srustiops:entity:"+provisionerEntity+":env:"+p.Tenant+":stack:"+stackName(p.Tenant, st.Name)+":phase:"+ph)
			}
		}
	}
	return append(out, "srustiops:discovery:pv-"+p.Tenant)
}

// trustFor is what the client runs in their account: a role that trusts
// only this workspace's provisioning stacks (the OIDC subject is pinned to
// the workspace's own environment in the platform tenant). With OIDC
// federation no External ID is involved; the pinned subject is what stops a
// confused deputy, and it is unique per workspace.
func (s *Server) trustFor(p *Provisioning, issuer string) *trustSetup {
	switch p.Cloud {
	case "gcp":
		return s.gcpTrust(p, issuer)
	case "azure":
		return s.azureTrust(p, issuer)
	}
	sub := "srustiops:entity:" + provisionerEntity + ":env:" + p.Tenant + ":stack:*"
	discovery := "srustiops:discovery:pv-" + p.Tenant
	role := "srustiops-provisioner-" + p.Tenant
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	t := &trustSetup{Issuer: issuer, Subject: sub, Audience: "sts.amazonaws.com", RoleARN: "arn:aws:iam::" + p.Account + ":role/" + role}
	t.CloudFormation = `AWSTemplateFormatVersion: "2010-09-09"
Description: Lets the SrustiOps provisioner build workspace ` + p.Tenant + ` in this account. Delete this stack to revoke it.
Parameters:
  OIDCProviderExists:
    Type: String
    AllowedValues: ["true", "false"]
    Default: "false"
    Description: true when this account already trusts ` + host + ` as an OIDC provider
Conditions:
  CreateProvider: !Equals [!Ref OIDCProviderExists, "false"]
Resources:
  Provider:
    Type: AWS::IAM::OIDCProvider
    Condition: CreateProvider
    Properties:
      Url: ` + issuer + `
      ClientIdList: [sts.amazonaws.com]
  Role:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ` + role + `
      MaxSessionDuration: 3600
      Description: SrustiOps provisioner for workspace ` + p.Tenant + ` (OIDC, no static keys)
      # Least privilege: the role can only create what its own policies allow.
      PermissionsBoundary: !Ref Boundary
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Sub arn:aws:iam::${AWS::AccountId}:oidc-provider/` + host + `
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals: {"` + host + `:aud": sts.amazonaws.com}
              # The workspace's provisioning stacks, and the connection's own
              # check (the tenant tests every connection with its discovery identity).
              StringLike: {"` + host + `:sub": ["` + sub + `", "` + discovery + `"]}
      ManagedPolicyArns: [!Ref Provision]
  Provision:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: What the provisioner may create for SrustiOps (network, cluster, VM, KMS, bucket, database, endpoints, the tenant's roles), and run on its VM through Systems Manager to remove SrustiOps
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: [ec2:*, eks:*, rds:*, s3:*, kms:*, secretsmanager:*, ssm:GetParameter, ssm:GetParameters, ssm:CreateAssociation, ssm:DescribeAssociation, ssm:UpdateAssociation, ssm:DeleteAssociation, ssm:ListAssociations, ssm:DescribeAssociationExecutions, ssm:AddTagsToResource, ssm:ListTagsForResource, ssm:RemoveTagsFromResource, logs:*, autoscaling:*, elasticloadbalancing:Describe*, sts:GetCallerIdentity]
            Resource: "*"
          - Effect: Allow
            Action: [iam:CreateRole, iam:DeleteRole, iam:GetRole, iam:TagRole, iam:UntagRole, iam:PutRolePolicy, iam:DeleteRolePolicy, iam:GetRolePolicy,
              iam:AttachRolePolicy, iam:DetachRolePolicy, iam:ListRolePolicies, iam:ListAttachedRolePolicies, iam:ListInstanceProfilesForRole, iam:PassRole,
              iam:CreateInstanceProfile, iam:DeleteInstanceProfile, iam:GetInstanceProfile, iam:AddRoleToInstanceProfile, iam:RemoveRoleFromInstanceProfile, iam:TagInstanceProfile,
              iam:CreateOpenIDConnectProvider, iam:DeleteOpenIDConnectProvider, iam:GetOpenIDConnectProvider, iam:TagOpenIDConnectProvider, iam:CreateServiceLinkedRole,
              iam:CreatePolicy, iam:DeletePolicy, iam:GetPolicy, iam:GetPolicyVersion, iam:ListPolicyVersions, iam:CreatePolicyVersion, iam:DeletePolicyVersion, iam:TagPolicy]
            Resource: "*"
  Boundary:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: The ceiling for the provisioner role; it cannot grant itself more
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: [ec2:*, eks:*, rds:*, s3:*, kms:*, secretsmanager:*, ssm:GetParameter, ssm:GetParameters, ssm:CreateAssociation, ssm:DescribeAssociation, ssm:UpdateAssociation, ssm:DeleteAssociation, ssm:ListAssociations, ssm:DescribeAssociationExecutions, ssm:AddTagsToResource, ssm:ListTagsForResource, ssm:RemoveTagsFromResource, logs:*, autoscaling:*, elasticloadbalancing:Describe*, sts:GetCallerIdentity, iam:*]
            Resource: "*"
          - Effect: Deny
            Action: [iam:CreateUser, iam:CreateAccessKey, iam:CreateLoginProfile, iam:UpdateAssumeRolePolicy, organizations:*, account:*]
            Resource: "*"
          - Effect: Deny
            Action: [iam:DeleteRolePermissionsBoundary, iam:PutRolePermissionsBoundary, iam:DeleteRole, iam:PutRolePolicy, iam:AttachRolePolicy]
            Resource: !Sub arn:aws:iam::${AWS::AccountId}:role/` + role + `
Outputs:
  RoleArn:
    Value: !GetAtt Role.Arn
`
	t.CloudFormationURL = "https://console.aws.amazon.com/cloudformation/home?region=" + p.Region + "#/stacks/create/template"
	t.Script = "aws cloudformation deploy --region " + p.Region + " --stack-name srustiops-provisioner-" + p.Tenant +
		" --template-file srustiops-provisioner.yaml --capabilities CAPABILITY_NAMED_IAM"
	t.Revoke = "aws cloudformation delete-stack --region " + p.Region + " --stack-name srustiops-provisioner-" + p.Tenant
	return t
}

// ---- the platform tenant ----

// platform is the tenant whose stacks do the provisioning. It must decide
// roles from central's directory (access_source central): the provisioner
// and the guards are central identities.
func (s *Server) platform(ctx context.Context) (*Tenant, error) {
	if s.cfg.ProvisionerTenant == "" {
		return nil, errors.New("the provisioner is off on this platform (SRUSTIOPS_PROVISIONER_TENANT)")
	}
	t, err := s.store.Tenant(ctx, s.cfg.ProvisionerTenant)
	if err != nil {
		return nil, fmt.Errorf("the provisioner tenant %s does not exist", s.cfg.ProvisionerTenant)
	}
	if t.AccessSource == "tenant" {
		return nil, fmt.Errorf("the provisioner tenant %s must use central access", t.Slug)
	}
	return t, nil
}

// actor is a principal in the platform tenant for one provisioning: the
// provisioner (sets up, creates stacks and runs), the client admin (manager
// of the workspace's business unit) or a guard (FinOps or Security).
func (s *Server) actor(ctx context.Context, pt *Tenant, bu, who string, tenantRoles []string, buRoles []string) *identity.Principal {
	p := &identity.Principal{Subject: who, Tenant: pt.Slug, TenantRoles: tenantRoles, EntityRoles: map[string][]string{}, BURoles: map[string][]string{}, BUEntity: map[string]string{},
		UserIssuer: s.cfg.PublicURL, UserSubject: "provisioner:" + who, EmailVerified: true}
	if bus, err := s.store.BUs(ctx, pt.ID); err == nil {
		for _, b := range bus {
			p.BUEntity[b.Slug] = b.Entity
		}
	}
	p.BUEntity[bu] = provisionerEntity
	if len(buRoles) > 0 {
		p.BURoles[bu] = buRoles
	}
	return p
}

func (s *Server) provisionerActor(ctx context.Context, pt *Tenant, bu string) *identity.Principal {
	return s.actor(ctx, pt, bu, provisionerUser, []string{identity.TenantAdmin}, []string{identity.Developer})
}

// call is a request to the platform tenant as p, decoding a JSON answer.
func (s *Server) call(ctx context.Context, pt *Tenant, p *identity.Principal, method, path string, body, out any) (int, error) {
	code, b, err := s.callTenantAs(ctx, pt, p, method, path, body)
	if err != nil {
		return 0, err
	}
	if code >= 300 {
		return code, fmt.Errorf("%s %s: HTTP %d: %s", method, path, code, errText(b))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return code, fmt.Errorf("%s %s: reading the answer: %w", method, path, err)
		}
	}
	return code, nil
}

// ensureBU makes the provisioner entity and the workspace's business unit in
// the platform tenant.
func (s *Server) ensureBU(ctx context.Context, pt *Tenant, bu, slug string) error {
	ents, err := s.store.Entities(ctx, pt.ID)
	if err != nil {
		return err
	}
	var ent *Entity
	for _, e := range ents {
		if e.Slug == provisionerEntity {
			ent = e
		}
	}
	if ent == nil {
		if ent, err = s.store.CreateEntity(ctx, pt.ID, provisionerEntity, "Provisioner", provisionerUser); err != nil {
			return err
		}
	}
	bus, err := s.store.BUs(ctx, pt.ID)
	if err != nil {
		return err
	}
	for _, b := range bus {
		if b.Slug == bu {
			return nil
		}
	}
	_, err = s.store.CreateBU(ctx, pt.ID, ent.ID, bu, "Provisioning "+slug, provisionerUser)
	return err
}

// ---- API ----

func (s *Server) provisionerBlueprints(w http.ResponseWriter, r *http.Request) {
	if _, err := s.platform(r.Context()); err != nil {
		httpx.WriteJSON(w, 200, map[string]any{"enabled": false, "reason": err.Error(), "blueprints": []any{}, "sizes": map[string]any{}})
		return
	}
	bps, sizes, err := s.blueprints()
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	out := []*Blueprint{}
	for _, b := range bps {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b *Blueprint) int { return strings.Compare(a.ID, b.ID) })
	httpx.WriteJSON(w, 200, map[string]any{"enabled": true, "blueprints": out, "sizes": sizes})
}

func (s *Server) getProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	p, err := s.store.provisioningFor(r.Context(), t.ID)
	if err != nil {
		httpx.WriteErr(w, http.StatusNotFound, "this workspace is not provisioned")
		return
	}
	s.decorate(r.Context(), p)
	httpx.WriteJSON(w, 200, p)
}

func (s *Server) decorate(ctx context.Context, p *Provisioning) {
	if inst := p.Stacks; len(inst) > 0 && inst[len(inst)-1].Created {
		in := &installState{GatewayURL: s.cfg.LinkPublicURL}
		s.store.Pool().QueryRow(ctx, `SELECT created_at, expires_at, used_at FROM install_tokens WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`, p.TenantID).
			Scan(&in.TokenIssuedAt, &in.TokenExpiresAt, &in.TokenUsedAt)
		s.store.Pool().QueryRow(ctx, `SELECT count(*) FROM tenant_links WHERE tenant_id = $1`, p.TenantID).Scan(&in.Tunnels)
		var st string
		s.store.Pool().QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, p.TenantID).Scan(&st)
		in.Online = in.Tunnels > 0 && st == "active"
		p.Install = in
	}
	if pt, err := s.platform(ctx); err == nil {
		iss := s.platformIssuer(ctx, pt)
		p.Trust = s.trustFor(p, iss)
		if !s.cfg.ProvisionerAllowPrivateIssuer {
			if msg := issuerProblem(iss); msg != "" {
				p.Trust.Problem, p.Trust.CloudFormation, p.Trust.CloudFormationURL, p.Trust.Script = msg, "", "", ""
			}
		}
	}
}

// platformIssuer is the OIDC issuer the platform tenant's runs present to clouds.
func (s *Server) platformIssuer(ctx context.Context, pt *Tenant) string {
	var d struct {
		Issuer string `json:"issuer"`
	}
	if code, b, err := s.callTenantAs(ctx, pt, s.system(pt), http.MethodGet, "/.well-known/openid-configuration", nil); err == nil && code == 200 {
		json.Unmarshal(b, &d)
	}
	if d.Issuer == "" {
		return pt.BackendURL
	}
	return d.Issuer
}

// provisioningLogs streams the OpenTofu output of one piece's latest run
// from the platform tenant, so the console can show it while it builds.
func (s *Server) provisioningLogs(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	var ps *ProvStack
	for _, x := range p.Stacks {
		if x.Name == r.URL.Query().Get("piece") {
			ps = x
		}
	}
	if ps == nil {
		httpx.WriteErr(w, http.StatusNotFound, "no such piece")
		return
	}
	out := map[string]any{"piece": ps.Name, "run_id": ps.RunID, "status": ps.Status, "operation": ps.Op, "chunks": []any{}}
	if ps.RunID == "" {
		httpx.WriteJSON(w, 200, out)
		return
	}
	pt, err := s.platform(ctx)
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, err.Error())
		return
	}
	after := r.URL.Query().Get("after")
	if _, err := strconv.ParseInt(after, 10, 64); err != nil {
		after = "0"
	}
	var chunks []map[string]any
	if _, err := s.call(ctx, pt, s.provisionerActor(ctx, pt, p.PlatformBU), http.MethodGet, "/api/v1/runs/"+ps.RunID+"/logs?after="+after, nil, &chunks); err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if chunks != nil {
		out["chunks"] = chunks
	}
	httpx.WriteJSON(w, 200, out)
}

// startProvisioning records the request and answers with the trust setup.
func (s *Server) startProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	if t.Status != "pending" || t.Connectivity != "tunnel" {
		httpx.WriteErr(w, http.StatusConflict, "only a workspace waiting for its connection can be provisioned")
		return
	}
	pt, err := s.platform(ctx)
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, err.Error())
		return
	}
	var b struct {
		Blueprint string            `json:"blueprint"`
		Size      string            `json:"size"`
		Region    string            `json:"region"`
		Account   string            `json:"account"`
		BudgetUSD float64           `json:"budget_usd"`
		Inputs    map[string]string `json:"inputs"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	bps, sizes, err := s.blueprints()
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	bp := bps[b.Blueprint]
	size, okSize := sizes[b.Size]
	var probs []string
	if bp == nil {
		probs = append(probs, "unknown blueprint "+b.Blueprint)
	}
	if !okSize {
		probs = append(probs, "size must be one of the listed sizes")
	}
	cloud := "aws"
	if bp != nil {
		cloud = bp.Cloud
	}
	if c := cloudChecks[cloud]; !c.region.MatchString(b.Region) {
		probs = append(probs, "region must look like "+c.regionExample)
	} else if !c.account.MatchString(b.Account) {
		probs = append(probs, "account must be "+c.accountHint)
	}
	inputs := map[string]any{}
	if bp != nil {
		for _, in := range bp.Inputs {
			v := strings.TrimSpace(b.Inputs[in.Name])
			if v == "" {
				v = in.Default
			}
			if v == "" {
				if in.Required {
					probs = append(probs, in.Label+" is required")
				}
				continue
			}
			vals := []string{v}
			if in.List {
				vals = nil
				for _, x := range strings.Split(v, ",") {
					if x = strings.TrimSpace(x); x != "" {
						vals = append(vals, x)
					}
				}
			}
			for _, x := range vals {
				if in.Pattern != "" && !regexp.MustCompile(in.Pattern).MatchString(x) {
					probs = append(probs, in.Label+": "+x+" is not valid")
				}
			}
			if in.List {
				inputs[in.Name] = vals
			} else {
				inputs[in.Name] = v
			}
		}
	}
	budget := b.BudgetUSD
	if okSize && budget == 0 {
		budget, _ = toFloat(size["budget_usd"])
	}
	if budget <= 0 || budget > 100000 {
		probs = append(probs, "budget_usd must be a monthly cap above 0")
	}
	if len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid provisioning request", probs...)
		return
	}
	in, _ := json.Marshal(inputs)
	p, err := scanProv(s.store.Pool().QueryRow(ctx, `WITH n AS (INSERT INTO provisionings (tenant_id, blueprint, cloud, mode, target, size, region, account, inputs, budget_usd, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *) SELECT `+strings.ReplaceAll(provCols, "p.", "n.")+` FROM n JOIN tenants t ON t.id = n.tenant_id`,
		t.ID, bp.ID, bp.Cloud, bp.Mode, bp.Target, b.Size, b.Region, b.Account, in, budget, current(r).Email))
	if store.IsUnique(err) {
		httpx.WriteErr(w, http.StatusConflict, "this workspace is already being provisioned")
		return
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.store.AddInstallEvent(ctx, t.ID, "provisioning_requested", bp.Title+" in "+b.Account+" ("+b.Region+")")
	s.audit(ctx, current(r).Email, "provisioning.request", "tenant/"+t.Slug, t.Slug, map[string]any{"blueprint": bp.ID, "size": b.Size, "region": b.Region, "account": b.Account, "budget_usd": budget, "platform": pt.Slug})
	s.decorate(ctx, p)
	httpx.WriteJSON(w, 201, p)
}

// connectProvisioning checks the client's trust role, then creates the
// workspace's environment, connection and stacks in the platform tenant and
// starts planning.
func (s *Server) connectProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	if p.Status != "awaiting_trust" && p.Status != "failed" {
		httpx.WriteErr(w, http.StatusConflict, "already connected (status "+p.Status+")")
		return
	}
	var cb struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&cb) // optional body
	if p.Cloud == "azure" {
		if cb.ClientID != "" {
			if !guidRe.MatchString(strings.ToLower(cb.ClientID)) {
				httpx.WriteErr(w, 422, "the application (client) ID is a GUID")
				return
			}
			if p.Inputs == nil {
				p.Inputs = map[string]any{}
			}
			p.Inputs["client_id"] = strings.ToLower(cb.ClientID)
		}
		if id, _ := p.Inputs["client_id"].(string); id == "" {
			httpx.WriteErr(w, 422, "paste the application (client) ID the trust script printed")
			return
		}
	}
	pt, err := s.platform(ctx)
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, err.Error())
		return
	}
	if msg := issuerProblem(s.platformIssuer(ctx, pt)); msg != "" && !s.cfg.ProvisionerAllowPrivateIssuer {
		httpx.WriteErr(w, http.StatusConflict, msg)
		return
	}
	if err := s.setUpPlatform(ctx, pt, p); err != nil {
		p.Status, p.Detail = "awaiting_trust", err.Error()
		s.store.saveProvisioning(ctx, p)
		httpx.WriteErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(ctx, current(r).Email, "provisioning.connect", "tenant/"+t.Slug, t.Slug, map[string]string{"role_arn": s.trustFor(p, "").RoleARN})
	s.store.AddInstallEvent(ctx, t.ID, "provisioning_connected", "trust role verified; planning")
	go s.advanceProvisioning(context.WithoutCancel(ctx), t.ID)
	s.decorate(ctx, p)
	httpx.WriteJSON(w, 200, p)
}

var blueprintModuleRe = regexp.MustCompile(`(?m)^\s*module:\s*([a-z0-9-]+)\s*$`)

// checkPlatformCatalog makes sure the platform tenant's active catalog has
// every module the blueprint uses, before anything is created: a missing
// one would otherwise only show later, as a stack that never plans.
func (s *Server) checkPlatformCatalog(ctx context.Context, pt *Tenant, pa *identity.Principal, p *Provisioning) error {
	bps, _, err := s.blueprints()
	if err != nil {
		return err
	}
	bp := bps[p.Blueprint]
	if bp == nil {
		return errors.New("blueprint " + p.Blueprint + " no longer exists")
	}
	var cat struct {
		Modules []struct {
			ID string `json:"id"`
		} `json:"modules"`
		Release *struct {
			Number int `json:"number"`
		} `json:"release"`
	}
	if _, err := s.call(ctx, pt, pa, http.MethodGet, "/api/v1/catalog", nil, &cat); err != nil {
		return fmt.Errorf("reading the platform tenant's catalog: %w", err)
	}
	have := map[string]bool{}
	for _, m := range cat.Modules {
		have[m.ID] = true
	}
	var missing []string
	for _, st := range bp.Stacks {
		for _, m := range blueprintModuleRe.FindAllStringSubmatch(st.Spec, -1) {
			if !have[m[1]] && !slices.Contains(missing, m[1]) {
				missing = append(missing, m[1])
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	from := "its bundled catalog"
	if cat.Release != nil {
		from = fmt.Sprintf("module release %d", cat.Release.Number)
	}
	return fmt.Errorf("%s (%s) lacks %s; activate a module release that includes the first-party SrustiOps modules, then connect again", pt.Slug, from, strings.Join(missing, ", "))
}

func (s *Server) setUpPlatform(ctx context.Context, pt *Tenant, p *Provisioning) error {
	bu := p.PlatformBU
	if err := s.ensureBU(ctx, pt, bu, p.Tenant); err != nil {
		return err
	}
	pa := s.provisionerActor(ctx, pt, bu)
	if err := s.checkPlatformCatalog(ctx, pt, pa, p); err != nil {
		return err
	}
	conn := "pv-" + p.Tenant
	cloud, err := s.provisionerCloud(p)
	if err != nil {
		return err
	}
	var c struct {
		ID string `json:"id"`
	}
	code, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/connections", map[string]any{"name": conn, "cloud": cloud, "entities": []string{provisionerEntity}, "shared_account": true}, &c)
	if err != nil && code != http.StatusConflict {
		return err
	}
	// A conflict is fine only when it is this workspace's own connection,
	// left by an earlier attempt; anything else is the real error.
	if err != nil {
		if gc, _ := s.call(ctx, pt, pa, http.MethodGet, "/api/v1/connections/"+conn, nil, nil); gc != http.StatusOK {
			return fmt.Errorf("creating connection %s: %w", conn, err)
		}
	}
	// The trust role must work before anything is planned.
	checks, err := s.testTrust(ctx, pt, pa, p)
	if err != nil {
		return err
	}
	for _, c := range checks {
		if c.Status == "fail" {
			return errors.New("the trust role does not work yet: " + c.Name + ": " + c.Detail + " (create it with the template, then connect again)")
		}
	}
	p.TrustIssuer = s.platformIssuer(ctx, pt)
	env := map[string]any{"name": p.PlatformEnv, "entity": provisionerEntity, "tier": "nonprod", "connection": conn, "runner_pool": s.cfg.ProvisionerPool,
		"max_destroys": 500, "allow_destroy": true}
	if code, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/environments", env, nil); err != nil && code != http.StatusConflict {
		return err
	}
	bps, sizes, err := s.blueprints()
	if err != nil {
		return err
	}
	bp := bps[p.Blueprint]
	if bp == nil {
		return errors.New("blueprint " + p.Blueprint + " no longer exists")
	}
	d := s.renderData(p, sizes[p.Size], "")
	if len(p.Stacks) == 0 {
		for _, st := range bp.Stacks {
			p.Stacks = append(p.Stacks, &ProvStack{Name: st.Name, Stack: stackName(p.Tenant, st.Name), Role: st.Role, Status: "not_started"})
		}
	}
	// Every stack but the install one now; it is made with a fresh install
	// token once the rest is applied.
	for i, st := range bp.Stacks {
		ps := p.Stacks[i]
		if st.Role == roleInstall || ps.Created {
			continue
		}
		spec, err := render(p.Tenant, st, d)
		if err != nil {
			return fmt.Errorf("blueprint %s: %w", bp.ID, err)
		}
		if code, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/stacks", map[string]any{"name": ps.Stack, "bu": bu, "environment": provisionerEntity + ":" + p.PlatformEnv,
			"spec": json.RawMessage(spec)}, nil); err != nil && code != http.StatusConflict {
			return err
		}
		ps.Created = true
		if err := s.startRun(ctx, pt, pa, ps, "apply"); err != nil {
			return err
		}
	}
	p.Status, p.Detail = "planning", "planning the infrastructure"
	return s.store.saveProvisioning(ctx, p)
}

func (s *Server) renderData(p *Provisioning, size Size, token string) renderData {
	name := "pv-" + p.Tenant
	if len(name) > 31 {
		name = name[:31]
	}
	return renderData{Slug: p.Tenant, Name: strings.TrimRight(name, "-"), Region: p.Region, Account: p.Account, Inputs: p.Inputs, Size: size, Platform: s.platformRefs(), InstallToken: token}
}

func (s *Server) startRun(ctx context.Context, pt *Tenant, pa *identity.Principal, ps *ProvStack, op string) error {
	var run struct {
		ID      string   `json:"id"`
		Pending bool     `json:"pending"`
		WaitsOn []string `json:"waits_on"`
	}
	if _, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/stacks/"+ps.Stack+"/runs", map[string]string{"operation": op}, &run); err != nil {
		return err
	}
	ps.RunID, ps.Op, ps.WaitsOn, ps.Status, ps.Error = run.ID, op, run.WaitsOn, "queued", ""
	if run.Pending {
		ps.Status = "waiting"
	}
	return nil
}

func (s *Server) approveProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	var b struct {
		BudgetUSD float64 `json:"budget_usd"`
	}
	httpx.Decode(w, r, &b)
	s.syncStacks(ctx, p)
	if p.Status != "awaiting_approval" {
		httpx.WriteErr(w, http.StatusConflict, "nothing waits for approval (status "+p.Status+")")
		return
	}
	if b.BudgetUSD > 0 {
		p.BudgetUSD = b.BudgetUSD
	}
	if p.CostUSD > p.BudgetUSD {
		httpx.WriteErr(w, 422, fmt.Sprintf("the plans are estimated at $%.0f a month, above the $%.0f cap; raise the cap or pick a smaller size", p.CostUSD, p.BudgetUSD))
		return
	}
	now := time.Now()
	p.ApprovedBy, p.ApprovedAt, p.Status, p.Detail = current(r).Email, &now, "applying", "approved; applying"
	if err := s.store.saveProvisioning(ctx, p); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(ctx, current(r).Email, "provisioning.approve", "tenant/"+t.Slug, t.Slug, map[string]any{"monthly_cost_usd": p.CostUSD, "budget_usd": p.BudgetUSD})
	go s.advanceProvisioning(context.WithoutCancel(ctx), t.ID)
	httpx.WriteJSON(w, 200, p)
}

// retryProvisioning starts a new run for every stack whose last one failed.
func (s *Server) retryProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	pt, err := s.platform(ctx)
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, err.Error())
		return
	}
	pa := s.provisionerActor(ctx, pt, p.PlatformBU)
	n := 0
	// The install applied but the tenant plane never connected (its token
	// expired, or the instance is not starting): reinstall with a fresh token.
	if inst := p.Stacks[len(p.Stacks)-1]; (p.Status == "failed" || p.Status == "installing") && p.DecomBy == "" && inst.Created && runDone(inst.Status) && t.Status != "active" {
		if err := s.reinstall(ctx, pt, p, t, inst); err != nil {
			httpx.WriteErr(w, http.StatusBadGateway, "reinstalling: "+err.Error())
			return
		}
		n++
	}
	for _, ps := range p.Stacks {
		if ps.Created && runFailed(ps.Status) {
			op := ps.Op
			if op == "" {
				op = "apply"
			}
			if err := s.startRun(ctx, pt, pa, ps, op); err == nil {
				n++
			}
		}
	}
	if p.Status == "failed" {
		p.Status, p.Detail = "applying", "retrying"
		if p.DecomBy != "" {
			p.Status = "decommissioning"
		}
		if p.ApprovedAt == nil {
			p.Status = "planning"
		}
	}
	s.store.saveProvisioning(ctx, p)
	s.audit(ctx, current(r).Email, "provisioning.retry", "tenant/"+t.Slug, t.Slug, map[string]int{"runs": n})
	go s.advanceProvisioning(context.WithoutCancel(ctx), t.ID)
	httpx.WriteJSON(w, 200, p)
}

// handOver ends the platform's part once the workspace is active: the client
// accepts it and revokes the trust role. The stacks stay in the platform
// tenant as the record of what was built, and are no longer run.
func (s *Server) handOverProvisioning(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	if p.Status != "active" {
		httpx.WriteErr(w, http.StatusConflict, "hand-over comes once the workspace is active (status "+p.Status+")")
		return
	}
	now := time.Now()
	p.HandedOver, p.Status, p.Detail = &now, "handed_over", "handed over to "+current(r).Email+"; revoke the trust role"
	s.store.saveProvisioning(ctx, p)
	s.audit(ctx, current(r).Email, "provisioning.hand_over", "tenant/"+t.Slug, t.Slug, nil)
	s.store.AddInstallEvent(ctx, t.ID, "handed_over", "the provisioner's access ends")
	s.decorate(ctx, p)
	httpx.WriteJSON(w, 200, p)
}

// ---- the loop ----

func (s *Server) provisionLoop(ctx context.Context) {
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if s.cfg.ProvisionerTenant == "" {
			continue
		}
		rows, err := s.store.Pool().Query(ctx, `SELECT tenant_id FROM provisionings WHERE status IN ('planning','awaiting_approval','applying','installing','decommissioning')`)
		if err != nil {
			continue
		}
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		// Workspaces advance side by side, a few at a time; each one only
		// on one replica at once (advanceProvisioning holds its lock).
		sem := make(chan struct{}, provisionParallel)
		var wg sync.WaitGroup
		for _, id := range ids {
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				s.advanceProvisioning(ctx, id)
			}()
		}
		wg.Wait()
	}
}

// provisionParallel is how many workspaces one replica advances at once.
const provisionParallel = 4

// lockProvisioning takes a workspace's provisioning lock: a Postgres advisory
// lock, so only one goroutine on one replica advances a workspace at a time,
// while different workspaces proceed in parallel.
func (s *Server) lockProvisioning(ctx context.Context, tenantID string) (func(), bool) {
	conn, err := s.store.Pool().Acquire(ctx)
	if err != nil {
		return nil, false
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(7101, hashtext($1))`, tenantID).Scan(&got); err != nil || !got {
		conn.Release()
		return nil, false
	}
	return func() {
		conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(7101, hashtext($1))`, tenantID)
		conn.Release()
	}, true
}

func runFailed(st string) bool {
	return st == "failed" || st == "policy_failed" || st == "discarded"
}

func runDone(st string) bool { return st == "applied" || st == "no_changes" }

// syncStacks refreshes each stack's latest run from the platform tenant.
func (s *Server) syncStacks(ctx context.Context, p *Provisioning) {
	pt, err := s.platform(ctx)
	if err != nil {
		return
	}
	pa := s.provisionerActor(ctx, pt, p.PlatformBU)
	for _, ps := range p.Stacks {
		if !ps.Created {
			continue
		}
		var runs []struct {
			ID        string          `json:"id"`
			Operation string          `json:"operation"`
			Status    string          `json:"status"`
			Error     *string         `json:"error"`
			Summary   json.RawMessage `json:"plan_summary"`
			Cost      json.RawMessage `json:"cost"`
			Required  []string        `json:"required_approvals"`
			Approvals []struct {
				Step string `json:"step"`
			} `json:"approvals"`
		}
		if _, err := s.call(ctx, pt, pa, http.MethodGet, "/api/v1/stacks/"+ps.Stack+"/runs?limit=1", nil, &runs); err != nil || len(runs) == 0 {
			continue
		}
		run := runs[0]
		ps.RunID, ps.Op, ps.Status, ps.Required, ps.Signed = run.ID, run.Operation, run.Status, run.Required, nil
		if ps.Status == "planning" || ps.Status == "queued" || ps.Status == "planned" || ps.Status == "applying" || ps.Status == "apply_queued" || runDone(ps.Status) {
			ps.WaitsOn = nil
		}
		for _, a := range run.Approvals {
			ps.Signed = append(ps.Signed, a.Step)
		}
		ps.Error = ""
		if run.Error != nil {
			ps.Error = trim(*run.Error, 400)
		}
		var sum struct{ Add, Change, Destroy, Replace int }
		json.Unmarshal(run.Summary, &sum)
		ps.Add, ps.Change, ps.Destroy, ps.Replace = sum.Add, sum.Change, sum.Destroy, sum.Replace
		var cost struct {
			Monthly float64 `json:"monthly_delta_usd"`
		}
		if json.Unmarshal(run.Cost, &cost) == nil && run.Operation == "apply" && ps.Status != "applied" {
			ps.CostUSD = cost.Monthly
		}
	}
	p.CostUSD = 0
	for _, ps := range p.Stacks {
		p.CostUSD += ps.CostUSD
	}
	if p.Status == "planning" || p.Status == "awaiting_approval" {
		planned := false
		for _, ps := range p.Stacks {
			if ps.Status == "planned" {
				planned = true
			}
		}
		if planned && p.ApprovedAt == nil {
			p.Status, p.Detail = "awaiting_approval", fmt.Sprintf("plans ready: about $%.0f a month (cap $%.0f)", p.CostUSD, p.BudgetUSD)
		}
	}
}

// advanceProvisioning moves one provisioning on: signs what the client's
// approval and the guards cover, creates the install stack when the rest is
// applied, and notices the end.
func (s *Server) advanceProvisioning(ctx context.Context, tenantID string) {
	unlock, ok := s.lockProvisioning(ctx, tenantID)
	if !ok {
		return // another goroutine or replica is advancing it
	}
	defer unlock()
	p, err := s.store.provisioningFor(ctx, tenantID)
	if err != nil {
		return
	}
	pt, err := s.platform(ctx)
	if err != nil {
		return
	}
	t, err := s.store.Tenant(ctx, p.Tenant)
	if err != nil && p.Status != "decommissioning" {
		return
	}
	s.syncStacks(ctx, p)
	defer s.store.saveProvisioning(ctx, p)
	for _, ps := range p.Stacks {
		// While decommissioning, a failed apply is simply destroyed next;
		// only a failed destroy stops it.
		if ps.Created && runFailed(ps.Status) && (p.Status != "decommissioning" || ps.Op == "destroy" || ps.Uninstalling) {
			p.Status, p.Detail = "failed", ps.Name+": "+ps.Status+" "+ps.Error
			if p.DecomBy != "" {
				p.Detail = "removing " + p.Detail
			}
			return
		}
	}
	switch p.Status {
	case "planning", "awaiting_approval", "applying", "installing":
		if p.ApprovedAt == nil {
			return
		}
		for _, ps := range p.Stacks {
			if ps.Status == "planned" {
				if why := s.signRun(ctx, pt, p, ps, p.ApprovedBy); why != "" {
					p.Status, p.Detail = "awaiting_approval", ps.Name+": "+why
					p.ApprovedAt = nil // a person decides again
					return
				}
			}
		}
		if p.Status == "awaiting_approval" || p.Status == "planning" {
			p.Status, p.Detail = "applying", "applying"
		}
		inst := p.Stacks[len(p.Stacks)-1]
		rest := true
		for _, ps := range p.Stacks[:len(p.Stacks)-1] {
			if !runDone(ps.Status) {
				rest = false
			}
		}
		if rest && !inst.Created && t != nil {
			if err := s.createInstall(ctx, pt, p, t, inst); err != nil {
				p.Detail = "creating the install stack: " + err.Error()
				return
			}
			p.Status, p.Detail = "installing", "installing the tenant plane"
		}
		if inst.Created && p.Status == "applying" {
			p.Status = "installing" // a reinstall: only the install stack is left
		}
		if runDone(inst.Status) && t != nil {
			if t.Status == "active" {
				p.Status, p.Detail = "active", "the workspace is connected and running"
				s.store.AddInstallEvent(ctx, t.ID, "provisioned", "built by the provisioner")
			} else if exp, dead := s.store.installTokenExpired(ctx, t.ID); dead {
				p.Status = "failed"
				p.Detail = fmt.Sprintf("the tenant plane did not connect before its one-time install token expired at %s; check that the instance can reach the gateway (%s), then retry to reinstall it with a fresh token",
					exp.Format("15:04 MST"), s.cfg.LinkPublicURL)
			} else {
				p.Detail = "installed; waiting for the tenant plane to connect"
			}
		}
	case "decommissioning":
		// Removing a workspace takes SrustiOps off the client's infrastructure
		// and nothing else: the network, the data pieces and the machine
		// stay. Only the install piece changes, as its blueprint says.
		finish := func() {
			p.Status, p.Detail = "decommissioned", "SrustiOps services removed; the infrastructure and the tenant's data are kept. Revoke the trust role to end the provisioner's access."
			s.audit(ctx, "system:provisioner", "provisioning.decommissioned", "tenant/"+p.Tenant, p.Tenant, nil)
		}
		inst := p.Stacks[len(p.Stacks)-1]
		if !inst.Created {
			finish()
			return
		}
		pa := s.provisionerActor(ctx, pt, p.PlatformBU)
		how := "destroy"
		if bps, _, err := s.blueprints(); err == nil && bps[p.Blueprint] != nil {
			how = bps[p.Blueprint].Stacks[len(bps[p.Blueprint].Stacks)-1].Uninstall
		}
		input, applyIt := strings.CutPrefix(how, "input:")
		done := (applyIt && inst.Uninstalling || inst.Op == "destroy") && runDone(inst.Status)
		if done {
			finish()
			return
		}
		if inst.Status == "planned" && (inst.Uninstalling || inst.Op == "destroy") {
			if why := s.signRun(ctx, pt, p, inst, p.DecomBy); why != "" {
				p.Detail = inst.Name + ": " + why
			}
			return
		}
		if inst.Uninstalling || inst.Op == "destroy" {
			return // running, or waiting for its run
		}
		if busyStatus(inst.Status) {
			return // let the last install run finish first
		}
		if inst.Status == "planned" {
			s.call(ctx, pt, pa, http.MethodPost, "/api/v1/runs/"+inst.RunID+"/discard", map[string]string{"reason": "workspace removed"}, nil)
		}
		if applyIt {
			if err := s.setStackInput(ctx, pt, pa, inst.Stack, input, true); err != nil {
				p.Detail = inst.Name + ": " + err.Error()
				return
			}
			if err := s.startRun(ctx, pt, pa, inst, "apply"); err != nil {
				p.Detail = inst.Name + ": " + err.Error()
				return
			}
			inst.Uninstalling = true
			p.Detail = "removing the SrustiOps services from " + inst.Name + "; the machine, network and data stay"
			return
		}
		if err := s.startRun(ctx, pt, pa, inst, "destroy"); err != nil {
			p.Detail = inst.Name + ": " + err.Error()
		} else {
			p.Detail = "removing the SrustiOps release (" + inst.Name + "); the infrastructure and data stay"
		}
		return
	}
}

func (s *Server) createInstall(ctx context.Context, pt *Tenant, p *Provisioning, t *Tenant, inst *ProvStack) error {
	bps, sizes, err := s.blueprints()
	if err != nil {
		return err
	}
	bp := bps[p.Blueprint]
	if bp == nil {
		return errors.New("blueprint " + p.Blueprint + " no longer exists")
	}
	tok, _, err := s.issueInstallToken(ctx, t, provisionerUser)
	if err != nil {
		return err
	}
	spec, err := render(p.Tenant, bp.Stacks[len(bp.Stacks)-1], s.renderData(p, sizes[p.Size], tok))
	if err != nil {
		return err
	}
	pa := s.provisionerActor(ctx, pt, p.PlatformBU)
	if code, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/stacks", map[string]any{"name": inst.Stack, "bu": p.PlatformBU,
		"environment": provisionerEntity + ":" + p.PlatformEnv, "spec": json.RawMessage(spec)}, nil); err != nil && code != http.StatusConflict {
		return err
	}
	inst.Created = true
	return s.startRun(ctx, pt, pa, inst, "apply")
}

func busyStatus(st string) bool {
	return st == "queued" || st == "planning" || st == "apply_queued" || st == "applying" || st == "waiting"
}

// setStackInput sets one input on the modules of a platform stack whose
// spec already names it (the blueprint spells it out), keeping the rest of
// the spec as it is.
func (s *Server) setStackInput(ctx context.Context, pt *Tenant, pa *identity.Principal, stack, name string, v any) error {
	var st struct {
		Spec map[string]any `json:"spec"`
	}
	if _, err := s.call(ctx, pt, pa, http.MethodGet, "/api/v1/stacks/"+stack, nil, &st); err != nil {
		return err
	}
	mods, _ := st.Spec["modules"].([]any)
	n := 0
	for _, m := range mods {
		if mm, ok := m.(map[string]any); ok {
			if in, _ := mm["inputs"].(map[string]any); in != nil {
				if _, has := in[name]; has {
					in[name] = v
					n++
				}
			}
		}
	}
	if n == 0 {
		return fmt.Errorf("no module of stack %s has the input %s", stack, name)
	}
	_, err := s.call(ctx, pt, pa, http.MethodPut, "/api/v1/stacks/"+stack, map[string]any{"spec": st.Spec}, nil)
	return err
}

// reinstall gives the install stack a fresh install token and applies it:
// the token's change replaces the instance (or the release), which boots
// with the new token. Everything the workspace keeps is untouched.
func (s *Server) reinstall(ctx context.Context, pt *Tenant, p *Provisioning, t *Tenant, inst *ProvStack) error {
	bps, sizes, err := s.blueprints()
	if err != nil {
		return err
	}
	bp := bps[p.Blueprint]
	if bp == nil {
		return errors.New("blueprint " + p.Blueprint + " no longer exists")
	}
	tok, _, err := s.issueInstallToken(ctx, t, provisionerUser)
	if err != nil {
		return err
	}
	spec, err := render(p.Tenant, bp.Stacks[len(bp.Stacks)-1], s.renderData(p, sizes[p.Size], tok))
	if err != nil {
		return err
	}
	pa := s.provisionerActor(ctx, pt, p.PlatformBU)
	if _, err := s.call(ctx, pt, pa, http.MethodPut, "/api/v1/stacks/"+inst.Stack, map[string]any{"spec": json.RawMessage(spec)}, nil); err != nil {
		return err
	}
	s.audit(ctx, "system:provisioner", "provisioning.reinstall", "tenant/"+p.Tenant, p.Tenant, nil)
	return s.startRun(ctx, pt, pa, inst, "apply")
}

// installTokenExpired reports whether the tenant's newest install token ran
// out without being used, and when.
func (st *Store) installTokenExpired(ctx context.Context, tenantID string) (time.Time, bool) {
	var exp time.Time
	var used *time.Time
	if err := st.Pool().QueryRow(ctx, `SELECT expires_at, used_at FROM install_tokens WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&exp, &used); err != nil {
		return time.Time{}, false
	}
	return exp, used == nil && time.Now().After(exp)
}

// signRun signs the planned run's open steps that the approval and guards
// cover, or says why it cannot.
func (s *Server) signRun(ctx context.Context, pt *Tenant, p *Provisioning, ps *ProvStack, approver string) string {
	open := []string{}
	for _, st := range ps.Required {
		if !slices.Contains(ps.Signed, st) {
			open = append(open, st)
		}
	}
	for _, step := range open {
		var who *identity.Principal
		switch step {
		case identity.StepManager:
			if approver == "" {
				return "needs the client's approval"
			}
			who = s.actor(ctx, pt, p.PlatformBU, approver, nil, []string{identity.Manager})
		case identity.StepFinOps:
			if p.CostUSD > p.BudgetUSD {
				return fmt.Sprintf("estimated $%.0f a month is above the $%.0f cap", p.CostUSD, p.BudgetUSD)
			}
			who = s.actor(ctx, pt, p.PlatformBU, budgetGuard, []string{identity.FinOps}, nil)
		case identity.StepSecurity:
			if ps.Op == "destroy" && ps.Role == roleData {
				return "would destroy the tenant's data"
			}
			if ps.Op != "destroy" && ps.Role == roleData && (ps.Destroy > 0 || ps.Replace > 0) {
				return "would destroy or replace resources holding the tenant's data"
			}
			who = s.actor(ctx, pt, p.PlatformBU, blueprintGuard, []string{identity.Security}, nil)
		default:
			return "needs the " + step + " approval from a person in the platform tenant"
		}
		if ps.Op != "destroy" && ps.Role == roleData && (ps.Destroy > 0 || ps.Replace > 0) {
			return "would destroy or replace resources holding the tenant's data"
		}
		reason := "provisioning " + p.Tenant + ": approved by " + approver
		if who.Subject != approver {
			reason = "provisioning " + p.Tenant + ": within the rule of " + who.Subject
		}
		if _, err := s.call(ctx, pt, who, http.MethodPost, "/api/v1/runs/"+ps.RunID+"/approve", map[string]string{"step": step, "reason": reason}, nil); err != nil {
			return "signing " + step + ": " + err.Error()
		}
		s.audit(ctx, who.Subject, "provisioning.sign", "tenant/"+p.Tenant, p.Tenant, map[string]string{"stack": ps.Stack, "run": ps.RunID, "step": step})
	}
	return ""
}

// decommissionProvisioned starts removing what the provisioner installed for
// a workspace (its install and service stacks, destroyed newest first),
// keeping the stacks that hold the tenant's data. It returns what it
// started, or nil when the workspace was installed by hand or handed over.
func (s *Server) decommissionProvisioned(ctx context.Context, t *Tenant, by string) map[string]any {
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.Status == "handed_over" || p.Status == "decommissioned" || p.Status == "awaiting_trust" {
		return nil
	}
	p.Status, p.DecomBy, p.Detail = "decommissioning", by, "removing the SrustiOps services; the infrastructure and the tenant's data are kept"
	if err := s.store.saveProvisioning(ctx, p); err != nil {
		return nil
	}
	s.audit(ctx, by, "provisioning.decommission", "tenant/"+t.Slug, t.Slug, nil)
	go s.advanceProvisioning(context.WithoutCancel(ctx), t.ID)
	// Nothing the provisioner built is destroyed: only SrustiOps comes off it.
	kept := []string{}
	for _, ps := range p.Stacks {
		if ps.Created {
			kept = append(kept, ps.Name)
		}
	}
	return map[string]any{"status": p.Status, "kept": kept, "revoke_trust": s.trustFor(p, "").Revoke}
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func nullJSON(v any) []byte {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Pointer && reflect.ValueOf(v).IsNil()) {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

// testTrust runs the platform tenant's connection test on the workspace's
// provisioning connection: it assumes the client's role over OIDC.
func (s *Server) testTrust(ctx context.Context, pt *Tenant, pa *identity.Principal, p *Provisioning) ([]struct{ Name, Status, Detail string }, error) {
	var test struct {
		Checks []struct{ Name, Status, Detail string } `json:"checks"`
	}
	if _, err := s.call(ctx, pt, pa, http.MethodPost, "/api/v1/connections/pv-"+p.Tenant+"/test", map[string]any{}, &test); err != nil {
		return nil, fmt.Errorf("checking the trust role: %w", err)
	}
	return test.Checks, nil
}

// checkTrust re-checks the client's trust role from the console, at any
// time after it was connected: whether the role can still be assumed, and
// whether the platform issuer moved since the role was made (then the
// client updates the CloudFormation stack with the template returned).
func (s *Server) checkTrust(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ctx := r.Context()
	p, err := s.store.provisioningFor(ctx, t.ID)
	if err != nil || p.ID != r.PathValue("id") {
		httpx.WriteErr(w, http.StatusNotFound, "no such provisioning")
		return
	}
	if p.Status == "awaiting_trust" || p.Status == "decommissioned" {
		httpx.WriteErr(w, http.StatusConflict, "the trust role is checked when you connect (status "+p.Status+")")
		return
	}
	pt, err := s.platform(ctx)
	if err != nil {
		httpx.WriteErr(w, http.StatusConflict, err.Error())
		return
	}
	iss := s.platformIssuer(ctx, pt)
	tc := &trustCheck{CheckedAt: time.Now().UTC(), CheckedBy: current(r).Email, Issuer: iss,
		IssuerChanged: p.TrustIssuer != "" && p.TrustIssuer != iss}
	checks, err := s.testTrust(ctx, pt, s.provisionerActor(ctx, pt, p.PlatformBU), p)
	if err != nil {
		tc.Detail = err.Error()
	} else {
		tc.Checks, tc.OK = checks, len(checks) > 0
		for _, c := range checks {
			if c.Status == "fail" {
				tc.OK = false
				tc.Detail = c.Name + ": " + c.Detail
				break
			}
		}
	}
	switch {
	case tc.IssuerChanged && !tc.OK:
		tc.Detail = fmt.Sprintf("the platform issuer moved from %s to %s; update the trust stack in account %s with the new template (%s)", p.TrustIssuer, iss, p.Account, tc.Detail)
	case tc.IssuerChanged:
		tc.Detail = fmt.Sprintf("the role still works, but the platform issuer moved from %s to %s; update the trust stack with the new template", p.TrustIssuer, iss)
	case tc.OK:
		tc.Detail = "the trust role works"
		if p.TrustIssuer == "" {
			p.TrustIssuer = iss // connected before issuers were recorded
		}
	}
	p.TrustCheck = tc
	s.store.saveProvisioning(ctx, p)
	s.audit(ctx, current(r).Email, "provisioning.trust_check", "tenant/"+t.Slug, t.Slug, map[string]any{"ok": tc.OK, "issuer_changed": tc.IssuerChanged})
	if !tc.OK || tc.IssuerChanged {
		s.store.AddInstallEvent(ctx, t.ID, "trust_check_failed", tc.Detail)
	}
	s.decorate(ctx, p)
	httpx.WriteJSON(w, 200, p)
}

// provisionerCloud is the platform tenant's connection to the client's
// account, project or subscription, through the trust the client made.
func (s *Server) provisionerCloud(p *Provisioning) (map[string]any, error) {
	switch p.Cloud {
	case "gcp":
		num, _ := p.Inputs["project_number"].(string)
		pool, prov, sa := gcpIDs(p.Tenant)
		return map[string]any{"provider": "gcp", "auth": "oidc", "gcp": map[string]string{"project_id": p.Account, "region": p.Region,
			"service_account_email":      sa + "@" + p.Account + ".iam.gserviceaccount.com",
			"workload_identity_provider": "projects/" + num + "/locations/global/workloadIdentityPools/" + pool + "/providers/" + prov}}, nil
	case "azure":
		tid, _ := p.Inputs["tenant_id"].(string)
		cid, _ := p.Inputs["client_id"].(string)
		if cid == "" {
			return nil, errors.New("connect with the application (client) ID the trust script printed")
		}
		return map[string]any{"provider": "azure", "auth": "oidc", "azure": map[string]string{"tenant_id": tid, "subscription_id": p.Account, "client_id": cid}}, nil
	}
	return map[string]any{"provider": "aws", "auth": "oidc", "aws": map[string]string{"region": p.Region, "role_arn": s.trustFor(p, "").RoleARN}}, nil
}

// gcpTrust: a workload identity pool whose provider accepts only this
// workspace's provisioning subjects, and a service account it may
// impersonate, holding the roles the GKE blueprint needs.
func (s *Server) gcpTrust(p *Provisioning, issuer string) *trustSetup {
	pool, prov, sa := gcpIDs(p.Tenant)
	num, _ := p.Inputs["project_number"].(string)
	email := sa + "@" + p.Account + ".iam.gserviceaccount.com"
	prefix := "srustiops:entity:" + provisionerEntity + ":env:" + p.Tenant + ":stack:"
	discovery := "srustiops:discovery:pv-" + p.Tenant
	t := &trustSetup{Issuer: issuer, Subject: prefix + "*", Audience: "//iam.googleapis.com/projects/" + num + "/locations/global/workloadIdentityPools/" + pool + "/providers/" + prov, RoleARN: email}
	roles := []string{"roles/editor", "roles/resourcemanager.projectIamAdmin", "roles/iam.serviceAccountAdmin", "roles/container.admin",
		"roles/secretmanager.admin", "roles/cloudkms.admin", "roles/storage.admin", "roles/servicenetworking.networksAdmin", "roles/serviceusage.serviceUsageAdmin"}
	var b strings.Builder
	fmt.Fprintf(&b, `# Lets the SrustiOps provisioner build workspace %s in project %s (OIDC, no keys).
# Run it in Cloud Shell or with gcloud signed in as a project owner. Revoke: see below.
set -euo pipefail
PROJECT=%s
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com cloudresourcemanager.googleapis.com serviceusage.googleapis.com --project "$PROJECT"
gcloud iam workload-identity-pools create %s --project "$PROJECT" --location global --display-name "SrustiOps %s"
gcloud iam workload-identity-pools providers create-oidc %s --project "$PROJECT" --location global --workload-identity-pool %s \
  --issuer-uri %q --allowed-audiences %q \
  --attribute-mapping "google.subject=assertion.sub" \
  --attribute-condition %q
gcloud iam service-accounts create %s --project "$PROJECT" --display-name "SrustiOps provisioner (%s)"
gcloud iam service-accounts add-iam-policy-binding %s --project "$PROJECT" --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/*"
for ROLE in %s; do
  gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:%s" --role "$ROLE" --condition None >/dev/null
done
`, p.Tenant, p.Account, p.Account, pool, p.Tenant, prov, pool, issuer, t.Audience,
		`assertion.sub.startsWith("`+prefix+`") || assertion.sub == "`+discovery+`"`, sa, p.Tenant, email, num, pool, strings.Join(roles, " "), email)
	t.Script = b.String()
	t.Revoke = "gcloud iam workload-identity-pools delete " + pool + " --project " + p.Account + " --location global --quiet && gcloud iam service-accounts delete " + email + " --project " + p.Account + " --quiet"
	return t
}

// azureTrust: an app registration with one federated credential per
// provisioning subject (Azure matches subjects exactly), Contributor and
// role-assignment rights on the subscription.
func (s *Server) azureTrust(p *Provisioning, issuer string) *trustSetup {
	name := "srustiops-provisioner-" + p.Tenant
	t := &trustSetup{Issuer: issuer, Subject: "srustiops:entity:" + provisionerEntity + ":env:" + p.Tenant + ":stack:<stack>:phase:<plan|apply>", Audience: "api://AzureADTokenExchange"}
	var b strings.Builder
	fmt.Fprintf(&b, `# Lets the SrustiOps provisioner build workspace %s in subscription %s (OIDC, no secrets).
# Run it in Cloud Shell or with az signed in as an owner of the subscription,
# then paste the application (client) ID it prints into the console.
set -euo pipefail
SUB=%s
az account set --subscription "$SUB"
for RP in Microsoft.ContainerService Microsoft.DBforPostgreSQL Microsoft.KeyVault Microsoft.Storage Microsoft.Network Microsoft.ManagedIdentity Microsoft.OperationalInsights; do
  az provider register --namespace "$RP" >/dev/null
done
APP=$(az ad app create --display-name %s --query appId -o tsv)
az ad sp create --id "$APP" >/dev/null || true
`, p.Tenant, p.Account, p.Account, name)
	for i, sub := range s.trustSubjects(p) {
		cred, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("srustiops-%d", i+1), "issuer": issuer, "subject": sub, "audiences": []string{"api://AzureADTokenExchange"}})
		fmt.Fprintf(&b, "az ad app federated-credential create --id \"$APP\" --parameters '%s' >/dev/null\n", cred)
	}
	fmt.Fprintf(&b, `az role assignment create --assignee "$APP" --role Contributor --scope "/subscriptions/$SUB" >/dev/null
az role assignment create --assignee "$APP" --role "Role Based Access Control Administrator" --scope "/subscriptions/$SUB" >/dev/null
echo "Application (client) ID: $APP"
`)
	t.Script = b.String()
	t.Revoke = "az ad app delete --id $(az ad app list --display-name " + name + " --query '[0].appId' -o tsv)"
	return t
}
