package central

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/config"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
)

// Every built-in blueprint renders, for every size, into stack specs whose
// cross-stack references name the workspace's own stacks.
func TestBlueprintsRender(t *testing.T) {
	s := &Server{cfg: &config.Central{PublicURL: "https://srustiops.example.com", LinkPublicURL: "https://link.srustiops.example.com", ImageRepo: "docker.io/acme", ImageTag: "0.2.0"}}
	bps, sizes, err := s.blueprints()
	if err != nil {
		t.Fatal(err)
	}
	if len(bps) != 5 || len(sizes) != 3 {
		t.Fatalf("blueprints %d, sizes %d", len(bps), len(sizes))
	}
	inputs := map[string]any{"vpc_cidr": "10.42.0.0/16", "kubernetes_version": "1.33", "cluster_name": "prod", "vpc_id": "vpc-0a1b2c3d4e5f60718",
		"private_subnet_ids": []string{"subnet-0a1b2c3d4e5f60718"}, "eks_oidc_provider_arn": "arn:aws:iam::123456789012:oidc-provider/x", "eks_oidc_issuer": "https://oidc.eks.x",
		"project_number": "123456789012", "tenant_id": "00000000-0000-0000-0000-000000000001", "vnet_cidr": "10.62.0.0/16"}
	where := map[string][2]string{"aws": {"eu-west-1", "123456789012"}, "gcp": {"europe-west1", "acme-prod-1234"}, "azure": {"westeurope", "00000000-0000-0000-0000-000000000002"}}
	cat, err := catalog.Load("../../../srustiops-modules/catalog/modules")
	if err != nil {
		cat, err = catalog.Load("../../../srustiops-modules/catalog")
	}
	if err != nil {
		t.Skip("no module catalog next to the backend:", err)
	}
	for id, bp := range bps {
		for sz, size := range sizes {
			p := &Provisioning{Tenant: "acme", Cloud: bp.Cloud, Region: where[bp.Cloud][0], Account: where[bp.Cloud][1], Inputs: inputs}
			for _, st := range bp.Stacks {
				raw, err := render("acme", st, s.renderData(p, size, "sop_i_abcdefghijklmnopqrstuvwxyz"))
				if err != nil {
					t.Fatalf("%s/%s/%s: %v", id, sz, st.Name, err)
				}
				var v struct {
					Modules []map[string]any `json:"modules"`
				}
				if json.Unmarshal(raw, &v) != nil || len(v.Modules) == 0 {
					t.Fatalf("%s/%s: no modules in %s", id, st.Name, raw)
				}
				// As the platform tenant does: references become the other
				// stack's applied outputs before validation.
				resolved, errs := spec.ResolveStackRefs(raw, func(r spec.StackRef) (json.RawMessage, error) {
					switch r.Output {
					case "vpc_id":
						return json.RawMessage(`"vpc-0a1b2c3d4e5f60718"`), nil
					case "private_subnets":
						return json.RawMessage(`["subnet-0a1b2c3d4e5f60718","subnet-0f1e2d3c4b5a69788"]`), nil
					}
					return json.RawMessage(`"` + r.Output + `-value"`), nil
				})
				if len(errs) > 0 {
					t.Fatalf("%s/%s: %v", id, st.Name, errs)
				}
				st2, err := spec.Decode(resolved)
				if err != nil {
					t.Fatalf("%s/%s: %v", id, st.Name, err)
				}
				if err := st2.Validate(cat, bp.Cloud); err != nil {
					t.Fatalf("%s/%s/%s does not validate against the catalog: %v", id, sz, st.Name, err)
				}
				if strings.Contains(string(raw), `"$ref"`) && !strings.Contains(string(raw), `stack/pv-acme-`) {
					t.Fatalf("%s/%s: references outside the workspace: %s", id, st.Name, raw)
				}
			}
		}
	}
	net, _ := render("acme", bps["aws-account-vm"].Stacks[0], s.renderData(&Provisioning{Tenant: "acme", Region: "eu-west-1", Inputs: inputs}, sizes["trial"], ""))
	for _, want := range []string{`"10.42.0.0/19"`, `"10.42.32.0/19"`, `"10.42.96.0/22"`, `"eu-west-1a"`} {
		if !strings.Contains(string(net), want) {
			t.Fatalf("network spec lacks %s: %s", want, net)
		}
	}
}

func TestTrustPinsTheWorkspace(t *testing.T) {
	s := &Server{cfg: &config.Central{}}
	tr := s.trustFor(&Provisioning{Tenant: "acme", Account: "123456789012", Region: "eu-west-1"}, "https://srustiops.example.com")
	if tr.RoleARN != "arn:aws:iam::123456789012:role/srustiops-provisioner-acme" || !strings.Contains(tr.CloudFormation, `"srustiops:entity:provisioner:env:acme:stack:*"`) ||
		!strings.Contains(tr.CloudFormation, `"srustiops:discovery:pv-acme"`) {
		t.Fatalf("trust: %+v", tr)
	}
}

func TestIssuerMustBePublic(t *testing.T) {
	for _, iss := range []string{"https://localhost:8444", "http://example.com", "https://127.0.0.1", "https://10.1.2.3", "https://srustiops.acme.internal", ""} {
		if issuerProblem(iss) == "" {
			t.Errorf("%q accepted as an issuer AWS can reach", iss)
		}
	}
	for _, iss := range []string{"https://x.trycloudflare.com", "https://srustiops.example.com/tenant"} {
		if msg := issuerProblem(iss); msg != "" {
			t.Errorf("%q refused: %s", iss, msg)
		}
	}
}

func TestBlueprintModulesAreFound(t *testing.T) {
	s := &Server{cfg: &config.Central{}}
	bps, _, err := s.blueprints()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, st := range bps["aws-account-vm"].Stacks {
		for _, m := range blueprintModuleRe.FindAllStringSubmatch(st.Spec, -1) {
			got = append(got, m[1])
		}
	}
	if strings.Join(got, ",") != "aws-vpc,aws-srustiops-landing,aws-srustiops-vm" {
		t.Fatalf("modules: %v", got)
	}
}

func TestRemovalNeverDestroysInfrastructure(t *testing.T) {
	s := &Server{cfg: &config.Central{}}
	bps, _, err := s.blueprints()
	if err != nil {
		t.Fatal(err)
	}
	for id, bp := range bps {
		inst := bp.Stacks[len(bp.Stacks)-1]
		if inst.Uninstall == "destroy" && bp.Target == "vm" {
			t.Errorf("%s: a VM install piece must not be destroyed on removal (it is the client's machine)", id)
		}
		if inst.Uninstall == "" {
			t.Errorf("%s: install piece has no uninstall mode", id)
		}
	}
	if got := bps["aws-account-vm"].Stacks[2].Uninstall; got != "input:remove_srustiops" {
		t.Fatalf("aws-account-vm uninstall = %q", got)
	}
}

func TestTrustOnGCPAndAzure(t *testing.T) {
	s := &Server{cfg: &config.Central{}}
	g := &Provisioning{Tenant: "acme", Cloud: "gcp", Blueprint: "gcp-project-kubernetes", Account: "acme-prod-1234", Region: "europe-west1", Inputs: map[string]any{"project_number": "4242"}}
	tr := s.trustFor(g, "https://srustiops.example.com")
	for _, want := range []string{`assertion.sub.startsWith(\"srustiops:entity:provisioner:env:acme:stack:\")`, `assertion.sub == \"srustiops:discovery:pv-acme\"`,
		"workload-identity-pools create sop-acme", "principalSet://iam.googleapis.com/projects/4242/locations/global/workloadIdentityPools/sop-acme/*", "roles/container.admin"} {
		if !strings.Contains(tr.Script, want) {
			t.Fatalf("gcp script lacks %s:\n%s", want, tr.Script)
		}
	}
	if tr.RoleARN != "sop-prov-acme@acme-prod-1234.iam.gserviceaccount.com" || tr.CloudFormation != "" {
		t.Fatalf("gcp trust %+v", tr)
	}
	c, err := s.provisionerCloud(g)
	if err != nil || c["gcp"].(map[string]string)["workload_identity_provider"] != "projects/4242/locations/global/workloadIdentityPools/sop-acme/providers/srustiops" {
		t.Fatalf("gcp connection %v %v", c, err)
	}
	a := &Provisioning{Tenant: "acme", Cloud: "azure", Blueprint: "azure-subscription-kubernetes", Account: "00000000-0000-0000-0000-000000000002", Region: "westeurope",
		Inputs: map[string]any{"tenant_id": "00000000-0000-0000-0000-000000000001"}}
	tr = s.trustFor(a, "https://srustiops.example.com")
	// One exact credential per stack and phase, plus the connection check.
	if n := strings.Count(tr.Script, "federated-credential create"); n != 9 {
		t.Fatalf("%d federated credentials:\n%s", n, tr.Script)
	}
	for _, want := range []string{`"subject":"srustiops:entity:provisioner:env:acme:stack:pv-acme-landing:phase:apply"`, `"subject":"srustiops:discovery:pv-acme"`, `"issuer":"https://srustiops.example.com"`} {
		if !strings.Contains(tr.Script, want) {
			t.Fatalf("azure script lacks %s:\n%s", want, tr.Script)
		}
	}
	if _, err := s.provisionerCloud(a); err == nil {
		t.Fatal("an Azure connection without the app's client ID")
	}
	a.Inputs["client_id"] = "00000000-0000-0000-0000-000000000003"
	if c, err := s.provisionerCloud(a); err != nil || c["azure"].(map[string]string)["client_id"] != "00000000-0000-0000-0000-000000000003" {
		t.Fatalf("azure connection %v %v", c, err)
	}
}
