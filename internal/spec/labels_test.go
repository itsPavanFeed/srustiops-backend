package spec

import "testing"

func TestProvisionerStacksLabelTheClientWorkspace(t *testing.T) {
	l := Labels(GenerateInput{Tenant: "acme", Entity: "provisioner", BU: "pv-globex", Environment: "globex", StackName: "pv-globex-vm"})
	if l["srustiops-tenant"] != "globex" || l["srustiops-built-by"] != "acme" || l["managed-by"] != "srustiops-provisioner" {
		t.Fatalf("provisioner labels: %v", l)
	}
	l = Labels(GenerateInput{Tenant: "acme", Entity: "retail", BU: "pv-payments", Environment: "dev", StackName: "x"})
	if l["srustiops-tenant"] != "acme" || l["srustiops-built-by"] != "" {
		t.Fatalf("an ordinary stack keeps its tenant: %v", l)
	}
}
