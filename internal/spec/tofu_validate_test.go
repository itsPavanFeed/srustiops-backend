package spec

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
)

// TestAWSKindsValidateWithTofu generates a stack for every AWS kind (with the
// arguments its adoption sets) and runs `tofu init` and `tofu validate`
// against the real module and the pinned provider. Set SRUSTIOPS_TOFU_VALIDATE=1
// (and TF_PLUGIN_CACHE_DIR to reuse providers).
func TestAWSKindsValidateWithTofu(t *testing.T) {
	if os.Getenv("SRUSTIOPS_TOFU_VALIDATE") == "" {
		t.Skip("SRUSTIOPS_TOFU_VALIDATE not set")
	}
	tofu, err := exec.LookPath("tofu")
	if err != nil {
		t.Skip("tofu not installed")
	}
	cat, err := catalog.Load("../../../srustiops-modules/catalog")
	if err != nil {
		t.Fatal(err)
	}
	// Smallest valid inputs per kind; adoption gaps are added from the kind.
	samples := map[string]string{
		"S3Bucket":                    `{"bucket":"acme-validate-1"}`,
		"KMSKey":                      `{"description":"validate"}`,
		"SecurityGroup":               `{"name":"validate","vpc_id":"vpc-0123456789abcdef0"}`,
		"VPC":                         `{"name":"validate","cidr":"10.0.0.0/16","azs":["eu-west-1a"],"private_subnets":["10.0.1.0/24"]}`,
		"RDSDatabase":                 `{"identifier":"validate","engine_version":"16.3","family":"postgres16","instance_class":"db.t4g.micro","subnet_ids":["subnet-0123456789abcdef0"],"vpc_security_group_ids":["sg-0123456789abcdef0"],"username":"app"}`,
		"EKSCluster":                  `{"name":"validate","kubernetes_version":"1.31","vpc_id":"vpc-0123456789abcdef0","subnet_ids":["subnet-0123456789abcdef0","subnet-0123456789abcdef1"]}`,
		"DynamoDBTable":               `{"name":"validate","hash_key":"id","attributes":[{"name":"id","type":"S"}]}`,
		"SQSQueue":                    `{"name":"validate","redrive_policy":{"deadLetterTargetArn":"arn:aws:sqs:eu-west-1:123456789012:dlq","maxReceiveCount":5}}`,
		"SNSTopic":                    `{"name":"validate"}`,
		"CloudWatchLogGroup":          `{"name":"/validate/app"}`,
		"ECRRepository":               `{"repository_name":"validate"}`,
		"IAMRole":                     `{"name":"validate","source_trust_policy_documents":["{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"]}`,
		"SecretsManagerSecret":        `{"name":"validate"}`,
		"EC2Instance":                 `{"name":"validate","ami":"ami-0123456789abcdef0","subnet_id":"subnet-0123456789abcdef0","vpc_security_group_ids":["sg-0123456789abcdef0"]}`,
		"IAMPolicy":                   `{"name":"validate","policy":"{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:ListAllMyBuckets\",\"Resource\":\"*\"}]}"}`,
		"Subnet":                      `{"name":"validate","vpc_id":"vpc-0123456789abcdef0","cidr_block":"10.0.1.0/24","availability_zone":"eu-west-1a"}`,
		"RouteTable":                  `{"vpc_id":"vpc-0123456789abcdef0"}`,
		"NetworkACL":                  `{"name":"validate","vpc_id":"vpc-0123456789abcdef0"}`,
		"InternetGateway":             `{"vpc_id":"vpc-0123456789abcdef0"}`,
		"ElasticIP":                   `{"name":"validate"}`,
		"ACMCertificate":              `{"domain_name":"app.example.com","zone_id":"Z0123456789ABCDEFGHIJ"}`,
		"Route53Zone":                 `{"name":"example.com"}`,
		"EFSFileSystem":               `{"name":"validate"}`,
		"ApplicationLoadBalancer":     `{"name":"validate","vpc_id":"vpc-0123456789abcdef0","subnets":["subnet-0123456789abcdef0","subnet-0123456789abcdef1"],"security_groups":["sg-0123456789abcdef0"]}`,
		"AutoScalingGroup":            `{"name":"validate","vpc_zone_identifier":["subnet-0123456789abcdef0"],"image_id":"ami-0123456789abcdef0"}`,
		"ElastiCacheReplicationGroup": `{"replication_group_id":"validate","subnet_ids":["subnet-0123456789abcdef0"],"security_group_ids":["sg-0123456789abcdef0"]}`,
		"ECSCluster":                  `{"cluster_name":"validate"}`,
		"EventBridgeBus":              `{"bus_name":"validate","create_bus":true}`,
	}
	for _, m := range cat.Modules {
		if m.Cloud != "aws" || !(strings.HasPrefix(m.Source, "terraform-aws-modules/") || catalog.IsFirstParty(m.Source)) {
			continue
		}
		sample, ok := samples[m.Kind]
		if !ok {
			t.Errorf("%s: no sample inputs", m.Kind)
			continue
		}
		m := m
		t.Run(m.Kind, func(t *testing.T) {
			mod := map[string]any{"name": "res", "kind": m.Kind, "inputs": json.RawMessage(sample)}
			if m.Adopt != nil && len(m.Adopt.Gaps) > 0 {
				gaps := map[string]any{}
				for k, v := range m.Adopt.Gaps {
					if b, _ := json.Marshal(v); strings.Contains(string(b), "{{") {
						continue // filled from the live resource
					}
					gaps[k] = v
				}
				mod["baseline_gaps"] = gaps
			}
			raw, _ := json.Marshal(map[string]any{"modules": []any{mod}})
			var st Stack
			if err := json.Unmarshal(raw, &st); err != nil {
				t.Fatal(err)
			}
			if err := st.Validate(cat, "aws"); err != nil {
				t.Fatalf("validate spec: %v", err)
			}
			gen, err := st.Generate(cat, GenerateInput{StackName: "validate", Environment: "dev", Cloud: awsOIDC, TofuVersion: "1.13.2"})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for name, b := range gen.Files {
				p := filepath.Join(dir, name)
				os.MkdirAll(filepath.Dir(p), 0o700)
				os.WriteFile(p, b, 0o600)
			}
			for _, args := range [][]string{{"init", "-backend=false", "-input=false", "-no-color"}, {"validate", "-no-color"}} {
				cmd := exec.Command(tofu, args...)
				cmd.Dir = dir
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("tofu %s: %v\n%s", args[0], err, tail(string(out), 6000))
				}
			}
		})
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
