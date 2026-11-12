# Helm charts

| Chart | Installs | Where |
| --- | --- | --- |
| `srustiops-central` | Central plane: web UI, identity, tenant directory, routing | Platform provider's cluster |
| `srustiops-tenant` | One tenant plane and its runners | Each client's cluster (the central tenant installs one too) |

Both charts:
- **Secrets:** read from existing Secrets; no secrets in values.
- **Pods:** run non-root with read-only file systems, all capabilities dropped and RuntimeDefault seccomp.
- **Certificates:** optionally issued by cert-manager. Rotated certificates are picked up without restarts.

## Central

```bash
kubectl -n srustiops-central create secret generic srustiops-central \
  --from-literal=database-url='postgres://…' --from-literal=master-key="$(openssl rand -base64 32)"
helm install srustiops ./srustiops-central -n srustiops-central \
  --set publicURL=https://srustiops.example.com --set tls.certManager.enabled=true \
  --set sso.issuer=https://acme.okta.com --set sso.clientID=…
```

## Tenant

The tenant chart needs:
- **The tenant slug**, as onboarded in central.
- **Central's URL.**
- **The CA that issued central's client certificate**, as a Secret with `ca.crt`. Only certificates from that CA can call the tenant's user API.
- **The tenant database and master key**, plus the runner token and state key.

```bash
helm install acme ./srustiops-tenant -n srustiops \
  --set tenant=acme --set publicURL=https://srustiops.acme.internal \
  --set central.url=https://srustiops.example.com \
  --set bucket.url='s3://acme-srustiops?region=eu-west-1' \
  --set temporal.address=temporal-frontend.temporal:7233 \
  --set runner.serviceAccountAnnotations."eks\.amazonaws\.com/role-arn"=arn:aws:iam::123456789012:role/srustiops-runner
```

To enable the assistant, add `assistant-api-key` to the tenant Secret and set `assistant.enabled=true`. It sends questions and the retrieved passages to the Anthropic API, or to `assistant.baseURL` if set. The tenant pod then needs outbound HTTPS to that host.

Network policies let only central's namespace (`central.ingressFrom`) and the release's runners reach the tenant API. Runners accept no inbound traffic.

## Connectivity: the tenant link

With `connectivity: tunnel` (the default) the chart runs the **link agent**. It dials out to central's gateway on 443 and keeps two tunnels open. Nothing dials in: the tenant needs no ingress, public endpoint or peering. The network policy lets only the agent and the runners reach the tenant API.

1. Platform admin → Platform → the tenant → **Issue enrolment token**. The token works once and expires after an hour.
2. Store it in the namespace:
   ```bash
   kubectl -n srustiops create secret generic srustiops-link-enroll --from-literal=token=sop_l_…
   ```
3. Install with `link.gatewayURL` set (and `link.serverCASecret` if the gateway uses a private CA).

The agent keeps its key and 24-hour certificate on a small volume and renews the certificate itself. You can delete the token Secret after the first connection.

Use `connectivity: direct` for a tenant in central's network, a peered VPC, or behind a private endpoint (PrivateLink, Private Service Connect, Private Link Service). Central then calls `publicURL`.

On central, `link.enabled` exposes the gateway through a layer-4 load balancer that passes TLS through. Replicas relay to each other, so a tunnel held by any one of them serves requests arriving at any of them.

## Per cloud

`deploy/landing/{aws,gcp,azure}` create each cloud's prerequisites, all private:
- a KMS key;
- the state bucket and an image registry;
- PostgreSQL on a private address;
- the master key's secret (the value is added by you, never in OpenTofu state);
- private endpoints for the cloud APIs;
- workload identities for the tenant plane and its runners.

Their outputs fill `values-eks.yaml`, `values-gke.yaml` or `values-aks.yaml`:

```bash
helm install acme ./srustiops-tenant -n srustiops -f srustiops-tenant/values-eks.yaml --set tenant=acme …
```

With `masterKey.source: csi`, the master key is read through the Secrets Store CSI driver. Example `SecretProviderClass` for AWS (GCP and Azure use their provider's equivalent):

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: { name: srustiops-master-key, namespace: srustiops }
spec:
  provider: aws
  parameters:
    usePodIdentity: "false"
    objects: |
      - objectName: "<master_key_secret_arn>"
        objectAlias: master-key
```

## Air-gapped tenants

On a connected machine:

```bash
scripts/airgap-bundle.sh -v 0.2.0 -r staging.example.com/srustiops -k cosign.key -o bundle/
```

This builds and signs the images (`cosign save` keeps the signatures with them). It also writes:
- the **module mirror**: every registry module package the catalog pins, in a signed index;
- the **provider mirror**: every pinned OpenTofu provider;
- the chart;
- `SHA256SUMS`, signed.

Inside the isolated network:

```bash
scripts/airgap-import.sh -b bundle/ -r registry.internal/srustiops -k cosign.pub
```

The import script verifies the bundle against the key you brought separately, loads the images into the internal registry, and verifies every image signature there. Then:
1. Copy `modules/` and `providers/` into two PVCs.
2. Install with `airgap.moduleMirror.*`, `airgap.providerMirror.existingClaim` and `imageVerification.enabled=true`.

What the tenant then does:
- **Module releases** vendor packages only from the mirror, after checking its signature and every package's checksum.
- **Runners** install providers only from the provider mirror. Lock-file hashes still apply.
- **Kyverno** admits only images signed with your key.

The only outbound connection left is the tenant link to central.

### OpenBao auto-unseal with the cloud KMS

For the [OpenBao chart](https://github.com/openbao/openbao-helm), add one seal stanza to `server.ha.config`. Unsealing then needs no operator and no key outside the KMS:

```hcl
seal "awskms"         { region = "eu-west-1"  kms_key_id = "<kms_key_arn>" }             # EKS (IRSA)
seal "gcpckms"        { project = "<project>" region = "<region>" key_ring = "<name>" crypto_key = "<name>-data" }  # GKE
seal "azurekeyvault"  { vault_name = "<name>-kv" key_name = "openbao-unseal" }           # AKS (Workload ID)
```
