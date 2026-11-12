# SrustiOps

SrustiOps is a multi-tenant platform for running infrastructure as code safely. Teams describe what they want as small YAML **contracts** built from an approved catalog of **kinds** (`S3Bucket`, `RDSDatabase`, `EKSCluster`, …). SrustiOps then:
- generates the OpenTofu code;
- plans every change;
- rates its risk and checks it against policy;
- collects the approvals the risk requires;
- applies exactly the plan that was approved.

Nobody writes HCL, nobody holds cloud keys, and every action is recorded in a tamper-evident audit log.

Each client company gets its own **workspace**: its own backend, database, state, runners and cloud identity, running in its own network. A shared **central plane** provides one sign-in and one console, and routes each request to the right workspace.

- [Features](#features)
- [Architecture](#architecture)
- [Concepts](#concepts)
- [Run it locally](#run-it-locally)
- [Signing in and tokens](#signing-in-and-tokens)
- [End to end: from a new workspace to a deployed change](#end-to-end-from-a-new-workspace-to-a-deployed-change)
- [Operating the platform](#operating-the-platform)
- [Deploying](#deploying)
- [Repositories and tests](#repositories-and-tests)

For every setting, API and design detail, see the [reference](docs/REFERENCE.md); for the security controls, see [SECURITY.md](SECURITY.md).

## Features

| Area | What you get |
| --- | --- |
| **Contracts, not code** | Resources are kinds from a pinned catalog. You set only what differs from the defaults (kind → tenant → tier → contract). Security baselines are enforced and cannot be overridden. Secrets are Vault/OpenBao references, never values |
| **Two ways to change** | Edit stacks in the console, or keep them as YAML in GitHub, GitLab, Bitbucket or Azure DevOps: pull requests are planned, approved and applied *before* they merge |
| **Plans you can trust** | Every plan gets a risk level (low / medium / high), an estimated monthly cost, built-in policy checks plus your own Rego policies, and a summary with sensitive values removed |
| **Approvals by risk** | Low risk needs a manager; medium adds FinOps; high adds Security. Nobody signs their own change or two steps of one change. Approve from the console or from Slack. DevOps can override with a recorded reason |
| **No standing credentials** | Runs get short-lived OIDC tokens from the workspace's own issuer, which AWS, GCP, Azure and Vault trust. State and plans are encrypted on the runner |
| **Inventory and adoption** | Scan cloud accounts, see what is managed and what is not, and adopt existing resources into stacks with zero-diff imports: one resource, a selection, a whole service (EC2, S3, …) or a whole account, as console stacks or as one or many pull requests |
| **Drift** | Check any stack for drift, or schedule checks per environment (opt-in, with quiet hours). Checks only report; you then revert the live resources to the code, or keep the live change by updating the stack. Nothing is remediated automatically |
| **Everyday delivery** | Stack pages show managed resources and outputs; lock a stack during a freeze; cancel a running plan or apply; clone a stack to another environment and promote changes dev → prod; start stacks from templates; delete stacks that manage nothing |
| **Releases** | Changes to kinds, defaults and policies are built into releases that DevOps approve before runs use them |
| **Workspaces anywhere** | A workspace's backend can be reached directly (mTLS) or through the **tenant link**: an outbound-only tunnel, so nothing in the client's network accepts inbound connections. Air-gapped installs are supported |
| **Provisioner** | SrustiOps can build a new workspace in the client's own AWS account, GCP project or Azure subscription (network, database, bucket, VM, EKS, GKE or AKS) from a blueprint, after the client approves the plan and its monthly cost, through OIDC trust the client creates (an IAM role, a workload identity pool, or an app registration). The trust can be re-checked from the console at any time |
| **Costs and budgets** | Actual monthly cost per BU and stack from each cloud's billing (AWS Cost Explorer, Azure Cost Management, GCP's billing export), by the tags SrustiOps puts on what it creates; monthly budgets per BU with alerts, and a policy that holds new cost when a BU is over |
| **Identity** | One sign-in (GitHub, Google, any OpenID Connect or SAML 2.0 provider configured in the console, or a workspace's own OIDC or SAML provider), SCIM provisioning, and roles per workspace, product and business unit, granted to people or to teams. Invitations lapse if unused; everyone's last activity is shown. A workspace can take over its own access control and approve support access |
| **Notifications** | A bell with unread counts, per-person muting, and opt-in email (through the workspace's mail server) about what each person can see, plus Slack, Microsoft Teams, PagerDuty (incidents opened on errors and resolved on success) and a daily digest email |
| **Operations** | Per-client rate limits and in-flight caps, live run logs and change streams, Prometheus metrics, platform alerts (Slack or webhook), a workspace health banner, and a hash-chained audit log for both the platform and each workspace, with date ranges, CSV downloads and export to a SIEM (signed webhook, Splunk HEC, S3) |
| **Backups and upgrades** | Scheduled, sealed backups of each workspace's database and state with a restore drill after each one, and `srustiops tenant restore`. Staged fleet upgrades from central (canary, then waves), applied by an updater beside each workspace |
| **Plans and limits** | Platform admins give workspaces plans: limits on stacks, environments, connections, runners, runs a month and people, enforced on every path that creates them. No payments are involved |
| **Assistant** | An optional assistant that answers questions about the workspace with retrieval over its docs and data (Anthropic API), set up from the console (Integrations → Assistant) |

## Architecture

```
                          ┌────────────────────────── CENTRAL PLANE (platform operator) ──────────────────────────┐
  people, CLI,            │ console · sign-in (SSO, SCIM, tokens) · workspace directory · platform audit           │
  Terraform provider ────▶│ rate limits and in-flight caps · request cache · alerts · metrics                       │
        HTTPS             │ the wrapper: /api/v1/t/<ws>/… → that workspace, with a 60-second signed assertion       │
                          │ the gateway: outbound tunnels from workspaces (tenant link)                             │
                          └───────────────┬───────────────────────────────────────────┬────────────────────────────┘
                                          │ mTLS, direct                              ▲ outbound 443 only
                                          ▼                                           │ (tenant link)
            ┌────────────── WORKSPACE "acme" ──────────────┐        ┌────────────── WORKSPACE "globex" ─────────────┐
            │ tenant plane: stacks, runs, approvals,        │        │ link agent ──▶ tenant plane                    │
            │ policies, releases, inventory, audit,         │        │ own PostgreSQL, bucket, OIDC issuer            │
            │ OIDC issuer · own PostgreSQL · own bucket     │        │                                                │
            │        ▲ runners poll outbound                │        │        ▲ runners                               │
            │   RUNNERS ──▶ AWS / GCP / Azure / Vault       │        │   RUNNERS ──▶ clouds                            │
            └───────────────────────────────────────────────┘        └────────────────────────────────────────────────┘
```

One Go binary, `srustiops`, runs every role:

| Command | Role | Runs where |
| --- | --- | --- |
| `srustiops central` | Console, identity, directory, routing, gateway, platform settings | Operated by the platform provider |
| `srustiops tenant` | One workspace's backend: stacks, runs, approvals, state, audit, OIDC issuer | In the client's environment |
| `srustiops link` | The tenant link agent: dials the gateway and carries the workspace's API | Next to the tenant plane, when it cannot be reached directly |
| `srustiops runner` | Runs OpenTofu for one workspace, polling it for work | Near the client's clouds |

### Design principles

- **Data stays with the client.** Central keeps only identity and the directory. Stacks, plans, state, logs and audit stay in each workspace's own database and bucket.
- **Central is not trusted by the workspace for authority.** Every request a workspace receives carries central's client certificate and a short-lived assertion bound to the exact method and path, usable once. A workspace that controls its own access decides roles itself.
- **Nothing dials in.** With the tenant link, the workspace's agent opens outbound tunnels: one for interactive requests, one for bulk traffic (log streams, state, exports). Runners also only poll outbound.
- **Exactly what was approved is applied.** Every approval re-checks that the configuration and state are unchanged. The runner verifies the saved plan's checksum before applying.

### How a request flows

1. The console calls central, for example `GET /api/v1/t/acme/stacks`.
2. Central checks the session, then the caller's per-address and per-person rate limits. It looks up the workspace and the caller's roles there; these are cached for a few seconds, and cleared after any change.
3. Central applies the workspace's rate limit and in-flight cap. A short burst queues briefly; past the limit the request gets `429` or `503` with `Retry-After`.
4. Central signs an assertion and forwards the request over mTLS, directly or through the tenant link.
5. The tenant plane verifies the assertion and the caller's role for the resource's business unit, then answers.

Open pages stay current through two server-sent-event streams: a workspace's change feed, and a run's live log. The streams are driven by PostgreSQL notifications, and the console falls back to polling if they are unavailable.

### How a change flows

1. **Contract.** Resources by kind, only values that differ from the defaults, `ref`s between resources, `secretRef`s for secrets.
2. **Generated code.** The tenant plane resolves defaults and writes `main.tf`, with:
   - exact engine, provider and module pins;
   - the enforced baselines;
   - workload-identity authentication;
   - its own encrypted state backend.
3. **Plan.** A runner claims the run and plans. It installs only allowlisted providers, preferring the mirror baked into its image, and verifies every module and provider. It uploads a redacted summary.
4. **Checks.** Built-in policy and your Rego policies; risk and cost.
5. **Approvals.** The steps the risk requires, by different people.
6. **Apply.** The runner applies the saved plan, verified by its checksum. Outputs feed stacks that depend on this one, which are then planned in turn.

## Concepts

| Term | Meaning |
| --- | --- |
| **Workspace** (tenant) | One client company: its own backend, data and people. Trial or production |
| **Product** (entity) | A product inside the workspace, for example *Retail* |
| **Business unit (BU)** | A team inside a product, for example *Payments*. Stacks, runs and audit events belong to a BU |
| **Environment** | Where a product deploys (`dev`, `prod`): a tier, cloud connections and a runner pool, shared by the product's BUs |
| **Connection** | A cloud account, project or subscription, identified only by IDs. Access is by OIDC trust, not keys |
| **Kind** | A catalog entry wrapping one pinned public module with defaults, an enforced baseline and allowed outputs |
| **Stack** | A unit of infrastructure with one state: one or more resources of kinds |
| **Run** | A plan and, once approved, an apply (or a drift check, or a destroy) of one stack |
| **Roles** | Platform admin; per workspace `tenant_admin`, `devops`, `finops`, `security`, `auditor`; per product or BU `admin`, `manager`, `developer`, `viewer` |

## Run it locally

Requirements: Go 1.26, Docker, Node 20, OpenTofu 1.13. Clone the four repositories side by side:

```
srustiops-backend   srustiops-web   srustiops-modules   srustiops-test-resources
```

Then start everything:

```bash
cd srustiops-backend && ./scripts/dev-up.sh
```

This builds the binary and the console, then starts the following, with seed data:

| Service | Address |
| --- | --- |
| Central plane and console | http://127.0.0.1:8090 |
| Workspace **acme** (direct mTLS) | https://localhost:8444 |
| Workspace **srustiops-1** (through the tenant link) | https://localhost:8445 |
| Gateway | https://localhost:8091 |
| PostgreSQL, Temporal, OpenBao | Docker containers |

The seed data is:
- **Products and BUs:** Retail (Payments, Checkout) and Platform (Data).
- **Connections:** sample cloud connections.
- **Environments and stacks:** a few of each.
- **People:** one person per role.

**Options**

| Variable | Effect |
| --- | --- |
| `DEV_CLOUD=real` | Send cloud calls to real clouds instead of the local fake |
| `DEV_PROVISIONER_TENANT=acme` | Turn on the provisioner, with acme as the platform's own workspace |
| `DEV_ACME_PUBLIC_URL`, `DEV_LINK_PUBLIC_URL` | Public addresses (for example a tunnel) when real clouds or VMs must reach your laptop |

To start over with empty databases, stop `dev-up` (Ctrl-C) and run:

```bash
docker rm -f srustiops-dev-mt-pg srustiops-dev-temporal srustiops-dev-openbao && docker volume rm srustiops-dev-mt-pg && rm -rf .dev
```

## Signing in and tokens

The sign-in page asks for your work email. If your company's domain has its own identity provider, it takes you there; otherwise it offers the platform's sign-in options.

**Local development.** `dev-up` writes one token per seeded person to `.dev/multi-tenant/tokens.env`:

| Token | Who |
| --- | --- |
| `ROOT` | Platform admin |
| `TINA` | acme tenant admin |
| `ALICE` | Developer |
| `MIKE` | Manager |
| `FIONA` | FinOps |
| `SAM` | Security |
| `EVE` | Developer in another BU |
| `AVA` | Auditor |
| `DORA` | DevOps |

On the sign-in page choose **Recovery or API token sign-in** and paste one. Signing in as different people is how you try the approval chain.

**Tokens anywhere**

| Need | How |
| --- | --- |
| The platform root (first sign-in, or recovery) | `srustiops central bootstrap -email root@example.com` against central's database. It creates, or rotates, the root's single token |
| Your own tokens (CLI, scripts) | Console → user menu → **My tokens**, or `POST /api/v1/me/tokens` |
| A first token for a workspace member | **Tenant settings → People & roles → Issue token** (tenant admins) |
| A runner token | **Tenant settings → Runners → Register runner** |

Tokens are sent as `Authorization: Bearer sop_…` and expire (90 days at most); signing out revokes a session.

**Single sign-on.** As a platform admin, open **Platform → Sign-in**:

- **Google or GitHub:** add the OAuth app's client ID and secret, and register `<central URL>/auth/callback/<provider>` as the callback.
- **Enterprise sign-in (OpenID Connect):** add Okta, Entra ID, Ping, Keycloak, Auth0 or any OIDC provider with its issuer URL, client ID and (optional) secret; register the redirect URI the console shows (`<central URL>/auth/oidc/<id>/callback`).
- **Enterprise sign-in (SAML 2.0):** paste the IdP's metadata, give its metadata URL, or enter its entity ID, SSO URL and signing certificate. Register the ACS URL and entity ID the console shows (`<central URL>/auth/saml/<id>/acs` and `/metadata`). Responses must be signed by the IdP, answer a request SrustiOps made (no IdP-initiated sign-in, no replays) and be current.
- An enterprise provider must name the email domains it may sign in. People who type such an address on the sign-in page are sent straight to it.

A workspace that controls its own access can also use its own provider, **OIDC or SAML**, under **Tenant settings → Access & sign-in → Identity provider**. The workspace's backend runs that sign-in and verifies the ID token or SAML assertion itself; central only passes the browser along. A generic OIDC provider can still be set with the `SRUSTIOPS_OIDC_*` settings ([reference](docs/REFERENCE.md#configuration)).

Sign-in only proves who someone is: people get access when an admin adds them, or through SCIM.

## End to end: from a new workspace to a deployed change

### 1. Create a workspace (platform admin)

Go to **Platform → Onboard tenant** (or **New workspace**) and choose who sets it up.

**The client installs it**
- Pick Kubernetes or Docker Compose.
- SrustiOps gives a one-time install command, valid for one hour. The install bootstraps its own keys and certificates and dials the gateway.
- The workspace opens once its tenant plane is connected.

**SrustiOps builds it (AWS)**
1. Enter the client's AWS account ID and region, and pick a blueprint (account + VM, account + Kubernetes, or an existing cluster) and a size.
2. The client creates the CloudFormation trust stack SrustiOps shows: an OIDC provider and a role with a permission boundary. No keys are shared.
3. SrustiOps plans the network, the data layer and the install, and shows the monthly cost estimate against a budget cap.
4. The client approves the plan and its cost. The build and install then run with live logs.
5. When the workspace is live, the provisioner hands it over and the client can revoke the trust role.

Other people can create **trial workspaces** at once, within quotas, if their email domain is allowed under **Platform → Creation policy**. They can also request production workspaces, which wait under **Requests**.

### 2. Set up the workspace (tenant admin)

Open the workspace, then **Tenant settings**:
1. **Organisation:** create products, their business units, and environments (tier, connections, runner pool).
2. **People & roles:** add people with roles per workspace, product or BU. **Access & sign-in** can move access control into the workspace, with its own identity provider, SCIM and support-access approvals.
3. **Runners:** register a runner and start it with its token (it only polls outbound).
4. **Risk policy:** thresholds for large changes and cost, and who signs each level.

Then go to **Integrations**:
- **Cloud connections:** register AWS accounts, GCP projects and Azure subscriptions. Each connection's setup guide gives the trust policy for the workspace's OIDC issuer. **Organisations** onboards a whole AWS Organization or GCP organization by OU.
- **GitHub:** connect the GitHub App, so contracts repositories, pull-request plans and status checks work.
- **Slack:** send notifications to a channel, and approve or reject from Slack.
- **Secret store:** point at OpenBao or Vault. Runs log in with their own short-lived token; nothing is stored.
- **Event tracking:** cloud change events flag the stack that manages a resource changed outside SrustiOps.

### 3. Describe infrastructure

**In the console**
1. **Stacks → New stack:** choose the BU and environment.
2. Add resources from **Kinds & defaults**.
3. Set only what differs. The preview validates as you go.

**In Git**
- **Tenant settings → Contracts repository:** point at a branch. One folder per stack, one YAML file per resource:

```yaml
# stacks/retail/dev/payments/orders/db.yaml
apiVersion: srustiops/v1
kind: RDSDatabase
spec:
  identifier: orders
  kms_key_id: { ref: orders-key.key_arn }
  master_password: { secretRef: vault://kv/payments/orders-db#password }
```

- Pull requests are planned and must be approved and applied before they merge (require the `srustiops/apply` status check). **Pull requests** lists them.
- **Hosts:** GitHub (through the GitHub App, with webhooks), GitLab (gitlab.com or self-managed), Bitbucket Cloud and Azure DevOps. On GitLab, Bitbucket and Azure DevOps, SrustiOps finds pull requests by polling, so nothing on the Git side has to reach your workspace. It sets a status and keeps one comment on each, and squash-merges only from the commit it applied. The access token needs:

| Host | Repository | Token |
| --- | --- | --- |
| GitLab | `group/project` | project access token, scope `api` |
| Bitbucket Cloud | `workspace/repository` | repository access token (pull requests and repository: write), or `user:app-password` |
| Azure DevOps | `organization/project/repository` | personal access token: Code (read & write) and Code (status) |

### 4. Plan, approve, apply

1. **Plan:** **Plan changes** on a stack queues a run. The run page streams the log live and shows:
   - the resource changes;
   - policy results;
   - the risk level and the reasons for it;
   - the estimated cost.
2. **Approve:** **Approvals** lists what waits for you. Each step must be signed by a different person, who did not author the change.
3. **Apply:** the last signature queues the apply. The runner applies the exact plan, and dependent stacks plan next.
4. **Retry or cancel:** a failed or cancelled run has **Run again**. **Cancel run** stops a queued run at once; a plan or apply in progress is interrupted by its runner within seconds, and OpenTofu saves state before it stops. **Runs** filters by stack, operation and status, and pages back through history.
5. **Promote:** **Manage → Clone to an environment** copies a stack (without its imports) into, say, `prod`; references to other stacks follow their clones there. Later, **Promote** copies the contract into that clone after a side-by-side preview; its plan needs that environment's approvals.
6. **Templates:** **Manage → Save as template** keeps a stack's resources for reuse; **New stack → Start from** offers them (per product, or every product when a tenant admin shares one).

### 5. Keep it healthy

- **Drift:** **Check drift** on a stack compares the live resources with the last apply. From the result, revert or keep the live change. To check regularly, open **Tenant settings → Organisation → (environment) → Scheduled checks**: drift checks and inventory rescans every N hours, quiet hours, and **Check everything now**. Scheduled checks are refresh-only and only notify.
- **Stack page:** resources the stack manages (from state), its outputs (values sealed until revealed, which is audited), **Lock** with a reason (no plan or apply until unlocked; drift checks still run), and **Delete stack** once it manages nothing (after an applied destroy, or if it was never applied). History is kept and the name can be reused.
- **Inventory:** scan connections and see coverage per service. Adopt unmanaged resources (with what they depend on) into stacks as zero-diff imports. **Bulk import** takes a whole account (**Import account** on a connection), a whole service (**Import all N** on a service) or a selection (**Bulk import…**): it groups them into a stack per service, per resource or one stack, previews every stack, and creates console stacks or opens one pull request (or one per stack). At most 200 resources at a time.
- **Costs & budgets:** each BU shows its month-end forecast at the current pace; the library policy holds a plan when the forecast plus the plan's increase would pass the budget. Turn on reading actual cost under **Costs & budgets → Settings** (each connection's role needs billing read access: AWS `ce:GetCostAndUsage`, Azure Cost Management Reader, GCP BigQuery read on the billing export table, which you name per connection). Spend appears per BU and stack, by the `srustiops-bu` and `srustiops-stack` tags (on AWS, activate them as cost allocation tags). FinOps sets a monthly budget per BU with alert thresholds (default 80% and 100%); each threshold notifies once a month. The library policy **Stay within the BU's budget** holds plans that add cost to a BU over its budget (`input.budget` in your own policies).
- **Backups:** **Tenant settings → Backups**: daily by default, the newest 7 kept, each one restore-drilled into a scratch schema, sealed in 64 MiB parts. Set `SRUSTIOPS_BACKUP_COPY_URL` to a second bucket (another account or region) to keep a copy of each. Overdue backups and failed drills raise an alert. **Retention** (same page) prunes notifications, cloud events, webhook deliveries, inventory scans, old state versions and database-held run logs; the audit log is never pruned. **Back up now**, **Drill**, and **Download** (sealed: only this workspace's master key opens it). Restore into a new, empty database with `srustiops tenant restore -file <backup>`.
- **Plan & usage:** **Tenant settings → Plan & usage** shows the workspace's plan and what it uses of each limit. At a limit, creating one more is refused; drift checks and destroys always run.
- **Policies:** add Rego policy sets (hard or advisory) per workspace, product or BU. The **Policy library** has ready-made sets (required tags, encryption at rest, no public access, allowed regions, instance sizes, no deletes in production, monthly cost limit) with parameters. **Test against recent plans** shows what a set would have stopped before you save it.
- **Git accounts:** **Tenant settings → People → Git accounts** links each person's GitHub, GitLab, Bitbucket or Azure DevOps login, so the author of a pull request cannot approve its plans (whoever proposes a stack from the console is recorded automatically). People link their own under Notifications; only tenant admins remove links.
- **Environments:** besides per-run limits, **Runs at once** caps how many plans and applies run together in an environment. Runners take approved applies first, then share fairly between BUs.
- **People:** **Tenant settings → Teams** grants roles to a group at once (not `tenant_admin`). People added who have never signed in are invited for 7 days (extendable); unused invitations lapse and their roles go. People & roles shows each person's last activity.
- **Notifications:** **bell → Preferences** mutes kinds and turns on email for yourself. A tenant admin sets the mail server under **Integrations → Email** (STARTTLS, TLS, or plain SMTP to a local relay).
- **Releases:** changes to kinds, defaults and policies are built into releases. DevOps approve before runs use them.
- **Audit log:** every action, hash-chained. **Verify integrity** checks the chain.

### 6. Remove a workspace

**Platform → Tenants → (workspace) → Remove workspace**:
- deregisters the workspace and revokes its link certificates and tokens;
- stops its tenant plane and takes SrustiOps off any machine the provisioner built;
- never touches the client's infrastructure or data. The network, database, bucket, keys and state stay.

## Operating the platform

| Page | Purpose |
| --- | --- |
| **Platform → Tenants** | Every workspace's connection and health. A banner lists workspaces that are offline, never connected, or whose link certificates lapsed |
| **Platform → Rate limits** | Live load per workspace (requests, turned away, running, streams, tunnels) and the limits: per address, per person, per workspace, changes per person, requests at once, gateway, and overrides per workspace. Limits are split between central replicas, so together they hold |
| **Platform → Alerts** | Send offline, never-connected and failed-provisioning alerts to Slack and/or a webhook (PagerDuty, Opsgenie, your own). Each problem is sent once, and again when it clears |
| **Platform → Audit log** | What platform admins, sign-ins and the gateway did, hash-chained and verifiable; date ranges, CSV, and export to the platform's SIEM |
| **Platform → Fleet** | The version each workspace runs, and staged rollouts of a new one: canary workspaces, then percentage waves, a soak time between waves; pause, resume or abort (abort sends every workspace back). Each workspace's updater (`srustiops updater`, enabled in the tenant chart with `updater.enabled`) applies it with no downtime and reports back |
| **Platform → Plans** | Plans (trial, team, enterprise, or your own) with limits, and which plan each workspace is on. Limits reach a workspace's plane at once, or when it is next online |
| **Platform → Sign-in / Admins / Creation policy / Requests** | Sign-in providers, platform admins, who may create workspaces, pending requests |

**Metrics.** Set `SRUSTIOPS_METRICS_LISTEN` (for example `:9090`) on central, tenant planes and runners. Prometheus metrics are then served on that separate port, never on the public listener.

| Series | Use |
| --- | --- |
| `srustiops_http_requests_total`, `srustiops_http_request_duration_seconds` | Traffic and latency per plane |
| `srustiops_rate_limited_total`, `srustiops_workspace_in_flight` | Load shedding and pressure |
| `srustiops_workspace_online`, `srustiops_workspace_tunnels` | Workspace health |
| `srustiops_runs_queued`, `srustiops_runs_queued_oldest_seconds` | Runner capacity; what an autoscaler watches |
| `srustiops_runner_last_seen_seconds`, `srustiops_runner_jobs_total`, `srustiops_runner_job_duration_seconds` | Runner health and throughput |

**Timers for tests.** `SRUSTIOPS_SCHEDULE_EVERY` (tenant plane, default 1m) is how often scheduled checks are looked at; `SRUSTIOPS_INVITE_SWEEP` (central, default 10m) how often lapsed invitations are removed. Shorten them only in tests.

**Tracing.** Every request carries a W3C `traceparent` (kept from the caller or started) and answers with its trace ID in `X-Request-Id`; central passes it on to the workspace, and both planes log slow (over 2 s) and failed requests with it. `/healthz` shows a workspace's audit backlog and the single-replica jobs the replica is running.

**API.** Each plane describes its API at `/api/v1/openapi.json` (OpenAPI 3.1, generated from the routes and checked by a test). Long lists take `?limit=`; the Stacks list returns summaries with `X-Total-Count` (`?full=1` for whole stacks).

**Tools.** `srustiops policy test -dir <policies>` compiles policies, runs their Rego unit tests (`*_test.rego`) and fixture plans (`fixtures/*.json`: an input and the denials it must get); run it in the policy repository's CI. `srustiops loadtest -url <central> -tenant <t> -token-file <f> -c 50 -d 60s` loads a workspace's read paths and reports latency percentiles and errors. The database pool is `pool_max_conns` in the URL or `SRUSTIOPS_DB_MAX_CONNS` (default 20).

**Behind a load balancer**, set `SRUSTIOPS_TRUSTED_PROXIES` to its CIDRs. Rate limits and sign-in lockouts then see each client's address instead of the proxy's.

## Deploying

| Option | Where |
| --- | --- |
| Docker Compose (evaluation) | `docker-compose.yml`; see [reference → Evaluation install](docs/REFERENCE.md#evaluation-install-docker-compose) |
| Kubernetes | Helm charts in [`deploy/helm`](deploy/helm): `srustiops-central` and `srustiops-tenant` (tenant plane, link agent, runners, updater). They support cert-manager, network policies, `metrics.enabled`, and KEDA runner autoscaling on the run queue (`runner.autoscaling.enabled`). The tenant bucket is `s3://`, `gs://` or `azblob://`; with `bucket.credentials: workload` it is reached with the pod's identity (EKS IRSA, GKE Workload Identity, Entra Workload ID) and no keys are stored |
| Images | `docker.io/mukkarapavankumarreddy/srustiops-server` (central and tenant, distroless, non-root) and `srustiops-runner` (OpenTofu, git and the catalog's pinned providers), for linux/amd64 and linux/arm64 |
| Air-gapped | `scripts/airgap-bundle.sh` and `scripts/airgap-import.sh`: signed images, module and provider mirrors |

Build the images from this repository, with the web and modules repositories as named contexts:

```bash
docker buildx build --platform linux/amd64,linux/arm64 --target server \
  --build-context web=../srustiops-web --build-context catalog=../srustiops-modules/catalog \
  -t docker.io/<you>/srustiops-server:<tag> --push .
```

Use `--target runner` and the `srustiops-runner` name for the runner.

## Repositories and tests

| Repository | Contents |
| --- | --- |
| `srustiops-backend` (this one) | Central plane, tenant plane, link agent, runner, Helm charts, the OpenTofu/Terraform provider |
| `srustiops-web` | The console (React + TypeScript) |
| `srustiops-modules` | The catalog: kinds, pinned modules and providers, baselines, first-party modules |
| `srustiops-test-resources` | End-to-end suite, sample contracts and policies, provisioner blueprints, the AWS runbook, and blueprint tests for real clouds |

```bash
go test ./...                                    # unit tests
../srustiops-test-resources/e2e/run.sh           # 1,000+ end-to-end checks across several workspaces
../srustiops-test-resources/e2e/compose-smoke.sh # the Docker Compose install
```
