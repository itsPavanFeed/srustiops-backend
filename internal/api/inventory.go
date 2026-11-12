package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/cloudapi"
	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
	"github.com/itsPavanFeed/srustiops-backend/internal/vaultkv"
)

// Inventory: a person scans a connection, the tenant plane reads the cloud's
// own resource index with the connection's read-only identity, and the
// resources are listed with the kind that can adopt each one and the stack
// that manages it (from the platform's ownership labels). Adopting resources
// creates a stack (or a contract pull request) whose spec is generated from
// the live resource and whose first plan must show no changes: the zero-diff
// gate blocks the import otherwise, and live -> code proposes the fix.

// discoverySubject is the "sub" of scan tokens: cloud trust policies can
// allow it on the read-only identity only.
func discoverySubject(conn string) string { return "srustiops:discovery:" + conn }

// discoveryClient is the client for a connection's read-only calls: a token
// exchange with the tenant's issuer (oidc), or the credentials kept in the
// secret store (vault), read with a discovery token for the store's audience.
func (s *Server) discoveryClient(ctx context.Context, conn string, cl *spec.Cloud) (*cloudapi.Client, error) {
	c := s.cloudClient(conn)
	if cl.Auth != "vault" {
		return c, nil
	}
	v := s.secretStore(ctx)
	if v == nil {
		return nil, errors.New("the connection keeps its credentials in the secret store, but no secret store is configured")
	}
	jwt, err := s.issuer.Sign(oidc.Claims{Subject: discoverySubject(conn), Audience: v.TokenAudience(), Phase: "discovery", TTL: 5 * time.Minute}, time.Now())
	if err != nil {
		return nil, err
	}
	vals, err := vaultkv.ReadAll(ctx, v, jwt, cl.SecretEnv())
	if err != nil {
		// Signing in and reading fail for different reasons; hint at the right one.
		if strings.Contains(err.Error(), "logging in to the secret store") {
			return nil, fmt.Errorf("%w (allow subject %s on the secret store's JWT role)", err, discoverySubject(conn))
		}
		return nil, fmt.Errorf("%w (check that the secret exists and the role's policy can read that path)", err)
	}
	switch cl.Provider {
	case "aws":
		c.AWSKeys = &cloudapi.AWSKeys{AccessKeyID: vals["AWS_ACCESS_KEY_ID"], SecretAccessKey: vals["AWS_SECRET_ACCESS_KEY"]}
	case "gcp":
		c.GCPKey = []byte(vals["GOOGLE_CREDENTIALS"])
	case "azure":
		c.AzureSecret = vals["ARM_CLIENT_SECRET"]
	}
	return c, nil
}

func (s *Server) cloudClient(conn string) *cloudapi.Client {
	return &cloudapi.Client{Base: s.cfg.CloudAPIURL, Tokens: func(aud string) (string, error) {
		return s.issuer.Sign(oidc.Claims{Subject: discoverySubject(conn), Audience: aud, Phase: "discovery", TTL: 10 * time.Minute}, time.Now())
	}}
}

// connVisible reports whether the caller may see a connection's inventory.
func connVisible(p *identity.Principal, c *store.Connection) bool {
	if p.ManagesTenant() || len(c.Entities) == 0 {
		return true
	}
	for _, e := range c.Entities {
		if p.CanViewEntity(e) {
			return true
		}
	}
	return false
}

// adoptKinds maps cloud -> inventory type -> kind.
func adoptKinds(cat *catalog.Catalog) map[string]map[string]*catalog.Module {
	out := map[string]map[string]*catalog.Module{}
	for _, m := range cat.Modules {
		if m.Adopt == nil {
			continue
		}
		for cloud, types := range m.Adopt.Match {
			if out[cloud] == nil {
				out[cloud] = map[string]*catalog.Module{}
			}
			for _, t := range types {
				if out[cloud][t] == nil {
					out[cloud][t] = m
				}
			}
		}
	}
	return out
}

// managedStack is the stack named by the platform's ownership labels.
func managedStack(tags map[string]string) string {
	if tags["managed-by"] == "srustiops" {
		return tags["srustiops-stack"]
	}
	return ""
}

func (s *Server) scanConnection(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "scanning a connection needs the tenant admin or devops role")
		return
	}
	conn, err := s.store.GetConnection(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	cl, err := spec.DecodeCloud(conn.Cloud)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	if cl.Provider == "none" || cl.Provider == "" {
		writeErr(w, 422, "this connection has no cloud to scan")
		return
	}
	if cl.Auth != "oidc" && cl.Auth != "vault" {
		writeErr(w, 422, cloudapi.ErrUnsupported.Error())
		return
	}
	scan, err := s.store.StartScan(r.Context(), conn.ID, p.Subject)
	if err != nil {
		s.writeStoreErr(w, err, "a scan of this connection is already running")
		return
	}
	s.audit(r.Context(), p.Actor(), "inventory.scan", "connection/"+conn.Name, "", map[string]any{"scan": scan.ID, "subject": discoverySubject(conn.Name)})
	go s.runScan(conn, cl, scan.ID)
	writeJSON(w, 202, scan)
}

func (s *Server) runScan(conn *store.Connection, cl *spec.Cloud, scanID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	var items []cloudapi.Item
	c, err := s.discoveryClient(ctx, conn.Name, cl)
	pick := func(apply, plan string) string {
		if plan != "" {
			return plan
		}
		return apply
	}
	switch {
	case err != nil:
	case cl.Provider == "aws":
		items, err = c.AWSInventory(ctx, pick(cl.AWS.RoleARN, cl.AWS.PlanRoleARN), cl.AWS.Region)
	case cl.Provider == "gcp":
		items, err = c.GCPInventory(ctx, cl.GCP.WorkloadIdentityProvider, pick(cl.GCP.ServiceAccountEmail, cl.GCP.PlanServiceAccountEmail), cl.GCP.ProjectID)
	case cl.Provider == "azure":
		items, err = c.AzureInventory(ctx, cl.Azure.TenantID, pick(cl.Azure.ClientID, cl.Azure.PlanClientID), cl.Azure.SubscriptionID)
	default:
		err = fmt.Errorf("cannot scan provider %q", cl.Provider)
	}
	if err == nil {
		kinds := adoptKinds(s.plat().cat)[cl.Provider]
		rows := make([]*store.InventoryItem, 0, len(items))
		for _, it := range items {
			row := &store.InventoryItem{ResourceID: it.ID, Type: it.Type, Name: it.Name, Region: it.Region, Account: it.Account, Project: it.Project, Tags: it.Tags, Stack: managedStack(it.Tags)}
			if row.Tags == nil {
				row.Tags = map[string]string{}
			}
			if m := kinds[it.Type]; m != nil {
				row.Kind = m.Kind
			}
			rows = append(rows, row)
		}
		err = s.store.ReplaceInventory(ctx, conn.ID, rows)
	}
	if ferr := s.store.FinishScan(ctx, scanID, len(items), err); ferr != nil {
		s.log.Error("finishing inventory scan", "scan", scanID, "err", ferr)
	}
	sev, title, body := "info", "Inventory scan finished: "+conn.Name, fmt.Sprintf("%d resources found.", len(items))
	if err != nil {
		sev, title, body = "error", "Inventory scan failed: "+conn.Name, err.Error()
	}
	s.notifyEvent(ctx, store.Notification{Kind: "inventory.scan", Severity: sev, Title: title, Body: body, Link: "inventory/" + conn.Name})
}

func (s *Server) visibleConnections(r *http.Request) (map[string]*store.Connection, []string, error) {
	cs, err := s.store.ListConnections(r.Context())
	if err != nil {
		return nil, nil, err
	}
	p := user(r)
	byID, ids := map[string]*store.Connection{}, []string{}
	for _, c := range cs {
		if connVisible(p, c) {
			byID[c.ID] = c
			ids = append(ids, c.ID)
		}
	}
	return byID, ids, nil
}

func (s *Server) listInventory(w http.ResponseWriter, r *http.Request) {
	byID, ids, err := s.visibleConnections(r)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	q := r.URL.Query()
	f := store.InventoryFilter{Connections: ids, Kind: q.Get("kind"), Managed: q.Get("managed"), Query: q.Get("q"), Service: q.Get("service"), Type: q.Get("type"), Limit: limit(r, 100, 500)}
	f.Offset, _ = strconv.Atoi(q.Get("offset"))
	if c := q.Get("connection"); c != "" {
		for id, conn := range byID {
			if conn.Name == c || id == c {
				f.Connection = id
			}
		}
		if f.Connection == "" {
			writeErr(w, 404, "unknown connection "+c)
			return
		}
	}
	items, total, err := s.store.ListInventory(r.Context(), f)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	type row struct {
		*store.InventoryItem
		Connection string `json:"connection"`
	}
	out := make([]row, 0, len(items))
	for _, it := range items {
		out = append(out, row{it, byID[it.ConnectionID].Name})
	}
	writeJSON(w, 200, map[string]any{"items": out, "total": total})
}

// inventorySummary lists every visible connection with its counts and last
// scan: the provider and connection levels of the inventory.
func (s *Server) inventorySummary(w http.ResponseWriter, r *http.Request) {
	byID, ids, err := s.visibleConnections(r)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	counts, services, err := s.store.InventorySummary(r.Context(), ids)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	scans, err := s.store.ListScans(r.Context(), "", 500)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	last := map[string]*store.InventoryScan{}
	for _, x := range scans {
		if last[x.ConnectionID] == nil {
			last[x.ConnectionID] = x
		}
	}
	type row struct {
		Connection  string               `json:"connection"`
		ID          string               `json:"id"`
		Provider    string               `json:"provider"`
		Scope       string               `json:"scope"` // account, project or subscription ID
		Region      string               `json:"region,omitempty"`
		Scannable   bool                 `json:"scannable"`
		Environment string               `json:"environment,omitempty"`
		Services    int                  `json:"services"`
		LastScan    *store.InventoryScan `json:"last_scan,omitempty"`
		store.InventoryCounts
	}
	out := []row{}
	seen := s.store.InventoryAccounts(r.Context(), ids)
	for _, id := range ids {
		c := byID[id]
		cl, err := spec.DecodeCloud(c.Cloud)
		if err != nil || cl.Provider == "none" {
			continue
		}
		x := row{Connection: c.Name, ID: c.ID, Provider: cl.Provider, Scannable: cl.Auth == "oidc" || cl.Auth == "vault", Environment: c.Environment,
			Services: services[id], LastScan: last[id], InventoryCounts: counts[id]}
		switch cl.Provider {
		case "aws":
			x.Scope, x.Region = accountOf(cl.AWS.RoleARN), cl.AWS.Region
		case "gcp":
			x.Scope, x.Region = cl.GCP.ProjectID, cl.GCP.Region
		case "azure":
			x.Scope = cl.Azure.SubscriptionID
		}
		if x.Scope == "" {
			x.Scope = seen[id] // as the last scan found it
		}
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}

func accountOf(roleARN string) string {
	if p := strings.Split(roleARN, ":"); len(p) > 4 {
		return p[4]
	}
	return ""
}

// visibleConnection resolves a connection (ID or name) the caller may see.
func (s *Server) visibleConnection(w http.ResponseWriter, r *http.Request, ref string) *store.Connection {
	c, err := s.store.GetConnection(r.Context(), ref)
	if err != nil || !connVisible(user(r), c) {
		writeErr(w, 404, "unknown connection "+ref)
		return nil
	}
	return c
}

// inventoryServices lists a connection's services and resource types.
func (s *Server) inventoryServices(w http.ResponseWriter, r *http.Request) {
	c := s.visibleConnection(w, r, r.URL.Query().Get("connection"))
	if c == nil {
		return
	}
	svcs, err := s.store.InventoryServices(r.Context(), c.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if svcs == nil {
		svcs = []*store.InventoryService{}
	}
	writeJSON(w, 200, svcs)
}

// inventoryResource shows one resource with the changes reported for it.
func (s *Server) inventoryResource(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c := s.visibleConnection(w, r, q.Get("connection"))
	if c == nil {
		return
	}
	it, err := s.store.GetInventoryItem(r.Context(), c.ID, q.Get("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	f := store.EventFilter{Connection: c.ID, Resource: it.ResourceID, Limit: 50}
	if p := user(r); !p.ManagesTenant() {
		f.BUs = p.VisibleBUs()
		if f.BUs == nil {
			f.BUs = []string{}
		}
	}
	evs, err := s.store.ListEvents(r.Context(), f)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var adopt any
	if m := s.plat().cat.Kind(it.Kind); m != nil && m.Adopt != nil {
		adopt = map[string]any{"kind": m.Kind, "title": m.Title, "imports": len(m.Adopt.Imports)}
	}
	writeJSON(w, 200, map[string]any{"item": it, "connection": c.Name, "events": evs, "adopt": adopt})
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	byID, _, err := s.visibleConnections(r)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	scans, err := s.store.ListScans(r.Context(), "", 200)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	type row struct {
		*store.InventoryScan
		Connection string `json:"connection"`
	}
	out := []row{}
	for _, x := range scans {
		if c := byID[x.ConnectionID]; c != nil {
			out = append(out, row{x, c.Name})
		}
	}
	writeJSON(w, 200, out)
}

// --- adopt ---------------------------------------------------------------

type adoptBody struct {
	Connection  string   `json:"connection"`
	Resources   []string `json:"resources"` // inventory resource IDs
	Stack       string   `json:"stack"`
	BU          string   `json:"bu"`
	Environment string   `json:"environment"`
	Via         string   `json:"via"` // stack (console) | git (contract pull request)
	DryRun      bool     `json:"dry_run"`
}

var instanceCleanRe = regexp.MustCompile(`[^a-z0-9_]+`)

// instanceName turns a resource name into a module instance name.
func instanceName(name string, used map[string]bool) string {
	n := strings.Trim(instanceCleanRe.ReplaceAllString(strings.ToLower(name), "_"), "_")
	if n == "" || n[0] < 'a' || n[0] > 'z' {
		n = "r_" + n
	}
	if len(n) > 36 {
		n = strings.TrimRight(n[:36], "_")
	}
	base := n
	for i := 2; used[n]; i++ {
		n = base + "_" + strconv.Itoa(i)
	}
	used[n] = true
	return n
}

// fillTemplate replaces the adopt placeholders with values of an item;
// {{id_tail}} is the last part of the ID (sg-…, a key's UUID).
func fillTemplate(t string, it *store.InventoryItem) string {
	t = arnPathRe.ReplaceAllStringFunc(t, func(m string) string {
		prefix := arnPathRe.FindStringSubmatch(m)[1]
		if _, rest, ok := strings.Cut(it.ResourceID, prefix); ok {
			return rest
		}
		return idTail(it.ResourceID)
	})
	return strings.NewReplacer("{{id}}", it.ResourceID, "{{id_tail}}", idTail(it.ResourceID), "{{arn}}", it.ResourceID, "{{name}}", it.Name, "{{region}}", it.Region,
		"{{project}}", it.Project, "{{account}}", it.Account).Replace(t)
}

// {{arn_path:log-group:}}: the part of the ID after that prefix (log group
// names contain slashes, so the last part is not enough).
var arnPathRe = regexp.MustCompile(`\{\{arn_path:([A-Za-z0-9_./:-]+)\}\}`)

func idTail(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 {
		return id[i+1:]
	}
	return id
}

var (
	propTmplRe = regexp.MustCompile(`\{\{(prop|propjson):([A-Za-z0-9_.]+)\}\}`)
	// {{propmap:Path:name=AttributeName,type=AttributeType}} reshapes a list of objects;
	// {{propfind:Path:KeyType=HASH:AttributeName}} picks a field of the first matching item.
	propMapRe  = regexp.MustCompile(`^\{\{propmap:([A-Za-z0-9_.]+):([A-Za-z0-9_=,]+)\}\}$`)
	propFindRe = regexp.MustCompile(`^\{\{propfind:([A-Za-z0-9_.]+):([A-Za-z0-9_]+)=([A-Za-z0-9_-]+):([A-Za-z0-9_.]+)\}\}$`)
	nonStackRe = regexp.MustCompile(`[^a-z0-9-]+`)
)

// adoptInputs renders a kind's adopt inputs for one live resource.
func adoptInputs(m *catalog.Module, it *store.InventoryItem) (map[string]json.RawMessage, error) {
	return adoptInputsWith(m, it, nil)
}

// adoptInputsWith renders a kind's adopt inputs for one live resource, with
// its live properties for {{prop:…}}. Platform ownership labels are not part
// of the contract: they are added on every resource by the platform itself.
func adoptInputsWith(m *catalog.Module, it *store.InventoryItem, props map[string]any) (map[string]json.RawMessage, error) {
	out := map[string]json.RawMessage{}
	for name, t := range m.Adopt.Inputs {
		in := m.Input(name)
		if in == nil {
			continue
		}
		var v any
		if t == "{{tags}}" {
			tags := map[string]string{}
			for k, val := range it.Tags {
				if !ownershipLabel(k) {
					tags[k] = val
				}
			}
			if len(tags) == 0 {
				continue
			}
			v = tags
		} else {
			if props != nil && (propMapRe.MatchString(t) || propFindRe.MatchString(t)) {
				pv, _ := fillProps(t, props)
				if pv != nil {
					out[name], _ = json.Marshal(pv)
				}
				continue
			}
			if pm := propTmplRe.FindStringSubmatch(t); pm != nil && pm[0] == t && props != nil {
				pv, _ := livePath(props, pm[2])
				if pv == nil {
					continue
				}
				if _, isStr := pv.(string); !isStr {
					b, _ := json.Marshal(pv)
					out[name] = b
					continue
				}
			}
			str := fillTemplate(t, it)
			if props != nil {
				filled, _ := fillProps(str, props)
				str, _ = filled.(string)
			}
			if str == "" {
				continue
			}
			switch {
			case strings.HasPrefix(in.Type, "list(") || strings.HasPrefix(in.Type, "set("):
				v = []string{str}
			case in.Type == "bool" || in.Type == "number":
				if err := json.Unmarshal([]byte(str), &v); err != nil {
					return nil, fmt.Errorf("input %s: %q is not a %s", name, str, in.Type)
				}
			default:
				v = str
			}
		}
		b, _ := json.Marshal(v)
		out[name] = b
	}
	return out, nil
}

type adoptPlan struct {
	Stack    string          `json:"stack"`
	BU       string          `json:"bu"`
	Env      string          `json:"environment"`
	Via      string          `json:"via"`
	Spec     json.RawMessage `json:"spec,omitempty"` // the stack asked for
	Stacks   []*adoptStack   `json:"stacks"`         // every stack, dependencies first
	Problems []string        `json:"problems,omitempty"`
	Skipped  []string        `json:"skipped,omitempty"`
	Gate     string          `json:"gate"`
}

// validateAdoption builds each stack of an adoption. References to stacks of
// the adoption (or to stacks not applied yet) only mean a stack plans after them.
func (s *Server) validateAdoption(ctx context.Context, out *adoptPlan, bu string, env *store.Environment) {
	inAdoption := map[string]bool{}
	for _, st := range out.Stacks {
		inAdoption[st.Name] = true
	}
	for _, st := range out.Stacks {
		var waits []string
		for _, d := range st.DependsOn {
			if inAdoption[d] {
				waits = append(waits, d)
			}
		}
		if len(waits) > 0 {
			st.Waits = waits
			continue // validated when its dependencies have applied
		}
		gen, _, probs := s.build(ctx, st.Name, bu, env, st.Spec)
		if probs != nil {
			if w, ok := waitingOn(probs); ok {
				st.Waits = w
				continue
			}
			st.Problems = probs
			for _, pr := range probs {
				out.Problems = append(out.Problems, st.Name+": "+pr)
			}
			continue
		}
		st.Spec = gen.Spec
	}
}

func (s *Server) adoptResources(w http.ResponseWriter, r *http.Request) {
	var b adoptBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	ctx := r.Context()
	if b.Via == "" {
		b.Via = "stack"
	}
	if b.Via != "stack" && b.Via != "git" {
		writeErr(w, 422, "via must be stack or git")
		return
	}
	if !spec.StackNameRe.MatchString(b.Stack) {
		writeErr(w, 422, "stack must start with a letter and use lowercase letters, digits and dashes (2-63)")
		return
	}
	if len(b.Resources) == 0 || len(b.Resources) > 50 {
		writeErr(w, 422, "choose 1 to 50 resources to adopt")
		return
	}
	conn, err := s.store.GetConnection(ctx, b.Connection)
	if err != nil || !connVisible(p, conn) {
		writeErr(w, 404, "unknown connection "+b.Connection)
		return
	}
	bu, env0 := s.target(w, r, b.BU, b.Environment)
	if env0 == nil {
		return
	}
	if !p.CanChange(bu) {
		writeErr(w, http.StatusForbidden, "adopting resources needs the developer or admin role in "+bu)
		return
	}
	env, ok := env0.ForConnection(conn.ID)
	if !ok {
		writeErr(w, 422, "environment "+env0.Name+" does not use connection "+conn.Name+": adopt into an environment of the same account, project or subscription")
		return
	}
	if _, err := s.store.GetStack(ctx, b.Stack); err == nil {
		writeErr(w, 409, "a stack named "+b.Stack+" exists; choose another name")
		return
	}
	g, err := s.newAdoptGraph(ctx, conn)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	g.used[b.Stack] = true
	out := &adoptPlan{Stack: b.Stack, BU: bu, Env: env.Name, Via: b.Via,
		Gate: "Dependencies are adopted first, each into its own stack, and referenced (stack/<stack>/<resource>.<output>). Every stack's first plan imports its resource and must show no changes (zero-diff gate); a stack plans once the stacks it references have applied."}
	used := map[string]bool{}
	for _, id := range b.Resources {
		it, err := s.store.GetInventoryItem(ctx, conn.ID, id)
		if err != nil {
			out.Skipped = append(out.Skipped, id+": not in the inventory; scan the connection first")
			continue
		}
		if it.Stack != "" {
			out.Skipped = append(out.Skipped, it.Name+": already managed by stack "+it.Stack)
			continue
		}
		if m := g.cat.Kind(it.Kind); m == nil || m.Adopt == nil {
			out.Skipped = append(out.Skipped, it.Name+": no kind adopts "+it.Type+" yet")
			continue
		}
		if _, err := g.add(ctx, it, b.Stack, instanceName(it.Name, used), true); err != nil {
			out.Problems = append(out.Problems, err.Error())
		}
	}
	out.Problems = append(out.Problems, g.problems...)
	out.Stacks = g.stacks()
	if len(out.Stacks) == 0 {
		writeJSON(w, 422, map[string]any{"error": "nothing to adopt", "details": append(out.Problems, out.Skipped...)})
		return
	}
	s.validateAdoption(ctx, out, bu, env)
	root := out.Stacks[len(out.Stacks)-1]
	for _, st := range out.Stacks {
		if st.Name == b.Stack {
			root = st
		}
	}
	out.Spec = root.Spec
	for i, pr := range out.Problems {
		if strings.Contains(pr, "is required (set it in the contract") {
			hint := "(the live resource has no value for it)"
			if strings.Contains(pr, `input "name"`) {
				hint = "(the live resource has no Name tag: add one in AWS and scan the connection again)"
			}
			out.Problems[i] = strings.Replace(pr, "(set it in the contract or as a tenant default)", hint, 1)
		}
	}
	if b.DryRun { // a preview always shows its stacks, with any problems
		writeJSON(w, 200, out)
		return
	}
	if len(out.Problems) > 0 {
		writeJSON(w, 422, map[string]any{"error": "the adoption has problems: " + strings.Join(out.Problems, "; "), "adopt": out})
		return
	}
	mark := func() {
		for _, st := range out.Stacks {
			for _, n := range st.Resources {
				s.store.MarkAdopted(ctx, conn.ID, n.ID, st.Name, n.Resource, p.Subject)
			}
		}
	}
	names := make([]string, 0, len(out.Stacks))
	for _, st := range out.Stacks {
		names = append(names, st.Name)
	}
	if b.Via == "git" {
		stacks := make([]prStack, 0, len(out.Stacks))
		for _, st := range out.Stacks {
			stacks = append(stacks, prStack{Name: st.Name, BU: bu, Env: env, Spec: st.Spec})
		}
		note := fmt.Sprintf("Adopts existing resources from connection `%s`: %d stack(s), dependencies first. Each first plan imports its resources and must show no changes (zero-diff gate).\n\n", conn.Name, len(stacks))
		pr, code, err := s.openStacksPR(ctx, p, stacks, "Adopt existing resources: "+b.Stack, note, nil)
		if err != nil {
			writeErr(w, code, err.Error())
			return
		}
		mark()
		s.audit(ctx, p.Actor(), "inventory.adopt", "stack/"+b.Stack, bu, map[string]any{"connection": conn.Name, "stacks": names, "via": "git", "pr": pr["pr_number"]})
		writeJSON(w, 201, map[string]any{"adopt": out, "pull_request": pr})
		return
	}
	// Console: create the stacks, dependencies first; each plans now or,
	// when it references stacks not applied yet, once they are.
	var rootStack *store.Stack
	var rootRun *store.Run
	for _, st := range out.Stacks {
		created, err := s.store.CreateStack(ctx, st.Name, bu, env.Entity, env.ID, &conn.ID, st.Spec, p.Subject)
		if err != nil {
			s.writeStoreErr(w, err, "a stack named "+st.Name+" exists")
			return
		}
		if st.Name == b.Stack {
			rootStack = created
		}
	}
	mark()
	s.audit(ctx, p.Actor(), "inventory.adopt", "stack/"+b.Stack, bu, map[string]any{"connection": conn.Name, "stacks": names, "via": "stack"})
	for _, st := range out.Stacks {
		created, err := s.store.GetStack(ctx, st.Name)
		if err != nil {
			continue
		}
		s.startStackPlan(ctx, created, p.Subject, "adopt")
		if created.Name == b.Stack {
			if runs, err := s.store.LatestRuns(ctx, created.ID, 1); err == nil && len(runs) > 0 {
				rootRun = runs[0]
			}
		}
	}
	writeJSON(w, 201, map[string]any{"adopt": out, "stack": rootStack, "run": rootRun})
}
