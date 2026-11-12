package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- bulk import from the inventory ----
//
// Adopt a whole account (project, subscription), a whole service of it (EC2,
// S3, …) or a hand-picked selection in one go. The resources are grouped
// into stacks — one per service, one per resource, or one for all — and
// their dependencies come along, each adopted once. Every stack's first plan
// imports its resources and must pass the zero-diff gate, exactly like a
// single adoption. Through the console the stacks are created and planned;
// through Git they are proposed as one pull request, or one per group.

const (
	maxBulkResources = 300
	maxPerStack      = 50
)

var prefixRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

type bulkBody struct {
	Connection  string   `json:"connection"`
	Scope       string   `json:"scope"`     // account | service | selection
	Service     string   `json:"service"`   // for scope service, e.g. "ec2", "s3"
	Resources   []string `json:"resources"` // for scope selection: inventory resource IDs
	BU          string   `json:"bu"`
	Environment string   `json:"environment"`
	Grouping    string   `json:"grouping"` // service (default) | resource | single
	Prefix      string   `json:"prefix"`   // stack names: <prefix>-<service>, <prefix>
	Via         string   `json:"via"`      // stack (console) | git
	PRs         string   `json:"prs"`      // single (default) | per_group — with via git
	DryRun      bool     `json:"dry_run"`
}

// bulkGroup is one group of the import: its stack and what goes in it.
type bulkGroup struct {
	Stack     string   `json:"stack"`
	Service   string   `json:"service,omitempty"`
	Resources []string `json:"resources"` // names
	Stacks    []string `json:"stacks"`    // its stack and the dependency stacks it brings, dependencies first
}

type bulkPlan struct {
	*adoptPlan
	Scope    string                     `json:"scope"`
	Groups   []bulkGroup                `json:"groups"`
	Counts   map[string]int             `json:"counts"` // candidates, adopting, stacks, skipped
	PRs      []map[string]any           `json:"pull_requests,omitempty"`
	Services map[string]int             `json:"services"` // adoptable resources per service in scope
	Created  []string                   `json:"created,omitempty"`
	Runs     map[string]*store.RunBrief `json:"runs,omitempty"`
}

func (s *Server) bulkImport(w http.ResponseWriter, r *http.Request) {
	var b bulkBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	ctx := r.Context()
	if b.Via == "" {
		b.Via = "stack"
	}
	if b.Grouping == "" {
		b.Grouping = "service"
	}
	if b.PRs == "" {
		b.PRs = "single"
	}
	var probs []string
	switch {
	case b.Scope != "account" && b.Scope != "service" && b.Scope != "selection":
		probs = append(probs, `scope must be "account", "service" or "selection"`)
	case b.Scope == "service" && b.Service == "":
		probs = append(probs, "name the service to import (e.g. ec2, s3)")
	case b.Scope == "selection" && (len(b.Resources) == 0 || len(b.Resources) > maxBulkResources):
		probs = append(probs, fmt.Sprintf("select 1 to %d resources", maxBulkResources))
	}
	if b.Grouping != "service" && b.Grouping != "resource" && b.Grouping != "single" {
		probs = append(probs, `grouping must be "service", "resource" or "single"`)
	}
	if b.Via != "stack" && b.Via != "git" {
		probs = append(probs, `via must be "stack" or "git"`)
	}
	if b.PRs != "single" && b.PRs != "per_group" {
		probs = append(probs, `prs must be "single" or "per_group"`)
	}
	if b.Prefix == "" {
		b.Prefix = "imported"
	}
	if !prefixRe.MatchString(b.Prefix) {
		probs = append(probs, "prefix must be lowercase letters, digits and dashes (up to 31)")
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid bulk import", probs...)
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
		writeErr(w, http.StatusForbidden, "importing resources needs the developer or admin role in "+bu)
		return
	}
	env, ok := env0.ForConnection(conn.ID)
	if !ok {
		writeErr(w, 422, "environment "+env0.Name+" does not use connection "+conn.Name+": import into an environment of the same account, project or subscription")
		return
	}

	// The candidates: what the scope covers and is not managed yet.
	out := &bulkPlan{adoptPlan: &adoptPlan{Stack: b.Prefix, BU: bu, Env: env.Name, Via: b.Via,
		Gate: "Every stack's first plan imports its resources and must show no changes (zero-diff gate). Dependencies are adopted first; a stack plans once the stacks it references have applied."},
		Scope: b.Scope, Counts: map[string]int{}, Services: map[string]int{}}
	var items []*store.InventoryItem
	if b.Scope == "selection" {
		for _, id := range b.Resources {
			it, err := s.store.GetInventoryItem(ctx, conn.ID, id)
			if err != nil {
				out.Skipped = append(out.Skipped, id+": not in the inventory; scan the connection first")
				continue
			}
			items = append(items, it)
		}
	} else {
		f := store.InventoryFilter{Connection: conn.ID, Limit: 500}
		if b.Scope == "service" {
			f.Service = b.Service
		}
		for {
			page, total, err := s.store.ListInventory(ctx, f)
			if err != nil {
				s.writeStoreErr(w, err, "")
				return
			}
			items = append(items, page...)
			f.Offset += len(page)
			if len(page) == 0 || f.Offset >= total || len(items) > 5000 {
				break
			}
		}
	}
	g, err := s.newAdoptGraph(ctx, conn)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	g.max = maxBulkResources * 2 // the selection and the dependencies it brings
	var chosen []*store.InventoryItem
	notAdoptable := map[string]int{}
	for _, it := range items {
		switch {
		case it.Stack != "":
			if b.Scope == "selection" {
				out.Skipped = append(out.Skipped, it.Name+": already managed by stack "+it.Stack)
			}
			out.Counts["managed"]++
		case g.cat.Kind(it.Kind) == nil || g.cat.Kind(it.Kind).Adopt == nil:
			notAdoptable[it.Type]++
		default:
			chosen = append(chosen, it)
			out.Services[it.Service]++
		}
	}
	for t, n := range notAdoptable {
		out.Skipped = append(out.Skipped, fmt.Sprintf("%d × %s: no kind adopts it yet", n, t))
	}
	sort.Strings(out.Skipped)
	out.Counts["candidates"] = len(items)
	if len(chosen) > maxBulkResources {
		writeErr(w, 422, fmt.Sprintf("the scope has %d adoptable resources; import at most %d at a time (choose a service or a selection)", len(chosen), maxBulkResources))
		return
	}
	if len(chosen) == 0 {
		writeJSON(w, 422, map[string]any{"error": "nothing to import in this scope", "details": out.Skipped, "import": out})
		return
	}

	// Group them: a stack per service, per resource, or one for all (each
	// stack at most maxPerStack resources).
	sort.Slice(chosen, func(i, j int) bool {
		if chosen[i].Service != chosen[j].Service {
			return chosen[i].Service < chosen[j].Service
		}
		return chosen[i].Name < chosen[j].Name
	})
	groupOf := map[string]string{} // resource ID -> stack
	var groups []bulkGroup
	taken := func(name string) bool {
		_, err := s.store.GetStack(ctx, name)
		return err == nil || g.used[name]
	}
	freeName := func(base string) string {
		base = strings.Trim(nonStackRe.ReplaceAllString(base, "-"), "-")
		if len(base) > 60 {
			base = strings.TrimRight(base[:60], "-")
		}
		n := base
		for i := 2; taken(n); i++ {
			n = fmt.Sprintf("%s-%d", base, i)
		}
		g.used[n] = true
		return n
	}
	switch b.Grouping {
	case "resource":
		for _, it := range chosen {
			st := freeName(b.Prefix + "-" + strings.ToLower(it.Service) + "-" + strings.ToLower(it.Name))
			groupOf[it.ResourceID] = st
			groups = append(groups, bulkGroup{Stack: st, Service: it.Service})
		}
	default:
		key := func(it *store.InventoryItem) string {
			if b.Grouping == "single" {
				return ""
			}
			return strings.ToLower(it.Service)
		}
		count := map[string]int{}
		current := map[string]string{}
		for _, it := range chosen {
			k := key(it)
			if current[k] == "" || count[current[k]] >= maxPerStack {
				base := b.Prefix
				if k != "" {
					base += "-" + k
				}
				current[k] = freeName(base)
				groups = append(groups, bulkGroup{Stack: current[k], Service: it.Service})
			}
			groupOf[it.ResourceID] = current[k]
			count[current[k]]++
		}
	}
	for _, it := range chosen {
		g.prefer[it.ResourceID] = groupOf[it.ResourceID]
	}
	for _, it := range chosen {
		if _, err := g.add(ctx, it, groupOf[it.ResourceID], "", true); err != nil {
			out.Problems = append(out.Problems, err.Error())
		}
	}
	out.Problems = append(out.Problems, g.problems...)
	out.Stacks = g.stacks()
	s.validateAdoption(ctx, out.adoptPlan, bu, env)
	friendlyAdoptProblems(out.adoptPlan)

	// Each group's stacks: its own and the dependency stacks first needed by it.
	byName := map[string]*adoptStack{}
	for _, st := range out.Stacks {
		byName[st.Name] = st
	}
	claimed := map[string]bool{}
	var collect func(name string, into *[]string)
	collect = func(name string, into *[]string) {
		st := byName[name]
		if st == nil || claimed[name] {
			return
		}
		claimed[name] = true
		for _, d := range st.DependsOn {
			collect(d, into)
		}
		*into = append(*into, name)
	}
	for i := range groups {
		collect(groups[i].Stack, &groups[i].Stacks)
		if st := byName[groups[i].Stack]; st != nil {
			for _, n := range st.Resources {
				groups[i].Resources = append(groups[i].Resources, n.Name)
			}
		}
	}
	// Groups whose resources all went elsewhere (as dependencies) are dropped.
	kept := groups[:0]
	for _, gr := range groups {
		if len(gr.Stacks) > 0 {
			kept = append(kept, gr)
		}
	}
	out.Groups = kept
	adopting := 0
	for _, st := range out.Stacks {
		adopting += len(st.Resources)
	}
	out.Counts["adopting"], out.Counts["stacks"], out.Counts["skipped"] = adopting, len(out.Stacks), len(out.Skipped)
	if b.Via == "git" {
		out.Counts["pull_requests"] = 1
		if b.PRs == "per_group" {
			out.Counts["pull_requests"] = len(out.Groups)
		}
	}
	if b.DryRun {
		writeJSON(w, 200, out)
		return
	}
	if len(out.Problems) > 0 {
		writeJSON(w, 422, map[string]any{"error": "the import has problems: " + strings.Join(firstN(out.Problems, 5), "; "), "import": out})
		return
	}
	mark := func(names []string) {
		for _, n := range names {
			if st := byName[n]; st != nil {
				for _, node := range st.Resources {
					s.store.MarkAdopted(ctx, conn.ID, node.ID, st.Name, node.Resource, p.Subject)
				}
			}
		}
	}
	scopeText := map[string]string{"account": "the whole of " + conn.Name, "service": "service " + b.Service + " of " + conn.Name, "selection": fmt.Sprintf("%d selected resource(s) of %s", len(b.Resources), conn.Name)}[b.Scope]
	if b.Via == "git" {
		batches := [][]string{}
		if b.PRs == "per_group" {
			for _, gr := range out.Groups {
				batches = append(batches, gr.Stacks)
			}
		} else {
			all := []string{}
			for _, st := range out.Stacks { // already dependencies first
				all = append(all, st.Name)
			}
			batches = append(batches, all)
		}
		for i, names := range batches {
			stacks := make([]prStack, 0, len(names))
			for _, n := range names {
				stacks = append(stacks, prStack{Name: n, BU: bu, Env: env, Spec: byName[n].Spec})
			}
			title := fmt.Sprintf("Import %s", scopeText)
			if len(batches) > 1 {
				title = fmt.Sprintf("Import %s (%d of %d: %s)", scopeText, i+1, len(batches), names[len(names)-1])
			}
			note := fmt.Sprintf("Bulk import of %s: %d stack(s) in this pull request, dependencies first. Each first plan imports its resources and must show no changes (zero-diff gate).\n\n", scopeText, len(stacks))
			if len(batches) > 1 {
				note += "Stacks that reference stacks of another pull request of this import plan once those are applied.\n\n"
			}
			pr, code, err := s.openStacksPR(ctx, p, stacks, title, note, nil)
			if err != nil {
				out.Problems = append(out.Problems, err.Error())
				if len(out.PRs) == 0 {
					writeErr(w, code, err.Error())
					return
				}
				break
			}
			mark(names)
			out.PRs = append(out.PRs, pr)
		}
		s.audit(ctx, p.Actor(), "inventory.bulk_import", "connection/"+conn.Name, bu, map[string]any{"scope": b.Scope, "service": b.Service,
			"grouping": b.Grouping, "via": "git", "stacks": out.Counts["stacks"], "resources": adopting, "pull_requests": len(out.PRs)})
		writeJSON(w, 201, out)
		return
	}
	// Console: create every stack, dependencies first, and plan them.
	for _, st := range out.Stacks {
		if _, err := s.store.CreateStack(ctx, st.Name, bu, env.Entity, env.ID, &conn.ID, st.Spec, p.Subject); err != nil {
			out.Problems = append(out.Problems, st.Name+": "+err.Error())
			continue
		}
		out.Created = append(out.Created, st.Name)
	}
	mark(out.Created)
	s.audit(ctx, p.Actor(), "inventory.bulk_import", "connection/"+conn.Name, bu, map[string]any{"scope": b.Scope, "service": b.Service,
		"grouping": b.Grouping, "via": "stack", "stacks": out.Created, "resources": adopting})
	out.Runs = map[string]*store.RunBrief{}
	for _, n := range out.Created {
		if created, err := s.store.GetStack(ctx, n); err == nil {
			s.startStackPlan(ctx, created, p.Subject, "bulk import")
			if runs, err := s.store.LatestRuns(ctx, created.ID, 1); err == nil && len(runs) > 0 {
				out.Runs[n] = &store.RunBrief{ID: runs[0].ID, Status: runs[0].Status, Operation: runs[0].Operation, CreatedAt: runs[0].CreatedAt}
			}
		}
	}
	writeJSON(w, 201, out)
}

// friendlyAdoptProblems explains "is required" problems of adopted resources.
func friendlyAdoptProblems(out *adoptPlan) {
	for i, pr := range out.Problems {
		if strings.Contains(pr, "is required (set it in the contract") {
			hint := "(the live resource has no value for it)"
			if strings.Contains(pr, `input "name"`) {
				hint = "(the live resource has no Name tag: add one in the cloud and scan the connection again)"
			}
			out.Problems[i] = strings.Replace(pr, "(set it in the contract or as a tenant default)", hint, 1)
		}
	}
}

var _ = spec.StackNameRe
var _ context.Context
