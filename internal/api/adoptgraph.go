package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/catalog"
	"github.com/itsPavanFeed/srustiops-backend/internal/cloudapi"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Dependency-aware adoption (backporting). Adopting a resource reads its live
// properties and follows the kind's dependency rules: a dependency already
// managed by SrustiOps is referenced (stack/<stack>/<resource>.<output>); one
// whose kind can be adopted is adopted first, into its own stack; anything
// else keeps its literal ID, with a note. The result is a DAG of stacks,
// dependencies first; each stack's first plan imports its resource and must
// pass the zero-diff gate, and dependents wait until their dependencies
// applied the outputs they reference.

const maxAdoptNodes = 25

// adoptNode is one stack of an adoption.
type adoptNode struct {
	Stack     string          `json:"stack"`
	Resource  string          `json:"resource"` // module instance
	Kind      string          `json:"kind"`
	ID        string          `json:"resource_id"`
	Name      string          `json:"name"`
	Selected  bool            `json:"selected"`             // chosen by the person (else a dependency)
	DependsOn []string        `json:"depends_on,omitempty"` // stacks it references
	Refs      []string        `json:"references,omitempty"` // human-readable wiring
	Notes     []string        `json:"notes,omitempty"`
	Spec      json.RawMessage `json:"spec,omitempty"`

	item    *store.InventoryItem
	mod     spec.ModuleRef
	imports []spec.Import
}

type adoptGraph struct {
	s        *Server
	conn     *store.Connection
	cl       *spec.Cloud
	client   *cloudapi.Client
	cat      *catalog.Catalog
	byID     map[string]*adoptNode // resource ID -> node
	order    []*adoptNode          // dependencies first
	visiting map[string]bool
	used     map[string]bool // stack names taken in this adoption
	problems []string
	// Bulk imports: the stack each selected resource goes to (also when it is
	// reached first as another's dependency), the most resources one
	// adoption may take, and the module names taken in each stack.
	prefer  map[string]string
	max     int
	modules map[string]map[string]bool
}

func (s *Server) newAdoptGraph(ctx context.Context, conn *store.Connection) (*adoptGraph, error) {
	cl, err := spec.DecodeCloud(conn.Cloud)
	if err != nil {
		return nil, err
	}
	g := &adoptGraph{s: s, conn: conn, cl: cl, cat: s.plat().cat, byID: map[string]*adoptNode{}, visiting: map[string]bool{}, used: map[string]bool{},
		prefer: map[string]string{}, max: maxAdoptNodes, modules: map[string]map[string]bool{}}
	if g.client, err = s.discoveryClient(ctx, conn.ID, cl); err != nil {
		return nil, err
	}
	return g, nil
}

// properties reads a live resource's properties, if its kind says how.
func (g *adoptGraph) properties(ctx context.Context, m *catalog.Module, it *store.InventoryItem) (map[string]any, error) {
	ps, ok := m.Adopt.Properties[g.cl.Provider]
	if !ok {
		return nil, nil
	}
	id := fillTemplate(ps.ID, it)
	switch g.cl.Provider {
	case "aws":
		role := g.cl.AWS.PlanRoleARN
		if role == "" {
			role = g.cl.AWS.RoleARN
		}
		props, err := g.client.AWSResource(ctx, role, regionOf(it, g.cl), ps.Type, id)
		if err != nil || ps.Related == nil {
			return props, err
		}
		if ps.Related.Type == "AWS::EC2::VPCGatewayAttachment" && ps.Related.Key == "InternetGatewayId" {
			// EC2 reports an internet gateway's attachment directly.
			vpc, err := g.client.AWSInternetGatewayVPC(ctx, role, regionOf(it, g.cl), id)
			if err != nil {
				return nil, err
			}
			if vpc != "" {
				props[ps.Related.As] = map[string]any{"InternetGatewayId": id, "VpcId": vpc}
			}
			return props, nil
		}
		rel, err := g.client.AWSListResources(ctx, role, regionOf(it, g.cl), ps.Related.Type)
		if err != nil {
			return nil, err
		}
		for _, r := range rel {
			if fmt.Sprint(r[ps.Related.Key]) == id {
				props[ps.Related.As] = r
				break
			}
		}
		return props, nil
	}
	return nil, fmt.Errorf("reading %s properties on %s is not supported yet", m.Kind, g.cl.Provider)
}

func regionOf(it *store.InventoryItem, cl *spec.Cloud) string {
	if it.Region != "" && it.Region != "global" {
		return it.Region
	}
	if cl.AWS != nil {
		return cl.AWS.Region
	}
	return ""
}

// stackName picks a free stack name for a dependency.
func (g *adoptGraph) stackName(ctx context.Context, kind, name string) string {
	base := strings.Trim(nonStackRe.ReplaceAllString(strings.ToLower(kind+"-"+name), "-"), "-")
	if len(base) > 50 {
		base = strings.TrimRight(base[:50], "-")
	}
	if base == "" || base[0] < 'a' || base[0] > 'z' {
		base = "r-" + base
	}
	n := base
	for i := 2; ; i++ {
		if _, err := g.s.store.GetStack(ctx, n); err != nil && !g.used[n] {
			g.used[n] = true
			return n
		}
		n = fmt.Sprintf("%s-%d", base, i)
	}
}

// add builds the node for one inventory item (and, first, its adoptable
// dependencies). stack and module name it when chosen by the person.
func (g *adoptGraph) add(ctx context.Context, it *store.InventoryItem, stack, module string, selected bool) (*adoptNode, error) {
	if n := g.byID[it.ResourceID]; n != nil {
		return n, nil
	}
	if len(g.byID) >= g.max {
		return nil, fmt.Errorf("adoption would take more than %d resources; adopt part of it first", g.max)
	}
	m := g.cat.Kind(it.Kind)
	if m == nil || m.Adopt == nil {
		return nil, fmt.Errorf("%s: no kind adopts %s yet", it.Name, it.Type)
	}
	g.visiting[it.ResourceID] = true
	defer delete(g.visiting, it.ResourceID)
	props, err := g.properties(ctx, m, it)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", it.Name, err)
	}
	inputs, err := adoptInputsWith(m, it, props)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", it.Name, err)
	}
	if stack == "" {
		if ps := g.prefer[it.ResourceID]; ps != "" {
			stack = ps
		} else {
			stack = g.stackName(ctx, m.Kind, it.Name)
		}
	}
	if g.modules[stack] == nil {
		g.modules[stack] = map[string]bool{}
	}
	if module == "" {
		module = instanceName(it.Name, g.modules[stack])
	} else {
		g.modules[stack][module] = true
	}
	n := &adoptNode{Stack: stack, Resource: module, Kind: m.Kind, ID: it.ResourceID, Name: it.Name, Selected: selected, item: it,
		mod: spec.ModuleRef{Name: module, Kind: m.Kind, Inputs: inputs}}
	// Adoption-time baseline gaps, from the live properties.
	if len(m.Adopt.Gaps) > 0 {
		gv, ok := fillProps(m.Adopt.Gaps, props)
		if gm, isMap := gv.(map[string]any); ok && isMap {
			n.mod.BaselineGaps = map[string]json.RawMessage{}
			for k, v := range gm {
				n.mod.BaselineGaps[k], _ = json.Marshal(v)
			}
		}
	}
	for _, im := range m.Adopt.Imports {
		if im.IfProp != "" {
			if v, _ := livePath(props, im.IfProp); v == nil {
				continue // the live resource has no such part; the module creates none
			}
		}
		n.imports = append(n.imports, spec.Import{To: "module." + module + "." + fillTemplate(im.To, it), ID: fillTemplate(im.ID, it)})
	}
	for _, dep := range m.Adopt.Dependencies {
		g.wire(ctx, n, dep, props)
	}
	g.byID[it.ResourceID] = n
	g.order = append(g.order, n) // post-order: dependencies were appended first
	return n, nil
}

// wire fills one dependency of a node: a reference to the stack managing the
// referenced resource, adopting it first when needed, or the literal ID.
func (g *adoptGraph) wire(ctx context.Context, n *adoptNode, dep catalog.AdoptDependency, props map[string]any) {
	raw, ok := livePath(props, dep.Path)
	if !ok || raw == nil {
		return
	}
	vals, isList := raw.([]any)
	if !isList {
		vals = []any{raw}
	}
	var wired []any
	for _, v := range vals {
		id, _ := v.(string)
		if id == "" {
			wired = append(wired, v)
			continue
		}
		ref, note := g.reference(ctx, n, dep, id)
		if note != "" {
			n.Notes = append(n.Notes, note)
		}
		if ref == "" {
			wired = append(wired, id)
			continue
		}
		wired = append(wired, map[string]any{"$ref": ref})
		n.Refs = append(n.Refs, fmt.Sprintf("%s ← %s", dependencyTarget(dep), ref))
	}
	var value any = wired
	if !isList {
		value = wired[0]
	}
	if dep.Input != "" {
		n.mod.Inputs[dep.Input], _ = json.Marshal(value)
		return
	}
	setGapPath(&n.mod, dep.Gap, value)
}

func dependencyTarget(dep catalog.AdoptDependency) string {
	if dep.Input != "" {
		return dep.Input
	}
	return "baselineGaps." + dep.Gap
}

// reference returns stack/<stack>/<resource>.<output> for the resource id
// names, adopting it first when it is not managed yet but adoptable.
func (g *adoptGraph) reference(ctx context.Context, n *adoptNode, dep catalog.AdoptDependency, id string) (string, string) {
	it, err := g.s.store.FindInventoryItem(ctx, g.conn.ID, id)
	if err != nil {
		return "", fmt.Sprintf("%s %s is not in the inventory (scan the connection); kept as the literal ID", dep.Kind, id)
	}
	if g.visiting[it.ResourceID] {
		return "", fmt.Sprintf("%s %s depends back on this resource (a cycle); kept as the literal ID", dep.Kind, id)
	}
	if it.Stack != "" {
		if it.AdoptedAs == "" {
			return "", fmt.Sprintf("%s %s is managed by stack %s, adopted before dependencies were tracked; kept as the literal ID", dep.Kind, id, it.Stack)
		}
		g.addDep(n, it.Stack)
		return "stack/" + it.Stack + "/" + it.AdoptedAs + "." + dep.Output, ""
	}
	if it.Kind == "" {
		return "", fmt.Sprintf("%s %s is not managed by SrustiOps and %s cannot be adopted yet; kept as the literal ID", dep.Kind, id, dep.Kind)
	}
	if it.Kind != dep.Kind {
		return "", fmt.Sprintf("%s %s is a %s, not a %s; kept as the literal ID", it.Type, id, it.Kind, dep.Kind)
	}
	if m := g.cat.Kind(it.Kind); m == nil || m.Adopt == nil {
		return "", fmt.Sprintf("%s %s is not managed by SrustiOps and %s cannot be adopted yet; kept as the literal ID", dep.Kind, id, dep.Kind)
	}
	d, err := g.add(ctx, it, "", "", false)
	if err != nil {
		g.problems = append(g.problems, err.Error())
		return "", ""
	}
	g.addDep(n, d.Stack)
	return "stack/" + d.Stack + "/" + d.Resource + "." + dep.Output, ""
}

func (g *adoptGraph) addDep(n *adoptNode, stack string) {
	for _, d := range n.DependsOn {
		if d == stack {
			return
		}
	}
	n.DependsOn = append(n.DependsOn, stack)
	sort.Strings(n.DependsOn)
}

// setGapPath sets a value at a dotted path inside a module's baseline gaps.
func setGapPath(m *spec.ModuleRef, path string, value any) {
	parts := strings.Split(path, ".")
	if m.BaselineGaps == nil {
		m.BaselineGaps = map[string]json.RawMessage{}
	}
	var root map[string]any
	if len(parts) == 1 {
		m.BaselineGaps[parts[0]], _ = json.Marshal(value)
		return
	}
	json.Unmarshal(m.BaselineGaps[parts[0]], &root)
	if root == nil {
		root = map[string]any{}
	}
	cur := root
	for _, p := range parts[1 : len(parts)-1] {
		next, _ := cur[p].(map[string]any)
		if next == nil {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
	m.BaselineGaps[parts[0]], _ = json.Marshal(root)
}

// adoptStack is one stack an adoption creates: the resources chosen go
// together into the stack the person named; each dependency gets its own.
type adoptStack struct {
	Name      string          `json:"name"`
	Selected  bool            `json:"selected"`
	DependsOn []string        `json:"depends_on,omitempty"`
	Resources []*adoptNode    `json:"resources"`
	Spec      json.RawMessage `json:"spec"`
	Problems  []string        `json:"problems,omitempty"`
	Waits     []string        `json:"waits_on,omitempty"` // dependencies not applied yet: it plans after them
}

// stacks groups the nodes into stacks, dependencies first.
func (g *adoptGraph) stacks() []*adoptStack {
	byName := map[string]*adoptStack{}
	var names []string
	for _, n := range g.order {
		st := byName[n.Stack]
		if st == nil {
			st = &adoptStack{Name: n.Stack}
			byName[n.Stack] = st
			names = append(names, n.Stack)
		}
		st.Selected = st.Selected || n.Selected
		st.Resources = append(st.Resources, n)
		for _, d := range n.DependsOn {
			if d != st.Name && !contains(st.DependsOn, d) {
				st.DependsOn = append(st.DependsOn, d)
			}
		}
	}
	var out []*adoptStack
	done := map[string]bool{}
	var visit func(name string)
	visit = func(name string) {
		st := byName[name]
		if st == nil || done[name] {
			return
		}
		done[name] = true
		for _, d := range st.DependsOn {
			visit(d)
		}
		out = append(out, st)
	}
	for _, n := range names {
		visit(n)
	}
	for _, st := range out {
		sort.Strings(st.DependsOn)
		var sp spec.Stack
		for _, n := range st.Resources {
			sp.Modules = append(sp.Modules, n.mod)
			sp.Imports = append(sp.Imports, n.imports...)
		}
		sort.SliceStable(sp.Modules, func(i, j int) bool { return sp.Modules[i].Name < sp.Modules[j].Name })
		st.Spec, _ = json.Marshal(sp)
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// fillProps replaces {{prop:path}} (the live value) and {{propjson:path}}
// (the value as JSON text) in a template; values that are missing are left
// out. Placeholders inside longer strings are replaced by the value's text.
func fillProps(v any, props map[string]any) (any, bool) {
	switch t := v.(type) {
	case string:
		if m := propMapRe.FindStringSubmatch(t); m != nil {
			list, _ := livePath(props, m[1])
			items, _ := list.([]any)
			if len(items) == 0 {
				return nil, true
			}
			var out []any
			for _, it := range items {
				src, _ := it.(map[string]any)
				o := map[string]any{}
				for _, pair := range strings.Split(m[2], ",") {
					dst, from, _ := strings.Cut(pair, "=")
					if v, ok := src[from]; ok {
						o[dst] = v
					}
				}
				out = append(out, o)
			}
			return out, true
		}
		if m := propFindRe.FindStringSubmatch(t); m != nil {
			list, _ := livePath(props, m[1])
			items, _ := list.([]any)
			for _, it := range items {
				src, _ := it.(map[string]any)
				if fmt.Sprint(src[m[2]]) == m[3] {
					v, _ := livePath(src, m[4])
					return v, true
				}
			}
			return nil, true
		}
		if m := propTmplRe.FindStringSubmatch(t); m != nil && m[0] == t {
			val, _ := livePath(props, m[2])
			if val == nil {
				return nil, true
			}
			if m[1] == "propjson" {
				b, _ := json.Marshal(val)
				return string(b), true
			}
			return val, true
		}
		return propTmplRe.ReplaceAllStringFunc(t, func(p string) string {
			m := propTmplRe.FindStringSubmatch(p)
			val, _ := livePath(props, m[2])
			if val == nil {
				return ""
			}
			if s, ok := val.(string); ok && m[1] == "prop" {
				return s
			}
			b, _ := json.Marshal(val)
			return string(b)
		}), true
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			y, _ := fillProps(x, props)
			if y != nil {
				out[k] = y
			}
		}
		if len(out) == 0 {
			return nil, true
		}
		return out, true
	case []any:
		var out []any
		for _, x := range t {
			if y, _ := fillProps(x, props); y != nil {
				out = append(out, y)
			}
		}
		return out, true
	}
	return v, true
}
