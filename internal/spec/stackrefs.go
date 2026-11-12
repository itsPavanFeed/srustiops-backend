package spec

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// References to another stack's outputs: {"$ref": "stack/<stack>/<module>.<output>"}.
// They may be a whole input value, a list item, or part of a baseline gap.
// Before a stack is validated and generated, each is replaced by the other
// stack's applied output value, so the usual input checks still apply.

var StackRefRe = regexp.MustCompile(`^stack/([a-z][a-z0-9-]{1,62})/([a-z][a-z0-9_]{0,40})\.([A-Za-z_][A-Za-z0-9_-]{0,63})$`)

// StackRef names one output of another stack.
type StackRef struct {
	Stack, Module, Output string
}

func (r StackRef) Key() string    { return r.Module + "." + r.Output }
func (r StackRef) String() string { return "stack/" + r.Stack + "/" + r.Key() }

func stackRefOf(v any) (StackRef, bool) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return StackRef{}, false
	}
	s, _ := m["$ref"].(string)
	p := StackRefRe.FindStringSubmatch(s)
	if p == nil {
		return StackRef{}, false
	}
	return StackRef{Stack: p[1], Module: p[2], Output: p[3]}, true
}

// walkStackRefs calls fn for every reference to another stack in the
// modules' inputs and baseline gaps; fn returns the replacement (or nil to
// keep it).
func walkStackRefs(raw []byte, fn func(StackRef) any) ([]byte, error) {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	var walk func(x any) any
	walk = func(x any) any {
		if r, ok := stackRefOf(x); ok {
			if rep := fn(r); rep != nil {
				return rep
			}
			return x
		}
		switch t := x.(type) {
		case map[string]any:
			for k, y := range t {
				t[k] = walk(y)
			}
		case []any:
			for i, y := range t {
				t[i] = walk(y)
			}
		}
		return x
	}
	mods, _ := v["modules"].([]any)
	for _, m := range mods {
		mm, _ := m.(map[string]any)
		for _, key := range []string{"inputs", "baseline_gaps"} {
			if x, ok := mm[key]; ok {
				mm[key] = walk(x)
			}
		}
	}
	return json.Marshal(v)
}

// StackRefs lists the distinct references to other stacks in a spec.
func StackRefs(raw []byte) ([]StackRef, error) {
	seen := map[string]bool{}
	var out []StackRef
	_, err := walkStackRefs(raw, func(r StackRef) any {
		if !seen[r.String()] {
			seen[r.String()] = true
			out = append(out, r)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, err
}

// DependsOn lists the stacks a spec references.
func DependsOn(raw []byte) []string {
	refs, _ := StackRefs(raw)
	seen := map[string]bool{}
	var out []string
	for _, r := range refs {
		if !seen[r.Stack] {
			seen[r.Stack] = true
			out = append(out, r.Stack)
		}
	}
	return out
}

// ResolveStackRefs replaces every reference to another stack with the value
// lookup returns for it; references lookup cannot resolve are reported.
func ResolveStackRefs(raw []byte, lookup func(StackRef) (json.RawMessage, error)) ([]byte, []error) {
	var errs []error
	out, err := walkStackRefs(raw, func(r StackRef) any {
		val, err := lookup(r)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r, err))
			return nil
		}
		var x any
		if json.Unmarshal(val, &x) != nil {
			errs = append(errs, fmt.Errorf("%s: the stored output is not JSON", r))
			return nil
		}
		return x
	})
	if err != nil {
		return nil, []error{err}
	}
	return out, errs
}

// ExportPrefix names the root outputs that export resource outputs:
// srustiops__<module>__<output>.
const ExportPrefix = "srustiops__"

// ExportKey turns an exported root output name back into module.output.
func ExportKey(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, ExportPrefix)
	if !ok {
		return "", false
	}
	i := strings.LastIndex(rest, "__") // outputs never contain "__"; module names might
	if i <= 0 || i+2 >= len(rest) {
		return "", false
	}
	return rest[:i] + "." + rest[i+2:], true
}

// RestoreStackRefs puts a spec's references to other stacks back into its
// normalized (resolved) form: every input or baseline gap of the original
// that contains such a reference replaces the resolved value.
func RestoreStackRefs(normalized, original []byte) []byte {
	if refs, _ := StackRefs(original); len(refs) == 0 {
		return normalized
	}
	var orig, norm map[string]any
	if json.Unmarshal(original, &orig) != nil || json.Unmarshal(normalized, &norm) != nil {
		return normalized
	}
	origMods := map[string]map[string]any{}
	for _, m := range asList(orig["modules"]) {
		if mm, ok := m.(map[string]any); ok {
			name, _ := mm["name"].(string)
			origMods[name] = mm
		}
	}
	for _, m := range asList(norm["modules"]) {
		mm, ok := m.(map[string]any)
		if !ok {
			continue
		}
		name, _ := mm["name"].(string)
		om := origMods[name]
		for _, key := range []string{"inputs", "baseline_gaps"} {
			ov, _ := om[key].(map[string]any)
			nv, _ := mm[key].(map[string]any)
			for k, v := range ov {
				if hasStackRef(v) && nv != nil {
					nv[k] = v
				}
			}
		}
	}
	out, err := json.Marshal(norm)
	if err != nil {
		return normalized
	}
	return out
}

func asList(v any) []any { l, _ := v.([]any); return l }

func hasStackRef(v any) bool {
	if _, ok := stackRefOf(v); ok {
		return true
	}
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			if hasStackRef(x) {
				return true
			}
		}
	case []any:
		for _, x := range t {
			if hasStackRef(x) {
				return true
			}
		}
	}
	return false
}
