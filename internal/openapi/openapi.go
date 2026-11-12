// Package openapi describes a plane's HTTP API (OpenAPI 3.1) from its route
// registrations, so the description cannot drift from the routes: a test in
// each plane regenerates it and fails when the committed file differs.
package openapi

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

var (
	routeRe   = regexp.MustCompile(`mux\.Handle(?:Func)?\("([A-Z]+) (/api/[^"]*)",\s*(.*)\)\s*$`)
	handlerRe = regexp.MustCompile(`s\.([A-Za-z0-9_]+)`)
	paramRe   = regexp.MustCompile(`\{([A-Za-z_]+)(\.\.\.)?\}`)
	gatedRe   = regexp.MustCompile(`gated(?:IfConfigured)?\("`)
)

// Generate builds the description of the routes registered in src (the
// plane's route table source).
func Generate(src, title, version, description string) []byte {
	paths := map[string]map[string]any{}
	for _, line := range strings.Split(src, "\n") {
		m := routeRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		method, path, rest := strings.ToLower(m[1]), m[2], m[3]
		hs := handlerRe.FindAllStringSubmatch(rest, -1)
		handler := ""
		if len(hs) > 0 {
			handler = hs[len(hs)-1][1]
		}
		op := map[string]any{"operationId": handler, "summary": words(handler), "tags": []string{tag(path)},
			"responses": map[string]any{"default": map[string]any{"description": "JSON; errors are {\"error\": \"...\", \"details\": [...]}"}}}
		if gatedRe.MatchString(rest) {
			op["description"] = "A change to a configured integration waits for DevOps approval (202 with the pending change); ?dry_run=1 validates only."
		}
		var params []map[string]any
		for _, p := range paramRe.FindAllStringSubmatch(path, -1) {
			params = append(params, map[string]any{"name": p[1], "in": "path", "required": true, "schema": map[string]string{"type": "string"}})
		}
		if params != nil {
			op["parameters"] = params
		}
		if method == "post" || method == "put" || method == "patch" {
			op["requestBody"] = map[string]any{"content": map[string]any{"application/json": map[string]any{"schema": map[string]string{"type": "object"}}}}
		}
		oaPath := paramRe.ReplaceAllString(path, "{$1}")
		if paths[oaPath] == nil {
			paths[oaPath] = map[string]any{}
		}
		paths[oaPath][method] = op
	}
	doc := map[string]any{
		"openapi": "3.1.0",
		"info":    map[string]string{"title": title, "version": version, "description": description},
		"components": map[string]any{"securitySchemes": map[string]any{
			"bearer": map[string]string{"type": "http", "scheme": "bearer", "description": "A SrustiOps API token or session"}}},
		"security": []map[string][]string{{"bearer": {}}},
		"paths":    paths,
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n')
}

// Paths lists the described paths, sorted (for tests).
func Paths(doc []byte) []string {
	var d struct {
		Paths map[string]any `json:"paths"`
	}
	json.Unmarshal(doc, &d)
	out := make([]string, 0, len(d.Paths))
	for p := range d.Paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func tag(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) >= 3 {
		if segs[2] == "tenants" || segs[2] == "platform" || segs[2] == "integrations" {
			if len(segs) >= 4 && !strings.HasPrefix(segs[3], "{") {
				return segs[3]
			}
			if len(segs) >= 5 {
				return segs[4]
			}
		}
		return segs[2]
	}
	return "api"
}

// words turns a handler name (putBudget) into a summary (Put budget).
func words(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte(' ')
			r = unicode.ToLower(r)
		}
		if i == 0 {
			r = unicode.ToUpper(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}
