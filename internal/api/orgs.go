package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/cloudapi"
	"github.com/itsPavanFeed/srustiops-backend/internal/spec"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Organisations: a tenant registers its AWS Organization, GCP organization
// or Azure management group with a read-only identity that can list it. The
// tree of OUs / folders / management groups and the accounts, projects or
// subscriptions in it are listed on demand (sync). OUs map to entities, and
// selected accounts are onboarded as connections from one template, scoped
// to the entity of their nearest mapped ancestor.

type orgDiscovery struct {
	AWS *struct {
		RoleARN string `json:"role_arn"` // in the management (or delegated admin) account
	} `json:"aws,omitempty"`
	GCP *struct {
		Organization             string `json:"organization"`
		WorkloadIdentityProvider string `json:"workload_identity_provider"`
		ServiceAccountEmail      string `json:"service_account_email"`
	} `json:"gcp,omitempty"`
	Azure *struct {
		TenantID        string `json:"tenant_id"`
		ClientID        string `json:"client_id"`
		ManagementGroup string `json:"management_group"`
	} `json:"azure,omitempty"`
}

type orgBody struct {
	Name         string          `json:"name"`
	Provider     string          `json:"provider"`
	Discovery    orgDiscovery    `json:"discovery"`
	Template     json.RawMessage `json:"template"`      // connection cloud config with placeholders
	NameTemplate string          `json:"name_template"` // e.g. aws-{{name}}
}

var (
	awsRoleARNRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]{1,128}$`)
	gcpOrgRe     = regexp.MustCompile(`^(organizations/)?\d{1,20}$`)
	gcpSARe      = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9-]+\.iam\.gserviceaccount\.com$`)
	gcpWIFRe     = regexp.MustCompile(`^projects/\d+/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	guidRe       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	mgmtGroupRe  = regexp.MustCompile(`^[\w().-]{1,90}$`)
	unitSlugRe   = regexp.MustCompile(`[^a-z0-9]+`)
)

// accountPlaceholder is what makes each onboarded connection distinct.
var accountPlaceholder = map[string]string{"aws": "{{account}}", "gcp": "{{project}}", "azure": "{{subscription}}"}

func (b *orgBody) validate(create bool) []string {
	var probs []string
	if create && !connNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes (2-48)")
	}
	d := b.Discovery
	switch b.Provider {
	case "aws":
		if d.AWS == nil || !awsRoleARNRe.MatchString(d.AWS.RoleARN) {
			probs = append(probs, "discovery.aws.role_arn must be an IAM role ARN that can list the organization")
		}
	case "gcp":
		if d.GCP == nil || !gcpOrgRe.MatchString(d.GCP.Organization) || !gcpWIFRe.MatchString(d.GCP.WorkloadIdentityProvider) || !gcpSARe.MatchString(d.GCP.ServiceAccountEmail) {
			probs = append(probs, "discovery.gcp needs organization (number), workload_identity_provider and service_account_email")
		}
	case "azure":
		if d.Azure == nil || !guidRe.MatchString(d.Azure.TenantID) || !guidRe.MatchString(d.Azure.ClientID) || !mgmtGroupRe.MatchString(d.Azure.ManagementGroup) {
			probs = append(probs, "discovery.azure needs tenant_id, client_id and management_group")
		}
	default:
		return append(probs, "provider must be aws, gcp or azure")
	}
	ph := accountPlaceholder[b.Provider]
	if !strings.Contains(string(b.Template), ph) {
		probs = append(probs, "the connection template must use "+ph+" so each onboarded connection points at its own "+strings.Trim(ph, "{}"))
	}
	if !strings.Contains(b.NameTemplate, "{{name}}") && !strings.Contains(b.NameTemplate, ph) {
		probs = append(probs, "name_template must use {{name}} or "+ph)
	}
	if len(probs) == 0 {
		sample := &store.OrgUnit{Name: "sample", External: map[string]string{"aws": "123456789012", "gcp": "sample-project", "azure": "00000000-0000-0000-0000-000000000000"}[b.Provider]}
		if _, _, err := renderConnection(b.Provider, b.Template, b.NameTemplate, sample); err != nil {
			probs = append(probs, err.Error())
		}
	}
	return probs
}

// renderConnection fills the template for one account, project or subscription.
func renderConnection(provider string, tmpl json.RawMessage, nameTmpl string, u *store.OrgUnit) (string, json.RawMessage, error) {
	slug := strings.Trim(unitSlugRe.ReplaceAllString(strings.ToLower(u.Name), "-"), "-")
	rep := strings.NewReplacer("{{name}}", slug, accountPlaceholder[provider], u.External)
	name := rep.Replace(nameTmpl)
	if len(name) > 48 {
		name = strings.TrimRight(name[:48], "-")
	}
	if !connNameRe.MatchString(name) {
		return "", nil, fmt.Errorf("name_template gives %q, which is not a connection name", name)
	}
	// Placeholders are replaced inside JSON string values only.
	var raw any
	if err := json.Unmarshal(tmpl, &raw); err != nil {
		return "", nil, fmt.Errorf("template must be a JSON object: %v", err)
	}
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			return rep.Replace(t)
		case map[string]any:
			for k, x := range t {
				t[k] = walk(x)
			}
		case []any:
			for i, x := range t {
				t[i] = walk(x)
			}
		}
		return v
	}
	b, _ := json.Marshal(walk(raw))
	c, err := spec.DecodeCloud(b)
	if err != nil {
		return "", nil, fmt.Errorf("template: %v", err)
	}
	if c.Provider != provider {
		return "", nil, fmt.Errorf("template provider must be %s", provider)
	}
	out, _ := json.Marshal(c)
	return name, out, nil
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, orgs)
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b orgBody
	if !decode(w, r, &b) {
		return
	}
	if probs := b.validate(true); len(probs) > 0 {
		writeErr(w, 422, "invalid organisation", probs...)
		return
	}
	disc, _ := json.Marshal(b.Discovery)
	o, err := s.store.CreateOrg(r.Context(), &store.CloudOrg{Name: b.Name, Provider: b.Provider, Discovery: disc, Template: b.Template, NameTemplate: b.NameTemplate, CreatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "an organisation with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "org.create", "org/"+o.Name, "", o)
	writeJSON(w, 201, o)
}

func (s *Server) updateOrg(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	cur, err := s.store.GetOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var b orgBody
	if !decode(w, r, &b) {
		return
	}
	b.Name, b.Provider = cur.Name, cur.Provider
	if probs := b.validate(false); len(probs) > 0 {
		writeErr(w, 422, "invalid organisation", probs...)
		return
	}
	disc, _ := json.Marshal(b.Discovery)
	if s.dryRun(w, r) {
		return
	}
	o, err := s.store.UpdateOrg(r.Context(), &store.CloudOrg{ID: cur.ID, Discovery: disc, Template: b.Template, NameTemplate: b.NameTemplate})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "org.update", "org/"+o.Name, "", map[string]any{"before": cur, "after": o})
	writeJSON(w, 200, o)
}

// deleteOrg forgets the organisation; onboarded connections stay.
func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	o, err := s.store.GetOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if s.dryRun(w, r) {
		return
	}
	if err := s.store.DeleteOrg(r.Context(), o.ID); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "org.delete", "org/"+o.Name, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

type orgUnitView struct {
	*store.OrgUnit
	EffectiveEntity string `json:"effective_entity"` // own mapping, or the nearest mapped ancestor's
	Connection      string `json:"connection,omitempty"`
}

func (s *Server) orgView(ctx context.Context, o *store.CloudOrg) ([]orgUnitView, error) {
	units, err := s.store.ListOrgUnits(ctx, o.ID)
	if err != nil {
		return nil, err
	}
	conns, err := s.store.ListConnections(ctx)
	if err != nil {
		return nil, err
	}
	connName := map[string]string{}
	for _, c := range conns {
		connName[c.ID] = c.Name
	}
	byID := map[string]*store.OrgUnit{}
	for _, u := range units {
		byID[u.UnitID] = u
	}
	effective := func(u *store.OrgUnit) string {
		for i := 0; u != nil && i < 32; i++ {
			if u.Entity != "" {
				return u.Entity
			}
			u = byID[u.ParentID]
		}
		return ""
	}
	out := make([]orgUnitView, 0, len(units))
	for _, u := range units {
		v := orgUnitView{OrgUnit: u, EffectiveEntity: effective(u)}
		if u.ConnectionID != nil {
			v.Connection = connName[*u.ConnectionID]
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	o, err := s.store.GetOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	units, err := s.orgView(r.Context(), o)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"org": o, "units": units, "oidc": map[string]string{"issuer": s.issuer.URL, "subject": discoverySubject("org:" + o.Name)}})
}

// syncOrg lists the organisation now, with its read-only identity.
func (s *Server) syncOrg(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "listing an organisation needs the tenant admin or devops role")
		return
	}
	o, err := s.store.GetOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var d orgDiscovery
	json.Unmarshal(o.Discovery, &d)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	c := s.cloudClient("org:" + o.Name)
	var units []cloudapi.Unit
	switch {
	case o.Provider == "aws" && d.AWS != nil:
		units, err = c.AWSOrganization(ctx, d.AWS.RoleARN)
	case o.Provider == "gcp" && d.GCP != nil:
		units, err = c.GCPOrganization(ctx, d.GCP.WorkloadIdentityProvider, d.GCP.ServiceAccountEmail, d.GCP.Organization)
	case o.Provider == "azure" && d.Azure != nil:
		units, err = c.AzureManagementGroup(ctx, d.Azure.TenantID, d.Azure.ClientID, d.Azure.ManagementGroup)
	default:
		err = errors.New("the organisation has no discovery identity")
	}
	rows := make([]*store.OrgUnit, 0, len(units))
	for _, u := range units {
		rows = append(rows, &store.OrgUnit{UnitID: u.ID, ParentID: u.ParentID, Name: u.Name, Kind: u.Kind, External: u.External, State: u.State})
	}
	if serr := s.store.SyncOrg(r.Context(), o.ID, rows, err); serr != nil {
		s.writeStoreErr(w, serr, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "org.sync", "org/"+o.Name, "", map[string]any{"units": len(rows), "error": errString(err)})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "listing the organisation failed: "+err.Error())
		return
	}
	s.getOrg(w, r)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// mapUnit sets (or clears) the entity of an OU, folder or account.
func (s *Server) mapUnit(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Unit   string `json:"unit"` // OU, folder, management group or account ID
		Entity string `json:"entity"`
	}
	if !decode(w, r, &b) {
		return
	}
	o, err := s.store.GetOrg(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if b.Entity != "" && !s.knownEntity(r, b.Entity) {
		writeErr(w, 422, "unknown entity "+b.Entity)
		return
	}
	unit := b.Unit
	if err := s.store.SetUnitEntity(r.Context(), o.ID, unit, b.Entity); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "org.map", "org/"+o.Name, b.Entity, map[string]string{"unit": unit, "entity": b.Entity})
	s.getOrg(w, r)
}

// onboardOrg creates a connection for each selected account, project or
// subscription from the organisation's template, scoped to its entity.
func (s *Server) onboardOrg(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Units  []string `json:"units"`
		DryRun bool     `json:"dry_run"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Units) == 0 || len(b.Units) > 200 {
		writeErr(w, 422, "choose 1 to 200 accounts, projects or subscriptions")
		return
	}
	ctx := r.Context()
	o, err := s.store.GetOrg(ctx, r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	view, err := s.orgView(ctx, o)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	byID := map[string]orgUnitView{}
	for _, v := range view {
		byID[v.UnitID] = v
	}
	type result struct {
		Unit       string          `json:"unit"`
		Name       string          `json:"name"`
		Connection string          `json:"connection,omitempty"`
		Entity     string          `json:"entity,omitempty"`
		Cloud      json.RawMessage `json:"cloud,omitempty"`
		Skipped    string          `json:"skipped,omitempty"`
	}
	out := []result{}
	created := 0
	for _, id := range b.Units {
		v, ok := byID[id]
		res := result{Unit: id, Name: v.Name}
		switch {
		case !ok:
			res.Skipped = "not in this organisation; sync it first"
		case v.Kind != "account" && v.Kind != "project" && v.Kind != "subscription":
			res.Skipped = "only accounts, projects and subscriptions are onboarded"
		case v.State != "" && v.State != "active" && v.State != "enabled":
			res.Skipped = "it is " + v.State
		case v.Connection != "":
			res.Skipped = "already onboarded as " + v.Connection
		case v.EffectiveEntity == "":
			res.Skipped = "map it, or an OU above it, to an entity first"
		}
		if res.Skipped != "" {
			out = append(out, res)
			continue
		}
		name, cloud, err := renderConnection(o.Provider, o.Template, o.NameTemplate, v.OrgUnit)
		if err != nil {
			res.Skipped = err.Error()
			out = append(out, res)
			continue
		}
		res.Connection, res.Entity, res.Cloud = name, v.EffectiveEntity, cloud
		if !b.DryRun {
			c, err := s.store.CreateConnection(ctx, &store.Connection{Name: name, Cloud: cloud, Entities: []string{v.EffectiveEntity}, CreatedBy: user(r).Subject})
			if err != nil {
				res.Skipped = "connection " + name + ": " + map[bool]string{true: "a connection with that name exists", false: err.Error()}[errors.Is(err, store.ErrConflict)]
				res.Connection, res.Cloud = "", nil
				out = append(out, res)
				continue
			}
			s.store.SetUnitConnection(ctx, o.ID, id, c.ID)
			s.audit(ctx, user(r).Actor(), "connection.create", "connection/"+c.Name, v.EffectiveEntity, map[string]any{"org": o.Name, "unit": id, "connection": c})
			created++
		}
		out = append(out, res)
	}
	code := 200
	if created > 0 {
		code = 201
	}
	writeJSON(w, code, map[string]any{"results": out, "created": created, "dry_run": b.DryRun})
}
