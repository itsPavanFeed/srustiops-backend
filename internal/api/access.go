package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/oidc"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Tenant-controlled access.
//
// With the access source "central" (the default, and how tenants started),
// this plane trusts the roles central puts in each assertion. With "tenant",
// central only says who the caller is and how they signed in; this plane
// resolves their roles from its own grants, its identity-provider group
// bindings and approved support access, and applies its own sign-in policy.
// Central keeps a read-only copy of the grants (the directory) for its
// workspace list; it can no longer grant anything here.

const (
	accessSetting = "access"
	// CentralSubject is the assertion subject central uses for its own calls
	// (directory sync, imports, support requests, session binding).
	CentralSubject = "system:central"
)

type accessSettings struct {
	Source          string `json:"source"` // central | tenant
	SupportAccess   bool   `json:"support_access"`
	IDPIssuer       string `json:"idp_issuer,omitempty"`
	IDPClientID     string `json:"idp_client_id,omitempty"`
	RequireIDP      bool   `json:"require_idp"`
	RequireMFA      bool   `json:"require_mfa"`
	MaxSessionHours int    `json:"max_session_hours"`
	// AcceptedProviders pins which sign-ins this tenant accepts ("oidc",
	// "google", "github", "token", "slack", "tenant:<slug>"); empty accepts all.
	AcceptedProviders []string `json:"accepted_providers,omitempty"`
	GroupClaim        string   `json:"group_claim,omitempty"`
	// The tenant's own provider speaks OIDC ("" or "oidc") or SAML ("saml").
	// For SAML, IDPIssuer is the IdP's entity ID and the metadata (with its
	// signing certificate) is kept here; there is no client ID.
	IDPProtocol      string `json:"idp_protocol,omitempty"`
	IDPSAMLMetadata  string `json:"idp_saml_metadata,omitempty"`
	IDPSAMLEmailAttr string `json:"idp_saml_email_attribute,omitempty"`
}

const idpSecretSetting = "idp_secret"

func defaultAccess() *accessSettings { return &accessSettings{Source: "central", SupportAccess: true} }

func (s *Server) access() *accessSettings {
	if a := s.accessSnap.Load(); a != nil {
		return a
	}
	return defaultAccess()
}

func (s *Server) loadAccess(ctx context.Context) {
	a := defaultAccess()
	if ok, err := s.store.Setting(ctx, accessSetting, a); err != nil || !ok {
		a = defaultAccess()
	}
	s.accessSnap.Store(a)
}

func (s *Server) saveAccess(ctx context.Context, a *accessSettings, by string) error {
	if err := s.store.PutSetting(ctx, accessSetting, a, by); err != nil {
		return err
	}
	s.accessSnap.Store(a)
	return nil
}

// accessDenied is a refusal the web console acts on: step_up_required sends
// the person through the tenant's identity provider again; no_access offers
// to ask for access.
type accessDenied struct{ code, msg string }

func (e *accessDenied) Error() string { return e.code + ": " + e.msg }

var mfaMethods = []string{"mfa", "otp", "hwk", "swk", "sms", "fido", "webauthn"}

// accepts reports whether the tenant accepts sign-ins from provider idp.
// Requiring the tenant's own provider accepts only that one.
func (s *Server) accepts(a *accessSettings, idp string) bool {
	if a.RequireIDP {
		return idp == "tenant:"+s.cfg.Tenant
	}
	return len(a.AcceptedProviders) == 0 || slices.Contains(a.AcceptedProviders, idp)
}

// resolveAccess turns central's assertion into the principal this tenant
// acts on. Who the person is comes from the provider's (issuer, subject) or,
// for the tenant's own provider, from the session this tenant issued.
func (s *Server) resolveAccess(ctx context.Context, p *identity.Principal) (*identity.Principal, error) {
	a := s.access()
	if a.Source != "tenant" || strings.HasPrefix(p.Subject, "system:") {
		return p, nil
	}
	email := strings.ToLower(p.Subject)
	iss, sub, verified, amr, authTime := p.UserIssuer, p.UserSubject, p.EmailVerified, p.AMR, p.AuthTime
	var groups []string
	own := false
	if p.TenantSession != "" && p.IDP == "tenant:"+s.cfg.Tenant {
		ts, err := s.store.LiveTenantSession(ctx, p.TenantSession)
		if err == nil && strings.EqualFold(ts.Email, email) {
			// This tenant verified the ID token itself: its record is authoritative.
			own = true
			iss, sub, verified, amr, groups, authTime = ts.Issuer, ts.Subject, true, ts.AMR, ts.Groups, ts.AuthTime.Unix()
		}
	}
	if a.RequireIDP && !own {
		return nil, &accessDenied{"step_up_required", "this tenant requires signing in with its own identity provider"}
	}
	if a.RequireMFA && !slices.ContainsFunc(amr, func(m string) bool { return slices.Contains(mfaMethods, strings.ToLower(m)) }) {
		return nil, &accessDenied{"step_up_required", "this tenant requires multi-factor sign-in"}
	}
	if a.MaxSessionHours > 0 && (authTime == 0 || time.Since(time.Unix(authTime, 0)) > time.Duration(a.MaxSessionHours)*time.Hour) {
		return nil, &accessDenied{"step_up_required", fmt.Sprintf("this tenant requires a sign-in within the last %d hours", a.MaxSessionHours)}
	}

	np := &identity.Principal{Subject: email, Tenant: p.Tenant, TenantRoles: []string{}, EntityRoles: map[string][]string{},
		BURoles: map[string][]string{}, BUEntity: map[string]string{}, IDP: p.IDP, AuthTime: authTime, AMR: amr, Groups: groups,
		TenantSession: p.TenantSession, UserIssuer: iss, UserSubject: sub, EmailVerified: verified}
	if cur := s.dirSnap.Load(); cur != nil {
		for bu, e := range *cur {
			np.BUEntity[bu] = e
		}
	}
	add := func(m map[string][]string, k, role string) {
		if !slices.Contains(m[k], role) {
			m[k] = append(m[k], role)
		}
	}
	grant := func(role, entity, bu string) {
		switch {
		case bu != "" && identity.IsScopedRole(role):
			add(np.BURoles, bu, role)
		case entity != "" && identity.IsScopedRole(role):
			add(np.EntityRoles, entity, role)
		case entity == "" && bu == "" && identity.IsTenantRole(role) && !slices.Contains(np.TenantRoles, role):
			np.TenantRoles = append(np.TenantRoles, role)
		}
	}
	// Support access was approved for this exact identity, so the provider
	// pin does not apply to it.
	var sup []*store.SupportGrant
	if a.SupportAccess && iss != "" {
		var err error
		if sup, err = s.store.ActiveSupportFor(ctx, iss, sub); err != nil {
			return nil, err
		}
	}
	if len(sup) == 0 && !s.accepts(a, p.IDP) {
		if s.accepts(a, "tenant:"+s.cfg.Tenant) && a.IDPIssuer != "" {
			return nil, &accessDenied{"step_up_required", "this tenant accepts only its own identity provider"}
		}
		return nil, &accessDenied{"no_access", "this tenant does not accept sign-ins from " + p.IDP + "; it accepts: " + strings.Join(a.AcceptedProviders, ", ")}
	}
	regular := false
	if len(sup) == 0 || s.accepts(a, p.IDP) {
		// Invitations by email bind to the first verified sign-in from an
		// accepted provider; a grant bound through a provider the tenant no
		// longer accepts may be claimed again the same way.
		gs, err := s.store.IdentityGrants(ctx, iss, sub, email, p.IDP, verified, func(g *store.AccessGrant) bool {
			return g.Issuer == "" || !s.accepts(a, g.IDP)
		})
		if err != nil {
			return nil, err
		}
		for _, g := range gs {
			grant(g.Role, g.Entity, g.BU)
		}
		var scimEmail string
		if verified {
			scimEmail = email
		}
		bs, err := s.store.BindingsFor(ctx, scimEmail, groups)
		if err != nil {
			return nil, err
		}
		for _, b := range bs {
			grant(b.Role, b.Entity, b.BU)
		}
		regular = len(gs)+len(bs) > 0
	}
	for _, g := range sup {
		grant(g.Role, "", "")
	}
	np.Support = len(sup) > 0 && !regular
	for bu, e := range np.BUEntity {
		for _, r := range np.EntityRoles[e] {
			add(np.BURoles, bu, r)
		}
	}
	if len(np.TenantRoles) == 0 && len(np.EntityRoles) == 0 && len(np.BURoles) == 0 {
		if p.PlatformAdmin {
			return nil, &accessDenied{"no_access", "platform admins have no standing access to this tenant: request support access and wait for a tenant admin to approve it"}
		}
		return nil, &accessDenied{"no_access", "you have no access to this tenant; ask one of its tenant admins"}
	}
	return np, nil
}

// pinDirectory merges central's business unit map into the known one without
// moving an existing business unit to another entity: under tenant-controlled
// access an entity-wide grant must not grow because central remapped a BU.
func pinDirectory(cur, m map[string]string) map[string]string {
	out := map[string]string{}
	for bu, e := range cur {
		out[bu] = e
	}
	for bu, e := range m {
		if _, ok := out[bu]; !ok {
			out[bu] = e
		}
	}
	return out
}

// ---- API: tenant admins ----

func (s *Server) canManageAccess(p *identity.Principal, entity, bu string) bool {
	if p.HasTenantRole(identity.TenantAdmin) {
		return true
	}
	if bu != "" {
		entity, _ = s.buEntity(bu)
	}
	return entity != "" && slices.Contains(p.EntityRoles[entity], identity.Admin)
}

type accessView struct {
	*accessSettings
	Tenant      string `json:"tenant"`
	Grants      int    `json:"grants"`
	Bindings    int    `json:"bindings"`
	Pending     int    `json:"pending_support_requests"`
	SecretSet   bool   `json:"idp_client_secret_set"`
	IDPCallback string `json:"-"`
}

func (s *Server) getAccess(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin, identity.Security, identity.Auditor) && !s.canManageAccess(p, "", "") {
		writeErr(w, http.StatusForbidden, "tenant admins, security and auditors see access settings")
		return
	}
	gs, _ := s.store.AccessGrants(r.Context(), "")
	bs, _ := s.store.GroupBindings(r.Context())
	sg, _ := s.store.SupportGrants(r.Context(), 200)
	pending := 0
	for _, g := range sg {
		if g.Status == "pending" {
			pending++
		}
	}
	var sealed []byte
	secretSet, _ := s.store.Setting(r.Context(), idpSecretSetting, &sealed)
	writeJSON(w, 200, accessView{accessSettings: s.access(), Tenant: s.cfg.Tenant, Grants: len(gs), Bindings: len(bs), Pending: pending, SecretSet: secretSet})
}

func (s *Server) putAccessSettings(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin) {
		writeErr(w, http.StatusForbidden, "only tenant admins change access settings")
		return
	}
	var b struct {
		SupportAccess   bool   `json:"support_access"`
		IDPIssuer       string `json:"idp_issuer"`
		IDPClientID     string `json:"idp_client_id"`
		RequireIDP      bool   `json:"require_idp"`
		RequireMFA      bool   `json:"require_mfa"`
		MaxSessionHours int    `json:"max_session_hours"`
		// The tenant's own OIDC client secret: kept here, sealed, never sent to central.
		IDPClientSecret   string   `json:"idp_client_secret,omitempty"`
		GroupClaim        string   `json:"group_claim,omitempty"`
		AcceptedProviders []string `json:"accepted_providers,omitempty"`
		IDPProtocol       string   `json:"idp_protocol,omitempty"`
		IDPSAMLMetadata   string   `json:"idp_saml_metadata,omitempty"`
		IDPSAMLEmailAttr  string   `json:"idp_saml_email_attribute,omitempty"`
	}
	if !decode(w, r, &b) {
		return
	}
	var probs []string
	// A save that leaves the protocol out (the Access page's toggles) keeps
	// the current SAML provider when it names the same issuer.
	if cur := s.access(); b.IDPProtocol == "" && cur.IDPProtocol == "saml" && b.IDPIssuer == cur.IDPIssuer {
		b.IDPProtocol, b.IDPSAMLMetadata = "saml", cur.IDPSAMLMetadata
		if b.IDPSAMLEmailAttr == "" {
			b.IDPSAMLEmailAttr = cur.IDPSAMLEmailAttr
		}
	}
	saml := b.IDPProtocol == "saml"
	if b.IDPProtocol != "" && b.IDPProtocol != "oidc" && !saml {
		probs = append(probs, `idp_protocol must be "oidc" or "saml"`)
	}
	if saml {
		// The entity ID comes from the metadata; SAML has no client ID.
		md, err := parseIdPMetadata([]byte(b.IDPSAMLMetadata))
		if err != nil || len(b.IDPSAMLMetadata) > 512<<10 {
			probs = append(probs, "idp_saml_metadata: "+errOr(err, "too large"))
		} else {
			b.IDPIssuer, b.IDPClientID = md.EntityID, "saml"
		}
	}
	for _, ap := range b.AcceptedProviders {
		if !slices.Contains([]string{"oidc", "google", "github", "token", "slack", "tenant:" + s.cfg.Tenant}, ap) {
			probs = append(probs, "accepted providers are oidc, google, github, token, slack and tenant:"+s.cfg.Tenant)
			break
		}
	}
	b.IDPIssuer = strings.TrimRight(strings.TrimSpace(b.IDPIssuer), "/")
	if !saml && b.IDPIssuer != "" && !strings.HasPrefix(b.IDPIssuer, "https://") && !strings.HasPrefix(b.IDPIssuer, "http://127.0.0.1") && !strings.HasPrefix(b.IDPIssuer, "http://localhost") {
		probs = append(probs, "idp_issuer must be an https URL")
	}
	if (b.IDPIssuer == "") != (b.IDPClientID == "") {
		probs = append(probs, "idp_issuer and idp_client_id go together")
	}
	if b.RequireIDP && b.IDPIssuer == "" {
		probs = append(probs, "requiring the tenant's identity provider needs its issuer and client ID")
	}
	if b.MaxSessionHours < 0 || b.MaxSessionHours > 24*30 {
		probs = append(probs, "max_session_hours must be between 0 (no limit) and 720")
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid access settings", probs...)
		return
	}
	a := *s.access()
	if b.RequireIDP && a.Source != "tenant" {
		writeErr(w, 422, "requiring the tenant's identity provider needs tenant-controlled access first")
		return
	}
	a.SupportAccess, a.IDPIssuer, a.IDPClientID, a.RequireIDP, a.RequireMFA, a.MaxSessionHours, a.AcceptedProviders =
		b.SupportAccess, b.IDPIssuer, b.IDPClientID, b.RequireIDP, b.RequireMFA, b.MaxSessionHours, b.AcceptedProviders
	if b.GroupClaim != "" {
		a.GroupClaim = b.GroupClaim
	}
	a.IDPProtocol, a.IDPSAMLMetadata, a.IDPSAMLEmailAttr = "", "", ""
	if saml {
		a.IDPProtocol, a.IDPSAMLMetadata, a.IDPSAMLEmailAttr = "saml", b.IDPSAMLMetadata, strings.TrimSpace(b.IDPSAMLEmailAttr)
	}
	if b.IDPClientSecret != "" {
		sealed, err := s.sealer.Seal([]byte(b.IDPClientSecret), []byte(idpSecretSetting))
		if err == nil {
			err = s.store.PutSetting(r.Context(), idpSecretSetting, sealed, p.Actor())
		}
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
	}
	if err := s.saveAccess(r.Context(), &a, p.Actor()); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.settings", "tenant/"+s.cfg.Tenant, "", map[string]any{"settings": a, "client_secret_changed": b.IDPClientSecret != ""})
	writeJSON(w, 200, a)
}

type grantBody struct {
	Email  string `json:"email"`
	Role   string `json:"role"`
	Entity string `json:"entity"`
	BU     string `json:"bu"`
}

func (b *grantBody) check(s *Server) []string {
	b.Email = strings.ToLower(strings.TrimSpace(b.Email))
	var probs []string
	if !strings.Contains(b.Email, "@") || len(b.Email) > 254 {
		probs = append(probs, "email is invalid")
	}
	switch {
	case b.Entity != "" && b.BU != "":
		probs = append(probs, "grant on an entity or on a business unit, not both")
	case b.Entity == "" && b.BU == "" && !identity.IsTenantRole(b.Role):
		probs = append(probs, "tenant-wide roles: "+strings.Join(identity.TenantRoles, ", "))
	case (b.Entity != "" || b.BU != "") && !identity.IsScopedRole(b.Role):
		probs = append(probs, "entity and business unit roles: "+strings.Join(identity.ScopedRoles, ", "))
	}
	if b.BU != "" {
		if _, ok := s.buEntity(b.BU); !ok {
			probs = append(probs, "unknown business unit "+b.BU)
		}
	}
	if b.Entity != "" && !identity.SlugRe.MatchString(b.Entity) {
		probs = append(probs, "entity must be a slug")
	}
	return probs
}

func (s *Server) listAccessGrants(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin, identity.Security, identity.Auditor) && !s.canManageAccess(p, "", "") {
		writeErr(w, http.StatusForbidden, "tenant admins, security and auditors see grants")
		return
	}
	gs, err := s.store.AccessGrants(r.Context(), "")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, gs)
}

func (s *Server) addAccessGrant(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	var b grantBody
	if !decode(w, r, &b) {
		return
	}
	if probs := b.check(s); len(probs) > 0 {
		writeErr(w, 422, "invalid grant", probs...)
		return
	}
	if !s.canManageAccess(p, b.Entity, b.BU) || (b.Entity == "" && b.BU == "" && !p.HasTenantRole(identity.TenantAdmin)) {
		writeErr(w, http.StatusForbidden, "you cannot grant roles there")
		return
	}
	g, err := s.store.AddAccessGrant(r.Context(), &store.AccessGrant{Email: b.Email, Role: b.Role, Entity: b.Entity, BU: b.BU, CreatedBy: p.Actor()})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.grant", "user/"+b.Email, b.Entity, b)
	writeJSON(w, 201, g)
}

func (s *Server) deleteAccessGrant(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	gs, err := s.store.AccessGrants(r.Context(), "")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	id := r.PathValue("id")
	var g *store.AccessGrant
	for _, x := range gs {
		if x.ID == id {
			g = x
		}
	}
	if g == nil {
		writeErr(w, 404, "not found")
		return
	}
	if !s.canManageAccess(p, g.Entity, g.BU) || (g.Entity == "" && g.BU == "" && !p.HasTenantRole(identity.TenantAdmin)) {
		writeErr(w, http.StatusForbidden, "you cannot remove that grant")
		return
	}
	if g.Role == identity.TenantAdmin && g.Entity == "" && g.BU == "" && strings.EqualFold(g.Email, p.Subject) {
		writeErr(w, 422, "you cannot remove your own tenant admin grant; ask another tenant admin")
		return
	}
	if _, err := s.store.DeleteAccessGrant(r.Context(), id); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.revoke", "user/"+g.Email, g.Entity, g)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listGroupBindings(w http.ResponseWriter, r *http.Request) {
	if !user(r).HasTenantRole(identity.TenantAdmin, identity.Security, identity.Auditor) {
		writeErr(w, http.StatusForbidden, "tenant admins, security and auditors see group bindings")
		return
	}
	bs, err := s.store.GroupBindings(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, bs)
}

func (s *Server) addGroupBinding(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin) {
		writeErr(w, http.StatusForbidden, "only tenant admins bind groups to roles")
		return
	}
	var b struct {
		Group  string `json:"group"`
		Role   string `json:"role"`
		Entity string `json:"entity"`
		BU     string `json:"bu"`
	}
	if !decode(w, r, &b) {
		return
	}
	b.Group = strings.TrimSpace(b.Group)
	gb := grantBody{Email: "group@binding", Role: b.Role, Entity: b.Entity, BU: b.BU}
	probs := gb.check(s)
	if b.Group == "" || len(b.Group) > 200 {
		probs = append(probs, "group is required (as your identity provider names it)")
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid group binding", probs...)
		return
	}
	if err := s.store.AddGroupBinding(r.Context(), &store.GroupBinding{Group: b.Group, Role: b.Role, Entity: b.Entity, BU: b.BU, CreatedBy: p.Actor()}); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.bind_group", "group/"+b.Group, b.Entity, b)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) deleteGroupBinding(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin) {
		writeErr(w, http.StatusForbidden, "only tenant admins unbind groups")
		return
	}
	b, err := s.store.DeleteGroupBinding(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.unbind_group", "group/"+b.Group, b.Entity, b)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSupportGrants(w http.ResponseWriter, r *http.Request) {
	if !user(r).HasTenantRole(identity.TenantAdmin, identity.Security, identity.Auditor) {
		writeErr(w, http.StatusForbidden, "tenant admins, security and auditors see support access")
		return
	}
	gs, err := s.store.SupportGrants(r.Context(), 200)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, gs)
}

func (s *Server) decideSupportGrant(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.TenantAdmin) || p.Support {
		writeErr(w, http.StatusForbidden, "only the tenant's own admins decide support access")
		return
	}
	status := map[string]string{"approve": "approved", "decline": "declined", "revoke": "revoked"}[r.PathValue("decision")]
	if status == "" {
		writeErr(w, 404, "not found")
		return
	}
	g, err := s.store.DecideSupportGrant(r.Context(), r.PathValue("id"), status, p.Actor())
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 409, "this request is not "+map[string]string{"approved": "pending", "declined": "pending", "revoked": "active"}[status])
		return
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "access.support_"+status, "user/"+g.Email, "", g)
	writeJSON(w, 200, g)
}

// ---- API: central (system:central) ----

func central(w http.ResponseWriter, r *http.Request) bool {
	if user(r).Subject != CentralSubject {
		writeErr(w, http.StatusForbidden, "central plane only")
		return false
	}
	return true
}

// importAccess takes central's grants for this tenant once and switches the
// access source to the tenant. Later imports are refused: from then on the
// tenant's own grants are the truth.
func (s *Server) importAccess(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		By     string      `json:"by"`
		Grants []grantBody `json:"grants"`
	}
	if !decode(w, r, &b) {
		return
	}
	if s.access().Source == "tenant" {
		writeErr(w, 409, "this tenant already controls its own access")
		return
	}
	n := 0
	admins := 0
	for _, g := range b.Grants {
		if probs := g.check(s); len(probs) > 0 {
			continue
		}
		if _, err := s.store.AddAccessGrant(r.Context(), &store.AccessGrant{Email: g.Email, Role: g.Role, Entity: g.Entity, BU: g.BU, Source: "import", CreatedBy: b.By}); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		n++
		if g.Role == identity.TenantAdmin && g.Entity == "" && g.BU == "" {
			admins++
		}
	}
	if admins == 0 {
		writeErr(w, 422, "the tenant needs at least one tenant admin before it takes over its access")
		return
	}
	a := *s.access()
	a.Source = "tenant"
	if err := s.saveAccess(r.Context(), &a, b.By); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), b.By, "access.takeover", "tenant/"+s.cfg.Tenant, "", map[string]int{"grants": n})
	writeJSON(w, 200, map[string]any{"imported": n, "source": "tenant"})
}

// accessDirectory is what central mirrors: who has access and how, for its
// workspace list. Central never writes back from it.
func (s *Server) accessDirectory(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	gs, err := s.store.AccessGrants(r.Context(), "")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	bs, _ := s.store.GroupBindings(r.Context())
	members, _ := s.store.GroupMembers(r.Context())
	// Effective grants through SCIM-provisioned groups count as grants here.
	for _, b := range bs {
		for _, e := range members[b.Group] {
			gs = append(gs, &store.AccessGrant{Email: e, Role: b.Role, Entity: b.Entity, BU: b.BU, Source: "group:" + b.Group})
		}
	}
	sg, _ := s.store.SupportGrants(r.Context(), 200)
	a := s.access()
	writeJSON(w, 200, s.signedDirectory(map[string]any{
		"source": a.Source, "support_access": a.SupportAccess, "require_idp": a.RequireIDP, "require_mfa": a.RequireMFA,
		"idp_issuer": a.IDPIssuer, "grants": gs, "support": sg,
	}))
}

// maxSupportHours caps a support grant: half a work shift, so access does
// not outlive the task it was asked for.
const maxSupportHours = 4

func (s *Server) requestSupport(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		Email   string `json:"email"`
		Issuer  string `json:"issuer"`
		Subject string `json:"subject"`
		Role    string `json:"role"`
		Reason  string `json:"reason"`
		Hours   int    `json:"hours"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Issuer == "" || b.Subject == "" {
		writeErr(w, 422, "a support request names the requesting identity (issuer and subject)")
		return
	}
	if !s.access().SupportAccess {
		writeErr(w, http.StatusForbidden, "this tenant has turned support access off")
		return
	}
	b.Reason = strings.TrimSpace(b.Reason)
	if b.Role != identity.Auditor && b.Role != identity.TenantAdmin || b.Hours < 1 || b.Hours > maxSupportHours || len(b.Reason) < 10 || len(b.Reason) > 500 {
		writeErr(w, 422, "support access is auditor (read-only) or tenant_admin, for 1 to 4 hours, with a reason of 10 to 500 characters")
		return
	}
	g, err := s.store.CreateSupportGrant(r.Context(), strings.ToLower(b.Email), b.Role, b.Reason, b.Hours)
	if err == nil {
		err = s.store.SetSupportIdentity(r.Context(), g.ID, b.Issuer, b.Subject)
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), "platform-admin:"+b.Email, "access.support_requested", "user/"+b.Email, "", g)
	writeJSON(w, 201, g)
}

func (s *Server) setGroupMembers(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		Emails []string `json:"emails"`
	}
	if !decode(w, r, &b) {
		return
	}
	group := r.PathValue("group")
	for i, e := range b.Emails {
		b.Emails[i] = strings.ToLower(strings.TrimSpace(e))
	}
	if err := s.store.SetGroupMembers(r.Context(), group, b.Emails); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), "scim", "access.group_members", "group/"+group, "", map[string]int{"members": len(b.Emails)})
	w.WriteHeader(http.StatusNoContent)
}

// The tenant's own sign-in. Central only redirects the browser: this tenant
// makes the state, nonce and PKCE verifier and keeps them, redeems the code
// with its own client credentials, and verifies the ID token. Central sees
// neither the token nor the secret.

type idpDoc struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURI  string `json:"jwks_uri"`
}

func randURL(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// oidcStart begins a sign-in: the authorization URL for central to redirect to.
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		RedirectURI string `json:"redirect_uri"`
		LoginHint   string `json:"login_hint"`
	}
	if !decode(w, r, &b) {
		return
	}
	a := s.access()
	if a.IDPIssuer == "" || a.IDPClientID == "" {
		writeErr(w, 409, "this tenant has no identity provider configured")
		return
	}
	doc, _, err := s.idpDiscovery(r.Context(), a.IDPIssuer, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "cannot reach the tenant's identity provider: "+err.Error())
		return
	}
	state, verifier, nonce := randURL(24), randURL(32), randURL(24)
	if err := s.store.CreateTenantAuthFlow(r.Context(), state, verifier, nonce, b.RedirectURI); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {a.IDPClientID}, "redirect_uri": {b.RedirectURI},
		"scope": {"openid email profile"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	if b.LoginHint != "" {
		q.Set("login_hint", b.LoginHint)
	}
	sep := "?"
	if strings.Contains(doc.AuthURL, "?") {
		sep = "&"
	}
	writeJSON(w, 200, map[string]string{"authorize_url": doc.AuthURL + sep + q.Encode(), "state": state})
}

// oidcFinish redeems the code central passed on, verifies the ID token and
// issues this tenant's session.
func (s *Server) oidcFinish(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		State string `json:"state"`
		Code  string `json:"code"`
	}
	if !decode(w, r, &b) {
		return
	}
	verifier, nonce, redirect, err := s.store.TakeTenantAuthFlow(r.Context(), b.State)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unknown or expired sign-in")
		return
	}
	a := s.access()
	doc, _, err := s.idpDiscovery(r.Context(), a.IDPIssuer, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "cannot reach the tenant's identity provider: "+err.Error())
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {b.Code}, "redirect_uri": {redirect}, "client_id": {a.IDPClientID}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, doc.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var sealed []byte
	if ok, _ := s.store.Setting(r.Context(), idpSecretSetting, &sealed); ok {
		secret, err := s.sealer.Open(sealed, []byte(idpSecretSetting))
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		req.SetBasicAuth(url.QueryEscape(a.IDPClientID), url.QueryEscape(string(secret)))
	}
	resp, err := s.idpClient().Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "token request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok) != nil || tok.IDToken == "" {
		writeErr(w, http.StatusUnauthorized, "the identity provider did not issue an ID token")
		return
	}
	_, v, err := s.idpDiscovery(r.Context(), a.IDPIssuer, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	c, err := v.Verify(tok.IDToken, a.IDPClientID, time.Now())
	if err != nil && err.Error() == "unknown signing key" {
		if _, v2, err2 := s.idpDiscovery(r.Context(), a.IDPIssuer, true); err2 == nil {
			c, err = v2.Verify(tok.IDToken, a.IDPClientID, time.Now())
		}
	}
	if err != nil || c["nonce"] != nonce {
		writeErr(w, http.StatusUnauthorized, "ID token rejected")
		return
	}
	email, _ := c["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	subject, _ := c["sub"].(string)
	if verified, _ := c["email_verified"].(bool); email == "" || subject == "" || !verified {
		writeErr(w, http.StatusUnauthorized, "the identity provider did not confirm the email address")
		return
	}
	claim := a.GroupClaim
	if claim == "" {
		claim = "groups"
	}
	ts := &store.TenantSession{Email: email, Issuer: a.IDPIssuer, Subject: subject, AMR: identityStrs(c["amr"]), Groups: identityStrs(c[claim]), AuthTime: time.Now()}
	if at, ok := c["auth_time"].(float64); ok {
		ts.AuthTime = time.Unix(int64(at), 0)
	}
	if len(ts.Groups) > 200 {
		ts.Groups = ts.Groups[:200]
	}
	id := "tsid_" + randURL(24)
	exp := time.Now().Add(12 * time.Hour)
	if err := s.store.CreateIdentitySession(r.Context(), id, ts, exp); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), email, "access.session", "user/"+email, "", map[string]any{"issuer": a.IDPIssuer, "subject": subject, "amr": ts.AMR, "groups": len(ts.Groups)})
	writeJSON(w, 200, map[string]any{"session": id, "email": email, "email_verified": true, "issuer": a.IDPIssuer, "subject": subject,
		"amr": ts.AMR, "auth_time": ts.AuthTime.Unix(), "expires_at": exp})
}

func errOr(err error, otherwise string) string {
	if err != nil {
		return err.Error()
	}
	return otherwise
}

func identityStrs(v any) []string {
	xs, _ := v.([]any)
	out := []string{}
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

type idpCache struct {
	mu      sync.Mutex
	issuer  string
	fetched time.Time
	doc     *idpDoc
	v       *oidc.Verifier
}

// idpClient reaches the tenant's identity provider: directly, or through the
// link agent's egress relay (SRUSTIOPS_IDP_PROXY) for tenants with no other way out.
func (s *Server) idpClient() *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if s.cfg.IDPProxy != "" {
		if u, err := url.Parse(s.cfg.IDPProxy); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}

func (s *Server) idpDiscovery(ctx context.Context, issuer string, refresh bool) (*idpDoc, *oidc.Verifier, error) {
	c := &s.idp
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v != nil && c.issuer == issuer && !refresh && time.Since(c.fetched) < time.Hour {
		return c.doc, c.v, nil
	}
	hc := s.idpClient()
	get := func(u string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("%s returned %s", u, resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	var doc idpDoc
	if err := get(issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, nil, err
	}
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, nil, errors.New("identity provider discovery names another issuer")
	}
	var jwks json.RawMessage
	if err := get(doc.JWKSURI, &jwks); err != nil {
		return nil, nil, err
	}
	v, err := oidc.NewVerifier(issuer, jwks)
	if err != nil {
		return nil, nil, err
	}
	c.issuer, c.doc, c.v, c.fetched = issuer, &doc, v, time.Now()
	return &doc, v, nil
}
