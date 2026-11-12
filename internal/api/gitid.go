package api

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- Git host logins of people (separation of duties on pull requests) ----
//
// A pull request opened on the Git host is authored by a host login, not a
// SrustiOps person. Linking logins to people lets SrustiOps refuse an
// approval from the author of the change. Anyone may link their own logins
// (it only limits what they can approve); tenant admins link anyone's and
// are the only ones who can remove a link.

var gitLoginRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,99}$`)

var gitProviders = map[string]bool{"github": true, "gitlab": true, "bitbucket": true, "azure": true}

func (s *Server) listGitIdentities(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	who := p.Subject
	if p.ManagesTenant() && r.URL.Query().Get("mine") == "" {
		who = ""
	}
	ids, err := s.store.ListGitIdentities(r.Context(), who)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, ids)
}

func (s *Server) addGitIdentity(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	var b store.GitIdentity
	if !decode(w, r, &b) {
		return
	}
	b.Provider = strings.ToLower(b.Provider)
	if !gitProviders[b.Provider] || !gitLoginRe.MatchString(b.Login) {
		writeErr(w, 422, "provider is github, gitlab, bitbucket or azure, and login is the account name on that host")
		return
	}
	if b.Subject == "" {
		b.Subject = p.Subject
	}
	if b.Subject != p.Subject && !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "you can link only your own logins")
		return
	}
	b.CreatedBy = p.Subject
	if err := s.store.PutGitIdentity(r.Context(), &b); err != nil {
		s.writeStoreErr(w, err, "that login is linked to someone else; a tenant admin can change it")
		return
	}
	s.audit(r.Context(), p.Actor(), "git_identity.link", "git/"+b.Provider+"/"+strings.ToLower(b.Login), "", map[string]string{"subject": b.Subject})
	writeJSON(w, 201, b)
}

func (s *Server) deleteGitIdentity(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.ManagesTenant() {
		writeErr(w, http.StatusForbidden, "only a tenant admin can remove a link: it would let its owner approve their own changes")
		return
	}
	g, err := s.store.DeleteGitIdentity(r.Context(), r.PathValue("provider"), r.PathValue("login"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "git_identity.unlink", "git/"+g.Provider+"/"+g.Login, "", map[string]string{"subject": g.Subject})
	w.WriteHeader(http.StatusNoContent)
}
