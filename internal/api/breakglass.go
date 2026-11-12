package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/identity"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// Break-glass: with no standing platform access, a tenant whose identity
// provider is broken needs its own way back in. One local credential (a TOTP
// secret sealed with the tenant's master key) works only on a loopback
// listener, so only from inside the tenant (kubectl exec … srustiops breakglass).
// It can do two things: reset the sign-in settings and grant tenant_admin.
// Every use is audited and alerts every tenant admin.

const breakglassSetting = "breakglass"

type breakglassState struct {
	Secret   []byte    `json:"secret"` // sealed
	Created  time.Time `json:"created"`
	LastStep int64     `json:"last_step"` // codes are single use
}

type bgLimiter struct {
	mu       sync.Mutex
	failures int
	until    time.Time
}

var bg bgLimiter

func totp(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", code%1_000_000)
}

// serveBreakglass listens on loopback only.
func (s *Server) serveBreakglass(ctx context.Context) {
	addr := s.cfg.BreakglassListen
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !(host == "127.0.0.1" || host == "::1" || host == "localhost") {
		s.log.Error("break-glass listens on loopback only; not started", "addr", addr)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /breakglass/init", s.breakglassInit)
	mux.HandleFunc("POST /breakglass/{action}", s.breakglassAct)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	context.AfterFunc(ctx, func() { srv.Close() })
	s.log.Info("break-glass listening on loopback", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.log.Error("break-glass listener stopped", "err", err)
	}
}

func (s *Server) breakglassState(ctx context.Context) (*breakglassState, error) {
	var st breakglassState
	ok, err := s.store.Setting(ctx, breakglassSetting, &st)
	if err != nil || !ok {
		return nil, err
	}
	return &st, nil
}

// breakglassInit creates the credential once and shows it once.
func (s *Server) breakglassInit(w http.ResponseWriter, r *http.Request) {
	if st, err := s.breakglassState(r.Context()); err != nil || st != nil {
		writeErr(w, http.StatusConflict, "break-glass is already set up; it is shown only once")
		return
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	sealed, err := s.sealer.Seal(secret, []byte(breakglassSetting))
	if err == nil {
		err = s.store.PutSetting(r.Context(), breakglassSetting, breakglassState{Secret: sealed, Created: time.Now()}, "breakglass")
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	s.audit(r.Context(), "breakglass", "breakglass.init", "tenant/"+s.cfg.Tenant, "", nil)
	s.alertAdmins(r.Context(), "Break-glass access was set up", "A local break-glass credential was created inside the tenant.")
	writeJSON(w, 201, map[string]string{
		"secret":  b32,
		"otpauth": "otpauth://totp/" + url.PathEscape("SrustiOps:"+s.cfg.Tenant+" break-glass") + "?secret=" + b32 + "&issuer=Cloud%20SrustiOps",
		"note":    "Store it in your vault or authenticator now; it is not shown again.",
	})
}

func (s *Server) breakglassAct(w http.ResponseWriter, r *http.Request) {
	bg.mu.Lock()
	if time.Now().Before(bg.until) {
		bg.mu.Unlock()
		writeErr(w, http.StatusTooManyRequests, "too many wrong codes; wait 15 minutes")
		return
	}
	bg.mu.Unlock()
	var b struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if !decode(w, r, &b) {
		return
	}
	st, err := s.breakglassState(r.Context())
	if err != nil || st == nil {
		writeErr(w, http.StatusConflict, "break-glass is not set up (srustiops breakglass init)")
		return
	}
	secret, err := s.sealer.Open(st.Secret, []byte(breakglassSetting))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	now := time.Now().Unix() / 30
	step := int64(0)
	for _, d := range []int64{-1, 0, 1} {
		if subtle.ConstantTimeCompare([]byte(totp(secret, now+d)), []byte(strings.TrimSpace(b.Code))) == 1 {
			step = now + d
		}
	}
	if step == 0 || step <= st.LastStep {
		bg.mu.Lock()
		if bg.failures++; bg.failures >= 5 {
			bg.failures, bg.until = 0, time.Now().Add(15*time.Minute)
		}
		bg.mu.Unlock()
		s.audit(r.Context(), "breakglass", "breakglass.denied", "tenant/"+s.cfg.Tenant, "", map[string]string{"action": r.PathValue("action")})
		writeErr(w, http.StatusUnauthorized, "wrong or reused code")
		return
	}
	st.LastStep = step
	if err := s.store.PutSetting(r.Context(), breakglassSetting, st, "breakglass"); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	switch r.PathValue("action") {
	case "reset-idp":
		// Sign-in back to what central offers: no provider requirement, no pin.
		a := *s.access()
		a.RequireIDP, a.RequireMFA, a.AcceptedProviders, a.MaxSessionHours = false, false, nil, 0
		if err := s.saveAccess(r.Context(), &a, "breakglass"); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(r.Context(), "breakglass", "breakglass.reset_idp", "tenant/"+s.cfg.Tenant, "", a)
		s.alertAdmins(r.Context(), "Break-glass used: sign-in settings reset", "The provider requirement, MFA requirement, provider pins and session age limit were cleared from inside the tenant.")
		writeJSON(w, 200, map[string]string{"result": "sign-in settings reset"})
	case "grant-admin":
		email := strings.ToLower(strings.TrimSpace(b.Email))
		if !strings.Contains(email, "@") {
			writeErr(w, 422, "email is required")
			return
		}
		// An invitation: it binds on that person's next verified sign-in.
		g, err := s.store.AddAccessGrant(r.Context(), &store.AccessGrant{Email: email, Role: identity.TenantAdmin, CreatedBy: "breakglass"})
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(r.Context(), "breakglass", "breakglass.grant_admin", "user/"+email, "", g)
		s.alertAdmins(r.Context(), "Break-glass used: tenant admin granted", email+" was made a tenant admin from inside the tenant.")
		writeJSON(w, 200, map[string]string{"result": email + " is invited as tenant_admin; it binds on their next sign-in"})
	case "status":
		s.audit(r.Context(), "breakglass", "breakglass.status", "tenant/"+s.cfg.Tenant, "", nil)
		writeJSON(w, 200, map[string]any{"access": s.access(), "created": st.Created})
	default:
		writeErr(w, http.StatusNotFound, "actions: reset-idp, grant-admin, status")
	}
}

func (s *Server) alertAdmins(ctx context.Context, title, body string) {
	s.notifyEvent(ctx, store.Notification{Kind: "breakglass.used", Severity: "error", Title: title, Body: body, Link: "settings/access"})
}
