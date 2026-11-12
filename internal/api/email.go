package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// ---- notification preferences and email ----
//
// Each person chooses which kinds of notification they see in the bell and
// which reach them by email. Email is opt-in per person and goes to their
// sign-in address, only about business units they could see when last
// active. A tenant admin configures the mail server (SMTP) under
// Integrations → Email; messages queue in an outbox one replica sends from.

// notificationKinds are the kinds people can mute or have emailed.
var notificationKinds = []struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Group string `json:"group"`
}{
	{"run.awaiting_approval", "A plan waits for my approval step", "Runs"},
	{"run.approved", "A plan was approved", "Runs"},
	{"run.applied", "An apply finished", "Runs"},
	{"run.failed", "A run failed", "Runs"},
	{"run.policy_failed", "A plan failed policy", "Runs"},
	{"run.cancelled", "A run was cancelled", "Runs"},
	{"run.discarded", "A plan was discarded", "Runs"},
	{"run.no_changes", "A plan found nothing to change", "Runs"},
	{"run.auto_approved", "A plan was approved automatically", "Runs"},
	{"run.overridden", "A policy result was overridden", "Runs"},
	{"run.state_refresh", "State was refreshed", "Runs"},
	{"drift.detected", "Drift detected", "Drift and changes"},
	{"stack.live_change", "A resource changed outside SrustiOps", "Drift and changes"},
	{"pr.planned", "A pull request was planned", "Pull requests and releases"},
	{"pr.merged", "A pull request was merged", "Pull requests and releases"},
	{"release.ready", "A release is ready", "Pull requests and releases"},
	{"release.requested", "A release waits for approval", "Pull requests and releases"},
	{"release.deployed", "A release was activated", "Pull requests and releases"},
	{"release.rejected", "A release was rejected", "Pull requests and releases"},
	{"release.failed", "A release build failed", "Pull requests and releases"},
	{"release.merge_failed", "Merging a release failed", "Pull requests and releases"},
	{"integration.change", "An integration change waits for approval", "Workspace"},
	{"contracts.sync_failed", "Syncing the contracts repository failed", "Workspace"},
	{"integration.audit_export_failed", "Exporting the audit log failed", "Workspace"},
	{"backup.failed", "A scheduled backup failed", "Workspace"},
	{"backup.drill_failed", "A restore drill failed", "Workspace"},
	{"breakglass.used", "The break-glass admin was used", "Workspace"},
	{"link.webhooks_dropped", "Webhooks were dropped while offline", "Workspace"},
}

func knownKind(k string) bool {
	for _, x := range notificationKinds {
		if x.Kind == k {
			return true
		}
	}
	return false
}

func (s *Server) mutedKinds(ctx context.Context, subject string) []string {
	p, err := s.store.NotificationPrefs(ctx, subject)
	if err != nil {
		return nil
	}
	return p.Muted
}

func (s *Server) getNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.NotificationPrefs(r.Context(), user(r).Subject)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"preferences": p, "kinds": notificationKinds, "email_configured": s.emailConfig(r.Context()) != nil,
		"email_to": emailAddress(user(r).Subject)})
}

func emailAddress(subject string) string {
	if a, err := mail.ParseAddress(subject); err == nil && !strings.HasPrefix(subject, "system:") {
		return a.Address
	}
	return ""
}

func (s *Server) putNotificationPrefs(w http.ResponseWriter, r *http.Request) {
	u := user(r)
	var b store.NotificationPrefs
	if !decode(w, r, &b) {
		return
	}
	for _, k := range append(append([]string{}, b.Muted...), b.EmailKinds...) {
		if !knownKind(k) {
			writeErr(w, 422, "unknown notification kind "+k)
			return
		}
	}
	if len(b.Muted) > 100 || len(b.EmailKinds) > 100 {
		writeErr(w, 422, "too many kinds")
		return
	}
	if b.EmailEnabled && emailAddress(u.Subject) == "" {
		writeErr(w, 422, "this sign-in has no email address to send to")
		return
	}
	b.Subject = u.Subject
	if err := s.store.PutNotificationPrefs(r.Context(), &b, u.VisibleBUs()); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.getNotificationPrefs(w, r)
}

// emailNotification queues the email for everyone who asked for this kind.
func (s *Server) emailNotification(ctx context.Context, n *store.Notification) {
	if s.emailConfig(ctx) == nil {
		return
	}
	to, err := s.store.EmailRecipients(ctx, n.Kind, n.BU)
	if err != nil || len(to) == 0 {
		return
	}
	subject := "[SrustiOps · " + s.cfg.Tenant + "] " + n.Title
	body := n.Title + "\n\n"
	if n.Body != "" {
		body += n.Body + "\n\n"
	}
	if n.BU != "" {
		body += "Business unit: " + n.Entity + " / " + n.BU + "\n"
	}
	if n.Link != "" {
		body += "Open in SrustiOps: " + s.consoleURL(n.Link) + "\n"
	}
	body += "\nYou get this because you turned on email for “" + kindLabel(n.Kind) + "”. Change it under your notification preferences.\n"
	for _, addr := range to {
		s.store.EnqueueEmail(ctx, addr, subject, body)
	}
	s.kickMailer()
}

func kindLabel(k string) string {
	for _, x := range notificationKinds {
		if x.Kind == k {
			return x.Label
		}
	}
	return k
}

// ---- the mail server (Integrations → Email) ----

type emailSettings struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls | tls | none (loopback only)
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
}

const (
	emailSetting = "email"
	emailAAD     = "email-smtp"
	mailerLock   = 7302
)

func (s *Server) emailConfig(ctx context.Context) *emailSettings {
	if p := s.emailSnap.Load(); p != nil {
		if p.Host == "" {
			return nil
		}
		return p
	}
	var e emailSettings
	if b, ok := s.openSetting(ctx, emailSetting, emailAAD); ok {
		json.Unmarshal(b, &e)
	}
	s.emailSnap.Store(&e)
	if e.Host == "" {
		return nil
	}
	return &e
}

func (e *emailSettings) validate() []string {
	var probs []string
	if e.Host == "" || strings.ContainsAny(e.Host, " /:") {
		probs = append(probs, "host must be a host name or address")
	}
	if e.Port == 0 {
		e.Port = 587
	}
	if e.Port < 1 || e.Port > 65535 {
		probs = append(probs, "port is invalid")
	}
	if e.Security == "" {
		e.Security = "starttls"
	}
	switch e.Security {
	case "starttls", "tls":
	case "none":
		if !isLoopback(e.Host) {
			probs = append(probs, `security "none" is only allowed for a mail server on this machine (localhost)`)
		}
	default:
		probs = append(probs, `security must be "starttls", "tls" or "none"`)
	}
	if _, err := mail.ParseAddress(e.From); err != nil {
		probs = append(probs, "from must be an email address")
	}
	if (e.Username == "") != (e.Password == "") {
		probs = append(probs, "give both a username and a password, or neither")
	}
	return probs
}

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) getEmailIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	e := s.emailConfig(r.Context())
	pending, failed, lastSent, lastErr := s.store.EmailStats(r.Context())
	out := map[string]any{"configured": e != nil, "pending": pending, "failed": failed, "last_sent": lastSent, "last_error": lastErr}
	if e != nil {
		out["host"], out["port"], out["security"], out["from"], out["username"], out["has_password"] = e.Host, e.Port, e.Security, e.From, e.Username, e.Password != ""
	}
	writeJSON(w, 200, out)
}

func (s *Server) putEmailIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b emailSettings
	if !decode(w, r, &b) {
		return
	}
	cur := s.emailConfig(r.Context())
	if b.Password == "" && cur != nil && b.Username == cur.Username {
		b.Password = cur.Password // keep the stored password
	}
	if probs := b.validate(); len(probs) > 0 {
		writeErr(w, 422, "invalid mail server", probs...)
		return
	}
	if s.dryRun(w, r) {
		return
	}
	raw, _ := json.Marshal(b)
	if err := s.sealSetting(r.Context(), emailSetting, emailAAD, raw, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.emailSnap.Store(&b)
	s.audit(r.Context(), user(r).Actor(), "integration.email.configure", "integration/email", "", map[string]any{"host": b.Host, "port": b.Port, "security": b.Security, "from": b.From, "auth": b.Username != ""})
	s.getEmailIntegration(w, r)
}

func (s *Server) deleteEmailIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	if s.dryRun(w, r) {
		return
	}
	if err := s.store.DeleteSetting(r.Context(), emailSetting); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.emailSnap.Store(&emailSettings{})
	s.audit(r.Context(), user(r).Actor(), "integration.email.remove", "integration/email", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

// testEmailIntegration sends one message to the caller now (not through the outbox).
func (s *Server) testEmailIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	e := s.emailConfig(r.Context())
	if e == nil {
		writeErr(w, http.StatusConflict, "no mail server is configured")
		return
	}
	to := emailAddress(user(r).Subject)
	if to == "" {
		writeErr(w, 422, "your sign-in has no email address to send the test to")
		return
	}
	if err := sendMail(e, to, "[SrustiOps · "+s.cfg.Tenant+"] Test email", "Email from SrustiOps works.\n\nSent by "+user(r).Subject+" from Integrations → Email.\n"); err != nil {
		writeErr(w, http.StatusBadGateway, "the mail server refused: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"sent_to": to})
}

// sendMail delivers one plain-text message.
func sendMail(e *emailSettings, to, subject, body string) error {
	addr := net.JoinHostPort(e.Host, strconv.Itoa(e.Port))
	from, _ := mail.ParseAddress(e.From)
	tcfg := &tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	d := &net.Dialer{Timeout: 15 * time.Second}
	if e.Security == "tls" {
		conn, err := tls.DialWithDialer(d, "tcp", addr, tcfg)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, e.Host); err != nil {
			return err
		}
	} else {
		conn, err := d.Dial("tcp", addr)
		if err != nil {
			return err
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		if c, err = smtp.NewClient(conn, e.Host); err != nil {
			return err
		}
		if e.Security == "starttls" {
			if err := c.StartTLS(tcfg); err != nil {
				c.Close()
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}
	defer c.Close()
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	msg := "From: " + from.String() + "\r\nTo: " + to + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", subject) +
		"\r\nDate: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n" +
		"Auto-Submitted: auto-generated\r\n\r\n" + strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (s *Server) kickMailer() {
	select {
	case s.mailKick <- struct{}{}:
	default:
	}
}

// mailer sends queued emails on whichever replica holds the mailer lock,
// retrying failures up to five times.
func (s *Server) mailer(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.mailKick:
		case <-prune.C:
			s.store.PruneEmails(ctx)
			continue
		}
		e := s.emailConfig(ctx)
		if e == nil {
			continue
		}
		s.store.TryLock(ctx, mailerLock, func(ctx context.Context) {
			pending, err := s.store.PendingEmails(ctx, 50)
			if err != nil {
				return
			}
			for _, m := range pending {
				if err := sendMail(e, m.To, m.Subject, m.Body); err != nil {
					s.store.EmailFailed(ctx, m.ID, err.Error())
					s.log.Warn("sending an email failed", "attempt", m.Attempts+1, "err", err)
					continue
				}
				s.store.EmailSent(ctx, m.ID)
			}
		})
	}
}

var _ = slices.Contains[[]string]
