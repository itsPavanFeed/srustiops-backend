package central

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/secure"
)

func TestPlatformRootIsTheOnlyRecoveryCredential(t *testing.T) {
	f := newSocial(t)
	srv, st, front := testServer(t, "")
	srv.cfg.SSOTestURL = f.srv.URL
	key := make([]byte, 32)
	rand.Read(key)
	srv.cfg.MasterKey = base64.StdEncoding.EncodeToString(key)
	ctx := context.Background()

	// The database may already have its root (other tests share it).
	rootEmail := "root@platform.test"
	st.Pool().QueryRow(ctx, `SELECT email FROM users WHERE platform_root`).Scan(&rootEmail)
	rotate := func(email string) (string, error) {
		plain, _ := secure.NewToken("u")
		_, _, err := st.RotateRoot(ctx, email, "test", secure.HashToken(plain), time.Now().Add(time.Hour))
		return plain, err
	}
	first, err := rotate(rootEmail)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rotate(rootEmail)
	if err != nil {
		t.Fatal(err)
	}
	if status(t, front.URL+"/api/v1/me", first) != 401 || status(t, front.URL+"/api/v1/me", second) != 200 {
		t.Fatal("rotating the root must revoke its earlier token")
	}
	if _, err := rotate("someone-else@platform.test"); !errors.Is(err, ErrRootExists) {
		t.Fatalf("a second root: %v", err)
	}

	call := func(method, path, tok, body string) int {
		req, _ := http.NewRequest(method, front.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	// The root mints no further tokens.
	if c := call("POST", "/api/v1/me/tokens", second, `{"name":"extra","ttl_days":1}`); c != 403 {
		t.Fatalf("root personal token: %d", c)
	}
	// Platform admins are added by email and sign in with SSO; the root
	// cannot be removed.
	admin := fmt.Sprintf("ops%d@acme.test", time.Now().UnixNano())
	if c := call("PUT", "/api/v1/platform/admins/"+admin, second, ""); c != 200 {
		t.Fatalf("add platform admin: %d", c)
	}
	if c := call("DELETE", "/api/v1/platform/admins/"+rootEmail, second, ""); c != 422 && c != 404 {
		t.Fatalf("remove root: %d", c)
	}

	// SSO signs the platform admin in, never the root.
	sealer, _ := srv.sealer()
	p := &SSOProvider{ID: "google", ClientID: "123-abc.apps.googleusercontent.com", AllowedDomains: []string{}, AllowedOrgs: []string{}, Enabled: true, UpdatedBy: "test"}
	p.ClientSecret, _ = sealer.Seal([]byte("test-secret-123"), ssoAAD(p.ID))
	if err := st.PutSSOProvider(ctx, p); err != nil {
		t.Fatal(err)
	}
	loc := socialLoginFlow(t, front.URL, "google", f, admin, "", true)
	if !strings.HasPrefix(loc, "/#/sso/") {
		t.Fatalf("platform admin SSO: %s", loc)
	}
	session := exchange(t, front.URL, strings.TrimPrefix(loc, "/#/sso/"), 200)
	if c := call("POST", "/api/v1/me/tokens", session, `{"name":"extra","ttl_days":1}`); c != 403 {
		t.Fatalf("platform admin personal token: %d", c)
	}
	if loc := socialLoginFlow(t, front.URL, "google", f, rootEmail, "", true); !strings.Contains(loc, "root_uses_recovery_token") {
		t.Fatalf("root SSO: %s", loc)
	}
	// Removing the platform admin ends their SSO session.
	if c := call("DELETE", "/api/v1/platform/admins/"+admin, second, ""); c != 200 {
		t.Fatalf("remove platform admin: %d", c)
	}
	if status(t, front.URL+"/api/v1/me", session) != 401 {
		t.Fatal("removed platform admin keeps a session")
	}
}
