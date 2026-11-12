package central

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
)

// A tenant's directory keys (see the tenant plane's linkkeys.go). Central pins
// them on first contact over the authenticated link and from then on:
//
//   - accepts a directory snapshot only if the pinned signing key signed it
//     and its sequence is newer than the last one;
//   - seals queued webhooks to the pinned encryption key;
//   - accepts a new signing key only when the pinned key signed it.

func verifySig(pubPEM string, msg []byte, sigB64 string) error {
	blk, _ := pem.Decode([]byte(pubPEM))
	if blk == nil {
		return errors.New("signing key is not PEM")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("signing key is not ECDSA")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// fetchTenantKeys reads the tenant's public keys and pins (or re-pins, after
// a signed rotation) them.
func (s *Server) fetchTenantKeys(ctx context.Context, t *Tenant) error {
	code, body, err := s.callTenantAs(ctx, t, s.system(t), http.MethodGet, "/api/v1/link/keys", nil)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("tenant answered %d", code)
	}
	var k struct {
		Sign    string `json:"sign_key"`
		Enc     string `json:"enc_key"`
		EncSig  string `json:"enc_sig"`
		PrevSig string `json:"prev_sig"`
	}
	if err := json.Unmarshal(body, &k); err != nil {
		return err
	}
	enc, err := base64.StdEncoding.DecodeString(k.Enc)
	if err != nil {
		return err
	}
	if err := verifySig(k.Sign, enc, k.EncSig); err != nil {
		return fmt.Errorf("encryption key not vouched for by the signing key: %w", err)
	}
	switch {
	case t.DirSignKey == "":
		s.audit(ctx, "system:link", "link.keys_pinned", "tenant/"+t.Slug, t.Slug, nil)
	case t.DirSignKey == k.Sign:
		if t.DirEncKey == k.Enc {
			return nil
		}
	default:
		if k.PrevSig == "" || verifySig(t.DirSignKey, []byte(k.Sign), k.PrevSig) != nil {
			s.audit(ctx, "system:link", "link.key_mismatch", "tenant/"+t.Slug, t.Slug, nil)
			return errors.New("the tenant presented a new directory key not signed by the pinned one")
		}
		s.audit(ctx, "system:link", "link.keys_rotated", "tenant/"+t.Slug, t.Slug, nil)
	}
	if err := s.store.PinTenantKeys(ctx, t.ID, k.Sign, k.Enc); err != nil {
		return err
	}
	t.DirSignKey, t.DirEncKey = k.Sign, k.Enc
	return nil
}

func (s *Server) tenantEncKey(t *Tenant) (*ecdh.PublicKey, error) {
	if t.DirEncKey == "" {
		return nil, errors.New("no encryption key pinned for this tenant yet")
	}
	b, err := base64.StdEncoding.DecodeString(t.DirEncKey)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

// openDirectory checks a signed directory snapshot and returns its payload.
func (s *Server) openDirectory(ctx context.Context, t *Tenant, raw []byte) ([]byte, error) {
	var env struct {
		Body json.RawMessage `json:"body"`
		Sig  string          `json:"sig"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Body) == 0 {
		return nil, errors.New("directory snapshot is not signed")
	}
	if t.DirSignKey == "" {
		if err := s.fetchTenantKeys(ctx, t); err != nil {
			return nil, err
		}
	}
	if err := verifySig(t.DirSignKey, env.Body, env.Sig); err != nil {
		return nil, fmt.Errorf("directory signature: %w", err)
	}
	var b struct {
		Tenant    string          `json:"tenant"`
		Seq       int64           `json:"seq"`
		Directory json.RawMessage `json:"directory"`
	}
	if err := json.Unmarshal(env.Body, &b); err != nil {
		return nil, err
	}
	if b.Tenant != t.Slug {
		return nil, errors.New("directory snapshot is for another tenant")
	}
	if !s.store.AdvanceDirectorySeq(ctx, t.ID, b.Seq) {
		return nil, errors.New("directory snapshot is older than the last one (replayed or out of order)")
	}
	return b.Directory, nil
}
