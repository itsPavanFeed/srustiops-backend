package api

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/link"
	"github.com/itsPavanFeed/srustiops-backend/internal/store"
)

// The tenant's directory keys, separate from the link agent's key:
//
//	signing (ECDSA P-256)  signs every directory snapshot it gives central
//	encryption (X25519)    what central seals queued webhooks to while the
//	                       tenant is offline, so central cannot read them
//
// Central pins the public keys on first contact over the authenticated link;
// a new signing key is accepted only when the old key signs it.

const linkKeysSetting = "link_keys"

type linkKeys struct {
	sign *ecdsa.PrivateKey
	enc  *ecdh.PrivateKey
	// prevSig: the previous signing key's signature over this signing key,
	// present after a rotation.
	prevSig string
}

type sealedKeys struct {
	Sign    []byte `json:"sign"` // sealed PKCS#8
	Enc     []byte `json:"enc"`  // sealed X25519 private key
	PrevSig string `json:"prev_sig,omitempty"`
}

func (s *Server) loadLinkKeys(ctx context.Context) error {
	var sk sealedKeys
	ok, err := s.store.Setting(ctx, linkKeysSetting, &sk)
	if err != nil {
		return err
	}
	if !ok {
		sign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(sign)
		if sk.Sign, err = s.sealer.Seal(der, []byte(linkKeysSetting+":sign")); err != nil {
			return err
		}
		if sk.Enc, err = s.sealer.Seal(enc.Bytes(), []byte(linkKeysSetting+":enc")); err != nil {
			return err
		}
		if err := s.store.PutSetting(ctx, linkKeysSetting, sk, "system:link"); err != nil {
			return err
		}
	}
	der, err := s.sealer.Open(sk.Sign, []byte(linkKeysSetting+":sign"))
	if err != nil {
		return err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	raw, err := s.sealer.Open(sk.Enc, []byte(linkKeysSetting+":enc"))
	if err != nil {
		return err
	}
	enc, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return err
	}
	sign, ok2 := k.(*ecdsa.PrivateKey)
	if !ok2 {
		return errors.New("directory signing key is not ECDSA")
	}
	s.keys = &linkKeys{sign: sign, enc: enc, prevSig: sk.PrevSig}
	return nil
}

func (s *Server) signBytes(b []byte) string {
	sum := sha256.Sum256(b)
	sig, _ := ecdsa.SignASN1(rand.Reader, s.keys.sign, sum[:])
	return base64.StdEncoding.EncodeToString(sig)
}

// linkKeysView gives central the public keys to pin.
func (s *Server) linkKeysView(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	der, _ := x509.MarshalPKIXPublicKey(&s.keys.sign.PublicKey)
	signPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	enc := s.keys.enc.PublicKey().Bytes()
	writeJSON(w, 200, map[string]string{
		"sign_key": signPEM,
		"enc_key":  base64.StdEncoding.EncodeToString(enc),
		"enc_sig":  s.signBytes(enc), // the encryption key, vouched for by the signing key
		"prev_sig": s.keys.prevSig,
	})
}

// signedDirectory wraps a directory snapshot with a sequence number and a
// signature, so central rejects forged, replayed or out-of-order snapshots.
func (s *Server) signedDirectory(payload any) map[string]any {
	seq := time.Now().UnixNano()
	body, _ := json.Marshal(map[string]any{"tenant": s.cfg.Tenant, "seq": seq, "directory": payload})
	return map[string]any{"body": json.RawMessage(body), "sig": s.signBytes(body)}
}

// queuedWebhook opens a webhook central kept sealed to this tenant while it
// was offline, and handles it like a live delivery.
func (s *Server) queuedWebhook(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Path     string `json:"path"`
		Envelope []byte `json:"envelope"`
	}
	if !decode(w, r, &b) {
		return
	}
	plain, err := link.OpenWith(s.keys.enc, []byte(s.cfg.Tenant+"|"+b.Path), b.Envelope)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "the queued delivery does not open with this tenant's key")
		return
	}
	var d struct {
		Headers map[string]string `json:"headers"`
		Body    []byte            `json:"body"`
	}
	if err := json.Unmarshal(plain, &d); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed queued delivery")
		return
	}
	req := httptest.NewRequest(http.MethodPost, b.Path, strings.NewReader(string(d.Body))).WithContext(r.Context())
	for k, v := range d.Headers {
		req.Header.Set(k, v)
	}
	switch {
	case b.Path == "/api/v1/webhooks/github":
		s.githubWebhook(w, req)
	case strings.HasPrefix(b.Path, "/api/v1/webhooks/cloud/"):
		req.SetPathValue("source", strings.TrimPrefix(b.Path, "/api/v1/webhooks/cloud/"))
		s.cloudEventHook(w, req)
	default:
		writeErr(w, http.StatusNotFound, "unknown webhook path")
	}
}

// linkEvent records something the link saw for this tenant, such as
// webhooks dropped from central's queue while it was offline.
func (s *Server) linkEvent(w http.ResponseWriter, r *http.Request) {
	if !central(w, r) {
		return
	}
	var b struct {
		Type   string `json:"type"`
		Count  int    `json:"count"`
		Detail string `json:"detail"`
	}
	if !decode(w, r, &b) {
		return
	}
	s.audit(r.Context(), "system:link", "link."+b.Type, "tenant/"+s.cfg.Tenant, "", b)
	if b.Type == "webhooks_dropped" {
		s.notifyEvent(r.Context(), store.Notification{Kind: "link.webhooks_dropped", Severity: "warning",
			Title: "Webhooks were dropped while this tenant was offline",
			Body:  b.Detail + " Resync from the sources (for example re-run a pull request check or a contracts sync).", Link: "integrations"})
	}
	w.WriteHeader(http.StatusNoContent)
}
