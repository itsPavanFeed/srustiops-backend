package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"
)

// runBreakglass talks to the tenant plane's loopback break-glass listener, so
// it works only from inside the tenant (kubectl exec into the tenant pod).
//
//	srustiops breakglass init                         create the credential (shown once)
//	srustiops breakglass reset-idp -code 123456       clear provider requirement, pins, MFA and session limits
//	srustiops breakglass grant-admin -code 123456 -email admin@acme.com
//	srustiops breakglass status -code 123456
func runBreakglass(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: srustiops breakglass init | status | reset-idp | grant-admin -email E  (with -code from the authenticator)")
	}
	action := args[0]
	fs := flag.NewFlagSet("breakglass", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9444", "the tenant plane's break-glass listener (loopback)")
	code := fs.String("code", "", "the current code from the break-glass authenticator")
	email := fs.String("email", "", "grant-admin: who becomes tenant admin")
	fs.Parse(args[1:])
	body, _ := json.Marshal(map[string]string{"code": *code, "email": *email})
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Post("http://"+*addr+"/breakglass/"+action, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("the break-glass listener is reachable only from inside the tenant: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	fmt.Println(string(bytes.TrimSpace(out)))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("refused (%d)", resp.StatusCode)
	}
	return nil
}
