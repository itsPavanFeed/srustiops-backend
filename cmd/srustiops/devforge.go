package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/itsPavanFeed/srustiops-backend/internal/forge"
)

// runDevForge serves an in-memory Git host speaking the GitLab, Bitbucket
// Cloud and Azure DevOps APIs the platform uses, for local development and
// tests. Each starts with branch main holding the files of -seed. Loopback only.
func runDevForge(ctx context.Context, args []string) error {
	fs_ := flag.NewFlagSet("dev-forge", flag.ExitOnError)
	listen := fs_.String("listen", "127.0.0.1:18992", "loopback address to listen on")
	token := fs_.String("token", "dev-forge-token", "the token every request must carry")
	seed := fs_.String("seed", "", "a directory whose files start on branch main")
	fs_.Parse(args)
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return errors.New("dev-forge listens on loopback only")
	}
	files := map[string][]byte{"README.md": []byte("contracts\n")}
	if *seed != "" {
		err := filepath.WalkDir(*seed, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(*seed, p)
			b, err := os.ReadFile(p)
			files[filepath.ToSlash(rel)] = b
			return err
		})
		if err != nil {
			return err
		}
	}
	srv := &http.Server{Addr: *listen, Handler: forge.NewFake(*token, files), ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); srv.Close() }()
	fmt.Printf("dev Git host at http://%s (GitLab /gitlab/api/v4, Bitbucket /bitbucket/2.0, Azure DevOps /azure)\n", *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
