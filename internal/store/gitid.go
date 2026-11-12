package store

import (
	"context"
	"strings"
	"time"
)

// SetPRProposer records who opened a pull request from SrustiOps (it is
// opened on the host with the workspace's token, not as them).
func (s *Store) SetPRProposer(ctx context.Context, number int, subject string) error {
	_, err := s.db.Exec(ctx, `INSERT INTO pr_proposers (repo_key, number, subject) VALUES ($1, $2, $3)
		ON CONFLICT (repo_key, number) DO UPDATE SET subject = $3`, s.prKey(), number, subject)
	return err
}

// GitIdentity links a login on a Git host to a person.
type GitIdentity struct {
	Provider  string    `json:"provider"`
	Login     string    `json:"login"`
	Subject   string    `json:"subject"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) ListGitIdentities(ctx context.Context, subject string) ([]*GitIdentity, error) {
	rows, err := s.db.Query(ctx, `SELECT provider, login, subject, created_by, created_at FROM git_identities
		WHERE $1 = '' OR subject = $1 ORDER BY subject, provider, login`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*GitIdentity{}
	for rows.Next() {
		var g GitIdentity
		if err := rows.Scan(&g.Provider, &g.Login, &g.Subject, &g.CreatedBy, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

// PutGitIdentity links a login; a login belongs to one person.
func (s *Store) PutGitIdentity(ctx context.Context, g *GitIdentity) error {
	tag, err := s.db.Exec(ctx, `INSERT INTO git_identities (provider, login, subject, created_by) VALUES ($1, lower($2), $3, $4)
		ON CONFLICT (provider, login) DO NOTHING`, g.Provider, g.Login, g.Subject, g.CreatedBy)
	if err == nil && tag.RowsAffected() == 0 {
		var cur string
		s.db.QueryRow(ctx, `SELECT subject FROM git_identities WHERE provider = $1 AND login = lower($2)`, g.Provider, g.Login).Scan(&cur)
		if cur != g.Subject {
			return ErrConflict
		}
	}
	return err
}

func (s *Store) DeleteGitIdentity(ctx context.Context, provider, login string) (*GitIdentity, error) {
	var g GitIdentity
	err := s.db.QueryRow(ctx, `DELETE FROM git_identities WHERE provider = $1 AND login = $2 RETURNING provider, login, subject, created_by, created_at`,
		provider, strings.ToLower(login)).Scan(&g.Provider, &g.Login, &g.Subject, &g.CreatedBy, &g.CreatedAt)
	return &g, NotFound(err)
}
