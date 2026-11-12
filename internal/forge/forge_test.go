package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestForges(t *testing.T) {
	fake := NewFake("tok-123", map[string][]byte{"stacks/net/vpc.yaml": []byte("kind: VPC\n"), "README.md": []byte("hi")})
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx := context.Background()
	helper := func(dialect, op string, body any) map[string]any {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/_fake/"+dialect+"/"+op, bytes.NewReader(b))
		req.Header.Set("PRIVATE-TOKEN", "tok-123")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	forges := map[string]Forge{
		"gitlab":    NewGitLab(srv.URL+"/gitlab/api/v4", "acme/contracts", "tok-123", nil),
		"bitbucket": NewBitbucket(srv.URL+"/bitbucket/2.0", "acme/contracts", "tok-123", nil),
		"azure":     NewAzure(srv.URL+"/azure", "acme/infra/contracts", "tok-123", nil),
	}
	for dialect, f := range forges {
		t.Run(dialect, func(t *testing.T) {
			main, err := f.BranchSHA(ctx, "main")
			if err != nil || len(main) != 40 {
				t.Fatalf("branch: %q %v", main, err)
			}
			files, err := f.Files(ctx, main)
			if err != nil || string(files["stacks/net/vpc.yaml"]) != "kind: VPC\n" || len(files) != 2 {
				t.Fatalf("files: %v %v", files, err)
			}
			if names, err := f.ListDir(ctx, "stacks/net", "main"); err != nil || len(names) != 1 || names[0] != "vpc.yaml" {
				t.Fatalf("listdir: %v %v", names, err)
			}
			if names, err := f.ListDir(ctx, "stacks/none", "main"); err != nil || len(names) != 0 {
				t.Fatalf("missing dir: %v %v", names, err)
			}
			// Propose a change: branch, one commit (update, add, delete), pull request.
			if err := f.CreateBranch(ctx, "srustiops/change", main); err != nil {
				t.Fatalf("create branch: %v", err)
			}
			upd, add := []byte("kind: VPC\nspec: {cidr: 10.0.0.0/16}\n"), []byte("kind: SQS\n")
			head, err := f.Commit(ctx, "srustiops/change", "e2e change", map[string]*[]byte{"stacks/net/vpc.yaml": &upd, "stacks/net/queue.yaml": &add, "README.md": nil})
			if err != nil || head == "" || head == main {
				t.Fatalf("commit: %q %v", head, err)
			}
			if got, _ := f.Files(ctx, head); string(got["stacks/net/vpc.yaml"]) != string(upd) || string(got["stacks/net/queue.yaml"]) != "kind: SQS\n" || got["README.md"] != nil {
				t.Fatalf("after commit: %v", got)
			}
			pr, err := f.OpenPR(ctx, "srustiops/change", "main", "Add a queue", "body")
			if err != nil || pr.Number == 0 || pr.State != "open" || pr.BaseBranch != "main" {
				t.Fatalf("open pr: %+v %v", pr, err)
			}
			got, err := f.GetPR(ctx, pr.Number)
			if err != nil || got.HeadSHA != head || got.HeadBranch != "srustiops/change" || got.Fork {
				t.Fatalf("get pr: %+v %v (head %s)", got, err, head)
			}
			open, err := f.OpenPRs(ctx, "main")
			if err != nil || len(open) != 1 || open[0].HeadSHA != head {
				t.Fatalf("open prs: %+v %v", open, err)
			}
			if err := f.SetStatus(ctx, pr.Number, head, "pending", "srustiops/plan", "planning", "https://example.test/run"); err != nil {
				t.Fatalf("status: %v", err)
			}
			id, err := f.Comment(ctx, pr.Number, 0, "first")
			if err != nil || id == 0 {
				t.Fatalf("comment: %d %v", id, err)
			}
			if id2, err := f.Comment(ctx, pr.Number, id, "edited"); err != nil || id2 != id {
				t.Fatalf("edit comment: %d %v", id2, err)
			}
			if id3, err := f.Comment(ctx, pr.Number, 999999, "again"); err != nil || id3 == 999999 {
				t.Fatalf("a deleted comment is posted anew: %d %v", id3, err)
			}
			// A merge from an older commit is refused; from the head it squashes.
			helper(dialect, "commit", map[string]any{"branch": "srustiops/change", "files": map[string]string{"stacks/net/extra.yaml": "kind: X\n"}, "message": "more"})
			if _, err := f.Merge(ctx, pr.Number, head, "t", "m"); err == nil {
				t.Fatal("merge from a stale head was accepted")
			}
			latest, _ := f.GetPR(ctx, pr.Number)
			merged, err := f.Merge(ctx, pr.Number, latest.HeadSHA, "Add a queue (#1)", "applied first")
			if err != nil {
				t.Fatalf("merge: %v", err)
			}
			after, _ := f.GetPR(ctx, pr.Number)
			newMain, _ := f.BranchSHA(ctx, "main")
			if after.State != "merged" || (merged != "" && merged != newMain) {
				t.Fatalf("after merge: %+v merged %s main %s", after, merged, newMain)
			}
			if fs, _ := f.Files(ctx, newMain); fs["stacks/net/extra.yaml"] == nil {
				t.Fatal("main lacks the merged change")
			}
			if open, _ := f.OpenPRs(ctx, "main"); len(open) != 0 {
				t.Fatalf("still open: %+v", open)
			}
			// The fake saw the status and the comment.
			st := stateOf(t, srv.URL, dialect)
			p := st.PRs[jsonKey(pr.Number)]
			if len(p.Statuses) != 1 || len(p.Comments) != 2 {
				t.Fatalf("fake state: %+v", p)
			}
		})
	}
	// A wrong token is refused.
	if _, err := NewGitLab(srv.URL+"/gitlab/api/v4", "acme/contracts", "nope", nil).BranchSHA(ctx, "main"); err == nil {
		t.Fatal("a wrong token was accepted")
	}
}

type fakeState struct {
	PRs map[string]fakePR `json:"prs"`
}

func jsonKey(n int) string { b, _ := json.Marshal(n); return string(b) }

func stateOf(t *testing.T, base, dialect string) fakeState {
	req, _ := http.NewRequest(http.MethodGet, base+"/_fake/"+dialect+"/state", nil)
	req.Header.Set("PRIVATE-TOKEN", "tok-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var s fakeState
	json.NewDecoder(resp.Body).Decode(&s)
	return s
}
