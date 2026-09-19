// Package effects performs the effect an allowed action names, with
// credentials the hands never see. This is the mediation the standard asks
// for (C7.1.4a): the credentials and the transport for the effect are held
// inside the attesting environment, which emits the request itself.
package effects

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/policy"
)

// Outcome of an effect: what the tool answered, never a secret.
type Outcome struct {
	OK     bool           `json:"ok"`
	Detail map[string]any `json:"detail,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// Adapter performs one kind of effect.
type Adapter interface {
	Kinds() []string
	Perform(ctx context.Context, a policy.Action) Outcome
}

// GitHub performs workflow.dispatch, branch.push, branch.delete, pull.open, pull.ready and
// preview.push on owner/repo resources, as the
// gateway's GitHub App when github-app-id and github-app-key are in the secrets
// directory (see githubapp.go), else with a token per owner read from the secrets
// directory as github-token-<owner>.
type GitHub struct {
	SecretsDir string
	Client     *http.Client
	Base       string // https://api.github.com
	// Reviewer, when set, is asked to review every pull request the gateway opens or
	// marks ready. A request, not a permission: it changes who gets notified, nothing
	// about what may happen, so a failure to request is noted in the outcome and does
	// not fail the effect.
	Reviewer string
}

func (g GitHub) Kinds() []string {
	return []string{"workflow.dispatch", "branch.push", "branch.delete", "pull.open", "pull.ready", "issue.open", policy.PreviewPushKind}
}

// FileChange is one file of a branch.push: the path and the full new content. The runner
// in the project's CI computes the change and hands it back instead of pushing; the
// gateway pushes with its own credential, so no write to a repository escapes judgement.
type FileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"` // base64
	// Executable keeps a script's bit (since v0.15.0: the rehearsal script arrived as a
	// plain file and the operator's next `rehearse.sh upgrade` would have been refused).
	// Part of the digest only when true, so a hand that never sets it digests as before.
	Executable bool `json:"executable,omitempty"`
	// Delete removes the path instead of writing it (since v0.16.0). Content must be
	// empty. Twice on 2026-09-12 a hand could add a file but not take one away: two
	// copies of a measurement landed at the wrong path and had to be removed by the
	// operator, and a rename was a person's job. A tree entry with a null sha is how
	// GitHub's tree API deletes; that is all this is.
	Delete bool `json:"delete,omitempty"`
}

// FilesDigest is what params.files_sha256 must equal: the canonical digest of the files.
func FilesDigest(files []FileChange) (string, error) {
	items := make([]map[string]any, len(files))
	for i, f := range files {
		items[i] = map[string]any{"path": f.Path, "content": f.Content}
		if f.Executable {
			items[i]["executable"] = true
		}
		if f.Delete {
			items[i]["delete"] = true
		}
	}
	return canonical.Digest(items)
}

// DecodeFiles reads the attachment of a branch.push, whatever JSON shape it arrived in.
func DecodeFiles(v any) ([]FileChange, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var files []FileChange
	if err := json.Unmarshal(raw, &files); err != nil {
		return nil, err
	}
	for _, f := range files {
		if f.Path == "" || strings.HasPrefix(f.Path, "/") || strings.Contains(f.Path, "..") {
			return nil, fmt.Errorf("file path %q is not a plain repository path", f.Path)
		}
		if f.Delete && f.Content != "" {
			return nil, fmt.Errorf("file %s: a deletion carries no content", f.Path)
		}
		if _, err := base64.StdEncoding.DecodeString(f.Content); err != nil {
			return nil, fmt.Errorf("file %s: content is not base64", f.Path)
		}
	}
	return files, nil
}

// token reads the credential for a repository owner. The file is named by the owner in
// lower case: GitHub compares owners case-insensitively, the grants name them as the
// repositories spell them (ShaneDeconinck, Hoet-design), and the boot script on the VM
// fetches the secrets under lower-case names. The first proposal of the workbench on
// 2026-09-11 was allowed, recorded, and then not performed: "no GitHub token for
// ShaneDeconinck", while github-token-shanedeconinck sat right there.
func (g GitHub) token(owner string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(g.SecretsDir, "github-token-"+strings.ToLower(owner)))
	if err != nil {
		return "", fmt.Errorf("no GitHub token for %s in the gateway's secrets", owner)
	}
	return strings.TrimSpace(string(raw)), nil
}

// credential is the token an effect on this owner is sent with, and whether it is the
// App's (see githubapp.go). The App first when it is configured and installed on the
// owner; the owner's own token when the App is not installed there; a refusal naming
// both roads when neither is there.
func (g GitHub) credential(ctx context.Context, client *http.Client, base, owner string) (token string, asApp bool, err error) {
	app, ok, err := g.appOf()
	if err != nil {
		return "", false, err
	}
	if ok {
		token, err := g.appToken(ctx, app, client, base, owner)
		if err == nil {
			return token, true, nil
		}
		if !errors.Is(err, errNotInstalled) {
			return "", false, err
		}
		token, fileErr := g.token(owner)
		if fileErr != nil {
			return "", false, fmt.Errorf("the App is not installed on %s and there is no github-token-%s either", owner, strings.ToLower(owner))
		}
		return token, false, nil
	}
	token, err = g.token(owner)
	return token, false, err
}

func (g GitHub) Perform(ctx context.Context, a policy.Action) Outcome {
	owner, repo, ok := strings.Cut(a.Resource, "/")
	if !ok || owner == "" || repo == "" {
		return Outcome{Error: "resource is not owner/repo"}
	}
	base := g.Base
	if base == "" {
		base = "https://api.github.com"
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	token, asApp, err := g.credential(ctx, client, base, owner)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	// Which road carried the effect, in the record. On 16 September 2026 the first effect
	// after the App went live still went out on an owner's token, because one of the two
	// App secrets had no version; the fallback did what it should, and nothing said so
	// except a serial log nobody reads. The road belongs beside the result.
	via := "owner-token"
	if asApp {
		via = "app"
	}
	done := func(detail map[string]any) Outcome {
		detail["via"] = via
		return Outcome{OK: true, Detail: detail}
	}
	call := func(method, path string, body any) (int, map[string]any, error) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, &buf)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return res.StatusCode, out, nil
	}
	switch a.Kind {
	case "workflow.dispatch":
		workflow, _ := a.Params["workflow"].(string)
		ref, _ := a.Params["ref"].(string)
		if workflow == "" || ref == "" {
			return Outcome{Error: "workflow.dispatch needs params.workflow and params.ref"}
		}
		inputs, _ := a.Params["inputs"].(map[string]any)
		status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/dispatches", owner, repo, workflow), map[string]any{"ref": ref, "inputs": inputs})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		carried := true
		if status == 422 && strings.Contains(fmt.Sprint(body["message"]), "Unexpected inputs") {
			// The workflow declares no evidence inputs yet: dispatch without them, and
			// say so. The far end cannot refuse what it was never handed; the outcome
			// names the gap so the rollout is visible per repository.
			trimmed := map[string]any{}
			for k, v := range inputs {
				if k != "evidence" && k != "capability" {
					trimmed[k] = v
				}
			}
			carried = false
			status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/actions/workflows/%s/dispatches", owner, repo, workflow), map[string]any{"ref": ref, "inputs": trimmed})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
		}
		if status != 204 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d: %v", status, body["message"])}
		}
		return done(map[string]any{"status": status, "evidence_carried": carried})
	case "branch.push":
		branch, _ := a.Params["branch"].(string)
		baseSHA, _ := a.Params["base_sha"].(string)
		message, _ := a.Params["message"].(string)
		want, _ := a.Params["files_sha256"].(string)
		if branch == "" || baseSHA == "" || want == "" {
			return Outcome{Error: "branch.push needs params.branch, params.base_sha and params.files_sha256"}
		}
		files, err := DecodeFiles(a.Attached["files"])
		if err != nil || len(files) == 0 {
			return Outcome{Error: "branch.push needs the files attached: " + fmt.Sprint(err)}
		}
		if got, _ := FilesDigest(files); got != want {
			return Outcome{Error: "the attached files do not match params.files_sha256"}
		}
		if message == "" {
			message = "Security updates"
		}
		// The base commit's tree, so the new tree changes only the files given.
		status, body, err := call("GET", fmt.Sprintf("/repos/%s/%s/git/commits/%s", owner, repo, baseSHA), nil)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 200 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the base commit: %v", status, body["message"])}
		}
		tree, _ := body["tree"].(map[string]any)
		baseTree, _ := tree["sha"].(string)
		if baseTree == "" {
			return Outcome{Error: "the base commit has no tree"}
		}
		entries := make([]map[string]any, 0, len(files))
		for _, f := range files {
			if f.Delete {
				entries = append(entries, map[string]any{"path": f.Path, "mode": "100644", "type": "blob", "sha": nil})
				continue
			}
			status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/git/blobs", owner, repo), map[string]any{"content": f.Content, "encoding": "base64"})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if status != 201 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d for blob %s: %v", status, f.Path, body["message"])}
			}
			mode := "100644"
			if f.Executable {
				mode = "100755"
			}
			entries = append(entries, map[string]any{"path": f.Path, "mode": mode, "type": "blob", "sha": body["sha"]})
		}
		status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/trees", owner, repo), map[string]any{"base_tree": baseTree, "tree": entries})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the tree: %v", status, body["message"])}
		}
		newTree, _ := body["sha"].(string)
		commitBody := map[string]any{"message": message, "tree": newTree, "parents": []string{baseSHA}}
		if !asApp {
			// Under an owner's token GitHub would stamp the owner as author; say who it
			// really was. Under the App, say nothing: GitHub then stamps <app>[bot] as
			// author and committer, which is the attribution this whole file is for.
			commitBody["author"] = map[string]any{"name": "elixir", "email": "elixir@abovebeyond.ai"}
		}
		status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/commits", owner, repo), commitBody)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the commit: %v", status, body["message"])}
		}
		commit, _ := body["sha"].(string)
		status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo), map[string]any{"ref": "refs/heads/" + branch, "sha": commit})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the branch: %v", status, body["message"])}
		}
		return done(map[string]any{"branch": branch, "commit": commit, "base": baseSHA, "files": len(files)})
	case policy.PreviewPushKind:
		// The one branch a preview site tracks, set to a pull request's head. A forced
		// update, because the preview moves from one pull request to the next and their
		// heads share no history; forced on this branch only, which the adapter holds to
		// as the policy does, so no grant and no parameter can turn this into a push
		// elsewhere. The previous head is in the record: what the preview showed until now.
		branch, _ := a.Params["branch"].(string)
		sha, _ := a.Params["sha"].(string)
		if branch != policy.PreviewBranch {
			return Outcome{Error: policy.PreviewPushKind + " sets the branch named " + policy.PreviewBranch + " and no other"}
		}
		if !commitID.MatchString(sha) {
			return Outcome{Error: policy.PreviewPushKind + " needs params.sha, the full commit id"}
		}
		detail := map[string]any{"branch": branch, "commit": sha}
		if n, ok := wholeNumber(a.Params["pull"]); ok {
			detail["pull"] = n
		}
		if head, _ := a.Params["head"].(string); head != "" {
			detail["head"] = head
		}
		status, body, err := call("GET", fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s", owner, repo, branch), nil)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		switch status {
		case 200:
			object, _ := body["object"].(map[string]any)
			detail["previous"] = object["sha"]
			status, body, err = call("PATCH", fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branch), map[string]any{"sha": sha, "force": true})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if status != 200 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d for the branch: %v", status, body["message"])}
			}
			detail["created"] = false
		case 404:
			// The site's first preview: the branch does not exist yet and is made here.
			status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/refs", owner, repo), map[string]any{"ref": "refs/heads/" + branch, "sha": sha})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if status != 201 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d for the branch: %v", status, body["message"])}
			}
			detail["created"] = true
		default:
			return Outcome{Error: fmt.Sprintf("GitHub answered %d reading the branch: %v", status, body["message"])}
		}
		return done(detail)
	case "branch.delete":
		branch, _ := a.Params["branch"].(string)
		if branch == "" || !strings.HasPrefix(branch, "elixir/") {
			// Only branches of the agent's own naming: the gateway deletes what it pushed, never a person's branch.
			return Outcome{Error: "branch.delete needs params.branch under elixir/"}
		}
		status, body, err := call("DELETE", fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s", owner, repo, branch), nil)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 204 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the branch: %v", status, body["message"])}
		}
		return done(map[string]any{"branch": branch, "deleted": true})
	case "pull.open":
		head, _ := a.Params["branch"].(string)
		basis, _ := a.Params["base"].(string)
		title, _ := a.Params["title"].(string)
		text, _ := a.Params["body"].(string)
		if head == "" || basis == "" || title == "" {
			return Outcome{Error: "pull.open needs params.branch, params.base and params.title"}
		}
		draft, _ := a.Params["draft"].(bool)
		status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), map[string]any{"head": head, "base": basis, "title": title, "body": text, "draft": draft})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d: %v", status, body["message"])}
		}
		detail := map[string]any{"url": body["html_url"], "number": body["number"], "draft": draft}
		if n, ok := wholeNumber(body["number"]); ok {
			g.requestReview(call, owner, repo, n, detail)
		}
		return done(detail)
	case "issue.open":
		// An issue is a finding that wants a person's attention: title, body, labels. The
		// finding itself lives in the repository (docs/bedrijfsregels/bevindingen); this is
		// its mirror, so the body carries the path and the record like a pull request does.
		title, _ := a.Params["title"].(string)
		text, _ := a.Params["body"].(string)
		if title == "" {
			return Outcome{Error: "issue.open needs params.title"}
		}
		payload := map[string]any{"title": title, "body": text}
		if raw, ok := a.Params["labels"].([]any); ok && len(raw) > 0 {
			labels := []string{}
			for _, v := range raw {
				if s, ok := v.(string); ok && s != "" {
					labels = append(labels, s)
				}
			}
			if len(labels) > 0 {
				payload["labels"] = labels
			}
		}
		status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/issues", owner, repo), payload)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d: %v", status, body["message"])}
		}
		return done(map[string]any{"url": body["html_url"], "number": body["number"]})
	case "pull.ready":
		// Only a draft of the gateway's own making: its head is a branch under elixir/
		// and its body carries the footer the gateway wrote. A person's draft is never
		// marked ready by a machine, and a body without our footer is not ours.
		number, ok := wholeNumber(a.Params["number"])
		if !ok {
			return Outcome{Error: "pull.ready needs params.number"}
		}
		status, body, err := call("GET", fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number), nil)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 200 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the pull request: %v", status, body["message"])}
		}
		head, _ := body["head"].(map[string]any)
		ref, _ := head["ref"].(string)
		if !strings.HasPrefix(ref, "elixir/") {
			return Outcome{Error: "pull.ready is for a pull request on a branch under elixir/, not " + ref}
		}
		old, _ := body["body"].(string)
		mark := strings.Index(old, FooterMark)
		if mark < 0 {
			return Outcome{Error: "the pull request carries no evidence footer of the gateway's"}
		}
		nodeID, _ := body["node_id"].(string)
		if text, given := a.Params["body"].(string); given {
			// The new body, then the footer as it was: the record that opened the draft
			// stays the one the merge check reads; this record is in the chain.
			status, res, err := call("PATCH", fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, number), map[string]any{"body": strings.TrimRight(text, "\n") + "\n\n" + old[mark:]})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if status != 200 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d for the body: %v", status, res["message"])}
			}
		}
		if isDraft, _ := body["draft"].(bool); isDraft {
			// Marking ready for review exists only in the GraphQL API.
			status, res, err := call("POST", "/graphql", map[string]any{
				"query":     "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { isDraft } } }",
				"variables": map[string]any{"id": nodeID},
			})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if errs, _ := res["errors"].([]any); status != 200 || len(errs) > 0 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d marking the pull request ready: %v", status, errs)}
			}
		}
		detail := map[string]any{"number": number, "url": body["html_url"], "ready": true}
		g.requestReview(call, owner, repo, number, detail)
		return done(detail)
	}
	return Outcome{Error: "no adapter for " + a.Kind}
}

// requestReview asks the configured reviewer to look at a pull request, and writes what
// GitHub said into the detail. Best effort by design: the proposal exists either way, and
// a review request that fails (a login that is not a collaborator, say) is a fact for the
// record, not a reason to undo the effect.
func (g GitHub) requestReview(call func(method, path string, body any) (int, map[string]any, error), owner, repo string, number int, detail map[string]any) {
	if g.Reviewer == "" {
		return
	}
	status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/pulls/%d/requested_reviewers", owner, repo, number), map[string]any{"reviewers": []string{g.Reviewer}})
	switch {
	case err != nil:
		detail["review_requested"] = false
		detail["review_problem"] = err.Error()
	case status != 201:
		detail["review_requested"] = false
		detail["review_problem"] = fmt.Sprintf("GitHub answered %d: %v", status, body["message"])
	default:
		detail["review_requested"] = g.Reviewer
	}
}

// FooterMark is the line the gateway's pull request footer starts with (relying.FooterMark);
// spelled here so the effects package does not import the relying party.
const FooterMark = "<!-- proof-of-control -->"

// commitID is a full git commit id, the only form preview.push sets a branch to: a short
// id or a branch name would let the far end resolve it to something else than what was judged.
var commitID = regexp.MustCompile(`^[0-9a-f]{40}$`)

// wholeNumber reads a JSON number that must be an integer.
func wholeNumber(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		if n == float64(int(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// Registry of adapters by kind.
type Registry map[string]Adapter

// Add registers an adapter for every kind it performs.
func (r Registry) Add(a Adapter) {
	for _, k := range a.Kinds() {
		r[k] = a
	}
}

// GitHub is the registered GitHub adapter, for what is not an effect (the read token).
func (r Registry) GitHub() (GitHub, bool) {
	g, ok := r["pull.open"].(GitHub)
	return g, ok
}

// ErrNoAdapter: an allowed action nobody can perform is not performed.
var ErrNoAdapter = errors.New("no effect adapter for this kind")
