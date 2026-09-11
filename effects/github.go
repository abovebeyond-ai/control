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

// GitHub performs workflow.dispatch and pull.open on owner/repo resources with
// a token per owner read from the secrets directory as github-token-<owner>.
type GitHub struct {
	SecretsDir string
	Client     *http.Client
	Base       string // https://api.github.com
}

func (g GitHub) Kinds() []string { return []string{"workflow.dispatch", "branch.push", "pull.open"} }

// FileChange is one file of a branch.push: the path and the full new content. The runner
// in the project's CI computes the change and hands it back instead of pushing; the
// gateway pushes with its own credential, so no write to a repository escapes judgement.
type FileChange struct {
	Path    string `json:"path"`
	Content string `json:"content"` // base64
}

// FilesDigest is what params.files_sha256 must equal: the canonical digest of the files.
func FilesDigest(files []FileChange) (string, error) {
	items := make([]map[string]any, len(files))
	for i, f := range files {
		items[i] = map[string]any{"path": f.Path, "content": f.Content}
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
		if _, err := base64.StdEncoding.DecodeString(f.Content); err != nil {
			return nil, fmt.Errorf("file %s: content is not base64", f.Path)
		}
	}
	return files, nil
}

func (g GitHub) token(owner string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(g.SecretsDir, "github-token-"+owner))
	if err != nil {
		return "", fmt.Errorf("no GitHub token for %s in the gateway's secrets", owner)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (g GitHub) Perform(ctx context.Context, a policy.Action) Outcome {
	owner, repo, ok := strings.Cut(a.Resource, "/")
	if !ok || owner == "" || repo == "" {
		return Outcome{Error: "resource is not owner/repo"}
	}
	token, err := g.token(owner)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	base := g.Base
	if base == "" {
		base = "https://api.github.com"
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
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
		return Outcome{OK: true, Detail: map[string]any{"status": status, "evidence_carried": carried}}
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
			status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/git/blobs", owner, repo), map[string]any{"content": f.Content, "encoding": "base64"})
			if err != nil {
				return Outcome{Error: err.Error()}
			}
			if status != 201 {
				return Outcome{Error: fmt.Sprintf("GitHub answered %d for blob %s: %v", status, f.Path, body["message"])}
			}
			entries = append(entries, map[string]any{"path": f.Path, "mode": "100644", "type": "blob", "sha": body["sha"]})
		}
		status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/trees", owner, repo), map[string]any{"base_tree": baseTree, "tree": entries})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d for the tree: %v", status, body["message"])}
		}
		newTree, _ := body["sha"].(string)
		status, body, err = call("POST", fmt.Sprintf("/repos/%s/%s/git/commits", owner, repo), map[string]any{
			"message": message, "tree": newTree, "parents": []string{baseSHA},
			"author": map[string]any{"name": "elixir", "email": "elixir@abovebeyond.ai"},
		})
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
		return Outcome{OK: true, Detail: map[string]any{"branch": branch, "commit": commit, "base": baseSHA, "files": len(files)}}
	case "pull.open":
		head, _ := a.Params["branch"].(string)
		basis, _ := a.Params["base"].(string)
		title, _ := a.Params["title"].(string)
		text, _ := a.Params["body"].(string)
		if head == "" || basis == "" || title == "" {
			return Outcome{Error: "pull.open needs params.branch, params.base and params.title"}
		}
		status, body, err := call("POST", fmt.Sprintf("/repos/%s/%s/pulls", owner, repo), map[string]any{"head": head, "base": basis, "title": title, "body": text})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status != 201 {
			return Outcome{Error: fmt.Sprintf("GitHub answered %d: %v", status, body["message"])}
		}
		return Outcome{OK: true, Detail: map[string]any{"url": body["html_url"], "number": body["number"]}}
	}
	return Outcome{Error: "no adapter for " + a.Kind}
}

// Registry of adapters by kind.
type Registry map[string]Adapter

// Add registers an adapter for every kind it performs.
func (r Registry) Add(a Adapter) {
	for _, k := range a.Kinds() {
		r[k] = a
	}
}

// ErrNoAdapter: an allowed action nobody can perform is not performed.
var ErrNoAdapter = errors.New("no effect adapter for this kind")
