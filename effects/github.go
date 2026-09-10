// Package effects performs the effect an allowed action names, with
// credentials the hands never see. This is the mediation the standard asks
// for (C7.1.4a): the credentials and the transport for the effect are held
// inside the attesting environment, which emits the request itself.
package effects

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

func (g GitHub) Kinds() []string { return []string{"workflow.dispatch", "pull.open"} }

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
