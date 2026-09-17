package effects

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// Forge performs forge.deploy: it asks Laravel Forge to deploy one site, the preview site of
// a project, by calling the site's deployment trigger URL. That URL is tokenless by
// design (the URL itself is the secret), so it is held here as forge-deploy-<slug> in the
// gateway's secrets and nowhere else. Until 17 September 2026 the preview of the Stocklist
// platform was deployed with a Forge API token on the operator's laptop, read by a script a
// session could run: the one credential a session's machine may not hold, on the one
// machine it must not be. The resource is "forge:<slug>", the project as Portal names it.
//
// Forge answers the trigger at once and deploys in the background; the outcome says the
// request was accepted, not that the deploy succeeded. What the site then runs is what
// preview.push set the branch to, which is why the policy admits this kind only after one.
type Forge struct {
	SecretsDir string
	Client     *http.Client
	// Base is where a trigger URL must live; a secret that points anywhere else is refused
	// unread, so the gateway cannot be turned into a client of an arbitrary address by a
	// file in its secrets. Tests point it at a local server.
	Base string // https://forge.laravel.com/
}

// ForgeResourcePrefix is what a Forge resource starts with.
const ForgeResourcePrefix = "forge:"

// ForgeSecret is the file in the secrets directory that holds the trigger URL of a project's
// preview site (Secret Manager: control-forge-deploy-<slug>).
func ForgeSecret(slug string) string { return "forge-deploy-" + slug }

func (f Forge) Kinds() []string { return []string{policy.ForgeDeployKind} }

// ForgeSlug reads the project out of a Forge resource.
func ForgeSlug(resource string) (string, bool) {
	slug, ok := strings.CutPrefix(resource, ForgeResourcePrefix)
	if !ok || slug == "" || strings.ContainsAny(slug, "/ ?#") {
		return "", false
	}
	return slug, true
}

func (f Forge) trigger(slug string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(f.SecretsDir, ForgeSecret(slug)))
	if err != nil {
		return "", fmt.Errorf("no Forge deploy trigger for %s in the gateway's secrets (%s)", slug, ForgeSecret(slug))
	}
	url := strings.TrimSpace(string(raw))
	base := f.Base
	if base == "" {
		base = "https://forge.laravel.com/"
	}
	if !strings.HasPrefix(url, base) {
		return "", fmt.Errorf("the Forge deploy trigger for %s is not a URL under %s", slug, base)
	}
	return url, nil
}

func (f Forge) Perform(ctx context.Context, a policy.Action) Outcome {
	slug, ok := ForgeSlug(a.Resource)
	if !ok {
		return Outcome{Error: "resource is not forge:<slug>"}
	}
	url, err := f.trigger(slug)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		// The error would carry the URL; the record gets the fact, not the secret.
		return Outcome{Error: "the Forge deploy trigger for " + slug + " could not be requested"}
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return Outcome{Error: "Forge could not be reached for " + slug}
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Outcome{Error: fmt.Sprintf("Forge answered %d for the deploy of %s", res.StatusCode, slug)}
	}
	detail := map[string]any{"project": slug, "status": res.StatusCode, "accepted": true}
	if sha, _ := a.Params["sha"].(string); sha != "" {
		detail["commit"] = sha
	}
	if n, ok := wholeNumber(a.Params["pull"]); ok {
		detail["pull"] = n
	}
	return Outcome{OK: true, Detail: detail}
}
