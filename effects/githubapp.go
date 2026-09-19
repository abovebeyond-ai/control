package effects

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A GitHub App as the gateway's identity on GitHub (since v0.24.0).
//
// Until then every push and every pull request the gateway made stood on GitHub under
// the owner whose token it carried: the record said #agent-elixir, GitHub said the owner,
// and the public story was the wrong one. It also left GitHub with no person in the loop,
// because the owner cannot review a pull request GitHub thinks the owner opened.
//
// An App fixes both without a second account to guard. GitHub attributes the work to
// `<app>[bot]`; the owner becomes the reviewer, and branch protection can demand it.
// The only long-lived secret on the VM is the App's private key. What the gateway
// actually sends is an installation token minted per owner at the moment of the effect,
// good for an hour, which is the same shape as the rest of this service: the record
// before the effect, the credential only when the effect leaves.
//
// Two files in the secrets directory switch it on: github-app-id (the numeric App id)
// and github-app-key (the PEM private key GitHub issued). Without them the adapter reads
// github-token-<owner> as before, so a fleet moves over one installation at a time; with
// them, an owner the App is not installed on still falls back to that owner's token if
// there is one, and the refusal names both roads when there is neither.
type githubApp struct {
	id  string
	key *rsa.PrivateKey
}

// appOf reads the App from the secrets directory; ok is false when it is not configured.
func (g GitHub) appOf() (*githubApp, bool, error) {
	idRaw, err := os.ReadFile(filepath.Join(g.SecretsDir, "github-app-id"))
	if err != nil {
		return nil, false, nil
	}
	keyRaw, err := os.ReadFile(filepath.Join(g.SecretsDir, "github-app-key"))
	if err != nil {
		return nil, false, fmt.Errorf("github-app-id is present but github-app-key is not")
	}
	block, _ := pem.Decode(keyRaw)
	if block == nil {
		return nil, false, errors.New("github-app-key is not PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else if k8, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, false, errors.New("github-app-key is not an RSA key")
		}
		key = rk
	} else {
		return nil, false, errors.New("github-app-key is neither PKCS#1 nor PKCS#8")
	}
	return &githubApp{id: strings.TrimSpace(string(idRaw)), key: key}, true, nil
}

// jwt is the App's own proof towards GitHub: RS256, issued a minute in the past against
// clock skew, valid nine minutes (GitHub allows ten). No library: the claim is three
// fields and the signature is one call.
func (a *githubApp) jwt(now time.Time) (string, error) {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	head := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims := enc(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": a.id})
	signing := head + "." + claims
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// errNotInstalled says the App exists but this owner never installed it: the one case
// where the per-owner token is still the right road.
var errNotInstalled = errors.New("the App is not installed on this owner")

// installationToken mints the hour-long token for one owner. Organisations and user
// accounts have different lookup routes; a 404 on both is errNotInstalled.
func (a *githubApp) installationToken(ctx context.Context, client *http.Client, base, owner string, permissions map[string]string) (string, time.Time, error) {
	bearer, err := a.jwt(time.Now())
	if err != nil {
		return "", time.Time{}, err
	}
	get := func(method, path string, send any) (int, map[string]any, error) {
		var payload io.Reader
		if send != nil {
			raw, _ := json.Marshal(send)
			payload = strings.NewReader(string(raw))
		}
		req, err := http.NewRequestWithContext(ctx, method, base+path, payload)
		if err != nil {
			return 0, nil, err
		}
		if send != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		return resp.StatusCode, body, nil
	}
	var id float64
	for _, path := range []string{"/orgs/" + owner + "/installation", "/users/" + owner + "/installation"} {
		status, body, err := get("GET", path, nil)
		if err != nil {
			return "", time.Time{}, err
		}
		if status == 200 {
			id, _ = body["id"].(float64)
			break
		}
		if status != 404 {
			return "", time.Time{}, fmt.Errorf("GitHub answered %d looking up the App's installation on %s: %v", status, owner, body["message"])
		}
	}
	if id == 0 {
		return "", time.Time{}, errNotInstalled
	}
	var scope any
	if permissions != nil {
		scope = map[string]any{"permissions": permissions}
	}
	status, body, err := get("POST", fmt.Sprintf("/app/installations/%d/access_tokens", int64(id)), scope)
	if err != nil {
		return "", time.Time{}, err
	}
	if status != 201 {
		return "", time.Time{}, fmt.Errorf("GitHub answered %d minting the App's token for %s: %v", status, owner, body["message"])
	}
	token, _ := body["token"].(string)
	expires, _ := time.Parse(time.RFC3339, fmt.Sprint(body["expires_at"]))
	if token == "" {
		return "", time.Time{}, fmt.Errorf("GitHub minted no token for %s", owner)
	}
	if expires.IsZero() {
		expires = time.Now().Add(55 * time.Minute)
	}
	return token, expires, nil
}

// appTokens is the per-owner cache of minted tokens: an effect is three to five calls,
// and minting on each would be a request per call for a token that lives an hour.
var appTokens = struct {
	sync.Mutex
	m map[string]struct {
		token   string
		expires time.Time
	}
}{m: map[string]struct {
	token   string
	expires time.Time
}{}}

// appToken returns a live installation token for the owner, minting one when the cache
// has none with more than five minutes left.
func (g GitHub) appToken(ctx context.Context, app *githubApp, client *http.Client, base, owner string) (string, error) {
	key := strings.ToLower(owner)
	appTokens.Lock()
	defer appTokens.Unlock()
	if c, ok := appTokens.m[key]; ok && time.Until(c.expires) > 5*time.Minute {
		return c.token, nil
	}
	token, expires, err := app.installationToken(ctx, client, base, owner, nil)
	if err != nil {
		return "", err
	}
	appTokens.m[key] = struct {
		token   string
		expires time.Time
	}{token, expires}
	return token, nil
}

// ReadPermissions is the downscope a read token carries: what Elixir's measurements need
// to see a repository and nothing that changes one. Every value is "read", and that is the
// line this downscope holds: it guards against writing, not against seeing.
//
// administration is here for one measurement, protection, which reads whether the main
// branch is guarded. GitHub has no narrower right for it, so the whole administration
// bundle comes along: collaborators and teams, the webhook list, the public half of deploy
// keys, runner and Actions settings. Weighed on 2026-09-19 against contents, which this
// same token already carries: a leaked read token hands over the source of the whole
// fleet, next to which a repository's configuration is small. Without it protection
// answered 403 on 20 of 24 measured projects, and twenty silent blind spots read as a
// fault rather than as a choice.
var ReadPermissions = map[string]string{"contents": "read", "metadata": "read", "actions": "read", "pull_requests": "read", "administration": "read"}

// ReadToken mints a read-only installation token for an owner (since v0.25.0), the road
// by which the measuring side stops holding GitHub tokens of its own.
//
// Until then Elixir read with six fine-grained personal tokens, no expiry, the same values
// the gateway used to write with; retiring the gateway's copies (v0.24.x) left the read
// side holding the very thing that had just been removed from the write side. A token
// minted here lives an hour, carries read permissions only, and stops the moment the App
// is uninstalled from the owner: reads become as revocable as writes, and the App key is
// the one GitHub credential in the system. Not an effect, so not judged and not recorded:
// nothing changes on GitHub when a repository is read. Authenticated all the same: the
// endpoint stands behind the client token, so only the box asks.
func (g GitHub) ReadToken(ctx context.Context, owner string) (token string, expires time.Time, err error) {
	app, ok, err := g.appOf()
	if err != nil {
		return "", time.Time{}, err
	}
	if !ok {
		return "", time.Time{}, errors.New("no GitHub App is configured, so there is no key to mint a read token from")
	}
	base := g.Base
	if base == "" {
		base = "https://api.github.com"
	}
	client := g.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	token, expires, err = app.installationToken(ctx, client, base, owner, ReadPermissions)
	if errors.Is(err, errNotInstalled) {
		return "", time.Time{}, fmt.Errorf("the App is not installed on %s", owner)
	}
	return token, expires, err
}
