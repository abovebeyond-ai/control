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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

func appDir(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github-app-id"), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "github-app-key"), pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, key
}

// The App's proof towards GitHub is a JWT the App's own public key verifies, issued by
// the App id, a minute in the past against clock skew, and under ten minutes long.
func TestTheAppSignsAJwtGitHubWouldAccept(t *testing.T) {
	dir, key := appDir(t)
	app, ok, err := GitHub{SecretsDir: dir}.appOf()
	if err != nil || !ok {
		t.Fatalf("the App must load: ok=%v err=%v", ok, err)
	}
	now := time.Now()
	tok, err := app.jwt(now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("a JWT has three parts, got %d", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("the signature must verify with the App's key: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	if claims["iss"] != "4242" {
		t.Fatalf("iss must be the App id, got %v", claims["iss"])
	}
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if iat > now.Unix()-59 || exp-iat > 600 {
		t.Fatalf("iat %d exp %d: must be issued in the past and live under ten minutes", iat, exp)
	}
}

// fakeGitHub answers the App's lookups and the effect's calls, and counts the mints.
func fakeGitHub(t *testing.T, installedOn string, mints *int32, gotAuthor *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/orgs/"+installedOn+"/installation":
			if !strings.HasPrefix(auth, "Bearer ") || strings.Count(strings.TrimPrefix(auth, "Bearer "), ".") != 2 {
				t.Errorf("the installation lookup must carry the App's JWT, got %q", auth)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 77})
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "Not Found"})
		case r.URL.Path == "/app/installations/77/access_tokens":
			atomic.AddInt32(mints, 1)
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_minted", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case strings.Contains(r.URL.Path, "/git/commits/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "base", "tree": map[string]any{"sha": "basetree"}})
		case strings.HasSuffix(r.URL.Path, "/git/blobs"), strings.HasSuffix(r.URL.Path, "/git/trees"), strings.HasSuffix(r.URL.Path, "/git/refs"):
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "x"})
		case strings.HasSuffix(r.URL.Path, "/git/commits"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			_, has := body["author"]
			gotAuthor.Store(has)
			if auth != "Bearer ghs_minted" && auth != "Bearer ownerfile" {
				t.Errorf("the effect must carry the minted or the owner's token, got %q", auth)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"sha": "newcommit"})
		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "unexpected " + r.URL.Path})
		}
	}))
}

func push(owner string) policy.Action {
	return policy.Action{Kind: "branch.push", Resource: owner + "/repo", Params: map[string]any{
		"branch": "elixir/x", "base_sha": "base", "message": "m",
		"files_sha256": mustDigest([]FileChange{{Path: "a.md", Content: "aGk="}}),
	}, Attached: map[string]any{"files": []map[string]any{{"path": "a.md", "content": "aGk="}}}}
}

func mustDigest(files []FileChange) string {
	d, _ := FilesDigest(files)
	return d
}

// With the App installed on the owner, the effect goes out on a minted installation
// token, the commit names no author so GitHub stamps the App, and a second effect on the
// same owner reuses the token instead of minting again.
func TestTheAppMintsOnceAndLetsGitHubStampTheCommit(t *testing.T) {
	dir, _ := appDir(t)
	var mints int32
	var author atomic.Value
	srv := fakeGitHub(t, "abovebeyond-ai", &mints, &author)
	defer srv.Close()
	appTokens.Lock()
	appTokens.m = map[string]struct {
		token   string
		expires time.Time
	}{}
	appTokens.Unlock()

	g := GitHub{SecretsDir: dir, Base: srv.URL, Client: srv.Client()}
	for i := 0; i < 2; i++ {
		out := g.Perform(context.Background(), push("abovebeyond-ai"))
		if !out.OK {
			t.Fatalf("push %d: %s", i, out.Error)
		}
	}
	if atomic.LoadInt32(&mints) != 1 {
		t.Fatalf("two effects on one owner must mint once, minted %d times", mints)
	}
	if author.Load() != false {
		t.Fatal("under the App the commit must name no author, so GitHub stamps the App")
	}
	if out := g.Perform(context.Background(), push("abovebeyond-ai")); out.Detail["via"] != "app" {
		t.Fatalf("the record must say the App carried the effect, got %v", out.Detail["via"])
	}
}

// The gateway asks the configured reviewer to look at what it opened, and the record says
// so; without a reviewer it asks nobody and says nothing.
func TestTheOwnerIsAskedToReview(t *testing.T) {
	dir, _ := appDir(t)
	var asked atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/abovebeyond-ai/installation":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 77})
		case r.URL.Path == "/app/installations/77/access_tokens":
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_minted", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pulls"):
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"html_url": "https://github.com/o/r/pull/9", "number": 9})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/pulls/9/requested_reviewers"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			asked.Store(body["reviewers"])
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			w.WriteHeader(404)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": "unexpected " + r.URL.Path})
		}
	}))
	defer srv.Close()
	appTokens.Lock()
	appTokens.m = map[string]struct {
		token   string
		expires time.Time
	}{}
	appTokens.Unlock()

	open := policy.Action{Kind: "pull.open", Resource: "abovebeyond-ai/repo", Params: map[string]any{"branch": "elixir/x", "base": "main", "title": "t", "body": "b"}}
	out := GitHub{SecretsDir: dir, Base: srv.URL, Client: srv.Client(), Reviewer: "ShaneDeconinck"}.Perform(context.Background(), open)
	if !out.OK || out.Detail["review_requested"] != "ShaneDeconinck" {
		t.Fatalf("the reviewer must be asked and recorded: %+v", out)
	}
	if got, _ := asked.Load().([]any); len(got) != 1 || got[0] != "ShaneDeconinck" {
		t.Fatalf("GitHub must be asked for exactly the reviewer, got %v", asked.Load())
	}

	asked.Store([]any{})
	out = GitHub{SecretsDir: dir, Base: srv.URL, Client: srv.Client()}.Perform(context.Background(), open)
	if got, _ := asked.Load().([]any); !out.OK || out.Detail["review_requested"] != nil || len(got) != 0 {
		t.Fatalf("without a reviewer nobody is asked and nothing is said: %+v", out)
	}
}

// An owner the App is not installed on still works through that owner's own token, and
// then the commit does name its author, because the token's owner would be stamped.
func TestAnOwnerWithoutTheAppFallsBackToItsToken(t *testing.T) {
	dir, _ := appDir(t)
	if err := os.WriteFile(filepath.Join(dir, "github-token-stocklistdealer-eu"), []byte("ownerfile"), 0o600); err != nil {
		t.Fatal(err)
	}
	var mints int32
	var author atomic.Value
	srv := fakeGitHub(t, "abovebeyond-ai", &mints, &author)
	defer srv.Close()

	g := GitHub{SecretsDir: dir, Base: srv.URL, Client: srv.Client()}
	out := g.Perform(context.Background(), push("stocklistdealer-eu"))
	if !out.OK {
		t.Fatalf("the owner's token must carry the effect: %s", out.Error)
	}
	if author.Load() != true {
		t.Fatal("under an owner's token the commit must name elixir as author")
	}
	if out.Detail["via"] != "owner-token" {
		t.Fatalf("the record must say the owner's token carried the effect, got %v", out.Detail["via"])
	}
	if atomic.LoadInt32(&mints) != 0 {
		t.Fatal("nothing must be minted for an owner without the App")
	}

	out = g.Perform(context.Background(), push("nobody"))
	if out.OK || !strings.Contains(out.Error, "not installed on nobody") || !strings.Contains(out.Error, "github-token-nobody") {
		t.Fatalf("neither road must be named in the refusal: %q", out.Error)
	}
}

// Half an App is a misconfiguration, not a fallback: an id without a key refuses loudly
// rather than quietly using the owner tokens as if nothing had been asked.
func TestHalfAnAppIsRefusedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "github-app-id"), []byte("1"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "github-token-x"), []byte("t"), 0o600)
	g := GitHub{SecretsDir: dir}
	_, _, err := g.credential(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "x")
	if err == nil || !strings.Contains(err.Error(), "github-app-key") {
		t.Fatalf("an id without a key must refuse naming the key: %v", err)
	}
}

// A read token is the App's, downscoped to reading, for an owner the App is installed on;
// without an App there is nothing to mint from, and the refusal says so.
func TestAReadTokenIsMintedReadOnlyFromTheApp(t *testing.T) {
	dir, _ := appDir(t)
	var scope atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/orgs/abovebeyond-ai/installation":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 77})
		case strings.HasSuffix(r.URL.Path, "/installation"):
			w.WriteHeader(404)
		case r.URL.Path == "/app/installations/77/access_tokens":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			scope.Store(body["permissions"])
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_read", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	g := GitHub{SecretsDir: dir, Base: srv.URL, Client: srv.Client()}
	tok, exp, err := g.ReadToken(context.Background(), "abovebeyond-ai")
	if err != nil || tok != "ghs_read" || time.Until(exp) < 50*time.Minute {
		t.Fatalf("a read token must be minted: %q %v %v", tok, exp, err)
	}
	perms, _ := scope.Load().(map[string]any)
	for k, v := range ReadPermissions {
		if perms[k] != v {
			t.Fatalf("the token must be downscoped to %v, GitHub was asked for %v", ReadPermissions, perms)
		}
	}
	// The downscope may widen in what it sees; it may never widen in what it does. A
	// "write" here would pass the loop above and quietly hand the measuring side a hand.
	for k, v := range ReadPermissions {
		if v != "read" {
			t.Fatalf("a read token carries read rights only, %q asks for %q", k, v)
		}
	}
	if _, _, err := g.ReadToken(context.Background(), "nobody"); err == nil || !strings.Contains(err.Error(), "not installed on nobody") {
		t.Fatalf("an owner without the App must be refused by name: %v", err)
	}
	if _, _, err := (GitHub{SecretsDir: t.TempDir()}).ReadToken(context.Background(), "abovebeyond-ai"); err == nil || !strings.Contains(err.Error(), "no GitHub App") {
		t.Fatalf("without an App there is nothing to mint from: %v", err)
	}
}
