package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func csFixture(t *testing.T) (*rsa.PrivateKey, *JWKS, ed25519.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return priv, &JWKS{Keys: map[string]*rsa.PublicKey{"k1": &priv.PublicKey}, At: time.Now()}, pub
}

func TestAConfidentialSpaceTokenHoldsAndEachClaimCanBreakIt(t *testing.T) {
	priv, keys, pub := csFixture(t)
	now := time.Now()
	sign := func(edit func(map[string]any)) string {
		c := CSClaimsFor(testDigest, pub, "http://acme-gate:8080", now)
		if edit != nil {
			edit(c)
		}
		tok, err := SignCSToken(priv, "k1", c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	opt := CSOptions{ImageDigest: testDigest, Key: pub, Audience: "http://acme-gate:8080", JWKS: keys}
	c, err := VerifyCS(context.Background(), sign(nil), opt)
	if err != nil {
		t.Fatalf("a good token: %v", err)
	}
	if c.ImageDigest != testDigest || c.HWModel != PlatformGCPTDX || !c.HasNonce(KeyNonce(pub)) {
		t.Fatalf("claims read wrong: %+v", c)
	}
	// eat_nonce as an array, as Google may send it.
	if _, err := VerifyCS(context.Background(), sign(func(m map[string]any) { m["eat_nonce"] = []string{"x-some-other-nonce", KeyNonce(pub)} }), opt); err != nil {
		t.Fatalf("an array of nonces: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]struct {
		edit func(map[string]any)
		opt  func(*CSOptions)
		want string
	}{
		"debug image":   {edit: func(m map[string]any) { m["dbgstat"] = "enabled" }, want: "debugging"},
		"plain GCE":     {edit: func(m map[string]any) { m["swname"] = "GCE" }, want: "software"},
		"AMD":           {edit: func(m map[string]any) { m["hwmodel"] = "GCP_AMD_SEV" }, want: "hardware"},
		"issuer":        {edit: func(m map[string]any) { m["iss"] = "https://example.com" }, want: "issued by"},
		"other image":   {opt: func(o *CSOptions) { o.ImageDigest = "sha256:22" }, want: "image"},
		"other key":     {opt: func(o *CSOptions) { o.Key = other }, want: "nonce"},
		"audience":      {opt: func(o *CSOptions) { o.Audience = "https://elsewhere" }, want: "is for"},
		"expired fresh": {edit: func(m map[string]any) { m["exp"] = now.Add(-time.Minute).Unix() }, opt: func(o *CSOptions) { o.Fresh = true }, want: "expired"},
	}
	for name, tc := range cases {
		o := opt
		if tc.opt != nil {
			tc.opt(&o)
		}
		_, err := VerifyCS(context.Background(), sign(tc.edit), o)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, tc.want)
		}
	}
	// A token signed by someone else's key, or tampered with after signing.
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged, _ := SignCSToken(stranger, "k1", CSClaimsFor(testDigest, pub, "a", now))
	if _, err := VerifyCS(context.Background(), forged, opt); err == nil {
		t.Fatal("a token under another key verified")
	}
	good := sign(nil)
	parts := strings.Split(good, ".")
	if _, err := VerifyCS(context.Background(), parts[0]+"."+parts[1]+"x."+parts[2], opt); err == nil {
		t.Fatal("a tampered token verified")
	}
}

func TestARecordFromTheLauncherBindsTheKeyAndVerifies(t *testing.T) {
	priv, keys, _ := csFixture(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	tok, _ := SignCSToken(priv, "k1", CSClaimsFor(testDigest, pub, "aud", time.Now()))
	r, err := CSRecord(tok, pub, "v1 sha256:x")
	if err != nil {
		t.Fatal(err)
	}
	if r.Platform != PlatformGCPTDX || r.Software != SoftwareCS || r.Measurement() != "sha-256:"+strings.TrimPrefix(testDigest, "sha256:") {
		t.Fatalf("record: %+v, measurement %s", r, r.Measurement())
	}
	if string(r.Evidence()) != tok {
		t.Fatal("the evidence of a token record is the token")
	}
	if err := Verify(context.Background(), r, Options{ImageDigest: testDigest, JWKS: keys}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := Verify(context.Background(), r, Options{ImageDigest: "sha256:99", JWKS: keys}); err == nil {
		t.Fatal("a record of another image verified against the expected one")
	}
	r2 := *r
	r2.PublicKey = hex.EncodeToString(make([]byte, 32))
	if err := Verify(context.Background(), &r2, Options{JWKS: keys}); err == nil {
		t.Fatal("a record naming another key verified")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := CSRecord(tok, other, ""); err == nil {
		t.Fatal("a token for another key made a record")
	}
}

func TestTheLauncherIsAskedOverItsSocket(t *testing.T) {
	sock := t.TempDir() + "/tee.sock"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Audience  string   `json:"audience"`
			TokenType string   `json:"token_type"`
			Nonces    []string `json:"nonces"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.URL.Path != "/v1/token" || r.Method != "POST" || body.TokenType != "OIDC" || body.Audience != "aud" || len(body.Nonces) != 1 {
			http.Error(w, "bad", 400)
			return
		}
		_, _ = w.Write([]byte("a.b.c"))
	}))
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets here:", err)
	}
	srv.Listener = l
	srv.Start()
	defer srv.Close()
	tok, err := RequestToken(context.Background(), sock, "aud", []string{"n"})
	if err != nil || tok != "a.b.c" {
		t.Fatalf("token %q, %v", tok, err)
	}
}
