package attest

// Confidential Space: Google's hardened image for one container on a confidential VM (here
// Intel TDX). The operator chooses the container image and nothing else: the boot chain, the
// launcher and the kernel are Google's, measured, and there is no SSH. The launcher asks Google
// Cloud Attestation for a token that names the hardware, the image, and whether the VM is a
// debug one, and Google signs it. That token is this record's evidence.
//
// Why this and not a plain TDX VM (attest.go): on a plain VM the startup script is not
// measured, so the operator could change what runs, and read the gateway's memory, without the
// quote changing. In Confidential Space what runs is the image whose digest Google signs into
// the token.
//
// The binding is a nonce: the gateway asks for a token whose eat_nonce carries the hex SHA-256
// of its record key (KeyNonce), so the token says "the workload in this image holds this key".
//
// Claims as Google documents them (docs.cloud.google.com/confidential-computing/confidential-
// space/docs/reference/token-claims, read 17 October 2026): hwmodel GCP_INTEL_TDX, swname
// CONFIDENTIAL_SPACE, dbgstat disabled-since-boot on a production image, submods.container.
// image_digest, eat_nonce a string or an array of strings (8 to 88 bytes each, at most six).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// What a Confidential Space record names.
const (
	PlatformGCPTDX   = "GCP_INTEL_TDX"
	SoftwareCS       = "CONFIDENTIAL_SPACE"
	CSIssuer         = "https://confidentialcomputing.googleapis.com"
	CSDiscovery      = CSIssuer + "/.well-known/openid-configuration"
	TeeServerSocket  = "/run/container_launcher/teeserver.sock"
	csDebugDisabled  = "disabled-since-boot"
	providerLauncher = "confidential-space-launcher"
)

// KeyNonce is the nonce that binds a record key into a token: hex SHA-256 of the public key.
func KeyNonce(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// RequestToken asks the Confidential Space launcher for an OIDC token with this audience and
// these nonces, over its unix socket. The answer is the token itself, as text.
func RequestToken(ctx context.Context, socket, audience string, nonces []string) (string, error) {
	if socket == "" {
		socket = TeeServerSocket
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}}
	body, _ := json.Marshal(map[string]any{"audience": audience, "token_type": "OIDC", "nonces": nonces})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: the launcher at %s: %v", ErrUnavailable, socket, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != 200 {
		return "", fmt.Errorf("the launcher answered %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	tok := strings.TrimSpace(string(raw))
	if strings.Count(tok, ".") != 2 {
		return "", errors.New("the launcher's answer is not a JWT")
	}
	return tok, nil
}

// CSClaims is what a verifier reads from a Confidential Space token.
type CSClaims struct {
	Issuer      string
	Audience    []string
	IssuedAt    time.Time
	Expires     time.Time
	HWModel     string
	SWName      string
	SWVersion   []string
	DbgStat     string
	ImageDigest string
	ImageRef    string
	Nonces      []string
	Support     []string
	Accounts    []string
	Raw         map[string]any
}

// ParseCSClaims reads the claims without checking the signature: for the gateway, which got the
// token from its own launcher, and as the first step of VerifyCS.
func ParseCSClaims(token string) (*CSClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("the token's payload is not base64url")
	}
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("the token's payload is not JSON")
	}
	c := &CSClaims{Raw: m, Issuer: str(m["iss"]), HWModel: str(m["hwmodel"]), SWName: str(m["swname"]), DbgStat: str(m["dbgstat"])}
	c.Audience = strs(m["aud"])
	c.SWVersion = strs(m["swversion"])
	c.Nonces = strs(m["eat_nonce"])
	c.Accounts = strs(m["google_service_accounts"])
	c.IssuedAt, c.Expires = unix(m["iat"]), unix(m["exp"])
	sub, _ := m["submods"].(map[string]any)
	ctr, _ := sub["container"].(map[string]any)
	c.ImageDigest, c.ImageRef = str(ctr["image_digest"]), str(ctr["image_reference"])
	cs, _ := sub["confidential_space"].(map[string]any)
	c.Support = strs(cs["support_attributes"])
	return c, nil
}

// HasNonce says whether the token's eat_nonce carries n.
func (c *CSClaims) HasNonce(n string) bool {
	for _, x := range c.Nonces {
		if x == n {
			return true
		}
	}
	return false
}

// CSRecord builds the attestation record of a gateway in Confidential Space from the token its
// launcher gave it: the platform, the image the token names, the key it binds.
func CSRecord(token string, pub ed25519.PublicKey, release string) (*Record, error) {
	c, err := ParseCSClaims(token)
	if err != nil {
		return nil, err
	}
	if !c.HasNonce(KeyNonce(pub)) {
		return nil, errors.New("the launcher's token does not carry this key's nonce")
	}
	if c.ImageDigest == "" {
		return nil, errors.New("the launcher's token names no image digest")
	}
	return &Record{Platform: PlatformGCPTDX, Software: SoftwareCS, Provider: providerLauncher, Token: token,
		ImageDigest: c.ImageDigest, PublicKey: hex.EncodeToString(pub), AcquiredAt: time.Now().UTC().Format(time.RFC3339), Release: release}, nil
}

// IsConfidentialSpace: is this record a Confidential Space token rather than a raw quote?
func (r *Record) IsConfidentialSpace() bool { return r != nil && r.Token != "" }

// Evidence is the bytes the record's digest is taken over: the token, or the raw quote.
func (r *Record) Evidence() []byte {
	if r.IsConfidentialSpace() {
		return []byte(r.Token)
	}
	raw, _ := base64.StdEncoding.DecodeString(r.QuoteB64)
	return raw
}

// JWKS is a set of Google's signing keys by kid.
type JWKS struct {
	Keys map[string]*rsa.PublicKey
	At   time.Time
}

var (
	jwksMu    sync.Mutex
	jwksCache *JWKS
)

// FetchCSJWKS reads Google's OIDC discovery document and the keys it points at. Kept for an
// hour; a kid not in the cache fetches again.
func FetchCSJWKS(ctx context.Context, client *http.Client) (*JWKS, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := getJSON(ctx, client, CSDiscovery, &disc); err != nil {
		return nil, fmt.Errorf("Google's discovery document: %w", err)
	}
	if disc.Issuer != CSIssuer || !strings.HasPrefix(disc.JWKSURI, "https://") {
		return nil, fmt.Errorf("Google's discovery document names issuer %q and keys at %q", disc.Issuer, disc.JWKSURI)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, N, E, Alg string
		} `json:"keys"`
	}
	if err := getJSON(ctx, client, disc.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("Google's keys: %w", err)
	}
	out := &JWKS{Keys: map[string]*rsa.PublicKey{}, At: time.Now()}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			continue
		}
		out.Keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(out.Keys) == 0 {
		return nil, errors.New("Google's key set holds no RSA key")
	}
	return out, nil
}

func cachedJWKS(ctx context.Context, client *http.Client, kid string) (*JWKS, error) {
	jwksMu.Lock()
	defer jwksMu.Unlock()
	if jwksCache != nil && time.Since(jwksCache.At) < time.Hour && jwksCache.Keys[kid] != nil {
		return jwksCache, nil
	}
	j, err := FetchCSJWKS(ctx, client)
	if err != nil {
		return nil, err
	}
	jwksCache = j
	return j, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s answered %d", url, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(into)
}

// CSOptions is what a Confidential Space token is held to.
type CSOptions struct {
	// ImageDigest is the image the verifier checked ("sha256:..."); empty accepts any image and
	// the caller must then compare CSClaims.ImageDigest itself.
	ImageDigest string
	// Key is the record key the token must bind through its nonce.
	Key ed25519.PublicKey
	// Audience, when set, must be among the token's audiences.
	Audience string
	// JWKS overrides Google's keys (tests); nil fetches them.
	JWKS   *JWKS
	Client *http.Client
	// Fresh, when set, requires the token not to have expired at Now. A record's token is
	// evidence of what ran when it was issued, so an old one is still read; a provisioning
	// check may ask for a fresh one.
	Fresh bool
	Now   time.Time
}

// VerifyCS holds a token to Google's signature and to what a production Confidential Space
// workload on Intel TDX says: the issuer, the hardware, the software, debugging disabled since
// boot, the image digest, and the key's nonce.
func VerifyCS(ctx context.Context, token string, opt CSOptions) (*CSClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the token is not a JWT")
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("the token's header is not base64url")
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(hraw, &hdr); err != nil {
		return nil, errors.New("the token's header is not JSON")
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("the token is signed with %q, not RS256", hdr.Alg)
	}
	keys := opt.JWKS
	if keys == nil {
		if keys, err = cachedJWKS(ctx, opt.Client, hdr.Kid); err != nil {
			return nil, err
		}
	}
	pub := keys.Keys[hdr.Kid]
	if pub == nil {
		return nil, fmt.Errorf("Google publishes no key %q (rotated away, or not Google's token)", hdr.Kid)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("the token's signature is not base64url")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("the token's signature does not verify under Google's key")
	}
	c, err := ParseCSClaims(token)
	if err != nil {
		return nil, err
	}
	switch {
	case c.Issuer != CSIssuer:
		return c, fmt.Errorf("the token is issued by %q, not Google Cloud Attestation", c.Issuer)
	case c.HWModel != PlatformGCPTDX:
		return c, fmt.Errorf("the token names hardware %q, not %s", c.HWModel, PlatformGCPTDX)
	case c.SWName != SoftwareCS:
		return c, fmt.Errorf("the token names software %q, not %s", c.SWName, SoftwareCS)
	case c.DbgStat != csDebugDisabled:
		return c, fmt.Errorf("the token says debugging is %q: a debug image lets the operator in", c.DbgStat)
	case opt.ImageDigest != "" && c.ImageDigest != opt.ImageDigest:
		return c, fmt.Errorf("the token names image %s, not the expected %s", c.ImageDigest, opt.ImageDigest)
	case opt.Key != nil && !c.HasNonce(KeyNonce(opt.Key)):
		return c, errors.New("the token's eat_nonce does not carry the record key's digest")
	}
	if opt.Audience != "" {
		ok := false
		for _, a := range c.Audience {
			ok = ok || a == opt.Audience
		}
		if !ok {
			return c, fmt.Errorf("the token is for %v, not %s", c.Audience, opt.Audience)
		}
	}
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	if c.IssuedAt.After(now.Add(5 * time.Minute)) {
		return c, errors.New("the token is issued in the future")
	}
	if opt.Fresh && !c.Expires.IsZero() && now.After(c.Expires) {
		return c, fmt.Errorf("the token expired at %s", c.Expires.UTC().Format(time.RFC3339))
	}
	return c, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func strs(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func unix(v any) time.Time {
	switch t := v.(type) {
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return time.Unix(n, 0)
		}
	case float64:
		return time.Unix(int64(t), 0)
	}
	return time.Time{}
}

// SignCSToken signs claims as an RS256 JWT under kid: for tests and rehearsals that stand in
// for Google Cloud Attestation with a key of their own, held to through CSOptions.JWKS.
func SignCSToken(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// CSClaimsFor are the claims of a production Confidential Space token on Intel TDX for an image
// and a key: what SignCSToken signs in a test.
func CSClaimsFor(imageDigest string, pub ed25519.PublicKey, audience string, iat time.Time) map[string]any {
	return map[string]any{
		"iss": CSIssuer, "aud": audience, "iat": iat.Unix(), "exp": iat.Add(time.Hour).Unix(),
		"hwmodel": PlatformGCPTDX, "swname": SoftwareCS, "swversion": []string{"26090100"}, "dbgstat": csDebugDisabled,
		"eat_nonce": KeyNonce(pub),
		"submods": map[string]any{"container": map[string]any{"image_digest": imageDigest, "image_reference": "europe-west4-docker.pkg.dev/p/gate/gate@" + imageDigest},
			"confidential_space": map[string]any{"support_attributes": []string{"LATEST", "STABLE", "USABLE"}}},
	}
}
