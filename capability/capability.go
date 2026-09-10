// Package capability is the per-task authorization token a principal issues
// for one piece of work (rows 4.2.1, 5.1.3): who may do what, where, until
// when, signed by the principal's key, carried by the hand into every
// submission, and held by the gateway to the standing grant. The delegation
// is one hop, principal to hand, and the gateway takes the intersection: a
// capability can narrow a grant, never widen it (row 4.2.3).
//
// Form: base64url(canonical JSON of the payload) "." base64url(Ed25519
// signature over those canonical bytes). Canonical means RFC 8785, the same
// form every record uses, so the digest a record carries names exactly the
// token the hand presented.
package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

// Payload is what the principal signs.
type Payload struct {
	Issuer    string   `json:"iss"` // the principal's key, as a DID fragment
	Subject   string   `json:"sub"` // the agent this is for
	Audience  string   `json:"aud"` // the gateway's issuer URL
	Task      Task     `json:"task"`
	Kinds     []string `json:"kinds"`
	Resources []string `json:"resources"`
	IssuedAt  int64    `json:"iat"`
	Expires   int64    `json:"exp"`
	ID        string   `json:"jti"`
}

// Task names the piece of work in the principal's own terms.
type Task struct {
	Playbook string `json:"playbook"`
	Project  string `json:"project"`
}

// Issue signs a payload with the principal's key.
func Issue(p Payload, key ed25519.PrivateKey) (string, error) {
	body, err := canonical.Encode(p)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(key, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Parse splits a token without verifying it.
func Parse(token string) (Payload, []byte, []byte, error) {
	var p Payload
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return p, nil, nil, errors.New("a capability is two base64url parts joined by a dot")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return p, nil, nil, err
	}
	sigRaw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return p, nil, nil, err
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, nil, nil, err
	}
	return p, raw, sigRaw, nil
}

// Verify holds a token to the principal's key, the gateway it was meant for,
// the agent it was issued to, and the time. It returns the payload, which the
// gateway then intersects with the grant.
func Verify(token string, principal ed25519.PublicKey, audience, subject string, now time.Time) (Payload, error) {
	p, raw, sig, err := Parse(token)
	if err != nil {
		return p, err
	}
	if !ed25519.Verify(principal, raw, sig) {
		return p, errors.New("the capability is not signed by the principal's key")
	}
	if p.Audience != audience {
		return p, fmt.Errorf("the capability is for %s, not this gateway", p.Audience)
	}
	if p.Subject != subject {
		return p, fmt.Errorf("the capability is for %s, not this agent", p.Subject)
	}
	if p.Expires <= now.Unix() {
		return p, errors.New("the capability has expired")
	}
	if p.IssuedAt > now.Unix()+60 {
		return p, errors.New("the capability is issued in the future")
	}
	return p, nil
}

// Covers says whether a capability names this kind on this resource.
func (p Payload) Covers(kind, resource string) bool {
	return contains(p.Kinds, kind) && contains(p.Resources, resource)
}

// Digest names the exact token presented, for the record.
func Digest(token string) string {
	d, _ := canonical.Digest(map[string]any{"capability": token})
	return canonical.Tag(d)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
