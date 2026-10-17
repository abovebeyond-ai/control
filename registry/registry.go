// Package registry is the chain of authority inside an organisation that is not ours: who
// may speak for it, for which kinds, up to which amount, until when. Each entry is signed by
// its parent, the first by the organisation's root key, which the gateway pins in its
// configuration. A person's word (a passkey capability) holds only when the entry naming
// that person's key descends from the pinned root and every step of the way narrows.
//
// Form: "re1." base64url(canonical JSON of the entry) "." base64url(Ed25519 signature over
// those bytes by the parent). Canonical means RFC 8785, the form every record uses; the
// gateway refuses an entry whose bytes are not in it, so two readers of the same bytes can
// never read two entries (a duplicated key, say).
package registry

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

// Prefix opens every registry entry.
const Prefix = "re1"

// MaxDepth bounds a chain: root, director, buyer is three; eight leaves room and stops a
// chain from being made long enough to cost the gateway anything.
const MaxDepth = 8

// Entry is what a parent signs about a child.
type Entry struct {
	ID     string `json:"id"`     // "acme#elise"
	Org    string `json:"org"`    // "acme"
	Parent string `json:"parent"` // the parent entry's id, or the org itself for an entry the root signs
	Holder JWK    `json:"holder"` // the child's public key: Ed25519 to sign entries, P-256 for a passkey
	// CredentialID names the passkey, so the relay can ask the right one; the gateway does
	// not need it, the key is what it checks.
	CredentialID string   `json:"credential_id,omitempty"`
	Role         string   `json:"role"`
	Kinds        []string `json:"kinds"`
	CeilingEUR   int64    `json:"ceiling_eur"` // the highest order total this holder may put a word to
	MayDelegate  bool     `json:"may_delegate"`
	IssuedAt     int64    `json:"iat"`
	Expires      int64    `json:"exp"`
}

// JWK is a public key as a JSON Web Key: {"kty":"OKP","crv":"Ed25519","x"} or
// {"kty":"EC","crv":"P-256","x","y"}, coordinates in base64url.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y,omitempty"`
}

// Ed25519 is the key when it is one.
func (j JWK) Ed25519() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("the key is %s/%s, not OKP/Ed25519", j.Kty, j.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("the Ed25519 key is not 32 bytes of base64url")
	}
	return ed25519.PublicKey(x), nil
}

// ECDSA is the key when it is a P-256 one, checked to lie on the curve.
func (j JWK) ECDSA() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, fmt.Errorf("the key is %s/%s, not EC/P-256", j.Kty, j.Crv)
	}
	x, errX := base64.RawURLEncoding.DecodeString(j.X)
	y, errY := base64.RawURLEncoding.DecodeString(j.Y)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("the P-256 key's coordinates are not 32 bytes of base64url each")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("the P-256 key is not a point on the curve: %w", err)
	}
	return pub, nil
}

// Issue signs an entry with the parent's key: the root's for a director, the director's for a buyer.
func Issue(e Entry, parent ed25519.PrivateKey) (string, error) {
	body, err := canonical.Encode(e)
	if err != nil {
		return "", err
	}
	return Prefix + "." + base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(parent, body)), nil
}

// Parse splits an entry without verifying its signature, and refuses bytes that are not
// canonical JSON.
func Parse(token string) (Entry, []byte, []byte, error) {
	var e Entry
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != Prefix {
		return e, nil, nil, errors.New("a registry entry is re1 and two base64url parts joined by dots")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return e, nil, nil, fmt.Errorf("the entry is not base64url: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return e, nil, nil, fmt.Errorf("the entry's signature is not base64url: %w", err)
	}
	if err := canonical.Check(raw); err != nil {
		return e, nil, nil, fmt.Errorf("the entry: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, nil, nil, fmt.Errorf("the entry: %w", err)
	}
	return e, raw, sig, nil
}

// VerifyChain holds a chain, root first, to the organisation's pinned root key and to the
// narrowing rule, and returns its entries; the last is the one whose holder speaks. Every
// entry must be in date, signed by its parent's key, belong to one organisation, and give no
// more than its parent: kinds a subset, a ceiling and an end no higher, and only a parent that
// may delegate signs children.
func VerifyChain(chain []string, roots map[string]ed25519.PublicKey, now time.Time) ([]Entry, error) {
	if len(chain) == 0 {
		return nil, errors.New("no registry chain")
	}
	if len(chain) > MaxDepth {
		return nil, fmt.Errorf("a registry chain of %d entries; at most %d", len(chain), MaxDepth)
	}
	entries := make([]Entry, 0, len(chain))
	seen := map[string]bool{}
	for i, tok := range chain {
		e, raw, sig, err := Parse(tok)
		if err != nil {
			return nil, fmt.Errorf("registry entry %d: %w", i, err)
		}
		if e.Org == "" || !strings.HasPrefix(e.ID, e.Org+"#") || len(e.ID) == len(e.Org)+1 {
			return nil, fmt.Errorf("registry entry %d: the id %q is not a name under the organisation %q", i, e.ID, e.Org)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("registry entry %d: %s appears twice in the chain", i, e.ID)
		}
		seen[e.ID] = true
		if e.IssuedAt > now.Unix()+60 {
			return nil, fmt.Errorf("registry entry %s is issued in the future", e.ID)
		}
		if e.Expires <= now.Unix() {
			return nil, fmt.Errorf("registry entry %s has expired", e.ID)
		}
		if e.Expires <= e.IssuedAt {
			return nil, fmt.Errorf("registry entry %s ends before it starts", e.ID)
		}
		if _, err := e.Holder.Ed25519(); err != nil {
			if _, err := e.Holder.ECDSA(); err != nil {
				return nil, fmt.Errorf("registry entry %s: the holder is neither an Ed25519 nor a P-256 key", e.ID)
			}
		}
		var signer ed25519.PublicKey
		if i == 0 {
			if e.Parent != e.Org {
				return nil, fmt.Errorf("registry entry %s is the first in the chain, so its parent must be the organisation %s, not %s", e.ID, e.Org, e.Parent)
			}
			root, ok := roots[e.Org]
			if !ok {
				return nil, fmt.Errorf("no root key is pinned for the organisation %s", e.Org)
			}
			signer = root
		} else {
			parent := entries[i-1]
			if e.Org != parent.Org {
				return nil, fmt.Errorf("registry entry %s belongs to %s, its parent to %s", e.ID, e.Org, parent.Org)
			}
			if e.Parent != parent.ID {
				return nil, fmt.Errorf("registry entry %s names the parent %s, but follows %s in the chain", e.ID, e.Parent, parent.ID)
			}
			if !parent.MayDelegate {
				return nil, fmt.Errorf("registry entry %s is signed by %s, who may not delegate", e.ID, parent.ID)
			}
			if signer, err = parent.Holder.Ed25519(); err != nil {
				return nil, fmt.Errorf("registry entry %s: its parent %s holds no key that signs entries: %v", e.ID, parent.ID, err)
			}
			if k := firstOutside(e.Kinds, parent.Kinds); k != "" {
				return nil, fmt.Errorf("registry entry %s gives the kind %s, which %s does not have", e.ID, k, parent.ID)
			}
			if e.CeilingEUR > parent.CeilingEUR {
				return nil, fmt.Errorf("registry entry %s has a ceiling of %d EUR, above the %d EUR of %s", e.ID, e.CeilingEUR, parent.CeilingEUR, parent.ID)
			}
			if e.Expires > parent.Expires {
				return nil, fmt.Errorf("registry entry %s ends after %s does", e.ID, parent.ID)
			}
		}
		if e.CeilingEUR < 0 {
			return nil, fmt.Errorf("registry entry %s has a negative ceiling", e.ID)
		}
		if !ed25519.Verify(signer, raw, sig) {
			return nil, fmt.Errorf("registry entry %s is not signed by its parent %s", e.ID, e.Parent)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// IDs lists the entries of a chain by id, root first, for the record.
func IDs(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}
	return out
}

// Digest names a chain exactly as presented, for the record.
func Digest(chain []string) string {
	list := make([]any, len(chain))
	for i, c := range chain {
		list[i] = c
	}
	d, _ := canonical.Digest(map[string]any{"chain": list})
	return canonical.Tag(d)
}

func firstOutside(sub, set []string) string {
	for _, x := range sub {
		found := false
		for _, y := range set {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			return x
		}
	}
	return ""
}
