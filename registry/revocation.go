package registry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
)

// RevocationPrefix starts a signed revocation of a registry entry: rv1.<payload>.<signature>,
// as re1. When a person enrols a new phone, the entry for the old passkey is revoked by the one
// who signed it, so a relay that kept serving the old entry cannot keep the old phone alive.
const RevocationPrefix = "rv1"

// Revocation says: the entry with this digest no longer speaks for ID, signed by By, the entry
// (or the organisation's root) that signed it.
type Revocation struct {
	Revokes  string `json:"revokes"` // EntryDigest of the re1 token
	ID       string `json:"id"`
	By       string `json:"by"`
	IssuedAt int64  `json:"iat"`
}

// EntryDigest names one re1 token: sha-256 over its exact text.
func EntryDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return canonical.Tag(hex.EncodeToString(sum[:]))
}

// IssueRevocation signs a revocation with the key of the entry (or root) that signed the entry.
func IssueRevocation(r Revocation, key ed25519.PrivateKey) (string, error) {
	body, err := canonical.Encode(r)
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString
	return RevocationPrefix + "." + b(body) + "." + b(ed25519.Sign(key, body)), nil
}

// ParseRevocation reads an rv1 token without verifying it.
func ParseRevocation(token string) (Revocation, []byte, []byte, error) {
	var r Revocation
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != RevocationPrefix {
		return r, nil, nil, errors.New("a revocation is rv1 and two base64url parts joined by dots")
	}
	raw, err1 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return r, nil, nil, errors.New("the revocation is not base64url")
	}
	if err := canonical.Check(raw); err != nil {
		return r, nil, nil, fmt.Errorf("the revocation: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, nil, nil, fmt.Errorf("the revocation: %w", err)
	}
	return r, raw, sig, nil
}

// Revoked looks up each entry of a verified chain (tokens and entries in the same order) in
// lookup (digest -> rv1 token) and answers why the chain no longer holds, or "". A revocation
// counts only when it names that entry and is signed by whoever signed the entry: the
// organisation's root for the first, the entry before it otherwise. Anything else is ignored,
// so whoever serves the list can only withhold, never invent.
func Revoked(chain []string, entries []Entry, roots map[string]ed25519.PublicKey, lookup func(digest string) string) string {
	if lookup == nil || len(chain) != len(entries) {
		return ""
	}
	for i, tok := range chain {
		d := EntryDigest(tok)
		rv := lookup(d)
		if rv == "" {
			continue
		}
		r, raw, sig, err := ParseRevocation(rv)
		if err != nil || r.Revokes != d || r.ID != entries[i].ID {
			continue
		}
		var key ed25519.PublicKey
		if i == 0 {
			if r.By != entries[i].Org {
				continue
			}
			key = roots[entries[i].Org]
		} else {
			if r.By != entries[i-1].ID {
				continue
			}
			if key, err = entries[i-1].Holder.Ed25519(); err != nil {
				continue
			}
		}
		if key != nil && ed25519.Verify(key, raw, sig) {
			return fmt.Sprintf("the registry entry for %s was revoked by %s on %s; a newer one replaces it", r.ID, r.By, time.Unix(r.IssuedAt, 0).UTC().Format("2 January 15:04 UTC"))
		}
	}
	return ""
}
