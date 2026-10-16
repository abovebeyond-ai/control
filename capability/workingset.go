package capability

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// A working set is what the owner works on, up to which layer, until when, signed once on
// a hardware token (docs/working-set.md). A capability Portal signed after a passkey touch
// carries it whole under task.workingSet.token, so the gateway can hold Portal's word to
// what the owner set out, and not only Portal itself.
//
// Form: the capability's own, base64url(JSON payload) "." base64url(Ed25519 signature over
// those bytes).
type WorkingSet struct {
	Type     string   `json:"type"`
	Issuer   string   `json:"iss"`
	Subject  string   `json:"sub"`
	Projects []string `json:"projects"`
	Layer    string   `json:"layer"`
	Expires  int64    `json:"exp"`
	ID       string   `json:"jti"`
}

// MaxWorkingSet is the longest a set may stand: a week, and five minutes for clocks.
const MaxWorkingSet = 7*24*time.Hour + 5*time.Minute

// layers a set may reach, lowest first; B3 and up stay with the token, per action.
var layers = policy.Layers

// InsideWorkingSet holds a capability to the working set it carries. keys are the owner's
// token keys by DID URL (the grant's principal_keys); did is the DID whose hands the set is
// for; kinds is the table the radius of each kind is read from. It returns the set, or the
// first reason the capability falls outside it.
func InsideWorkingSet(p Payload, keys map[string]string, did string, kinds policy.Kinds, now time.Time) (WorkingSet, error) {
	var ws WorkingSet
	if p.Task.WorkingSet == nil || p.Task.WorkingSet.Token == "" {
		return ws, errors.New("Portal's word for this hand must carry the working set the owner signed on the token")
	}
	body, sig, ok := strings.Cut(p.Task.WorkingSet.Token, ".")
	raw, err1 := base64.RawURLEncoding.DecodeString(body)
	sigRaw, err2 := base64.RawURLEncoding.DecodeString(sig)
	if !ok || err1 != nil || err2 != nil || json.Unmarshal(raw, &ws) != nil {
		return ws, errors.New("the working set it carries is not a signed token")
	}
	pub, err := hex.DecodeString(keys[ws.Issuer])
	if keys[ws.Issuer] == "" || err != nil || len(pub) != ed25519.PublicKeySize {
		return ws, fmt.Errorf("the working set is signed by %s, not a token key the grant names", ws.Issuer)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sigRaw) {
		return ws, fmt.Errorf("the working set's signature does not hold under %s", ws.Issuer)
	}
	if ws.Type != "working-set" || ws.Subject != did {
		return ws, errors.New("the token it carries is not a working set for these hands")
	}
	if ws.Expires < p.Expires {
		return ws, errors.New("the capability outlasts the working set")
	}
	if time.Unix(ws.Expires, 0).Sub(now) > MaxWorkingSet {
		return ws, errors.New("a working set stands a week at most")
	}
	if !contains(ws.Projects, p.Task.Project) {
		return ws, fmt.Errorf("the project %s is not in the working set", p.Task.Project)
	}
	top := -1
	for i, l := range layers {
		if l == ws.Layer {
			top = i
		}
	}
	if top < 0 {
		return ws, fmt.Errorf("a working set reaches B1 or B2, not %q", ws.Layer)
	}
	for _, k := range p.Kinds {
		at := -1
		for i, l := range layers {
			if kinds[k].Radius == l {
				at = i
			}
		}
		if at < 0 || at > top {
			return ws, fmt.Errorf("%s is above the working set's layer %s", k, ws.Layer)
		}
	}
	return ws, nil
}
