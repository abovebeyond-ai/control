package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// The policy log (docs/working-set.md, "The gateway reads its policy"): the grants a gateway
// serves after the configuration it booted with, as a chain of signed versions. Each version
// names the hash of the one before it, the first names the hash of the carried configuration,
// so the gateway only ever moves forward and a replayed older version, wider or not, is
// refused. A version that widens anything is signed by the owner on his token; a version that
// only takes away may be signed by Elixir, and the gateway itself checks that it does.

// VersionType is the type every version carries, so a token signed for something else (a
// working set, a capability) is never read as a policy.
const VersionType = "policy-version"

// HandGrant is one hand's entry, the shape config.json gives it.
type HandGrant struct {
	Grant Grant `json:"grant"`
}

// LogVersion is one version of what the gateway serves: every hand's grant and the addresses of
// the running systems, with the change in the words the signer was shown (row 4.1.6).
type LogVersion struct {
	Type    string               `json:"type"`
	Iss     string               `json:"iss"`
	Version int                  `json:"version"`
	Prev    string               `json:"prev"`
	Iat     int64                `json:"iat"`
	Agents  map[string]HandGrant `json:"agents"`
	Systems map[string]string    `json:"systems,omitempty"`
	Change  []string             `json:"change"`
}

// SignedVersion is a version as it travels: the payload as signed, its signature, and the
// hash the next version names.
type SignedVersion struct {
	Token   string
	Payload []byte
	Version LogVersion
}

// Hash names a signed version: sha-256 over the token as it travels, tagged.
func (s SignedVersion) Hash() string { return HashOf([]byte(s.Token)) }

// HashOf is the tag the chain uses for any document: the carried configuration for the first
// version, a token for every later one.
func HashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256:" + hex.EncodeToString(sum[:])
}

// Signers are the keys the gateway accepts a version from, by DID URL: Widen may sign any
// version (the owner's token keys), Narrow only one that takes away (Elixir).
type Signers struct {
	Widen  map[string]string `json:"widen"`
	Narrow map[string]string `json:"narrow,omitempty"`
}

// Head is what the gateway serves now: the version and hash the next must follow, and the
// grants and systems in force.
type Head struct {
	Version int
	Hash    string
	Agents  map[string]HandGrant
	Systems map[string]string
}

// maxSkew bounds how far a version's iat may lie ahead of the gateway's clock.
const maxSkew = 5 * time.Minute

// ParseVersion reads a token, base64url(payload) "." base64url(Ed25519 signature), the form a
// working set has: the token signs the payload bytes exactly as they travel.
func ParseVersion(token string) (SignedVersion, error) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return SignedVersion{}, errors.New("a version is two base64url parts joined by a dot")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return SignedVersion{}, fmt.Errorf("payload: %w", err)
	}
	var v LogVersion
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return SignedVersion{}, fmt.Errorf("payload: %w", err)
	}
	return SignedVersion{Token: strings.TrimSpace(token), Payload: payload, Version: v}, nil
}

// Next judges a version against the head: signed by a key the gateway knows, the very next
// number, naming the head's hash, not from the future, and, from a key that may only take
// away, narrower than what is served. It returns the new head, or the reason it is refused.
func Next(head Head, s SignedVersion, signers Signers, now time.Time) (Head, error) {
	v := s.Version
	if v.Type != VersionType {
		return head, fmt.Errorf("not a policy version but %q", v.Type)
	}
	key, widen := signers.Widen[v.Iss]
	if !widen {
		var ok bool
		if key, ok = signers.Narrow[v.Iss]; !ok {
			return head, fmt.Errorf("%s is not a key this gateway takes a policy from", v.Iss)
		}
	}
	if err := verifySignature(key, s); err != nil {
		return head, err
	}
	if v.Version != head.Version+1 {
		return head, fmt.Errorf("version %d does not follow %d", v.Version, head.Version)
	}
	if v.Prev != head.Hash {
		return head, fmt.Errorf("version %d names %s before it, the gateway holds %s", v.Version, v.Prev, head.Hash)
	}
	if time.Unix(v.Iat, 0).After(now.Add(maxSkew)) {
		return head, fmt.Errorf("version %d is signed in the future", v.Version)
	}
	if len(v.Agents) == 0 {
		return head, errors.New("a version names at least one hand")
	}
	if len(v.Change) == 0 {
		return head, errors.New("a version says its change in words")
	}
	if !widen {
		if reason := Narrower(head.Agents, head.Systems, v.Agents, v.Systems); reason != "" {
			return head, fmt.Errorf("%s may only take away, and version %d %s", v.Iss, v.Version, reason)
		}
	}
	return Head{Version: v.Version, Hash: s.Hash(), Agents: v.Agents, Systems: v.Systems}, nil
}

func verifySignature(keyHex string, s SignedVersion) error {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("the signer's key is not an Ed25519 public key")
	}
	parts := strings.Split(s.Token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(key), s.Payload, sig) {
		return fmt.Errorf("the signature of version %d does not hold", s.Version.Version)
	}
	return nil
}

// Narrower says why next is not narrower than cur, or "" when it is: no new hand, and for
// every hand that stays no new kind, resource, task or accepted judgement, no higher count,
// no premises or per-action word dropped, and nothing else about it changed; no new system,
// and no system at another address.
func Narrower(cur map[string]HandGrant, curSystems map[string]string, next map[string]HandGrant, nextSystems map[string]string) string {
	agents := make([]string, 0, len(next))
	for a := range next {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, a := range agents {
		was, ok := cur[a]
		if !ok {
			return "adds the hand " + a
		}
		if reason := grantNarrower(was.Grant, next[a].Grant); reason != "" {
			return reason + " for " + a
		}
	}
	for s, addr := range nextSystems {
		was, ok := curSystems[s]
		if !ok {
			return "adds the system " + s
		}
		if was != addr {
			return "moves the system " + s + " to another address"
		}
	}
	return ""
}

func grantNarrower(cur, next Grant) string {
	if cur.Principal != next.Principal || cur.SubmitterKey != next.SubmitterKey || cur.PrincipalKey != next.PrincipalKey ||
		cur.MaxSensitivity != next.MaxSensitivity || !reflect.DeepEqual(nonNil(cur.PrincipalKeys), nonNil(next.PrincipalKeys)) {
		return "changes who speaks for it"
	}
	if k := firstOutside(next.Kinds, cur.Kinds); k != "" {
		return "adds the kind " + k
	}
	if r := firstOutside(next.Resources, cur.Resources); r != "" {
		return "adds the resource " + r
	}
	if cur.MaxPerKind > 0 && (next.MaxPerKind == 0 || next.MaxPerKind > cur.MaxPerKind) {
		return "raises the count per kind"
	}
	if k := firstOutside(cur.PremisesFor, next.PremisesFor); k != "" {
		return "drops the certificate for " + k
	}
	if k := firstOutside(cur.PerAction, next.PerAction); k != "" {
		return "drops the word per action for " + k
	}
	if j := firstOutside(judgements(next.Judgements), judgements(cur.Judgements)); j != "" {
		return "accepts the judgement " + j
	}
	if len(cur.Tasks) > 0 && len(next.Tasks) == 0 {
		return "drops the narrowing per task"
	}
	for name, t := range next.Tasks {
		was, ok := cur.Tasks[name]
		if len(cur.Tasks) == 0 {
			// A grant newly narrowed per task: each task stays within the grant's own.
			was, ok = TaskGrant{Kinds: cur.Kinds, PremisesFor: cur.PremisesFor, Judgements: cur.Judgements}, true
		}
		if !ok {
			return "adds the task " + name
		}
		if k := firstOutside(t.Kinds, was.Kinds); k != "" {
			return "adds the kind " + k + " to the task " + name
		}
		if k := firstOutside(was.PremisesFor, t.PremisesFor); k != "" {
			return "drops the certificate for " + k + " in the task " + name
		}
		if j := firstOutside(judgements(t.Judgements), judgements(was.Judgements)); j != "" {
			return "accepts the judgement " + j + " in the task " + name
		}
	}
	return ""
}

// judgements is what a list accepts: the default when it names none.
func judgements(list []string) []string {
	if len(list) == 0 {
		return DefaultJudgements
	}
	return list
}

// firstOutside is the first entry of list that is not in of, or "".
func firstOutside(list, of []string) string {
	for _, s := range list {
		if !contains(of, s) {
			return s
		}
	}
	return ""
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}
