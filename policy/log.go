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
// only adds reversible kinds or resources may be signed by Portal's key after the owner's
// passkey (RepairOnly); a version that only takes away may be signed by Elixir. The gateway
// itself checks that each does no more.

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

// SignedVersion is a version as it travels: the token, the bytes its signature covers (the
// whole payload in the earlier form, the head in the digest form), and the version read out of
// it; Hash is what the next version names.
type SignedVersion struct {
	Token   string
	Payload []byte
	Version LogVersion
}

// versionHead is what the key signs in the digest form: who, which number, after what, when,
// and the body by its hash. A few hundred bytes whatever the grants weigh, so a key that takes
// only short input (a YubiKey's PIV slot signs about a kilobyte in one piece) signs any version.
type versionHead struct {
	Type     string `json:"type"`
	Iss      string `json:"iss"`
	Version  int    `json:"version"`
	Prev     string `json:"prev"`
	Iat      int64  `json:"iat"`
	BodyHash string `json:"body_hash"`
}

// versionBody is what the head names: the grants, the systems and the change in words.
type versionBody struct {
	Agents  map[string]HandGrant `json:"agents"`
	Systems map[string]string    `json:"systems,omitempty"`
	Change  []string             `json:"change"`
}

// Formats are the token forms this gateway reads, the preferred one first. Served on
// /v1/policy and /v1/agents, so a signer uses the digest form only once the gateway takes it:
// a version in a form the gateway does not read is refused, and a refused version blocks the
// chain until the owner replaces it.
var Formats = []string{"digest", "payload"}

// Fields are the optional grant fields this gateway reads that an earlier release did not.
// A body is decoded strictly, so a version naming a field the gateway does not know is
// refused and blocks the chain: a signer writes one only once it is served here, on
// /v1/policy and /v1/agents beside the formats.
var Fields = []string{"working_set"}

// Hash names a signed version: sha-256 over the token as it travels, tagged.
func (s SignedVersion) Hash() string { return HashOf([]byte(s.Token)) }

// HashOf is the tag the chain uses for any document: the carried configuration for the first
// version, a token for every later one.
func HashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha-256:" + hex.EncodeToString(sum[:])
}

// Signers are the keys the gateway accepts a version from, by DID URL: Widen may sign any
// version (the owner's token keys), Repair only one that adds nothing but reversible kinds and
// resources (Portal's key, after the owner's passkey), Narrow only one that takes away (Elixir).
type Signers struct {
	Widen  map[string]string `json:"widen"`
	Narrow map[string]string `json:"narrow,omitempty"`
	Repair map[string]string `json:"repair,omitempty"`
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

// ParseVersion reads a token in either of its forms. The digest form, since v0.40.0, is three
// base64url parts, head "." body "." signature: the Ed25519 signature covers the head's bytes
// exactly as they travel, and the head names the body by its sha-256, so what the key signed
// and what the gateway reads are bound together without the key ever seeing the body. The
// earlier form is two parts, base64url(payload) "." base64url(signature), the whole payload
// signed, the form a working set has; versions kept on disk from before the change are in it
// and are still read.
func ParseVersion(token string) (SignedVersion, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	switch len(parts) {
	case 2:
		payload, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return SignedVersion{}, fmt.Errorf("payload: %w", err)
		}
		var v LogVersion
		if err := decodeStrict(payload, &v); err != nil {
			return SignedVersion{}, fmt.Errorf("payload: %w", err)
		}
		return SignedVersion{Token: token, Payload: payload, Version: v}, nil
	case 3:
		head, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return SignedVersion{}, fmt.Errorf("head: %w", err)
		}
		body, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return SignedVersion{}, fmt.Errorf("body: %w", err)
		}
		var h versionHead
		if err := decodeStrict(head, &h); err != nil {
			return SignedVersion{}, fmt.Errorf("head: %w", err)
		}
		var b versionBody
		if err := decodeStrict(body, &b); err != nil {
			return SignedVersion{}, fmt.Errorf("body: %w", err)
		}
		if h.BodyHash != HashOf(body) {
			return SignedVersion{}, fmt.Errorf("the head of version %d names a body of %s, and the body is %s", h.Version, h.BodyHash, HashOf(body))
		}
		v := LogVersion{Type: h.Type, Iss: h.Iss, Version: h.Version, Prev: h.Prev, Iat: h.Iat, Agents: b.Agents, Systems: b.Systems, Change: b.Change}
		return SignedVersion{Token: token, Payload: head, Version: v}, nil
	}
	return SignedVersion{}, errors.New("a version is a head, a body and a signature, or a payload and a signature, as base64url parts joined by dots")
}

// decodeStrict reads JSON into a struct and refuses a field the struct does not name, so a
// version cannot carry anything the gateway does not read.
func decodeStrict(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// Next judges a version against the head: signed by a key the gateway knows, the very next
// number, naming the head's hash, not from the future, and, from a key that may only take
// away, narrower than what is served, or from a repair key, no more than a repair of it. It returns the new head, or the reason it is refused.
func Next(head Head, s SignedVersion, signers Signers, now time.Time) (Head, error) {
	v := s.Version
	if v.Type != VersionType {
		return head, fmt.Errorf("not a policy version but %q", v.Type)
	}
	key, widen := signers.Widen[v.Iss]
	narrowKey, narrow := signers.Narrow[v.Iss]
	repairKey, repair := signers.Repair[v.Iss]
	switch {
	case widen:
	case narrow:
		key = narrowKey
	case repair:
		key = repairKey
	default:
		return head, fmt.Errorf("%s is not a key this gateway takes a policy from", v.Iss)
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
	if !widen && narrow {
		if reason := Narrower(head.Agents, head.Systems, v.Agents, v.Systems); reason != "" {
			return head, fmt.Errorf("%s may only take away, and version %d %s", v.Iss, v.Version, reason)
		}
	}
	if !widen && !narrow {
		if reason := RepairOnly(head.Agents, head.Systems, v.Agents, v.Systems); reason != "" {
			return head, fmt.Errorf("%s may only add reversible kinds and resources, and version %d %s", v.Iss, v.Version, reason)
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
	sig, err := base64.RawURLEncoding.DecodeString(parts[len(parts)-1])
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
	if cur.WorkingSet && !next.WorkingSet {
		return "drops the working set for Portal's word"
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
