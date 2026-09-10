// Package relying is the far end (row 8.3.5): what a runner or a merge check does
// with the evidence a dispatch or a pull request carries, before it acts. It
// resolves the gateway's key and the principal's key from the DID log, holds the
// record's signature, its claims and its measurement to what is published, and
// holds the capability to the record. Nothing here needs an account, a token or a
// word from the operator, which is the point: the halt lives where the operator
// cannot switch it off.
package relying

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/evidence"
)

// Keys resolved from the DID document.
type Keys struct {
	Gateway   ed25519.PublicKey // #control-gateway: signs the records
	Principal ed25519.PublicKey // #portal: signs the capabilities
	DID       string            // the document's id
	Aliases   []string          // its alsoKnownAs: the did:webvh form of a did:web document, and back
}

// Under says whether an agent id is a fragment of the DID or one of its aliases.
func (k Keys) Under(agent string) bool {
	for _, d := range append([]string{k.DID}, k.Aliases...) {
		if d != "" && strings.HasPrefix(agent, d+"#") {
			return true
		}
	}
	return false
}

// ResolveKeys reads a did.json (the derived document of a did:webvh log) and
// picks the two keys by fragment.
func ResolveKeys(ctx context.Context, url, gatewayFragment, principalFragment string) (Keys, error) {
	var k Keys
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return k, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return k, fmt.Errorf("the DID document answered %d", res.StatusCode)
	}
	var doc struct {
		ID                 string   `json:"id"`
		AlsoKnownAs        []string `json:"alsoKnownAs"`
		VerificationMethod []struct {
			ID           string `json:"id"`
			PublicKeyJwk struct {
				X string `json:"x"`
			} `json:"publicKeyJwk"`
		} `json:"verificationMethod"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&doc); err != nil {
		return k, err
	}
	k.DID = doc.ID
	k.Aliases = doc.AlsoKnownAs
	for _, m := range doc.VerificationMethod {
		raw, err := base64.RawURLEncoding.DecodeString(m.PublicKeyJwk.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		switch {
		case strings.HasSuffix(m.ID, "#"+gatewayFragment):
			k.Gateway = ed25519.PublicKey(raw)
		case strings.HasSuffix(m.ID, "#"+principalFragment):
			k.Principal = ed25519.PublicKey(raw)
		}
	}
	if k.Gateway == nil {
		return k, fmt.Errorf("the DID document names no #%s key", gatewayFragment)
	}
	if k.Principal == nil {
		return k, fmt.Errorf("the DID document names no #%s key", principalFragment)
	}
	return k, nil
}

// Options for one check.
type Options struct {
	Repository string        // owner/repo the runner or the check runs in
	Kind       string        // the action kind expected: workflow.dispatch, pull.open
	MaxAge     time.Duration // how old the record may be; zero means no bound (a merge check)
	MRTD       string        // the measurement the mirror publishes, hex; empty means not checked
	Now        time.Time
}

// Result is what was held and what was found.
type Result struct {
	OK       bool
	Reasons  []string
	Agent    string
	Task     map[string]any
	Step     int
	Verdict  string
	Measured string
}

// DecodeToken takes the evidence as a dispatch carries it: base64url of the
// record's JSON.
func DecodeToken(b64 string) (evidence.Token, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, errors.New("the evidence is not base64")
		}
	}
	var t evidence.Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("the evidence is not a record: %v", err)
	}
	return t, nil
}

// Check holds a record and a capability to the keys and the options. Every
// failing condition is a reason; the caller acts only on OK.
func Check(tok evidence.Token, capTok string, keys Keys, o Options) Result {
	r := Result{}
	fail := func(f string, a ...any) { r.Reasons = append(r.Reasons, fmt.Sprintf(f, a...)) }
	if tok == nil {
		fail("no evidence")
		return r
	}
	if !evidence.Verify(tok, keys.Gateway) {
		fail("the record is not signed by the gateway's key from the DID log")
	}
	c := tok.Claims()
	str := func(k string) string { s, _ := c[k].(string); return s }
	r.Agent, r.Verdict = str("agent_id"), str("verdict")
	if n, ok := c["step_index"].(float64); ok {
		r.Step = int(n)
	}
	if r.Verdict != "ALLOW" {
		fail("the record's verdict is %s, not ALLOW", r.Verdict)
	}
	if str("control_phase") != "request" {
		fail("the record is a %s record, not the request", str("control_phase"))
	}
	if str("target_resource") != o.Repository {
		fail("the record is for %s, this is %s", str("target_resource"), o.Repository)
	}
	if m := str("control_matched"); o.Kind != "" && !strings.HasPrefix(m, o.Kind+" on ") {
		fail("the record matched %q, not %s", m, o.Kind)
	}
	if !keys.Under(str("agent_id")) {
		fail("the record's agent %s is not under the DID %s or its aliases", str("agent_id"), keys.DID)
	}
	if o.MaxAge > 0 {
		if iat, ok := tok["iat"].(float64); !ok || o.Now.Sub(time.Unix(int64(iat), 0)) > o.MaxAge {
			fail("the record is older than %s", o.MaxAge)
		}
	}
	att, _ := tok["submods"].(map[string]any)
	attestation, _ := att["attestation"].(map[string]any)
	platform, _ := attestation["platform"].(string)
	if _, m, err := canonical.UntagAny(fmt.Sprint(attestation["measurement"])); err == nil {
		r.Measured = m
	}
	if platform != "INTEL_TDX" {
		fail("the record was written on platform %s, not a hardware-attested one", platform)
	}
	if o.MRTD != "" && r.Measured != o.MRTD {
		fail("the record's measurement is not the one the mirror's attestation names")
	}
	task, _ := c["control_task"].(map[string]any)
	r.Task = task
	if capTok == "" {
		fail("no capability from the principal")
	} else {
		issuer, _ := tok["iss"].(string) // the gateway the capability was meant for
		p, err := capability.Verify(capTok, keys.Principal, issuer, str("agent_id"), o.Now)
		if err != nil && !(o.MaxAge == 0 && strings.Contains(err.Error(), "expired")) {
			fail("capability: %v", err)
		}
		if err == nil || (o.MaxAge == 0 && strings.Contains(err.Error(), "expired")) {
			if !contains(p.Resources, o.Repository) || (o.Kind != "" && !contains(p.Kinds, o.Kind)) {
				fail("the capability does not cover %s on %s", o.Kind, o.Repository)
			}
			if jti, _ := task["jti"].(string); jti != p.ID {
				fail("the capability (%s) is not the one the record names (%s)", p.ID, jti)
			}
		}
	}
	r.OK = len(r.Reasons) == 0
	return r
}

// Footer is how a pull request carries its evidence: two lines at the end of
// the body, machine-readable and short enough to read.
const FooterMark = "<!-- proof-of-control -->"

func Footer(tokenB64, capTok string) string {
	return "\n\n" + FooterMark + "\nEvidence: " + tokenB64 + "\nCapability: " + capTok + "\n"
}

// FromBody finds the evidence and the capability in a pull request body.
func FromBody(body string) (tokenB64, capTok string, err error) {
	i := strings.Index(body, FooterMark)
	if i < 0 {
		return "", "", errors.New("the pull request carries no evidence footer")
	}
	for _, line := range strings.Split(body[i:], "\n") {
		switch {
		case strings.HasPrefix(line, "Evidence: "):
			tokenB64 = strings.TrimSpace(strings.TrimPrefix(line, "Evidence: "))
		case strings.HasPrefix(line, "Capability: "):
			capTok = strings.TrimSpace(strings.TrimPrefix(line, "Capability: "))
		}
	}
	if tokenB64 == "" || capTok == "" {
		return "", "", errors.New("the evidence footer is incomplete")
	}
	return tokenB64, capTok, nil
}

// EncodeToken is the inverse of DecodeToken.
func EncodeToken(t evidence.Token) string {
	raw, _ := json.Marshal(t)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// KeyHex is a convenience for tests and logs.
func KeyHex(k ed25519.PublicKey) string { return hex.EncodeToString(k) }
