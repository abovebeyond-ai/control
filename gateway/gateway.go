// Package gateway is the Action Interception Gateway together with the
// attesting environment the reference keeps beside it: one intercepted step
// evaluates the premises, then the policy, extends the chain and the tree,
// signs a token, writes it durably, and only then answers. A refusal has its
// own record; a store that cannot be written yields FAIL_CLOSED and nothing.
//
// Inside this package is only what can change a verdict or hold a credential.
// Anchors, witnesses and verifiers read the signed checkpoint from outside.
package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/merkle"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
	"github.com/abovebeyond-ai/control/registry"
)

// Engine names the code that judges; it is the software measurement.
var Engine = "control-1"

func engineForTest(name string) { Engine = name }

// Verdict is the gateway's answer with the evidence that answers for it.
type Verdict struct {
	Verdict  string
	Reason   string
	Token    evidence.Token // nil for FAIL_CLOSED: nothing could be written
	Step     int
	ActionID string // shared by the three records of one action: request, effect, result
	// Signer is the registry entry whose holder gave the word, under a grant that names an
	// organisation: the effect is held to its ceiling.
	Signer *registry.Entry
}

// Phases of one intercepted action (row 7.1.2): the request judged before anything
// happens, the effect as performed, and the result as handed back. Each is its own
// signed record on the chain; all three carry the same control_action.
const (
	PhaseRequest = "request"
	PhaseEffect  = "effect"
	PhaseResult  = "result"
)

// Allowed says whether the effect may proceed.
func (v Verdict) Allowed() bool { return v.Verdict == "ALLOW" }

// Config of a gateway for one agent under one policy.
type Config struct {
	Issuer      string
	Agent       string
	Policy      policy.Policy
	Store       *log.Store
	Key         ed25519.PrivateKey
	AgbomDigest string // digest of the agent bill of materials when the hand submits none; the deployed commit is honest for deterministic hands
	Release     string // the gateway's own release and checksum, named in every record as control_gateway
	// PolicyVersion names the version of the policy log served ("v3 sha-256:…"), in every
	// record as control_policy; empty when the gateway reads no policy log.
	PolicyVersion string
	Platform      string           // SOFTWARE until an enclave attests
	Clock         func() time.Time // injectable for reproducible records
	// Attestation, when present, is the hardware's word: the platform becomes
	// INTEL_TDX and the measurement the MRTD from the quote, which must bind
	// this gateway's key. Without it the measurement is the software one, the
	// digest of the engine and the policy bundle, and nobody but the operator
	// vouches for it.
	Attestation *attest.Record
	// Revoked, when set, says whether the owner ended a capability before it expired, and
	// since when: Portal's list of words withdrawn early (cmd/gateway/revoked.go). A
	// capability holds to its signature and expiry on its own; this is what lets ending a
	// word at Portal reach an action the hand already holds a token for.
	Revoked func(jti string) (since string, revoked bool)
	// RevokedEntry answers the signed revocation (rv1) of a registry entry by its digest, or "":
	// a person who enrolled a new phone has the old entry revoked by whoever signed it, so the
	// old passkey stops speaking even where a relay still serves its entry.
	RevokedEntry func(digest string) string
	// Orgs are the root keys pinned per organisation, for a grant that names one: the start of
	// every registry chain (docs/odoo-gate.md).
	Orgs map[string]ed25519.PublicKey
	// Passkey is the relying party a person's passkey word is held to.
	Passkey capability.Party
}

// Gateway holds the chain state of one agent. One instance is one path.
type Gateway struct {
	cfg         Config
	measurement string // hex, untagged
	alg         string // the measurement's algorithm: sha-256 for software, sha-384 for an MRTD
	mu          sync.Mutex
	head        string
	heads       []string // the chain head after each record, for a checkpoint at any size
	tree        *merkle.Tree
	step        int
	runs        map[string]policy.PathSummary // path summary per run; "" is the run of a hand that names none
	// att is the attestation in force: a Confidential Space token is taken again every day
	// (SetAttestation), and each record names the one it was written under.
	att atomic.Pointer[attest.Record]
	// agboms remembers, per action, the digest of the bill of materials the hand
	// submitted with the request, so the effect and result records name the same one.
	agboms map[string]string
}

// Open rebuilds the chain from the store. A log whose last record does not
// replay refuses to open: acting on top of a rewrite is how it gets covered.
func Open(cfg Config) (*Gateway, error) {
	if cfg.Store == nil || cfg.Key == nil || cfg.Agent == "" {
		return nil, errors.New("gateway: store, key and agent are required")
	}
	if cfg.Platform == "" {
		cfg.Platform = "SOFTWARE"
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.AgbomDigest == "" {
		cfg.AgbomDigest, _ = canonical.Digest(map[string]any{"agbom": "control", "version": "unknown"})
	}
	// The software measurement names the code that judges and nothing else. The
	// policy is a claim of its own on every record (policy_bundle_hash), so a
	// grant that changes does not break the chain; a chain is one measured
	// environment, and a verifier holds every record to the same measurement.
	// Folding the bundle in here made Elixir's own chain, whose grant names
	// one repository per run, fail verification at its third record.
	measurement, err := canonical.Digest(map[string]any{"engine": Engine})
	if err != nil {
		return nil, err
	}
	alg := canonical.Algorithm
	if cfg.Attestation != nil {
		if err := bindsKey(cfg.Attestation, cfg.Key.Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
		cfg.Platform = cfg.Attestation.Platform
		alg, measurement, err = canonical.UntagAny(cfg.Attestation.Measurement())
		if err != nil {
			return nil, err
		}
	}
	g := &Gateway{cfg: cfg, measurement: measurement, alg: alg, head: evidence.GenesisHead(), tree: merkle.New(), runs: map[string]policy.PathSummary{}}
	g.att.Store(cfg.Attestation)
	records, err := cfg.Store.Records(cfg.Agent)
	if err != nil {
		return nil, err
	}
	for i, tok := range records {
		c := tok.Claims()
		// The link alone is not the proof. Until 22 September 2026 this replay checked
		// the measurement, the sequence and the chain link but not the signature, so a
		// log rewritten with recomputed links opened as if it held: the one thing an
		// attacker cannot forge is exactly the one thing that was not read.
		if !evidence.Verify(tok, g.cfg.Key.Public().(ed25519.PublicKey)) {
			return nil, fmt.Errorf("record %d of the evidence log for %s is not signed by this gateway's key; refusing to act on top of it", i, cfg.Agent)
		}
		if i == 0 {
			// A chain judged under another measurement is another environment's
			// chain: appending to it would hand the verifier a break at this
			// record. Rotate it (rename the log and its attachments) and start
			// anew; the retired chain verifies on its own with its own measurement.
			att, _ := tok["submods"].(map[string]any)
			attestation, _ := att["attestation"].(map[string]any)
			if _, m, err := canonical.UntagAny(str(attestation["measurement"])); err != nil || m != measurement {
				return nil, fmt.Errorf("the evidence log for %s was judged under measurement %s, this gateway measures %s:%s; rotate the log before acting", cfg.Agent, str(attestation["measurement"]), alg, measurement)
			}
		}
		snapshot, err := canonical.Untag(str(c["canonical_snapshot_hash"]))
		if err != nil || num(c["step_index"]) != i {
			return nil, fmt.Errorf("the evidence log for %s has a gap at record %d; refusing to act on top of it", cfg.Agent, i)
		}
		verdict := str(c["verdict"])
		link := evidence.Link(g.head, snapshot, verdict)
		if ch, err := canonical.Untag(str(c["chain_head"])); err != nil || ch != link {
			return nil, fmt.Errorf("the evidence log for %s breaks at record %d; refusing to act on top of it", cfg.Agent, i)
		}
		leaf, _ := evidence.Leaf(snapshot, verdict)
		g.tree.Append(leaf)
		g.head = link
		g.heads = append(g.heads, link)
		// The path summary of each run is rebuilt from the action written beside
		// the record, so a restart does not forget what a run already did.
		var done stepAction
		if found, _ := cfg.Store.Attachment(cfg.Agent, i, "action", &done); found {
			g.runs[done.Run] = g.summary(done.Run).Fold(done.Action, verdict)
		}
	}
	g.step = len(records)
	// An action with a request record and no effect record is an action the gateway was
	// stopped in the middle of (12 September 2026, 08:26 UTC: a pull.open judged ALLOW,
	// then the machine was reset before the effect was recorded). The effect may or may
	// not have reached the far end; what is certain is that nothing recorded it. The two
	// missing records are written now, saying exactly that, so every action on the chain
	// has its three and a verifier reads an interruption instead of a gap.
	g.closeInterrupted(records)
	return g, nil
}

// tailHolds reads the last record in the store and holds it to what this gateway believes:
// the same step, the same chain head, and a signature by this gateway's key. It is the
// per-action half of the fail-closed rule; Open is the once-per-start half that replays
// everything. A store that cannot be read is a halt as well, because a gateway that cannot
// see its own evidence cannot promise that the next record follows the last one.
//
// Called with g.mu held.
func (g *Gateway) tailHolds() (string, bool) {
	tail, count, err := g.cfg.Store.Tail(g.cfg.Agent)
	if err != nil {
		return "the evidence log cannot be read: " + err.Error(), false
	}
	if count != g.step {
		return fmt.Sprintf("the evidence log holds %d records where this gateway stands at step %d; refusing to act until it is replayed", count, g.step), false
	}
	if g.step == 0 {
		return "", true
	}
	if !evidence.Verify(tail, g.cfg.Key.Public().(ed25519.PublicKey)) {
		return "the last record in the evidence log is not signed by this gateway's key; refusing to act on top of it", false
	}
	head, err := canonical.Untag(str(tail.Claims()["chain_head"]))
	if err != nil || head != g.head {
		return "the last record in the evidence log does not carry the chain head this gateway holds; refusing to act on top of it", false
	}
	return "", true
}

// Interrupted is the outcome written for an action whose effect the gateway never recorded.
const Interrupted = "interrupted: the gateway stopped between the request record and the effect record; whether the effect reached the far end is not recorded"

func (g *Gateway) closeInterrupted(records []evidence.Token) {
	seen := map[string]map[string]bool{}
	var order []string
	principals := map[string]string{}
	steps := map[string]int{}
	for i, tok := range records {
		c := tok.Claims()
		id, phase := str(c["control_action"]), str(c["control_phase"])
		if id == "" {
			continue
		}
		if seen[id] == nil {
			seen[id] = map[string]bool{}
			order = append(order, id)
			principals[id] = str(c["initiating_user"])
			steps[id] = i
		}
		seen[id][phase] = true
	}
	for _, id := range order {
		if seen[id][PhaseEffect] && seen[id][PhaseResult] {
			continue
		}
		c := records[steps[id]].Claims()
		verdict := str(c["verdict"])
		outcome := map[string]any{"ok": false, "error": Interrupted}
		var done stepAction
		if found, _ := g.cfg.Store.Attachment(g.cfg.Agent, steps[id], "action", &done); !found {
			// The action beside the record went with the same reset (a file whose name
			// never reached the disk). The record's own claims still say what was judged:
			// the kind, from what the grant matched, and the resource. That is what the
			// closing records name, and they say the parameters are lost.
			kind, _, _ := strings.Cut(str(c["control_matched"]), " on ")
			done = stepAction{Action: policy.Action{Kind: kind, Resource: str(c["target_resource"])}}
			outcome["error"] = Interrupted + "; the action's parameters beside the request record were lost with the same stop, kind and resource are taken from the record"
		}
		if !seen[id][PhaseEffect] {
			g.Follow(done.Run, id, PhaseEffect, done.Action, principals[id], verdict, "effect interrupted", outcome)
		}
		if !seen[id][PhaseResult] {
			g.Follow(done.Run, id, PhaseResult, done.Action, principals[id], verdict, "result interrupted", map[string]any{"verdict": verdict, "action": id, "effect": outcome})
		}
	}
}

// stepAction is what is written beside each record so the run's path can be
// folded again at open: the run and the action, which the claims do not carry.
type stepAction struct {
	Run    string        `json:"run"`
	Action policy.Action `json:"action"`
}

func (g *Gateway) summary(run string) policy.PathSummary {
	if phi, ok := g.runs[run]; ok {
		return phi
	}
	return policy.PathSummary{PerKind: map[string]int{}}
}

// Measurement names what judges, as untagged hex: under hardware attestation
// the MRTD of the trust domain, otherwise the digest of the engine and the
// policy bundle.
func (g *Gateway) Measurement() string { return g.measurement }

// Platform is what vouches for the measurement.
func (g *Gateway) Platform() string { return g.cfg.Platform }

// Attestation is the hardware's record, or nil when software attests.
func (g *Gateway) Attestation() *attest.Record { return g.att.Load() }

// SetAttestation replaces the attestation in force by a newer one of the same key and the same
// measurement: the daily token of a gateway in Confidential Space.
func (g *Gateway) SetAttestation(r *attest.Record) error {
	if r == nil {
		return errors.New("gateway: no attestation")
	}
	if err := bindsKey(r, g.cfg.Key.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	if _, m, err := canonical.UntagAny(r.Measurement()); err != nil || m != g.measurement || r.Platform != g.cfg.Platform {
		return errors.New("gateway: the new attestation names another platform or measurement")
	}
	g.att.Store(r)
	return nil
}

// bindsKey: a quote whose REPORTDATA, or a token whose nonce, binds another key is somebody
// else's attestation.
func bindsKey(r *attest.Record, pub ed25519.PublicKey) error {
	if r.IsConfidentialSpace() {
		c, err := attest.ParseCSClaims(r.Token)
		if err != nil || !c.HasNonce(attest.KeyNonce(pub)) || r.ImageDigest == "" || c.ImageDigest != r.ImageDigest {
			return errors.New("gateway: the attestation token does not bind this gateway's key to its image")
		}
		return nil
	}
	quote, err := attest.Parse(mustDecodeB64(r.QuoteB64))
	if err != nil || !attest.BindsKey(quote, pub) {
		return errors.New("gateway: the attestation does not bind this gateway's key")
	}
	return nil
}

// submods is the attestation part of a record: the platform and measurement, and under
// Confidential Space the software and the digest of the token in force.
func (g *Gateway) submods() map[string]any {
	a := map[string]any{"platform": g.cfg.Platform, "measurement": g.alg + ":" + g.measurement}
	if r := g.att.Load(); r.IsConfidentialSpace() {
		a["software"] = r.Software
		a["image_digest"] = r.ImageDigest
		a["token"] = canonical.Tag(canonical.SHA256([]byte(r.Token)))
	}
	return map[string]any{"attestation": a}
}

// PublicKey of the evidence signer.
func (g *Gateway) PublicKey() ed25519.PublicKey { return g.cfg.Key.Public().(ed25519.PublicKey) }

// Step is the next step index.
func (g *Gateway) Step() int { g.mu.Lock(); defer g.mu.Unlock(); return g.step }

// Submit is one intercepted step of a hand that names no run: every step it
// ever takes counts as one run, the strictest reading of the grant.
func (g *Gateway) Submit(action policy.Action, principal string, extension map[string]any, prem *premises.Material) Verdict {
	return g.SubmitIn("", action, principal, extension, prem)
}

// SubmitSigned is SubmitIn for a hand that signs what it sends: body is exactly
// the bytes the hand signed, signature the Ed25519 signature over them. When the
// grant names a submitter key the signature must verify under it, or the request
// is refused and the refusal recorded; when it names none, the signature is noted
// if present. The record carries control_submitter: verified, unsigned or invalid.
func (g *Gateway) SubmitSigned(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material, body, signature []byte) Verdict {
	return g.SubmitWith(run, action, principal, extension, prem, body, signature, "")
}

// SubmitWith is SubmitSigned with the principal's capability for the task (rows
// 4.2.1, 5.1.3). When the grant names a principal key, the token must verify
// under it, be meant for this gateway and this agent, be in date, and cover the
// kind and the resource; otherwise the request is refused and the refusal
// recorded. The record carries the token's digest and the task it names.
func (g *Gateway) SubmitWith(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material, body, signature []byte, token string) Verdict {
	return g.SubmitChained(run, action, principal, extension, prem, body, signature, token, nil)
}

// SubmitChained is SubmitWith with the registry chain that vouches for the person behind a
// passkey capability, for a grant that names an organisation (Grant.Org, docs/odoo-gate.md):
// the chain must lead from the organisation's pinned root to the entry the capability names
// as its issuer, narrowing at every step, and the passkey must have signed under that entry's
// key. The person, not the grant's principal, is then the record's initiating user, and the
// verdict carries the entry, whose ceiling the effect is held to.
func (g *Gateway) SubmitChained(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material, body, signature []byte, token string, chain []string) Verdict {
	merged, state := g.submitter(body, signature, extension)
	var capReason string
	var signer *registry.Entry
	pol := g.cfg.Policy
	if g.cfg.Policy.Grant.Org != "" {
		var p capability.Payload
		p, signer, capReason = g.orgWord(run, action, token, chain, merged)
		if capReason == "" {
			principal = signer.ID
			pol, capReason = g.heldWord(p, action, merged, "the person's word")
		}
	} else if key := g.cfg.Policy.Grant.PrincipalKey; key != "" || len(g.cfg.Policy.Grant.PrincipalKeys) > 0 {
		switch {
		case token == "":
			capReason = "no capability from the principal for this task"
		default:
			// Which of the principal's keys: the one the token names as its issuer, when the
			// grant lists it by fragment (the operator's token keys), else the principal key.
			byToken := false
			if unverified, _, _, perr := capability.Parse(token); perr == nil {
				if k, named := g.cfg.Policy.Grant.PrincipalKeys[unverified.Issuer]; named {
					key, byToken = k, true
				}
			}
			if key == "" {
				capReason = "the capability's issuer is not a key the grant names"
				break
			}
			pub, err := hex.DecodeString(key)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				capReason = "the grant's principal key is not a valid key"
				break
			}
			p, err := capability.Verify(token, ed25519.PublicKey(pub), g.cfg.Issuer, g.cfg.Agent, g.cfg.Clock())
			if err != nil {
				capReason = err.Error()
				break
			}
			merged["control_capability"] = capability.Digest(token)
			task := map[string]any{"playbook": p.Task.Playbook, "project": p.Task.Project, "jti": p.ID, "exp": p.Expires, "iss": p.Issuer}
			merged["control_task"] = task
			// Portal's word is held to the set the owner signed on the token, when the grant says so.
			if g.cfg.Policy.Grant.WorkingSet && !byToken {
				did, _, _ := strings.Cut(g.cfg.Agent, "#")
				ws, err := capability.InsideWorkingSet(p, g.cfg.Policy.Grant.PrincipalKeys, did, g.cfg.Policy.Kinds(), g.cfg.Clock())
				if err != nil {
					capReason = err.Error()
					break
				}
				task["working_set"] = map[string]any{"jti": ws.ID, "iss": ws.Issuer}
			}
			pol, capReason = g.heldWord(p, action, merged, "the operator's word")
		}
	} else if token != "" {
		merged["control_capability"] = capability.Digest(token)
	} else if g.cfg.Policy.PerTask() {
		_, capReason = g.cfg.Policy.ForTask("")
	}
	v := g.submit(run, action, principal, merged, prem, pol, g.cfg.Policy.Grant.SubmitterKey != "" && state != "verified", capReason)
	if capReason == "" {
		v.Signer = signer
	}
	return v
}

// submitter adds to the extension whether the hand signed exactly these bytes: verified,
// unsigned or invalid.
func (g *Gateway) submitter(body, signature []byte, extension map[string]any) (map[string]any, string) {
	state := "unsigned"
	if len(signature) > 0 {
		state = "invalid"
		if key := g.cfg.Policy.Grant.SubmitterKey; key != "" {
			if pub, err := hex.DecodeString(key); err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(ed25519.PublicKey(pub), body, signature) {
				state = "verified"
			}
		}
	}
	merged := map[string]any{"control_submitter": state}
	for k, v := range extension {
		merged[k] = v
	}
	return merged, state
}

// SubmitterHolds says whether the submission meets the grant's submitter key: signed by it
// when the grant names one, anything when it names none.
func (g *Gateway) SubmitterHolds(body, signature []byte) bool {
	_, state := g.submitter(body, signature, nil)
	return g.cfg.Policy.Grant.SubmitterKey == "" || state == "verified"
}

// heldWord holds a verified capability to the action and returns the policy it is judged
// under, or why not: not ended early, covering the kind and the resource, a task the grant
// names, and for a kind that needs a word per act (NeedsWord), naming this act, spent here.
func (g *Gateway) heldWord(p capability.Payload, action policy.Action, merged map[string]any, whose string) (policy.Policy, string) {
	pol := g.cfg.Policy
	if g.cfg.Revoked != nil && p.ID != "" {
		if since, ended := g.cfg.Revoked(p.ID); ended {
			return pol, "the owner ended this capability at " + since + ", before it expired"
		}
	}
	if !p.Covers(action.Kind, action.Resource) {
		return pol, "the capability does not cover " + action.Kind + " on " + action.Resource
	}
	// The task the principal named selects the task's own rules out of the grant.
	pol, reason := g.cfg.Policy.ForTask(p.Task.Playbook)
	if reason != "" {
		return pol, reason
	}
	// A kind the grant lists under PerAction, or above B1 under an organisation, needs a word
	// for this act, spent here.
	if containsString(pol.Grant.PerAction, action.Kind) || g.orgActs(action.Kind) {
		if p.Act == "" {
			return pol, action.Kind + " needs " + whose + " for this act, and this word names a period instead"
		}
		if want := capability.ActDigest(action); p.Act != want {
			return pol, whose + " names another act than this one"
		}
		if p.ID == "" {
			return pol, "a word for one act needs an id to be spent under"
		}
		fresh, err := g.cfg.Store.Spend(p.ID)
		if err != nil {
			return pol, "the word could not be spent: " + err.Error()
		}
		if !fresh {
			return pol, "this word was already spent"
		}
		merged["control_word"] = map[string]any{"act": p.Act, "spent": true}
	}
	return pol, ""
}

// orgWord verifies a passkey capability and the registry chain behind it, for a grant that
// names an organisation, and adds what it found to the record: the capability's digest, the
// task, and the chain by its ids and digest with the role and ceiling of the entry that spoke,
// and its daily allowance with what was spent against it today when it has one.
func (g *Gateway) orgWord(run string, action policy.Action, token string, chain []string, merged map[string]any) (capability.Payload, *registry.Entry, string) {
	org := g.cfg.Policy.Grant.Org
	var p capability.Payload
	if token == "" {
		// Nothing to verify, so the refusal says what the grant would have said, if it refuses,
		// and otherwise which word is missing.
		if verdict, reason := g.Precheck(run, action); verdict != "ALLOW" {
			return p, nil, reason
		}
		if g.NeedsWord(action.Kind) {
			return p, nil, action.Kind + " needs the word of a person of " + org + " for this act"
		}
		return p, nil, "no mandate from a person of " + org
	}
	if !capability.IsPasskey(token) {
		return p, nil, "a capability under " + org + " is a passkey word (wa1)"
	}
	k, err := capability.ParsePasskey(token)
	if err != nil {
		return p, nil, err.Error()
	}
	entries, err := registry.VerifyChain(chain, g.cfg.Orgs, g.cfg.Clock())
	if err != nil {
		return p, nil, err.Error()
	}
	if why := registry.Revoked(chain, entries, g.cfg.Orgs, g.cfg.RevokedEntry); why != "" {
		return p, nil, why
	}
	leaf := entries[len(entries)-1]
	if leaf.Org != org {
		return p, nil, "the registry chain is of " + leaf.Org + ", and this grant listens to " + org
	}
	if k.Payload.Issuer != leaf.ID {
		return p, nil, "the word is signed as " + k.Payload.Issuer + ", and the registry chain ends at " + leaf.ID
	}
	holder, err := leaf.Holder.ECDSA()
	if err != nil {
		return p, nil, "the registry entry " + leaf.ID + " holds no passkey: " + err.Error()
	}
	p, err = capability.VerifyPasskey(token, holder, g.cfg.Passkey, g.cfg.Issuer, g.cfg.Agent, g.cfg.Clock())
	if err != nil {
		return p, nil, err.Error()
	}
	merged["control_capability"] = capability.Digest(token)
	merged["control_task"] = map[string]any{"playbook": p.Task.Playbook, "project": p.Task.Project, "jti": p.ID, "exp": p.Expires, "iss": p.Issuer}
	chained := map[string]any{"entries": registry.IDs(entries), "digest": registry.Digest(chain), "role": leaf.Role, "ceiling_eur": leaf.CeilingEUR}
	if leaf.DailyEUR > 0 {
		// The day as it stood before this act; the effect record says where it ends up.
		spent, err := g.cfg.Store.SpentOn(leaf.ID, log.AllowanceDay(g.cfg.Clock()))
		if err != nil {
			return p, nil, "the day's allowance of " + leaf.ID + " could not be read: " + err.Error()
		}
		chained["daily_eur"] = leaf.DailyEUR
		chained["spent_today_eur"] = fmt.Sprintf("%d.%02d", spent/100, spent%100)
	}
	merged["control_chain"] = chained
	if !containsString(leaf.Kinds, action.Kind) {
		return p, nil, "the registry gives " + leaf.ID + " no " + action.Kind
	}
	return p, &leaf, ""
}

// orgActs says whether a kind needs a word per act because the grant names an organisation:
// every kind but a B1 read.
func (g *Gateway) orgActs(kind string) bool {
	return g.cfg.Policy.Grant.Org != "" && g.cfg.Policy.Kinds()[kind].Radius != "B1"
}

// NeedsWord says whether an action of this kind needs a word naming the act: the grant lists
// it under PerAction, or names an organisation and the kind is more than a read.
func (g *Gateway) NeedsWord(kind string) bool {
	return containsString(g.cfg.Policy.Grant.PerAction, kind) || g.orgActs(kind)
}

// Precheck is the grant's judgement of an action without a record: what a person would be
// asked to put a word to has to be something the grant allows first. For a grant per task it
// judges by the whole grant, since the task is named by the word that is not there yet.
func (g *Gateway) Precheck(run string, action policy.Action) (string, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg.Policy.Evaluate(action, g.summary(run))
}

// Refuse records a request refused for a reason the gateway did not judge: a person said no
// to a word they were asked for, or the word did not come in time. Nothing is verified,
// because nothing was presented; the record says why, like any refusal.
func (g *Gateway) Refuse(run string, action policy.Action, principal string, extension map[string]any, body, signature []byte, reason string) Verdict {
	merged, _ := g.submitter(body, signature, extension)
	return g.submit(run, action, principal, merged, nil, g.cfg.Policy, false, reason)
}

// SubmitIn is one intercepted step within a run. The path summary the policy
// judges against is the run's: a second dispatch in the same run is refused,
// the first dispatch of the next run is not. The run's name is written as the
// claim control_run so a reader can tell the runs apart. The instance state
// moves only after the durable write, so a store failure leaves the chain
// exactly as it was.
func (g *Gateway) SubmitIn(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material) Verdict {
	capReason := ""
	if g.cfg.Policy.Grant.PrincipalKey != "" || len(g.cfg.Policy.Grant.PrincipalKeys) > 0 {
		capReason = "no capability from the principal for this task"
	} else if g.cfg.Policy.PerTask() {
		_, capReason = g.cfg.Policy.ForTask("")
	}
	return g.submit(run, action, principal, extension, prem, g.cfg.Policy, g.cfg.Policy.Grant.SubmitterKey != "", capReason)
}

// submit judges under pol: the agent's policy, or the one task of it the capability
// selected. The bundle a record names stays the agent's; the task is in control_task.
func (g *Gateway) submit(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material, pol policy.Policy, unsigned bool, capReason string) Verdict {
	g.mu.Lock()
	defer g.mu.Unlock()
	phi := g.summary(run)
	idRaw := make([]byte, 16)
	_, _ = rand.Read(idRaw)
	actionID := hex.EncodeToString(idRaw)
	merged := map[string]any{"control_action": actionID, "control_phase": PhaseRequest}
	if run != "" {
		merged["control_run"] = run
	}
	for k, v := range extension {
		merged[k] = v
	}
	extension = merged

	if prem != nil {
		premises.Check(prem)
		claims, err := premises.Claims(prem)
		if err != nil {
			return Verdict{Verdict: "FAIL_CLOSED", Reason: "premises cannot be digested: " + err.Error()}
		}
		merged := map[string]any{}
		for k, v := range claims {
			merged[k] = v
		}
		for k, v := range extension {
			merged[k] = v
		}
		extension = merged
	}

	// The halt, mechanically (row 8.3.3 of the standard). Open replays the whole chain and
	// refuses to start on a break, but while running the gateway trusted its own memory: a
	// log rewritten under a live gateway was only caught by the next restart or by the
	// daily replay, and in between every action went through. So before each judgement the
	// tail of the store has to still be the head we hold, and that reads one record and
	// not the whole log.
	if reason, ok := g.tailHolds(); !ok {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: reason}
	}

	snapshot := map[string]any{"agent_id": g.cfg.Agent, "action": action.ToMap(), "path_summary": phi.Digest(), "step_index": g.step}
	snapshotDigest, err := canonical.Digest(snapshot)
	if err != nil {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "the snapshot cannot be canonicalised: " + err.Error()}
	}

	var verdict, reason string
	switch {
	case unsigned:
		verdict, reason = "DENY", "the submission is not signed by the agent's key"
	case capReason != "":
		verdict, reason = "DENY", capReason
	case pol.RequiresPremises(action.Kind) && prem == nil:
		verdict, reason = "DENY", "no certificate of premises for "+action.Kind
	case prem != nil && !prem.Verified:
		verdict, reason = "DENY", "the certificate of premises does not verify: "+first(prem.Errors)
	case prem != nil && !acceptedJudgement(pol, prem):
		c, _ := pol.Accepted(prem.RequiredControls)
		if c == "" {
			verdict, reason = "DENY", "the certificate of premises argues no judgement"
		} else {
			verdict, reason = "DENY", "the certificate argues "+c+", which this grant does not accept"
		}
	default:
		verdict, reason = pol.Evaluate(action, phi)
	}

	link := evidence.Link(g.head, snapshotDigest, verdict)
	leaf, _ := evidence.Leaf(snapshotDigest, verdict)
	treeAfter := cloneTree(g.tree)
	treeAfter.Append(leaf)

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	params := action.Params
	if params == nil {
		params = map[string]any{}
	}
	paramsDigest, _ := canonical.Digest(params)
	if verdict == "ALLOW" {
		extension["control_matched"] = policy.Matched(action, phi, pol.Grant)
	}
	extension["control_params"] = canonical.Tag(paramsDigest)
	// The bill of materials in force: the one the hand submitted for this request (its
	// digest arrives in the extension, the document is kept beside the record by the
	// service), else the gateway's default for a hand that submits none.
	agbom := canonical.Tag(g.cfg.AgbomDigest)
	if v, ok := extension["agbom_digest"].(string); ok && v != "" {
		agbom = v
		delete(extension, "agbom_digest")
	}
	if g.agboms == nil {
		g.agboms = map[string]string{}
	}
	g.agboms[actionID] = agbom
	if g.cfg.PolicyVersion != "" {
		extension["control_policy"] = g.cfg.PolicyVersion
	}
	if g.cfg.Release != "" {
		extension["control_gateway"] = g.cfg.Release
	}
	claims := map[string]any{
		"agent_id": g.cfg.Agent, "initiating_user": principal,
		"agbom_digest": agbom, "interception_point": evidence.InterceptionPoint,
		"step_index": g.step, "chain_head": canonical.Tag(link),
		"merkle_root": canonical.Tag(hex.EncodeToString(treeAfter.Root())), "tree_size": treeAfter.Size(),
		"policy_bundle_hash": canonical.Tag(g.cfg.Policy.BundleHash()), "target_resource": action.Resource,
		"canonical_snapshot_hash": canonical.Tag(snapshotDigest), "path_summary_hash": canonical.Tag(phi.Digest()),
		"verdict": verdict, "reason": reason, "alg": "EdDSA",
	}
	for k, v := range extension {
		if _, taken := claims[k]; !taken {
			claims[k] = v
		}
	}
	token := evidence.Token{
		"iss": g.cfg.Issuer, "iat": g.cfg.Clock().Unix(), "nonce": "n-" + hex.EncodeToString(nonce),
		"eat_profile": evidence.Profile, "poc_claims": claims,
		"submods": g.submods(),
	}
	if err := evidence.Sign(token, g.cfg.Key); err != nil {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "the token cannot be signed: " + err.Error()}
	}

	if err := g.cfg.Store.Append(g.cfg.Agent, token); err != nil { // written before release
		if ferr := g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "nonce": token["nonce"], "action": action.ToMap(), "error": err.Error()}); ferr != nil {
			return Verdict{Verdict: "FAIL_CLOSED", Reason: err.Error() + "; " + ferr.Error()}
		}
		return Verdict{Verdict: "FAIL_CLOSED", Reason: err.Error()}
	}

	step := g.step
	g.head = link
	g.heads = append(g.heads, link)
	g.tree = treeAfter
	g.runs[run] = phi.Fold(action, verdict)
	g.step++

	if err := g.cfg.Store.Attach(g.cfg.Agent, step, "action", stepAction{Run: run, Action: action}); err != nil {
		_ = g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "step": step, "error": "action not attached: " + err.Error()})
	}
	// The authority the action was judged under, beside the record (row 4.1.1): the
	// bundle whose hash the claims carry, readable without the configuration.
	if err := g.cfg.Store.Attach(g.cfg.Agent, step, "grant", g.cfg.Policy.Bundle()); err != nil {
		_ = g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "step": step, "error": "grant not attached: " + err.Error()})
	}
	if prem != nil {
		if err := g.cfg.Store.Attach(g.cfg.Agent, step, "premises", prem); err != nil {
			_ = g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "step": step, "error": "premises not attached: " + err.Error()})
		}
	}
	return Verdict{Verdict: verdict, Reason: reason, Token: token, Step: step, ActionID: actionID}
}

// Follow writes the effect or result record of an action already judged: the same
// action id, the phase, and a digest of what happened, signed and chained like the
// request. The verdict repeats the binding decision; the reason says what the phase
// did. It folds nothing into the run's path: the request already counted.
func (g *Gateway) Follow(run, actionID, phase string, action policy.Action, principal, verdict, reason string, outcome any) Verdict {
	return g.follow(run, actionID, phase, action, principal, verdict, reason, outcome, nil)
}

// Event writes one record of something the gateway itself underwent rather than an action a
// hand proposed: control_event names it (provisioning, in Confidential Space), there is no
// action id, so no request or effect is expected beside it, and its phase is a result, so the
// checkpoint after it is anchored like an action's end.
func (g *Gateway) Event(name string, action policy.Action, principal, reason string, outcome any) Verdict {
	return g.follow("", "", PhaseResult, action, principal, "ALLOW", reason, outcome, map[string]any{"control_event": name})
}

func (g *Gateway) follow(run, actionID, phase string, action policy.Action, principal, verdict, reason string, outcome any, extra map[string]any) Verdict {
	g.mu.Lock()
	defer g.mu.Unlock()
	if phase != PhaseEffect && phase != PhaseResult {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "unknown phase " + phase}
	}
	phi := g.summary(run)
	outcomeDigest, err := canonical.Digest(outcome)
	if err != nil {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "the outcome cannot be canonicalised: " + err.Error()}
	}
	snapshot := map[string]any{"agent_id": g.cfg.Agent, "action": action.ToMap(), "phase": phase, "outcome": canonical.Tag(outcomeDigest), "step_index": g.step}
	snapshotDigest, err := canonical.Digest(snapshot)
	if err != nil {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "the snapshot cannot be canonicalised: " + err.Error()}
	}
	link := evidence.Link(g.head, snapshotDigest, verdict)
	leaf, _ := evidence.Leaf(snapshotDigest, verdict)
	treeAfter := cloneTree(g.tree)
	treeAfter.Append(leaf)
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	agbom := canonical.Tag(g.cfg.AgbomDigest)
	if v, ok := g.agboms[actionID]; ok {
		agbom = v
	}
	claims := map[string]any{
		"agent_id": g.cfg.Agent, "initiating_user": principal,
		"agbom_digest": agbom, "interception_point": "POST_CALL_TOOL_RESULT",
		"step_index": g.step, "chain_head": canonical.Tag(link),
		"merkle_root": canonical.Tag(hex.EncodeToString(treeAfter.Root())), "tree_size": treeAfter.Size(),
		"policy_bundle_hash": canonical.Tag(g.cfg.Policy.BundleHash()), "target_resource": action.Resource,
		"canonical_snapshot_hash": canonical.Tag(snapshotDigest), "path_summary_hash": canonical.Tag(phi.Digest()),
		"verdict": verdict, "reason": reason, "alg": "EdDSA",
		"control_phase": phase, "control_outcome": canonical.Tag(outcomeDigest),
	}
	if actionID != "" {
		claims["control_action"] = actionID
	}
	for k, v := range extra {
		claims[k] = v
	}
	if run != "" {
		claims["control_run"] = run
	}
	if g.cfg.PolicyVersion != "" {
		claims["control_policy"] = g.cfg.PolicyVersion
	}
	if g.cfg.Release != "" {
		claims["control_gateway"] = g.cfg.Release
	}
	token := evidence.Token{
		"iss": g.cfg.Issuer, "iat": g.cfg.Clock().Unix(), "nonce": "n-" + hex.EncodeToString(nonce),
		"eat_profile": evidence.Profile, "poc_claims": claims,
		"submods": g.submods(),
	}
	if err := evidence.Sign(token, g.cfg.Key); err != nil {
		return Verdict{Verdict: "FAIL_CLOSED", Reason: "the token cannot be signed: " + err.Error()}
	}
	if err := g.cfg.Store.Append(g.cfg.Agent, token); err != nil {
		_ = g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "nonce": token["nonce"], "action": actionID, "phase": phase, "error": err.Error()})
		return Verdict{Verdict: "FAIL_CLOSED", Reason: err.Error()}
	}
	step := g.step
	g.head = link
	g.heads = append(g.heads, link)
	g.tree = treeAfter
	g.step++
	if err := g.cfg.Store.Attach(g.cfg.Agent, step, "outcome", outcome); err != nil {
		_ = g.cfg.Store.RecordFailure(map[string]any{"agent": g.cfg.Agent, "step": step, "error": "outcome not attached: " + err.Error()})
	}
	return Verdict{Verdict: verdict, Reason: reason, Token: token, Step: step, ActionID: actionID}
}

// Checkpoint is the signed tree head an anchorer or a witness picks up.
type Checkpoint struct {
	Agent     string `json:"agent"`
	TreeSize  int    `json:"tree_size"`
	Root      string `json:"root"`
	ChainHead string `json:"chain_head"`
	// Attestation is the digest of the hardware quote the gateway runs under, when it
	// does: anchoring the checkpoint then anchors the attestation with it (row 8.1.7), so
	// the vendor-rooted report is committed to two independent clocks as well.
	Attestation string `json:"attestation,omitempty"`
	Signature   string `json:"signature"`
}

// CheckpointInput is what the checkpoint's signature covers: everything but the
// signature, the attestation digest only when there is one, so checkpoints from
// before it still verify.
func CheckpointInput(cp Checkpoint) ([]byte, error) {
	m := map[string]any{"agent": cp.Agent, "tree_size": cp.TreeSize, "root": cp.Root, "chain_head": cp.ChainHead}
	if cp.Attestation != "" {
		m["attestation"] = cp.Attestation
	}
	return canonical.Encode(m)
}

// Checkpoint of the current tree, signed by the evidence key.
func (g *Gateway) Checkpoint() (Checkpoint, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cp := Checkpoint{Agent: g.cfg.Agent, TreeSize: g.tree.Size(), Root: canonical.Tag(hex.EncodeToString(g.tree.Root())), ChainHead: canonical.Tag(g.head)}
	if r := g.att.Load(); r != nil {
		cp.Attestation = canonical.Tag(canonical.SHA256(r.Evidence()))
	}
	in, err := CheckpointInput(cp)
	if err != nil {
		return cp, err
	}
	cp.Signature = hex.EncodeToString(ed25519.Sign(g.cfg.Key, in))
	return cp, nil
}

// CheckpointAt signs the tree head as it stood after size records: a receipt names the
// checkpoint that closes its action, and the anchor anchors every such checkpoint.
func (g *Gateway) CheckpointAt(size int) (Checkpoint, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkpointAt(size)
}

func (g *Gateway) checkpointAt(size int) (Checkpoint, error) {
	if size < 1 || size > g.tree.Size() || size > len(g.heads) {
		return Checkpoint{}, fmt.Errorf("no tree of size %d; the log holds %d records", size, g.tree.Size())
	}
	cp := Checkpoint{Agent: g.cfg.Agent, TreeSize: size, Root: canonical.Tag(hex.EncodeToString(g.tree.RootAt(size))), ChainHead: canonical.Tag(g.heads[size-1])}
	if r := g.att.Load(); r != nil {
		cp.Attestation = canonical.Tag(canonical.SHA256(r.Evidence()))
	}
	in, err := CheckpointInput(cp)
	if err != nil {
		return cp, err
	}
	cp.Signature = hex.EncodeToString(ed25519.Sign(g.cfg.Key, in))
	return cp, nil
}

// ActionEnds are the signed checkpoints after size after: one at the end of every action (a
// result record) and the current one, at most limit. The anchor takes these, so every
// receipt's checkpoint is in a minute without the anchor holding a record.
func (g *Gateway) ActionEnds(after, limit int) ([]Checkpoint, error) {
	records, err := g.cfg.Store.Records(g.cfg.Agent)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []Checkpoint
	size := g.tree.Size()
	for n := after + 1; n <= size && n <= len(records) && len(out) < limit; n++ {
		if n != size && str(records[n-1].Claims()["control_phase"]) != PhaseResult {
			continue
		}
		cp, err := g.checkpointAt(n)
		if err != nil {
			return nil, err
		}
		out = append(out, cp)
	}
	return out, nil
}

// InclusionAt proves step in the tree of size records, hex hashes.
func (g *Gateway) InclusionAt(step, size int) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if size > g.tree.Size() {
		return nil, fmt.Errorf("no tree of size %d", size)
	}
	raw, err := g.tree.InclusionProof(step, size)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(raw))
	for i, p := range raw {
		out[i] = hex.EncodeToString(p)
	}
	return out, nil
}

// Consistency proves the tree of size n extends the tree of size m, hex hashes.
func (g *Gateway) Consistency(m, n int) ([]string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if m < 1 || n > g.tree.Size() || m > n {
		return nil, fmt.Errorf("no consistency proof from %d to %d; the log holds %d records", m, n, g.tree.Size())
	}
	raw, err := g.tree.ConsistencyProof(m, n)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(raw))
	for i, p := range raw {
		out[i] = hex.EncodeToString(p)
	}
	return out, nil
}

// VerifyCheckpoint checks a checkpoint's signature under a public key.
func VerifyCheckpoint(cp Checkpoint, pub ed25519.PublicKey) bool {
	in, err := CheckpointInput(cp)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(cp.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, in, sig)
}

// InclusionProof for one step against the current tree, hex hashes.
func (g *Gateway) InclusionProof(step int) (proof []string, treeSize int, root string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	raw, err := g.tree.InclusionProof(step, g.tree.Size())
	if err != nil {
		return nil, 0, "", err
	}
	for _, p := range raw {
		proof = append(proof, hex.EncodeToString(p))
	}
	return proof, g.tree.Size(), canonical.Tag(hex.EncodeToString(g.tree.Root())), nil
}

func cloneTree(t *merkle.Tree) *merkle.Tree {
	// The tree is rebuilt from its leaves; small logs make this cheap and
	// obviously correct. A tiled log replaces it when size demands.
	c := merkle.New()
	for i := 0; i < t.Size(); i++ {
		c.AppendLeafHash(t.LeafHash(i))
	}
	return c
}

func str(v any) string { s, _ := v.(string); return s }

func num(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case interface{ Int64() (int64, error) }:
		n, _ := x.Int64()
		return int(n)
	}
	return -1
}

func first(list []string) string {
	if len(list) == 0 {
		return "unknown"
	}
	return list[0]
}

func mustDecodeB64(s string) []byte {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return raw
}

// acceptedJudgement: the working argues only judgements the grant accepts, and at least one.
func acceptedJudgement(p policy.Policy, prem *premises.Material) bool {
	_, ok := p.Accepted(prem.RequiredControls)
	return ok
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
