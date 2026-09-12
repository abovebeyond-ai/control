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
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/merkle"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
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
	AgbomDigest string           // digest of the agent bill of materials when the hand submits none; the deployed commit is honest for deterministic hands
	Release     string           // the gateway's own release and checksum, named in every record as control_gateway
	Platform    string           // SOFTWARE until an enclave attests
	Clock       func() time.Time // injectable for reproducible records
	// Attestation, when present, is the hardware's word: the platform becomes
	// INTEL_TDX and the measurement the MRTD from the quote, which must bind
	// this gateway's key. Without it the measurement is the software one, the
	// digest of the engine and the policy bundle, and nobody but the operator
	// vouches for it.
	Attestation *attest.Record
}

// Gateway holds the chain state of one agent. One instance is one path.
type Gateway struct {
	cfg         Config
	measurement string // hex, untagged
	alg         string // the measurement's algorithm: sha-256 for software, sha-384 for an MRTD
	mu          sync.Mutex
	head        string
	tree        *merkle.Tree
	step        int
	runs        map[string]policy.PathSummary // path summary per run; "" is the run of a hand that names none
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
		// A quote that binds another key is somebody else's attestation.
		quote, err := attest.Parse(mustDecodeB64(cfg.Attestation.QuoteB64))
		if err != nil || !attest.BindsKey(quote, cfg.Key.Public().(ed25519.PublicKey)) {
			return nil, errors.New("gateway: the attestation does not bind this gateway's key")
		}
		cfg.Platform = attest.PlatformTDX
		alg, measurement, err = canonical.UntagAny(cfg.Attestation.Measurement())
		if err != nil {
			return nil, err
		}
	}
	g := &Gateway{cfg: cfg, measurement: measurement, alg: alg, head: evidence.GenesisHead(), tree: merkle.New(), runs: map[string]policy.PathSummary{}}
	records, err := cfg.Store.Records(cfg.Agent)
	if err != nil {
		return nil, err
	}
	for i, tok := range records {
		c := tok.Claims()
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
func (g *Gateway) Attestation() *attest.Record { return g.cfg.Attestation }

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
	var capReason string
	if key := g.cfg.Policy.Grant.PrincipalKey; key != "" {
		switch {
		case token == "":
			capReason = "no capability from the principal for this task"
		default:
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
			merged["control_task"] = map[string]any{"playbook": p.Task.Playbook, "project": p.Task.Project, "jti": p.ID, "exp": p.Expires}
			if !p.Covers(action.Kind, action.Resource) {
				capReason = "the capability does not cover " + action.Kind + " on " + action.Resource
			}
		}
	} else if token != "" {
		merged["control_capability"] = capability.Digest(token)
	}
	return g.submit(run, action, principal, merged, prem, g.cfg.Policy.Grant.SubmitterKey != "" && state != "verified", capReason)
}

// SubmitIn is one intercepted step within a run. The path summary the policy
// judges against is the run's: a second dispatch in the same run is refused,
// the first dispatch of the next run is not. The run's name is written as the
// claim control_run so a reader can tell the runs apart. The instance state
// moves only after the durable write, so a store failure leaves the chain
// exactly as it was.
func (g *Gateway) SubmitIn(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material) Verdict {
	capReason := ""
	if g.cfg.Policy.Grant.PrincipalKey != "" {
		capReason = "no capability from the principal for this task"
	}
	return g.submit(run, action, principal, extension, prem, g.cfg.Policy.Grant.SubmitterKey != "", capReason)
}

func (g *Gateway) submit(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material, unsigned bool, capReason string) Verdict {
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
	case g.cfg.Policy.RequiresPremises(action.Kind) && prem == nil:
		verdict, reason = "DENY", "no certificate of premises for "+action.Kind
	case prem != nil && !prem.Verified:
		verdict, reason = "DENY", "the certificate of premises does not verify: "+first(prem.Errors)
	case prem != nil && !acceptedJudgement(g.cfg.Policy, prem):
		c, _ := g.cfg.Policy.Accepted(prem.RequiredControls)
		if c == "" {
			verdict, reason = "DENY", "the certificate of premises argues no judgement"
		} else {
			verdict, reason = "DENY", "the certificate argues "+c+", which this grant does not accept"
		}
	default:
		verdict, reason = g.cfg.Policy.Evaluate(action, phi)
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
		extension["control_matched"] = policy.Matched(action, phi, g.cfg.Policy.Grant)
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
		"submods": map[string]any{"attestation": map[string]any{"platform": g.cfg.Platform, "measurement": g.alg + ":" + g.measurement}},
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
		"control_action": actionID, "control_phase": phase, "control_outcome": canonical.Tag(outcomeDigest),
	}
	if run != "" {
		claims["control_run"] = run
	}
	if g.cfg.Release != "" {
		claims["control_gateway"] = g.cfg.Release
	}
	token := evidence.Token{
		"iss": g.cfg.Issuer, "iat": g.cfg.Clock().Unix(), "nonce": "n-" + hex.EncodeToString(nonce),
		"eat_profile": evidence.Profile, "poc_claims": claims,
		"submods": map[string]any{"attestation": map[string]any{"platform": g.cfg.Platform, "measurement": g.alg + ":" + g.measurement}},
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
	if g.cfg.Attestation != nil {
		cp.Attestation = canonical.Tag(canonical.SHA256(mustDecodeB64(g.cfg.Attestation.QuoteB64)))
	}
	in, err := CheckpointInput(cp)
	if err != nil {
		return cp, err
	}
	cp.Signature = hex.EncodeToString(ed25519.Sign(g.cfg.Key, in))
	return cp, nil
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
