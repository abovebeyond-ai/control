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
	"sync"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
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
	AgbomDigest string           // digest of the agent bill of materials; the deployed commit is honest for deterministic hands
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
	return g, nil
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

// SubmitIn is one intercepted step within a run. The path summary the policy
// judges against is the run's: a second dispatch in the same run is refused,
// the first dispatch of the next run is not. The run's name is written as the
// claim control_run so a reader can tell the runs apart. The instance state
// moves only after the durable write, so a store failure leaves the chain
// exactly as it was.
func (g *Gateway) SubmitIn(run string, action policy.Action, principal string, extension map[string]any, prem *premises.Material) Verdict {
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
	case g.cfg.Policy.RequiresPremises(action.Kind) && prem == nil:
		verdict, reason = "DENY", "no certificate of premises for "+action.Kind
	case prem != nil && !prem.Verified:
		verdict, reason = "DENY", "the certificate of premises does not verify: "+first(prem.Errors)
	default:
		verdict, reason = g.cfg.Policy.Evaluate(action, phi)
	}

	link := evidence.Link(g.head, snapshotDigest, verdict)
	leaf, _ := evidence.Leaf(snapshotDigest, verdict)
	treeAfter := cloneTree(g.tree)
	treeAfter.Append(leaf)

	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	claims := map[string]any{
		"agent_id": g.cfg.Agent, "initiating_user": principal,
		"agbom_digest": canonical.Tag(g.cfg.AgbomDigest), "interception_point": evidence.InterceptionPoint,
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
	claims := map[string]any{
		"agent_id": g.cfg.Agent, "initiating_user": principal,
		"agbom_digest": canonical.Tag(g.cfg.AgbomDigest), "interception_point": "POST_CALL_TOOL_RESULT",
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
	Signature string `json:"signature"`
}

// Checkpoint of the current tree, signed by the evidence key.
func (g *Gateway) Checkpoint() (Checkpoint, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cp := Checkpoint{Agent: g.cfg.Agent, TreeSize: g.tree.Size(), Root: canonical.Tag(hex.EncodeToString(g.tree.Root())), ChainHead: canonical.Tag(g.head)}
	in, err := canonical.Encode(map[string]any{"agent": cp.Agent, "tree_size": cp.TreeSize, "root": cp.Root, "chain_head": cp.ChainHead})
	if err != nil {
		return cp, err
	}
	cp.Signature = hex.EncodeToString(ed25519.Sign(g.cfg.Key, in))
	return cp, nil
}

// VerifyCheckpoint checks a checkpoint's signature under a public key.
func VerifyCheckpoint(cp Checkpoint, pub ed25519.PublicKey) bool {
	in, err := canonical.Encode(map[string]any{"agent": cp.Agent, "tree_size": cp.TreeSize, "root": cp.Root, "chain_head": cp.ChainHead})
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
