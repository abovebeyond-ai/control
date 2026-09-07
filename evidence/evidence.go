// Package evidence is the Proof-of-Control claim set and its signature: the
// token an attesting environment issues for one intercepted action, in the
// shape the standard's schema and canonical form fix (profile v0.1), so the
// standard's own validator and reference verifier read it unchanged.
package evidence

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/merkle"
)

const (
	Profile           = "https://advancedaisociety.org/poc/v0.1"
	InterceptionPoint = "PRE_CALL_TOOL_INVOCATION"
	Genesis           = "poc-genesis"
)

// Token is one evidence record: the claim set as a map, because the profile
// leaves an open extension point and a verifier must carry unknown claims
// through untouched. Signature is hex over the canonical form of everything
// but the signature.
type Token map[string]any

// Claims returns the poc_claims map of a token.
func (t Token) Claims() map[string]any {
	c, _ := t["poc_claims"].(map[string]any)
	return c
}

// SigningInput is the exact bytes a signature covers: the token with
// `signature` removed, in canonical form.
func SigningInput(t Token) ([]byte, error) {
	body := make(map[string]any, len(t))
	for k, v := range t {
		if k != "signature" {
			body[k] = v
		}
	}
	return canonical.Encode(body)
}

// Sign fills the signature in place.
func Sign(t Token, key ed25519.PrivateKey) error {
	in, err := SigningInput(t)
	if err != nil {
		return err
	}
	t["signature"] = hex.EncodeToString(ed25519.Sign(key, in))
	return nil
}

// Verify checks the signature under a public key.
func Verify(t Token, pub ed25519.PublicKey) bool {
	sig, ok := t["signature"].(string)
	if !ok {
		return false
	}
	raw, err := hex.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return false
	}
	in, err := SigningInput(t)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, in, raw)
}

// Digest of a signed token, tagged: what a capability binds to.
func Digest(t Token) (string, error) {
	d, err := canonical.Digest(map[string]any(t))
	if err != nil {
		return "", err
	}
	return canonical.Tag(d), nil
}

// GenesisHead is the chain head before any record.
func GenesisHead() string { return canonical.SHA256([]byte(Genesis)) }

// Link extends the chain: L_t = H(L_{t-1} || H(snapshot) || verdict).
func Link(head, snapshotDigest, verdict string) string {
	return canonical.SHA256([]byte(head + snapshotDigest + verdict))
}

// Leaf is the committed material of one record in the tree.
func Leaf(snapshotDigest, verdict string) ([]byte, error) {
	return canonical.Encode(map[string]any{"snapshot": snapshotDigest, "verdict": verdict})
}

// ChainResult is the verdict of a replay.
type ChainResult struct {
	OK      bool
	Reason  string
	Records int
}

// VerifyChain replays a chain the way the reference verifier does: every
// signature, the measurement, the sequence, the chain link, and the tree
// root at every step. It detects an altered record, a missing one, a
// foreign one, and a record judged by another policy.
func VerifyChain(records []Token, pub ed25519.PublicKey, expectedMeasurement string) ChainResult {
	head := GenesisHead()
	tree := merkle.New()
	for i, tok := range records {
		if !Verify(tok, pub) {
			return ChainResult{false, fmt.Sprintf("invalid signature at record %d", i), i}
		}
		c := tok.Claims()
		att, _ := tok["submods"].(map[string]any)
		attestation, _ := att["attestation"].(map[string]any)
		m, err := canonical.Untag(str(attestation["measurement"]))
		if err != nil || m != expectedMeasurement {
			return ChainResult{false, fmt.Sprintf("measurement mismatch at record %d: judged by another policy", i), i}
		}
		if num(c["step_index"]) != i {
			return ChainResult{false, fmt.Sprintf("sequence gap: expected step %d, found %v (omission detected)", i, c["step_index"]), i}
		}
		snapshot, err := canonical.Untag(str(c["canonical_snapshot_hash"]))
		if err != nil {
			return ChainResult{false, fmt.Sprintf("record %d: %v", i, err), i}
		}
		verdict := str(c["verdict"])
		leaf := Link(head, snapshot, verdict)
		ch, err := canonical.Untag(str(c["chain_head"]))
		if err != nil || ch != leaf {
			return ChainResult{false, fmt.Sprintf("chain break at record %d (alteration detected)", i), i}
		}
		rec, _ := Leaf(snapshot, verdict)
		tree.Append(rec)
		root, err := canonical.Untag(str(c["merkle_root"]))
		if err != nil || num(c["tree_size"]) != tree.Size() || root != hex.EncodeToString(tree.Root()) {
			return ChainResult{false, fmt.Sprintf("tree root at record %d does not cover the records before it", i), i}
		}
		head = leaf
	}
	return ChainResult{true, fmt.Sprintf("chain verified: %d records", len(records)), len(records)}
}

// VerifyRecord checks one record against a published root, touching only the proof.
func VerifyRecord(record Token, pub ed25519.PublicKey, expectedMeasurement string, proof [][]byte, treeSize int, publishedRoot string) error {
	if !Verify(record, pub) {
		return errors.New("invalid signature on record")
	}
	c := record.Claims()
	att, _ := record["submods"].(map[string]any)
	attestation, _ := att["attestation"].(map[string]any)
	if m, err := canonical.Untag(str(attestation["measurement"])); err != nil || m != expectedMeasurement {
		return errors.New("measurement mismatch")
	}
	snapshot, err := canonical.Untag(str(c["canonical_snapshot_hash"]))
	if err != nil {
		return err
	}
	rec, _ := Leaf(snapshot, str(c["verdict"]))
	root, err := hex.DecodeString(publishedRoot)
	if err != nil {
		return err
	}
	if !merkle.VerifyInclusion(num(c["step_index"]), treeSize, merkle.LeafHash(rec), proof, root) {
		return fmt.Errorf("record %d is not in the published tree of size %d", num(c["step_index"]), treeSize)
	}
	return nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// num reads an integer claim whether it arrived as int, int64, float64 or json.Number.
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
