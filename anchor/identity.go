package anchor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/log"
)

// The identity log, pinned like the chain head.
//
// The did:webvh log at abovebeyond.ai is signed by the update key, and since 11 September
// 2026 that key lives on a hardware token. That settles who can write the log. It does not
// settle whether the operator wrote one log or two: a second history, signed with the same
// token, shown to a different reader, verifies just as well. The format's own answer is a
// witness, a named party that countersigns each version; the standard grades a named party
// at Tier 2. A public ledger answers the same question with no party to trust: every version
// is posted where everyone sees the same order, and two different version 7s cannot both be
// first. So the courier posts each new version's identifier, and a checker reads the topic
// back and refuses a log whose versions are not the ones posted first.

// LogEntry is what a checker needs of a did:webvh log line: the version and when.
type LogEntry struct {
	VersionID   string `json:"versionId"`
	VersionTime string `json:"versionTime"`
	DID         string `json:"did"`
}

// KeysOf reads every Ed25519 public key a fragment ever had in a did.jsonl, oldest
// first, the last being the current one. A rebuilt gateway has a new key, and the
// chains its predecessor signed stay verifiable only if a checker knows the old one;
// the identity log is that history (12 September 2026, ahead of the first rebuild).
func KeysOf(raw []byte, fragment string) ([][]byte, error) {
	var keys [][]byte
	seen := map[string]bool{}
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e struct {
			State struct {
				VerificationMethod []struct {
					ID  string `json:"id"`
					JWK struct {
						X string `json:"x"`
					} `json:"publicKeyJwk"`
				} `json:"verificationMethod"`
			} `json:"state"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		for _, m := range e.State.VerificationMethod {
			if !strings.HasSuffix(m.ID, "#"+fragment) || m.JWK.X == "" {
				continue
			}
			raw, err := base64.RawURLEncoding.DecodeString(m.JWK.X)
			if err != nil || len(raw) != 32 {
				return nil, fmt.Errorf("line %d: %s carries no 32-byte key", i+1, m.ID)
			}
			if !seen[m.JWK.X] {
				seen[m.JWK.X] = true
				keys = append(keys, raw)
			}
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("the log names no key under #%s", fragment)
	}
	return keys, nil
}

// ReadLog parses a did.jsonl; the DID is read from the state of the first entry.
func ReadLog(raw []byte) ([]LogEntry, error) {
	var out []LogEntry
	did := ""
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e struct {
			VersionID   string `json:"versionId"`
			VersionTime string `json:"versionTime"`
			State       struct {
				ID string `json:"id"`
			} `json:"state"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if e.State.ID != "" {
			did = e.State.ID
		}
		if e.VersionID == "" || did == "" {
			return nil, fmt.Errorf("line %d: no versionId or DID", i+1)
		}
		n, err := VersionNumber(e.VersionID)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if n != len(out)+1 {
			return nil, fmt.Errorf("line %d: version %d out of order", i+1, n)
		}
		out = append(out, LogEntry{VersionID: e.VersionID, VersionTime: e.VersionTime, DID: did})
	}
	if len(out) == 0 {
		return nil, errors.New("the log is empty")
	}
	return out, nil
}

// VersionNumber of a did:webvh versionId "N-<entry hash>".
func VersionNumber(versionID string) (int, error) {
	n, _, ok := strings.Cut(versionID, "-")
	if !ok {
		return 0, fmt.Errorf("versionId %q has no number", versionID)
	}
	v, err := strconv.Atoi(n)
	if err != nil || v < 1 {
		return 0, fmt.Errorf("versionId %q has no number", versionID)
	}
	return v, nil
}

// IdentityBytes is the message a ledger commits to for one version: the DID, the version
// identifier (which hashes the whole entry) and the time the entry claims. Canonical, so two
// couriers of the same version post the same bytes.
func IdentityBytes(e LogEntry) ([]byte, error) {
	return canonical.Encode(map[string]any{"kind": "did-log-version", "did": e.DID, "versionId": e.VersionID, "versionTime": e.VersionTime})
}

// IdentityReceipt is kept per version and backend, beside the chain receipts.
type IdentityReceipt struct {
	Backend    string         `json:"backend"`
	Entry      LogEntry       `json:"entry"`
	MessageSHA string         `json:"message_sha256"`
	AnchoredAt string         `json:"anchored_at"`
	TSA        *TSAReceipt    `json:"tsa,omitempty"`
	Hedera     *HederaReceipt `json:"hedera,omitempty"`
}

func identityDir(dir, did string) string { return filepath.Join(dir, "identity", log.Safe(did)) }

// PinIdentity posts every version of the log that has no receipt yet with this backend, in
// order, and writes dir/identity/<did>/<n>.<backend>.json. Returns how many were posted.
func PinIdentity(ctx context.Context, dir string, entries []LogEntry, b Backend) (int, error) {
	posted := 0
	for _, e := range entries {
		n, _ := VersionNumber(e.VersionID)
		path := filepath.Join(identityDir(dir, e.DID), fmt.Sprintf("%d.%s.json", n, b.Name()))
		if _, err := os.Stat(path); err == nil {
			continue
		}
		message, err := IdentityBytes(e)
		if err != nil {
			return posted, err
		}
		r := &Receipt{Backend: b.Name(), MessageSHA: canonical.SHA256(message)}
		if err := b.Publish(ctx, message, r); err != nil {
			return posted, fmt.Errorf("version %d: %w", n, err)
		}
		ir := IdentityReceipt{Backend: r.Backend, Entry: e, MessageSHA: r.MessageSHA, AnchoredAt: r.AnchoredAt, TSA: r.TSA, Hedera: r.Hedera}
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return posted, err
		}
		raw, _ := json.MarshalIndent(ir, "", " ")
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			return posted, err
		}
		posted++
	}
	return posted, nil
}

// IdentityReceipts reads what is kept for a DID, by version number and backend.
func IdentityReceipts(dir, did string) (map[int]map[string]IdentityReceipt, error) {
	out := map[int]map[string]IdentityReceipt{}
	entries, err := os.ReadDir(identityDir(dir, did))
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, f := range entries {
		parts := strings.SplitN(f.Name(), ".", 3)
		if f.IsDir() || len(parts) != 3 || parts[2] != "json" {
			continue
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(identityDir(dir, did), f.Name()))
		if err != nil {
			return nil, err
		}
		var r IdentityReceipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name(), err)
		}
		if out[n] == nil {
			out[n] = map[string]IdentityReceipt{}
		}
		out[n][parts[1]] = r
	}
	return out, nil
}

// CheckIdentity holds every version of the log against its receipts: each version has a
// receipt with the given backend, the receipt's bytes are this version's bytes, and the
// backend confirms them (offline for a timestamp, from the mirror node for the ledger).
func CheckIdentity(ctx context.Context, dir string, entries []LogEntry, b Backend, network bool) error {
	kept, err := IdentityReceipts(dir, entries[0].DID)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n, _ := VersionNumber(e.VersionID)
		r, ok := kept[n][b.Name()]
		if !ok {
			return fmt.Errorf("version %d has no %s receipt", n, b.Name())
		}
		if r.Entry.VersionID != e.VersionID {
			return fmt.Errorf("version %d: the receipt is for %s, the log says %s", n, r.Entry.VersionID, e.VersionID)
		}
		message, err := IdentityBytes(e)
		if err != nil {
			return err
		}
		if canonical.SHA256(message) != r.MessageSHA {
			return fmt.Errorf("version %d: the receipt's message hash does not match the log", n)
		}
		full := &Receipt{Backend: r.Backend, MessageSHA: r.MessageSHA, AnchoredAt: r.AnchoredAt, TSA: r.TSA, Hedera: r.Hedera}
		if err := b.Verify(ctx, message, full, network); err != nil {
			return fmt.Errorf("version %d: %w", n, err)
		}
	}
	return nil
}

// Equivocation reads the whole topic back from the mirror node, keeps the FIRST message
// posted for each version number of this DID, and compares with the log. This is the check
// that needs no receipt of ours: a stranger with the log and the topic id runs it, and a
// second history for the same DID shows as a version whose first posting is a different
// identifier. Versions the log has that were never posted are reported too: the operator
// may not skip the ledger for a version it would rather not have seen.
func (h Hedera) Equivocation(ctx context.Context, entries []LogEntry) error {
	base, ok := mirrors[h.Network]
	if !ok {
		return fmt.Errorf("unknown Hedera network %q", h.Network)
	}
	did := entries[0].DID
	first := map[int]LogEntry{}
	url := fmt.Sprintf("%s/api/v1/topics/%s/messages?limit=100&order=asc", base, h.TopicID)
	for url != "" {
		page, err := h.fetch(ctx, url, 3)
		if err != nil {
			return err
		}
		msgs, _ := page["messages"].([]any)
		for _, m := range msgs {
			mm, _ := m.(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(str(mm["message"]))
			var posted struct {
				Kind        string `json:"kind"`
				DID         string `json:"did"`
				VersionID   string `json:"versionId"`
				VersionTime string `json:"versionTime"`
			}
			if json.Unmarshal(raw, &posted) != nil || posted.Kind != "did-log-version" || posted.DID != did {
				continue
			}
			n, err := VersionNumber(posted.VersionID)
			if err != nil {
				continue
			}
			if _, seen := first[n]; !seen {
				first[n] = LogEntry{DID: posted.DID, VersionID: posted.VersionID, VersionTime: posted.VersionTime}
			}
		}
		url = ""
		if links, ok := page["links"].(map[string]any); ok {
			if next := str(links["next"]); next != "" {
				if strings.HasPrefix(next, "/") {
					next = base + next
				}
				url = next
			}
		}
	}
	var missing []string
	for _, e := range entries {
		n, _ := VersionNumber(e.VersionID)
		f, ok := first[n]
		if !ok {
			missing = append(missing, strconv.Itoa(n))
			continue
		}
		if f.VersionID != e.VersionID {
			return fmt.Errorf("version %d: the ledger's first posting is %s, the log says %s: two histories", n, f.VersionID, e.VersionID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("version(s) %s never posted to the ledger", strings.Join(missing, ", "))
	}
	return nil
}
