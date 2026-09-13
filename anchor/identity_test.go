package anchor

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleLog = `{"versionId":"1-QmA","versionTime":"2026-09-07T07:20:00Z","parameters":{},"state":{"id":"did:webvh:QmA:example.org"},"proof":[]}
{"versionId":"2-QmB","versionTime":"2026-09-07T10:19:53Z","parameters":{},"state":{"id":"did:webvh:QmA:example.org"},"proof":[]}
{"versionId":"3-QmC","versionTime":"2026-09-11T14:43:55Z","parameters":{},"state":{"id":"did:webvh:QmA:example.org"},"proof":[]}
`

// A mirror node that serves one message by sequence and the whole topic as pages of two,
// the way the real one paginates with links.next.
func fakeMirror(t *testing.T, ledger *fakeLedger) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/messages") {
			from := int64(1)
			if s := r.URL.Query().Get("from"); s != "" {
				_ = json.Unmarshal([]byte(s), &from)
			}
			var msgs []map[string]any
			for seq := from; seq < from+2; seq++ {
				if m, ok := ledger.topic[seq]; ok {
					msgs = append(msgs, m)
				}
			}
			page := map[string]any{"messages": msgs, "links": map[string]any{"next": nil}}
			if _, more := ledger.topic[from+2]; more {
				page["links"] = map[string]any{"next": "/api/v1/topics/0.0.5555/messages?limit=100&order=asc&from=" + itoa(from+2)}
			}
			_ = json.NewEncoder(w).Encode(page)
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		var seq int64
		_ = json.Unmarshal([]byte(parts[len(parts)-1]), &seq)
		if m, ok := ledger.topic[seq]; ok {
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		w.WriteHeader(404)
	}))
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestTheIdentityLogIsPinnedPerVersionAndReadBackFromTheTopic(t *testing.T) {
	entries, err := ReadLog([]byte(sampleLog))
	if err != nil || len(entries) != 3 || entries[2].DID != "did:webvh:QmA:example.org" {
		t.Fatalf("read: %v %+v", err, entries)
	}
	ledger := &fakeLedger{topic: map[int64]map[string]any{}}
	mirror := fakeMirror(t, ledger)
	defer mirror.Close()
	mirrors["fake"] = mirror.URL
	hashscan["fake"] = mirror.URL
	b := Hedera{Network: "fake", TopicID: "0.0.5555", Submitter: ledger, Tries: 2, Wait: time.Millisecond}
	dir := t.TempDir()

	posted, err := PinIdentity(context.Background(), dir, entries, b)
	if err != nil || posted != 3 {
		t.Fatalf("pin: %d %v", posted, err)
	}
	// Running again costs nothing: every version has its receipt.
	if posted, err = PinIdentity(context.Background(), dir, entries, b); err != nil || posted != 0 {
		t.Fatalf("second pin: %d %v", posted, err)
	}
	if err := CheckIdentity(context.Background(), dir, entries, b, true); err != nil {
		t.Fatalf("check: %v", err)
	}
	if err := b.Equivocation(context.Background(), entries); err != nil {
		t.Fatalf("equivocation: %v", err)
	}

	// A second history: version 3 rewritten. The receipts no longer fit, and the topic's
	// first posting for version 3 is the original, so the rewrite is named as two histories.
	forked := append([]LogEntry{}, entries...)
	forked[2].VersionID = "3-QmX"
	if err := CheckIdentity(context.Background(), dir, forked, b, false); err == nil || !strings.Contains(err.Error(), "the receipt is for 3-QmC") {
		t.Errorf("forked check: %v", err)
	}
	if err := b.Equivocation(context.Background(), forked); err == nil || !strings.Contains(err.Error(), "two histories") {
		t.Errorf("forked equivocation: %v", err)
	}
	// Even if the operator posts the fork afterwards, the first posting wins.
	if _, err := PinIdentity(context.Background(), t.TempDir(), forked[2:], b); err != nil {
		t.Fatal(err)
	}
	if err := b.Equivocation(context.Background(), forked); err == nil || !strings.Contains(err.Error(), "two histories") {
		t.Errorf("late fork posting: %v", err)
	}

	// A version that was never posted is named, not passed over.
	longer := append([]LogEntry{}, entries...)
	longer = append(longer, LogEntry{DID: entries[0].DID, VersionID: "4-QmD", VersionTime: "2026-09-12T00:00:00Z"})
	if err := b.Equivocation(context.Background(), longer); err == nil || !strings.Contains(err.Error(), "version(s) 4 never posted") {
		t.Errorf("unposted version: %v", err)
	}

	// The receipt on disk is a plain file a stranger can read.
	raw, err := os.ReadFile(filepath.Join(dir, "identity", "did_webvh_QmA_example.org", "2.hedera.json"))
	if err != nil || !strings.Contains(string(raw), `"versionId": "2-QmB"`) || !strings.Contains(string(raw), `"sequenceNumber": 2`) {
		t.Errorf("receipt: %v %s", err, raw)
	}
	_ = base64.StdEncoding
}

func TestReadLogRefusesGapsAndDisorder(t *testing.T) {
	bad := strings.Replace(sampleLog, "2-QmB", "5-QmB", 1)
	if _, err := ReadLog([]byte(bad)); err == nil || !strings.Contains(err.Error(), "out of order") {
		t.Errorf("gap: %v", err)
	}
	if _, err := ReadLog([]byte("\n")); err == nil {
		t.Error("empty log accepted")
	}
}

// The gateway's key history from the log: every key the fragment ever had, oldest first,
// the last being the current one; a version that does not change it adds nothing.
func TestKeysOfReadsTheFragmentsHistoryOldestFirst(t *testing.T) {
	line := func(x string) string {
		return `{"versionId":"1-Qm","versionTime":"2026-09-10T08:00:00Z","state":{"id":"did:webvh:Qm:x","verificationMethod":[{"id":"did:webvh:Qm:x#key-1","publicKeyJwk":{"x":"jc3CwjMlmEVTfZHEIap7X8lmYxm9WY89rLiHuzDWAn8"}},{"id":"did:webvh:Qm:x#control-gateway","publicKeyJwk":{"x":"` + x + `"}}]}}`
	}
	old := "jYwv3GY6N5KQ9oGqcc7BIFEua1s9cSH1eM15ZHhMbzE"
	renewed := "riK2vr2KLIGU8bUZw_gJ-i_9M0hF_xLV9b6qQdTN5t0"
	raw := []byte(line(old) + "\n" + line(old) + "\n" + line(renewed) + "\n")
	keys, err := KeysOf(raw, "control-gateway")
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %d", err, len(keys))
	}
	if hex.EncodeToString(keys[0]) != "8d8c2fdc663a379290f681aa71cec120512e6b5b3d7121f578cd7964784c6f31" {
		t.Errorf("first key: %x", keys[0])
	}
	if hex.EncodeToString(keys[1]) == hex.EncodeToString(keys[0]) {
		t.Error("the renewed key must come last")
	}
	if _, err := KeysOf(raw, "agent-nobody"); err == nil {
		t.Error("an unknown fragment must be refused")
	}
}

// The operator's keys resolve by fragment to the version that published them.
func TestKeysNamedResolvesAFragmentToItsVersion(t *testing.T) {
	x := func(b byte) string { return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	logRaw := []byte(`{"versionId":"1-a","versionTime":"2026-09-07T07:20:00Z","state":{"verificationMethod":[{"id":"did:web:e.org#key-1","publicKeyJwk":{"x":"` + x(1) + `"}}]}}
{"versionId":"2-b","versionTime":"2026-09-13T15:00:00Z","state":{"verificationMethod":[{"id":"did:web:e.org#key-1","publicKeyJwk":{"x":"` + x(1) + `"}},{"id":"did:web:e.org#operator","publicKeyJwk":{"x":"` + x(2) + `"}},{"id":"did:web:e.org#operator-2","publicKeyJwk":{"x":"` + x(3) + `"}}]}}
`)
	keys, err := KeysNamed(logRaw, "operator")
	if err != nil || len(keys) != 2 {
		t.Fatalf("two operator keys: %v %d", err, len(keys))
	}
	if keys[0].ID != "did:web:e.org#operator" || keys[0].Version != 2 || keys[0].Time != "2026-09-13T15:00:00Z" || !bytes.Equal(keys[0].Key, bytes.Repeat([]byte{2}, 32)) {
		t.Fatalf("operator: %+v", keys[0])
	}
	if keys[1].ID != "did:web:e.org#operator-2" || keys[1].Version != 2 {
		t.Fatalf("operator-2: %+v", keys[1])
	}
	if k, _ := KeysNamed(logRaw, "key-1"); len(k) != 1 || k[0].Version != 1 {
		t.Fatalf("key-1 first at version 1: %+v", k)
	}
}
