package attest

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/testing/testdata"
)

// The library's production sample quote (an SPR machine, 2023): it parses, it
// verifies offline against Intel's roots at the date the certificates were
// valid, and its measurement has the width the schema demands. The key binding
// is exercised with the reference's recipe on both sides.
func TestASampleQuoteParsesVerifiesAndMeasures(t *testing.T) {
	seed, _ := hex.DecodeString(strings.Repeat("55", 32))
	key := ed25519.NewKeyFromSeed(seed)
	r, err := FromRaw(testdata.RawQuote, "sample", key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if r.Platform != PlatformTDX || len(r.MRTD) != 96 || len(r.RTMRs) != 4 || len(r.ReportData) != 128 {
		t.Fatalf("record: %+v", r)
	}
	if !strings.HasPrefix(r.Measurement(), "sha-384:") {
		t.Error(r.Measurement())
	}
	// The sample quote was not produced for our key, so the binding must fail, and
	// only the binding: the quote itself verifies.
	err = Verify(context.Background(), r, Options{Now: time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)})
	if err == nil || !strings.Contains(err.Error(), "does not bind the key") {
		t.Fatalf("expected the binding to fail and nothing else: %v", err)
	}
	// In the future the certificates have expired and the quote no longer verifies.
	err = Verify(context.Background(), r, Options{Now: time.Date(2053, time.July, 1, 1, 0, 0, 0, time.UTC)})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("expected the quote to fail on time: %v", err)
	}
}

func TestTheBindingIsTheStandards(t *testing.T) {
	seed, _ := hex.DecodeString(strings.Repeat("55", 32))
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	rd := ReportDataForKey(pub)
	// SHA-512("poc-evidence-key\x00" || key), as impl/poc/tdx.py computes it.
	if len(rd) != 64 || hex.EncodeToString(rd[:]) == strings.Repeat("00", 64) {
		t.Fatal("report data")
	}
	quote, err := Parse(testdata.RawQuote)
	if err != nil {
		t.Fatal(err)
	}
	if BindsKey(quote, pub) {
		t.Error("the sample quote cannot bind a key it never saw")
	}
	// A quote whose report data IS the key's digest binds it: patch the parsed body.
	quote.TdQuoteBody.ReportData = rd[:]
	if !BindsKey(quote, pub) {
		t.Error("a quote carrying the key's digest must bind it")
	}
}

// A sample quote with our key's digest written into REPORTDATA binds the key
// as far as parsing goes. Its signature no longer verifies, and that is the
// point of the two checks being separate: binding is cheap and local, the
// signature is Intel's word and needs the roots.
func TestAPatchedSampleBindsButNoLongerVerifies(t *testing.T) {
	seed, _ := hex.DecodeString(strings.Repeat("55", 32))
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	raw := append([]byte(nil), testdata.RawQuote...)
	rd := ReportDataForKey(pub)
	copy(raw[ReportDataOffset:], rd[:])
	r, err := FromRaw(raw, "patched", pub)
	if err != nil {
		t.Fatal(err)
	}
	if r.ReportData != hex.EncodeToString(rd[:]) {
		t.Fatal("the patch missed the report data field")
	}
	quote, _ := Parse(raw)
	if !BindsKey(quote, pub) {
		t.Fatal("bound")
	}
	err = Verify(context.Background(), r, Options{Now: time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)})
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("a patched quote must fail Intel's signature: %v", err)
	}
}
