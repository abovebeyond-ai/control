// Package attest binds the evidence signing key to a hardware measurement: an
// Intel TDX quote whose REPORTDATA carries the digest of the key, so the
// hardware's signature covers both the code that runs and the key it holds.
// That is the statement a verifier needs, "this key lives inside this measured
// environment", and the one thing that lifts evidence from Tier 2 to Tier 3.
//
// The binding is the standard's own (impl/poc/tdx.py): REPORTDATA =
// SHA-512("poc-evidence-key\x00" || public key), so a quote produced here and a
// quote produced by the reference bind a key the same way and either verifier
// reads both.
package attest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

// Platform names as the standard's schema enumerates them.
const (
	PlatformSoftware = "SOFTWARE"
	PlatformTDX      = "INTEL_TDX"
)

// ErrUnavailable: no TDX guest device here; the gateway then attests software.
var ErrUnavailable = errors.New("no TDX quote provider on this machine")

// ReportDataForKey is the 64 bytes bound into the quote for a key.
func ReportDataForKey(pub ed25519.PublicKey) [64]byte {
	return sha512.Sum512(append([]byte("poc-evidence-key\x00"), pub...))
}

// Record is what is published beside the log so a stranger can check the
// binding: the raw quote, what it says, and the key it is claimed to bind.
type Record struct {
	Platform   string   `json:"platform"`
	Provider   string   `json:"provider,omitempty"`
	QuoteB64   string   `json:"quote"`
	ReportData string   `json:"report_data"`
	MRTD       string   `json:"mrtd"`
	RTMRs      []string `json:"rtmrs"`
	PublicKey  string   `json:"public_key"`
	AcquiredAt string   `json:"acquired_at"`
	// The boot event log (since v0.15.0): the ACPI CCEL table and the log it points
	// at, as the kernel exposes them, so a reader can replay RTMR0 to RTMR2 and name
	// what was measured instead of trusting three opaque digests.
	EventLogTable string `json:"event_log_table,omitempty"`
	EventLog      string `json:"event_log,omitempty"`
	// What the gateway extended into RTMR3 before this quote, in order: the SHA-384
	// of its own binary and of the configuration the operator carried. A reader
	// folds these from zero and holds RTMR3 to the result.
	RTMR3Inputs []Input `json:"rtmr3_inputs,omitempty"`
}

// Input is one extension of RTMR3: what it was and its SHA-384. A small input
// travels with the record (the carried configuration, base64), so a reader holds
// the digest to the bytes; a large one is found elsewhere (the binary, on the release).
type Input struct {
	Name    string `json:"name"`
	SHA384  string `json:"sha384"`
	Content string `json:"content,omitempty"`
}

// Measurement is the tagged digest the token carries under this record: the
// MRTD, a SHA-384 of the initial contents of the trust domain.
func (r Record) Measurement() string { return "sha-384:" + r.MRTD }

// Parse a raw DCAP v4 quote.
func Parse(raw []byte) (*pb.QuoteV4, error) {
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, err
	}
	quote, ok := q.(*pb.QuoteV4)
	if !ok {
		return nil, errors.New("not a TDX quote v4")
	}
	return quote, nil
}

// BindsKey: does the quote's REPORTDATA commit to this key?
func BindsKey(quote *pb.QuoteV4, pub ed25519.PublicKey) bool {
	want := ReportDataForKey(pub)
	got := quote.GetTdQuoteBody().GetReportData()
	if len(got) != 64 {
		return false
	}
	for i := range want {
		if want[i] != got[i] {
			return false
		}
	}
	return true
}

// Acquire asks the hardware for a quote bound to the key. Only inside a TDX
// trust domain with a quote provider; elsewhere ErrUnavailable.
//
// Two doors, tried in order. configfs-tsm is the current one, but the kernel
// creates each report entry root-only, so a gateway running as its own user
// cannot use it (found on the first rehearsal, 9 September 2026). The older
// /dev/tdx_guest device takes a group and a mode, so that is what an
// unprivileged gateway ends up using; the record says which door it was.
func Acquire(pub ed25519.PublicKey) (*Record, error) {
	rd := ReportDataForKey(pub)
	var first error
	if provider, err := client.GetQuoteProvider(); err == nil {
		raw, err := client.GetRawQuote(provider, rd)
		if err == nil {
			return record(raw, "configfs-tsm", pub)
		}
		first = err
	} else {
		first = err
	}
	device, err := client.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("%w: configfs-tsm: %v; device: %v", ErrUnavailable, first, err)
	}
	defer device.Close()
	raw, err := client.GetRawQuote(device, rd)
	if err != nil {
		return nil, fmt.Errorf("%w: configfs-tsm: %v; device: %v", ErrUnavailable, first, err)
	}
	return record(raw, "tdx_guest", pub)
}

// FromRaw builds the record for a quote obtained elsewhere (a test, another provider).
func FromRaw(raw []byte, provider string, pub ed25519.PublicKey) (*Record, error) {
	return record(raw, provider, pub)
}

// WithBootLog attaches the boot event log the kernel exposes, when it does; a
// machine without one (software, or a kernel that does not publish it) leaves the
// record as it was, and the verifier says so rather than failing.
func (r *Record) WithBootLog() {
	table, err := os.ReadFile(ccelTablePath)
	if err != nil {
		return
	}
	data, err := os.ReadFile(ccelDataPath)
	if err != nil {
		return
	}
	r.EventLogTable = base64.StdEncoding.EncodeToString(table)
	r.EventLog = base64.StdEncoding.EncodeToString(data)
}

func record(raw []byte, provider string, pub ed25519.PublicKey) (*Record, error) {
	quote, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	body := quote.GetTdQuoteBody()
	r := &Record{
		Platform: PlatformTDX, Provider: provider, QuoteB64: base64.StdEncoding.EncodeToString(raw),
		ReportData: hex.EncodeToString(body.GetReportData()), MRTD: hex.EncodeToString(body.GetMrTd()),
		PublicKey: hex.EncodeToString(pub), AcquiredAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, m := range body.GetRtmrs() {
		r.RTMRs = append(r.RTMRs, hex.EncodeToString(m))
	}
	return r, nil
}

// Options for verifying a record.
type Options struct {
	// Collateral fetches TCB info and QE identity from Intel's PCS over the network;
	// without it the quote's own certificate chain is checked against the roots only.
	Collateral bool
	// Now is the time certificates are checked against; zero means now.
	Now time.Time
}

// Verify a record: the quote verifies under Intel's roots (and collateral when
// asked), it binds the key the record names, and its MRTD is the record's.
// The caller then compares Measurement() with what the tokens carry.
func Verify(ctx context.Context, r *Record, opts Options) error {
	if r.Platform != PlatformTDX {
		return fmt.Errorf("platform %s is not hardware-attested", r.Platform)
	}
	raw, err := base64.StdEncoding.DecodeString(r.QuoteB64)
	if err != nil {
		return err
	}
	vo := verify.DefaultOptions()
	vo.GetCollateral = opts.Collateral
	vo.CheckRevocations = opts.Collateral
	if !opts.Now.IsZero() {
		vo.Now = opts.Now
	}
	if err := verify.RawTdxQuote(raw, vo); err != nil {
		return fmt.Errorf("the quote does not verify: %w", err)
	}
	quote, err := Parse(raw)
	if err != nil {
		return err
	}
	pub, err := hex.DecodeString(r.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("the record names no valid public key")
	}
	if !BindsKey(quote, ed25519.PublicKey(pub)) {
		return errors.New("the quote's REPORTDATA does not bind the key the record names")
	}
	if hex.EncodeToString(quote.GetTdQuoteBody().GetMrTd()) != r.MRTD {
		return errors.New("the record's MRTD is not the quote's")
	}
	_ = ctx
	return nil
}

// MeasurementOf is the tagged measurement a verifier expects for a record, or
// the software measurement when there is none.
func MeasurementOf(r *Record, software string) string {
	if r == nil {
		return canonical.Tag(software)
	}
	return r.Measurement()
}

// ReportDataOffset is where REPORTDATA sits in a raw v4 quote: after the
// 48-byte header and 520 bytes of TD report body. Tests use it to rehearse a
// bound quote from a sample; a real quote comes bound from the hardware.
const ReportDataOffset = 48 + 520
