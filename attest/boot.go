package attest

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	_ "embed"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	gceverify "github.com/google/gce-tcb-verifier/verify"
	"github.com/google/go-eventlog/ccel"
	"github.com/google/go-eventlog/extract"
	"github.com/google/go-eventlog/register"
	"google.golang.org/protobuf/proto"
)

// The boot layers of a trust domain, and what each is held to (row 7.2.x, the
// machine image). Until 12 September 2026 the record carried four measurement
// registers and a verifier could only say "the same as yesterday". Now:
//
//   - MRTD, Google's firmware: held to the launch endorsement Google signs for
//     that exact measurement, under Google's root for confidential computing.
//   - RTMR0 to RTMR2, the boot chain (firmware configuration and secure boot
//     variables; shim and grub; kernel, its command line, initrd): held to the
//     boot event log, replayed, so a reader sees a named list with digests.
//   - RTMR3, ours: the gateway extends it with its own binary and the carried
//     configuration before the quote is taken, so the quote binds the release.

// Where the kernel exposes the Confidential Computing event log.
const (
	ccelTablePath = "/sys/firmware/acpi/tables/CCEL"
	ccelDataPath  = "/sys/firmware/acpi/tables/data/CCEL"
	rtmr3Path     = "/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"
)

// Google's root for confidential computing launch endorsements, as published at
// https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt (valid 2023 to 2048).
// Pinned here so a verifier does not fetch its trust anchor from the party it checks.
//
//go:embed GCE-cc-tcb-root_1.crt
var gceRootDER []byte

// EndorsementURL is where Google publishes the signed golden measurement for a
// TDX firmware, keyed by the MRTD itself.
func EndorsementURL(mrtdHex string) string {
	return "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/" + mrtdHex + ".binarypb"
}

// Firmware is what Google's endorsement says about the firmware behind an MRTD.
type Firmware struct {
	UEFISHA384 string
	EndorsedAt time.Time
	SVN        uint32
}

// VerifyFirmware holds the record's MRTD to a launch endorsement: the endorsement
// verifies under Google's root, and one of the measurements it lists is the MRTD.
func VerifyFirmware(r *Record, endorsement []byte, now time.Time) (*Firmware, error) {
	der := gceRootDER
	if b, _ := pem.Decode(der); b != nil {
		der = b.Bytes
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("the pinned Google root does not parse: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if now.IsZero() {
		now = time.Now()
	}
	if err := gceverify.Endorsement(endorsement, &gceverify.Options{RootsOfTrust: pool, Now: now}); err != nil {
		return nil, fmt.Errorf("the endorsement does not verify under Google's root: %w", err)
	}
	var e epb.VMLaunchEndorsement
	if err := proto.Unmarshal(endorsement, &e); err != nil {
		return nil, err
	}
	var g epb.VMGoldenMeasurement
	if err := proto.Unmarshal(e.GetSerializedUefiGolden(), &g); err != nil {
		return nil, err
	}
	want, err := hex.DecodeString(r.MRTD)
	if err != nil {
		return nil, errors.New("the record's MRTD is not hex")
	}
	for _, m := range g.GetTdx().GetMeasurements() {
		if bytes.Equal(m.GetMrtd(), want) {
			return &Firmware{UEFISHA384: hex.EncodeToString(g.GetDigest()), EndorsedAt: g.GetTimestamp().AsTime(), SVN: g.GetTdx().GetSvn()}, nil
		}
	}
	return nil, errors.New("Google's endorsement for this firmware lists no measurement equal to the record's MRTD")
}

// FetchEndorsement gets the endorsement for the record's MRTD from Google's bucket.
func FetchEndorsement(client *http.Client, r *Record) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	res, err := client.Get(EndorsementURL(r.MRTD))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Google answered %d for the endorsement of MRTD %s", res.StatusCode, r.MRTD)
	}
	return io.ReadAll(io.LimitReader(res.Body, 1<<20))
}

// BootLog is what the replayed event log says the machine booted.
type BootLog struct {
	Events      int
	SecureBoot  bool
	Kernel      string // the kernel command line as grub passed it
	GrubCommand []string
	// Named digests, in boot order: EFI applications (shim, grub), grub files (the
	// kernel, initrd, grub.cfg as grub named them).
	Apps  []string
	Files []Named
}

// Named is a file grub measured, by the name grub used and its digest.
type Named struct {
	Name   string `json:"name"`
	SHA384 string `json:"sha384"`
}

// ReplayBootLog holds RTMR0 to RTMR2 to the event log: every event's digest is
// folded into a simulated register, and the three must land on the quote's values.
// It returns what was measured, named.
func ReplayBootLog(r *Record) (*BootLog, error) {
	if r.EventLog == "" || r.EventLogTable == "" {
		return nil, errors.New("the record carries no boot event log")
	}
	table, err := base64.StdEncoding.DecodeString(r.EventLogTable)
	if err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.DecodeString(r.EventLog)
	if err != nil {
		return nil, err
	}
	if len(r.RTMRs) < 3 {
		return nil, errors.New("the record carries fewer than three runtime registers")
	}
	bank := register.RTMRBank{}
	for i := 0; i < 3; i++ {
		d, err := hex.DecodeString(r.RTMRs[i])
		if err != nil || len(d) != sha512.Size384 {
			return nil, fmt.Errorf("RTMR%d in the record is not a SHA-384", i)
		}
		bank.RTMRs = append(bank.RTMRs, register.RTMR{Index: i, Digest: d})
	}
	state, err := ccel.ReplayAndExtract(table, data, bank, extract.Opts{Loader: extract.GRUB})
	if err != nil {
		return nil, fmt.Errorf("the boot log does not replay to the quote's registers: %w", err)
	}
	out := &BootLog{Events: len(state.GetRawEvents()), SecureBoot: state.GetSecureBoot().GetEnabled(), Kernel: state.GetLinuxKernel().GetCommandLine(), GrubCommand: state.GetGrub().GetCommands()}
	for _, a := range state.GetEfi().GetApps() {
		out.Apps = append(out.Apps, hex.EncodeToString(a.GetDigest()))
	}
	for _, f := range state.GetGrub().GetFiles() {
		out.Files = append(out.Files, Named{Name: string(f.GetUntrustedFilename()), SHA384: hex.EncodeToString(f.GetDigest())})
	}
	return out, nil
}

// FoldRTMR3 computes RTMR3 as the hardware would after extending the inputs in
// order from a zero register: R = SHA-384(R || input).
func FoldRTMR3(inputs []Input) (string, error) {
	reg := make([]byte, sha512.Size384)
	for _, in := range inputs {
		d, err := hex.DecodeString(in.SHA384)
		if err != nil || len(d) != sha512.Size384 {
			return "", fmt.Errorf("input %q is not a SHA-384", in.Name)
		}
		sum := sha512.Sum384(append(reg, d...))
		reg = sum[:]
	}
	return hex.EncodeToString(reg), nil
}

// VerifyRTMR3 holds the quote's RTMR3 to the inputs the record names.
func VerifyRTMR3(r *Record) error {
	if len(r.RTMRs) < 4 {
		return errors.New("the record carries no RTMR3")
	}
	if len(r.RTMR3Inputs) == 0 {
		if r.RTMRs[3] == strings.Repeat("0", 96) {
			return errors.New("RTMR3 is zero: the gateway did not measure itself into the quote")
		}
		return errors.New("RTMR3 is set but the record names no inputs for it")
	}
	for _, in := range r.RTMR3Inputs {
		if in.Content == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(in.Content)
		if err != nil {
			return fmt.Errorf("input %q carries content that is not base64", in.Name)
		}
		if InputOf(in.Name, raw).SHA384 != in.SHA384 {
			return fmt.Errorf("input %q carries content whose SHA-384 is not the one named", in.Name)
		}
	}
	want, err := FoldRTMR3(r.RTMR3Inputs)
	if err != nil {
		return err
	}
	if want != r.RTMRs[3] {
		return fmt.Errorf("RTMR3 %s is not the fold of the named inputs (%s)", r.RTMRs[3][:16], want[:16])
	}
	return nil
}

// ExtendRTMR3 measures the inputs into RTMR3 through the kernel's sysfs door
// (Linux 6.16 and later), unless the register already holds their fold: a retake
// of the quote on a running machine must not extend twice. A register that holds
// something else is left alone and reported, so the record never claims an input
// that is not in the chip.
func ExtendRTMR3(inputs []Input) error {
	current, err := os.ReadFile(rtmr3Path)
	if err != nil {
		return fmt.Errorf("no RTMR3 door on this kernel: %w", err)
	}
	if len(current) != sha512.Size384 {
		return fmt.Errorf("RTMR3 reads %d bytes, not a SHA-384", len(current))
	}
	have := hex.EncodeToString(current)
	want, err := FoldRTMR3(inputs)
	if err != nil {
		return err
	}
	if have == want {
		return nil
	}
	if have != strings.Repeat("0", 96) {
		return fmt.Errorf("RTMR3 already holds %s, not zero and not the fold of the inputs", have[:16])
	}
	for _, in := range inputs {
		d, _ := hex.DecodeString(in.SHA384)
		if err := os.WriteFile(rtmr3Path, d, 0); err != nil {
			return fmt.Errorf("extending RTMR3 with %s: %w", in.Name, err)
		}
	}
	after, err := os.ReadFile(rtmr3Path)
	if err != nil {
		return err
	}
	if hex.EncodeToString(after) != want {
		return errors.New("RTMR3 after extending is not the fold of the inputs")
	}
	return nil
}

// InputOf names a file and its SHA-384 for RTMR3.
func InputOf(name string, content []byte) Input {
	sum := sha512.Sum384(content)
	return Input{Name: name, SHA384: hex.EncodeToString(sum[:])}
}

// InputWithContent is InputOf for an input small enough to travel with the record.
func InputWithContent(name string, content []byte) Input {
	in := InputOf(name, content)
	in.Content = base64.StdEncoding.EncodeToString(content)
	return in
}
