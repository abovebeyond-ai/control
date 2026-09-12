package attest

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// Google's endorsement for the firmware the gateway booted on 11 September 2026,
// fetched by its MRTD: it verifies under Google's pinned root and lists that MRTD.
// A record with another MRTD is not covered by it.
func TestTheFirmwareIsOneGoogleSigned(t *testing.T) {
	raw, err := os.ReadFile("testdata/c1ee9c16.binarypb")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 12, 8, 0, 0, 0, time.UTC)
	rec := &Record{MRTD: "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"}
	fw, err := VerifyFirmware(rec, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fw.UEFISHA384) != 96 || fw.EndorsedAt.Year() != 2026 {
		t.Errorf("%+v", fw)
	}
	other := &Record{MRTD: strings.Repeat("ab", 48)}
	if _, err := VerifyFirmware(other, raw, now); err == nil || !strings.Contains(err.Error(), "no measurement equal") {
		t.Errorf("another MRTD must not be covered: %v", err)
	}
	if _, err := VerifyFirmware(rec, append([]byte{}, raw[:len(raw)-40]...), now); err == nil {
		t.Error("a truncated endorsement must not verify")
	}
}

// The boot event log of a TDX guest (Google's sample from a COS image) replays to the
// three registers it was taken with, and names the kernel command line; a register
// that differs by one bit is a break.
func TestTheBootLogReplaysToTheRegistersAndNamesTheKernel(t *testing.T) {
	table, _ := os.ReadFile("testdata/ccel-cos-113.table.bin")
	data, _ := os.ReadFile("testdata/ccel-cos-113.bin")
	rtmr0 := []byte("?\xa2\xf6\x1f9[\x7f_\xee\xfbN\xc2\xdfa)\x7f\x10\x9aث\xcdd\x10\xc1\xb7\xdf`\xf2\x1f7\xb1\x92\x97\xfc5\xe5D\x03\x9c~\x1e\xde\xceu*\xfd\x17\xf6")
	rtmr1 := []byte("\xf6-\xbc\a+\xd5\xd3\xf3C\x8b{5Úr\x7fZ\xea/\xfc$s\xf47#\x95?S\r\xafbPO\nyD\xaab\xc4\x1a\x86\xe8\xa8x±\"\xc1")
	rtmr2 := []byte("IihM\xc8s\x81\xfc;14\x17l\x8d\x88\x06\xea\xf0\xa9\x01\x85\x9f_pϮ\x8d\x17qKF\xc1\n\x8d\xe2\x19\x04\x8c\x9f\xc0\x9f\x11\xf3\x81\xa6\xfb\xe7\xc1")
	rec := &Record{
		EventLogTable: base64.StdEncoding.EncodeToString(table), EventLog: base64.StdEncoding.EncodeToString(data),
		RTMRs: []string{hex.EncodeToString(rtmr0), hex.EncodeToString(rtmr1), hex.EncodeToString(rtmr2), strings.Repeat("0", 96)},
	}
	boot, err := ReplayBootLog(rec)
	if err != nil {
		t.Fatal(err)
	}
	if boot.Events == 0 || boot.Kernel == "" || len(boot.Apps) == 0 {
		t.Errorf("%+v", boot)
	}
	flipped := append([]byte{}, rtmr2...)
	flipped[0] ^= 1
	rec.RTMRs[2] = hex.EncodeToString(flipped)
	if _, err := ReplayBootLog(rec); err == nil || !strings.Contains(err.Error(), "does not replay") {
		t.Errorf("a changed RTMR2 must break the replay: %v", err)
	}
}

// RTMR3 is the fold of the named inputs from zero, the way the hardware extends: a
// record whose register is not that fold, or that names nothing for a set register,
// is refused; a zero register with no inputs is a note, not a fold.
func TestRTMR3IsTheFoldOfTheNamedInputs(t *testing.T) {
	binary := InputOf("control-gateway-linux-amd64", []byte("the binary"))
	config := InputOf("carried-config", []byte(`{"agents":{}}`))
	one := sha512.Sum384(append(make([]byte, 48), mustHex(binary.SHA384)...))
	two := sha512.Sum384(append(one[:], mustHex(config.SHA384)...))
	got, err := FoldRTMR3([]Input{binary, config})
	if err != nil || got != hex.EncodeToString(two[:]) {
		t.Fatalf("%s %v", got, err)
	}
	rec := &Record{RTMRs: []string{"", "", "", got}, RTMR3Inputs: []Input{binary, config}}
	if err := VerifyRTMR3(rec); err != nil {
		t.Error(err)
	}
	rec.RTMR3Inputs = []Input{config, binary}
	if err := VerifyRTMR3(rec); err == nil {
		t.Error("the order is part of the fold")
	}
	// Content that travels with an input must hash to the digest it names.
	carried := InputWithContent("carried-config", []byte(`{"agents":{}}`))
	rec.RTMR3Inputs = []Input{binary, carried}
	if err := VerifyRTMR3(rec); err != nil {
		t.Error(err)
	}
	carried.Content = base64.StdEncoding.EncodeToString([]byte(`{"agents":{"x":1}}`))
	rec.RTMR3Inputs = []Input{binary, carried}
	if err := VerifyRTMR3(rec); err == nil || !strings.Contains(err.Error(), "content whose SHA-384") {
		t.Errorf("content that is not the digest's preimage: %v", err)
	}
	zero := &Record{RTMRs: []string{"", "", "", strings.Repeat("0", 96)}}
	if err := VerifyRTMR3(zero); err == nil || !strings.Contains(err.Error(), "did not measure itself") {
		t.Errorf("a zero RTMR3 without inputs: %v", err)
	}
	set := &Record{RTMRs: []string{"", "", "", got}}
	if err := VerifyRTMR3(set); err == nil || !strings.Contains(err.Error(), "names no inputs") {
		t.Errorf("a set RTMR3 without inputs: %v", err)
	}
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}
