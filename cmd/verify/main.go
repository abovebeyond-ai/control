// verify replays the evidence a gateway wrote, with nothing but the store,
// the public key and the measurement: every chain, every record's premises
// against the material beside it, and the checkpoint against the head.
//
//	verify --store DIR --key HEX [--measurement HEX] [--checkpoint checkpoint.json]
//
// Exit 0 when everything holds. Without --measurement the first record of each
// chain says which policy judged and the rest must agree with it.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/premises"
)

func main() {
	dir := flag.String("store", "", "the evidence store directory")
	keyHex := flag.String("key", "", "the gateway's public key, hex")
	measurement := flag.String("measurement", "", "the expected measurement, hex (default: the first record's)")
	checkpoint := flag.String("checkpoint", "", "a signed checkpoint to check against the chain")
	flag.Parse()
	if *dir == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "usage: verify --store DIR --key HEX [--measurement HEX] [--checkpoint FILE]")
		os.Exit(2)
	}
	pubRaw, err := hex.DecodeString(*keyHex)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "the key is not a 32-byte hex Ed25519 public key")
		os.Exit(2)
	}
	pub := ed25519.PublicKey(pubRaw)
	store, err := log.Open(*dir)
	fail(err)
	agents, err := store.Agents()
	fail(err)
	broken := 0
	for _, agent := range agents {
		records, err := store.Records(agent)
		if err != nil {
			fmt.Printf("BROKEN %s: %v\n", agent, err)
			broken++
			continue
		}
		if len(records) == 0 {
			continue
		}
		m := *measurement
		if m == "" {
			att, _ := records[0]["submods"].(map[string]any)
			attestation, _ := att["attestation"].(map[string]any)
			m, _ = canonical.Untag(fmt.Sprint(attestation["measurement"]))
		}
		r := evidence.VerifyChain(records, pub, m)
		if !r.OK {
			fmt.Printf("BROKEN %s: %s\n", agent, r.Reason)
			broken++
			continue
		}
		fmt.Printf("holds  %s: %s\n", agent, r.Reason)
		for i, tok := range records {
			c := tok.Claims()
			if _, ok := c["proveml_certificate_hash"]; !ok {
				continue
			}
			var material premises.Material
			found, err := store.Attachment(agent, i, "premises", &material)
			if err != nil || !found {
				fmt.Printf("BROKEN %s record %d: no premises material beside the record\n", agent, i)
				broken++
				continue
			}
			if err := premises.Replay(c, material); err != nil {
				fmt.Printf("BROKEN %s record %d: %v\n", agent, i, err)
				broken++
			}
		}
		if *checkpoint != "" {
			raw, err := os.ReadFile(*checkpoint)
			fail(err)
			var cp gateway.Checkpoint
			fail(json.Unmarshal(raw, &cp))
			if log.Safe(cp.Agent) != agent {
				continue
			}
			last := records[len(records)-1].Claims()
			switch {
			case !gateway.VerifyCheckpoint(cp, pub):
				fmt.Printf("BROKEN %s: the checkpoint's signature does not verify\n", agent)
				broken++
			case cp.TreeSize > len(records):
				fmt.Printf("BROKEN %s: truncation detected: the checkpoint covers %d records, only %d presented\n", agent, cp.TreeSize, len(records))
				broken++
			case cp.TreeSize == len(records) && (cp.ChainHead != last["chain_head"] || cp.Root != last["merkle_root"]):
				fmt.Printf("BROKEN %s: history rewritten: the chain presented does not fold to the checkpointed head\n", agent)
				broken++
			default:
				fmt.Printf("holds  %s: checkpoint at size %d matches the chain\n", agent, cp.TreeSize)
			}
		}
	}
	if broken > 0 {
		os.Exit(1)
	}
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
