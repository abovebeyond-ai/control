// verify replays the evidence a gateway wrote, with nothing but the store,
// the public key and the measurement: every chain, every record's premises
// against the material beside it, and the checkpoint against the head.
//
//	verify --store DIR --key HEX [--measurement HEX] [--checkpoint checkpoint.json] [--attestation attestation.json]
//	verify --gateway URL [--key HEX] [--offline]
//
// With --gateway everything is read from the running gateway over HTTP: its
// agents, records, attachments, attestation and live checkpoints, so a stranger
// verifies without the store directory. The key defaults to the one the
// gateway publishes; pass --key to hold it to a key you obtained elsewhere.
//
// Exit 0 when everything holds. Without --measurement the first record of each
// chain says which policy judged and the rest must agree with it. With
// --attestation the hardware's quote is verified under Intel's roots, it must
// bind the key given, and its MRTD becomes the measurement every record must
// carry: that is what makes the chain Tier 3 to a stranger.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/anchor"
	"github.com/abovebeyond-ai/control/attest"
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
	anchors := flag.String("anchors", "", "a receipts directory written by cmd/anchor: the latest receipt per agent is checked and the chain must extend it")
	offline := flag.Bool("offline", false, "check anchor receipts and the attestation without the network")
	attestation := flag.String("attestation", "", "the gateway's attestation record (attestation.json beside the store)")
	gatewayURL := flag.String("gateway", "", "read everything from a running gateway at this URL instead of a store directory")
	flag.Parse()
	var src source
	var live *remote
	if *gatewayURL != "" {
		live = &remote{base: strings.TrimRight(*gatewayURL, "/")}
		src = live
		if *keyHex == "" {
			var k struct {
				PublicKey string `json:"public_key"`
			}
			fail(live.get("/v1/key", nil, &k))
			*keyHex = k.PublicKey
			fmt.Printf("note   the key is the one the gateway publishes, %s; hold it to a published one with --key\n", *keyHex)
		}
	} else {
		if *dir == "" || *keyHex == "" {
			fmt.Fprintln(os.Stderr, "usage: verify --store DIR --key HEX [--measurement HEX] [--checkpoint FILE] | verify --gateway URL")
			os.Exit(2)
		}
	}
	pubRaw, err := hex.DecodeString(*keyHex)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "the key is not a 32-byte hex Ed25519 public key")
		os.Exit(2)
	}
	pub := ed25519.PublicKey(pubRaw)
	if src == nil {
		store, err := log.Open(*dir)
		fail(err)
		src = store
	}
	agents, err := src.Agents()
	fail(err)
	broken := 0
	var rec attest.Record
	haveAttestation := false
	if *attestation != "" {
		raw, err := os.ReadFile(*attestation)
		fail(err)
		fail(json.Unmarshal(raw, &rec))
		haveAttestation = true
	} else if live != nil {
		// The running gateway says what attests it; a software gateway answers 404.
		if err := live.get("/v1/attestation", nil, &rec); err == nil {
			haveAttestation = true
		} else {
			fmt.Printf("note   the gateway attests in software: the operator vouches for its measurement\n")
		}
	}
	var quoteDigest string
	if haveAttestation {
		if raw, err := base64.StdEncoding.DecodeString(rec.QuoteB64); err == nil {
			quoteDigest = canonical.Tag(canonical.SHA256(raw))
		}
		if rec.PublicKey != *keyHex {
			fmt.Printf("BROKEN attestation: it binds key %s, not %s\n", rec.PublicKey, *keyHex)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err = attest.Verify(ctx, &rec, attest.Options{Collateral: !*offline})
		cancel()
		if err != nil {
			fmt.Printf("BROKEN attestation: %v\n", err)
			os.Exit(1)
		}
		_, *measurement, _ = canonical.UntagAny(rec.Measurement())
		fmt.Printf("holds  attestation: %s quote binds the key, MRTD %s\n", rec.Platform, rec.MRTD)
	}
	for _, agent := range agents {
		records, err := src.Records(agent)
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
			_, m, _ = canonical.UntagAny(fmt.Sprint(attestation["measurement"]))
		}
		r := evidence.VerifyChain(records, pub, m)
		if !r.OK {
			fmt.Printf("BROKEN %s: %s\n", agent, r.Reason)
			broken++
			continue
		}
		fmt.Printf("holds  %s: %s\n", agent, r.Reason)
		// Row 7.1.2: every request has its effect and its result, under one action id.
		phases := map[string]map[string]bool{}
		order := []string{}
		for _, tok := range records {
			c := tok.Claims()
			id, _ := c["control_action"].(string)
			ph, _ := c["control_phase"].(string)
			if id == "" {
				continue
			}
			if phases[id] == nil {
				phases[id] = map[string]bool{}
				order = append(order, id)
			}
			phases[id][ph] = true
		}
		incomplete := 0
		for _, id := range order {
			if !phases[id]["request"] || !phases[id]["effect"] || !phases[id]["result"] {
				fmt.Printf("BROKEN %s: action %s lacks one of request, effect, result\n", agent, id[:8])
				incomplete++
			}
		}
		if incomplete > 0 {
			broken += incomplete
		} else if len(order) > 0 {
			fmt.Printf("holds  %s: %d action(s), each with request, effect and result\n", agent, len(order))
		}
		for i, tok := range records {
			c := tok.Claims()
			if _, ok := c["proveml_certificate_hash"]; !ok {
				continue
			}
			var material premises.Material
			found, err := src.Attachment(agent, i, "premises", &material)
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
		if *anchors != "" {
			r, err := anchor.Latest(*anchors, agent)
			fail(err)
			if r == nil {
				fmt.Printf("note   %s: no anchor receipt\n", agent)
			} else {
				b, err := anchor.BackendOf(r)
				fail(err)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				err = anchor.Check(ctx, r, pub, b, !*offline)
				cancel()
				size := r.Checkpoint.TreeSize
				switch {
				case err != nil:
					fmt.Printf("BROKEN %s: anchor %s: %v\n", agent, r.Backend, err)
					broken++
				case size > len(records):
					fmt.Printf("BROKEN %s: truncation detected: the anchor covers %d records, only %d presented\n", agent, size, len(records))
					broken++
				case size == 0:
					// An empty chain was anchored (its genesis head); anything written since extends it.
					fmt.Printf("holds  %s: anchored empty on %s at %s, and the chain extends it\n", agent, r.Backend, r.AnchoredAt)
				case records[size-1].Claims()["chain_head"] != r.Checkpoint.ChainHead:
					fmt.Printf("BROKEN %s: history rewritten: the chain presented at size %d does not fold to the anchored head\n", agent, size)
					broken++
				default:
					fmt.Printf("holds  %s: anchored at size %d on %s at %s, and the chain extends it\n", agent, size, r.Backend, r.AnchoredAt)
					// Row 8.1.7: the vendor-rooted attestation, committed to the anchor too.
					switch {
					case r.Checkpoint.Attestation == "":
						fmt.Printf("note   %s: the anchored checkpoint carries no attestation digest\n", agent)
					case quoteDigest != "" && r.Checkpoint.Attestation != quoteDigest:
						fmt.Printf("BROKEN %s: the anchored checkpoint commits to another attestation than the one presented\n", agent)
						broken++
					case quoteDigest != "":
						fmt.Printf("holds  %s: the attestation presented is the one anchored on %s\n", agent, r.Backend)
					}
				}
			}
		}
		var cp gateway.Checkpoint
		haveCheckpoint := false
		if *checkpoint != "" {
			raw, err := os.ReadFile(*checkpoint)
			fail(err)
			fail(json.Unmarshal(raw, &cp))
			haveCheckpoint = log.Safe(cp.Agent) == log.Safe(agent)
		} else if live != nil {
			// The live checkpoint: what the gateway signs right now must fold from
			// the records it just handed over.
			fail(live.get("/v1/checkpoint", map[string]string{"agent": agent}, &cp))
			haveCheckpoint = true
		}
		if haveCheckpoint {
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

// source is where the evidence comes from: the store directory, or a running
// gateway over HTTP, which serves the same things a stranger needs.
type source interface {
	Agents() ([]string, error)
	Records(agent string) ([]evidence.Token, error)
	Attachment(agent string, step int, name string, into any) (bool, error)
}

type remote struct{ base string }

func (r *remote) get(path string, query map[string]string, into any) error {
	u := r.base + path
	if len(query) > 0 {
		q := url.Values{}
		for k, v := range query {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}
	resp, err := http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return errNotFound
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("the gateway answered %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

var errNotFound = errors.New("not found")

func (r *remote) Agents() ([]string, error) {
	var out struct {
		Agents []string `json:"agents"`
	}
	return out.Agents, r.get("/v1/agents", nil, &out)
}

func (r *remote) Records(agent string) ([]evidence.Token, error) {
	var out struct {
		Records []evidence.Token `json:"records"`
	}
	return out.Records, r.get("/v1/records", map[string]string{"agent": agent}, &out)
}

func (r *remote) Attachment(agent string, step int, name string, into any) (bool, error) {
	err := r.get("/v1/attachment", map[string]string{"agent": agent, "step": strconv.Itoa(step), "name": name}, into)
	if errors.Is(err, errNotFound) {
		return false, nil
	}
	return err == nil, err
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
