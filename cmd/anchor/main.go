// anchor pins a gateway's signed checkpoint outside the operator's control and
// keeps the receipt. It runs outside the trusted boundary; it needs no trust.
//
//	anchor pin --gateway http://127.0.0.1:8471 --agent DID --out DIR (--tsa URL | --hedera operator.json)
//	anchor pin --checkpoint checkpoint.json --key HEX --out DIR (--tsa URL | --hedera operator.json)
//	anchor check --out DIR --agent DID --key HEX [--offline]
//	anchor identity pin --log FILE|URL --out DIR (--tsa URL | --hedera operator.json)
//	anchor identity check --log FILE|URL --out DIR (--tsa URL | --hedera operator.json) [--offline]
//
// identity pins the did:webvh log the same way, one message per version, so a checker
// can tell that the log it reads is the only one ever published (see anchor/identity.go).
//
// One receipt per tree size and backend; a size already anchored is skipped,
// so running this every minute costs nothing when nothing moved.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/anchor"
	"github.com/abovebeyond-ai/control/gateway"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	if os.Args[1] == "identity" {
		identity(os.Args[2:])
		return
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	gatewayURL := fs.String("gateway", "", "the gateway's base URL")
	agent := fs.String("agent", "", "the agent id")
	checkpoint := fs.String("checkpoint", "", "a checkpoint file instead of a gateway")
	keyHex := fs.String("key", "", "the gateway's public key, hex (with --checkpoint or check)")
	out := fs.String("out", "anchors", "the receipts directory")
	tsa := fs.String("tsa", "", "an RFC 3161 timestamp authority URL")
	hederaFile := fs.String("hedera", "", "a Hedera operator file {network, accountId, privateKey, topicId}")
	offline := fs.Bool("offline", false, "check receipts without the network")
	_ = fs.Parse(os.Args[2:])
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	switch os.Args[1] {
	case "pin":
		var cp gateway.Checkpoint
		var pub []byte
		var err error
		if *checkpoint != "" {
			raw, err := os.ReadFile(*checkpoint)
			fail(err)
			fail(json.Unmarshal(raw, &cp))
			pub, err = hex.DecodeString(*keyHex)
			fail(err)
			if !gateway.VerifyCheckpoint(cp, pub) {
				fail(fmt.Errorf("the checkpoint is not signed by that key"))
			}
		} else {
			if *gatewayURL == "" || *agent == "" {
				usage()
			}
			cp, pub, err = anchor.FetchCheckpoint(ctx, *gatewayURL, *agent)
			fail(err)
		}
		backends := chosen(*tsa, *hederaFile)
		for _, b := range backends {
			r, pinned, err := anchor.Pin(ctx, *out, cp, b)
			fail(err)
			if !pinned {
				fmt.Printf("%s: size %d already anchored\n", b.Name(), cp.TreeSize)
				continue
			}
			fmt.Printf("%s: anchored size %d at %s\n", b.Name(), cp.TreeSize, r.AnchoredAt)
		}
	case "check":
		pub, err := hex.DecodeString(*keyHex)
		fail(err)
		r, err := anchor.Latest(*out, *agent)
		fail(err)
		if r == nil {
			fail(fmt.Errorf("no receipt for %s", *agent))
		}
		b, err := anchor.BackendOf(r)
		fail(err)
		if err := anchor.Check(ctx, r, pub, b, !*offline); err != nil {
			fmt.Printf("BROKEN %s: %v\n", r.Backend, err)
			os.Exit(1)
		}
		fmt.Printf("holds  %s: size %d anchored at %s\n", r.Backend, r.Checkpoint.TreeSize, r.AnchoredAt)
	default:
		usage()
	}
}

// identity: the did:webvh log, pinned per version and read back from the ledger.
func identity(args []string) {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("identity "+args[0], flag.ExitOnError)
	logRef := fs.String("log", "", "the did.jsonl, a file or an https URL")
	out := fs.String("out", "anchors", "the receipts directory")
	tsa := fs.String("tsa", "", "an RFC 3161 timestamp authority URL")
	hederaFile := fs.String("hedera", "", "a Hedera operator file {network, accountId, privateKey, topicId}")
	offline := fs.Bool("offline", false, "check receipts without the network")
	_ = fs.Parse(args[1:])
	if *logRef == "" {
		usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	raw, err := readLog(ctx, *logRef)
	fail(err)
	entries, err := anchor.ReadLog(raw)
	fail(err)
	backends := chosen(*tsa, *hederaFile)
	switch args[0] {
	case "pin":
		for _, b := range backends {
			n, err := anchor.PinIdentity(ctx, *out, entries, b)
			fail(err)
			if n == 0 {
				fmt.Printf("%s: all %d version(s) already anchored\n", b.Name(), len(entries))
			} else {
				fmt.Printf("%s: anchored %d version(s), log at version %d\n", b.Name(), n, len(entries))
			}
		}
	case "check":
		broken := false
		kept, err := anchor.IdentityReceipts(*out, entries[0].DID)
		fail(err)
		for _, b := range backends {
			if len(kept) == 0 {
				fmt.Printf("%s: no receipts under %s; a stranger has none either, so only the ledger can answer\n", b.Name(), *out)
			} else if err := anchor.CheckIdentity(ctx, *out, entries, b, !*offline); err != nil {
				fmt.Printf("BROKEN %s: %v\n", b.Name(), err)
				broken = true
			} else {
				fmt.Printf("holds  %s: %d version(s), each with a receipt that matches the log\n", b.Name(), len(entries))
			}
			if h, ok := b.(anchor.Hedera); ok && !*offline {
				// The check that needs nothing of ours: the topic's first posting per version.
				if err := h.Equivocation(ctx, entries); err != nil {
					fmt.Printf("BROKEN hedera: %v\n", err)
					broken = true
					continue
				}
				fmt.Printf("holds  hedera: the ledger's first posting of every version is the one in the log\n")
			}
		}
		if broken {
			os.Exit(1)
		}
	default:
		usage()
	}
}

func readLog(ctx context.Context, ref string) ([]byte, error) {
	if !strings.HasPrefix(ref, "https://") && !strings.HasPrefix(ref, "http://") {
		return os.ReadFile(ref)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", ref, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", ref, res.Status)
	}
	return io.ReadAll(io.LimitReader(res.Body, 4<<20))
}

func chosen(tsa, hederaFile string) []anchor.Backend {
	var out []anchor.Backend
	if tsa != "" {
		out = append(out, anchor.TSA{URL: tsa})
	}
	if hederaFile != "" {
		raw, err := os.ReadFile(hederaFile)
		fail(err)
		var op anchor.Operator
		fail(json.Unmarshal(raw, &op))
		if op.TopicID == "" {
			fail(fmt.Errorf("the operator file has no topicId"))
		}
		out = append(out, anchor.Hedera{Network: op.Network, TopicID: op.TopicID, Submitter: anchor.SDKSubmitter{Operator: op}})
	}
	if len(out) == 0 {
		fail(fmt.Errorf("choose a backend: --tsa URL and/or --hedera operator.json"))
	}
	return out
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: anchor pin (--gateway URL --agent DID | --checkpoint FILE --key HEX) --out DIR (--tsa URL | --hedera FILE)\n       anchor check --out DIR --agent DID --key HEX [--offline]\n       anchor identity pin --log FILE|URL --out DIR (--tsa URL | --hedera FILE)\n       anchor identity check --log FILE|URL --out DIR (--tsa URL | --hedera FILE) [--offline]")
	os.Exit(2)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
