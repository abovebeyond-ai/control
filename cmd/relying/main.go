// relying is the far end: run it on a runner before it acts on a dispatch, or as
// a merge check on a pull request. It needs the network for the DID document
// and the mirror, and nothing from the operator.
//
//	relying dispatch --evidence B64 --capability TOKEN --repository owner/repo [--max-age 3h]
//	relying pull --body FILE --repository owner/repo
//
// Exit 0 when the evidence holds; 1 with the reasons when it does not; 2 on usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/abovebeyond-ai/control/relying"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	evidenceB64 := fs.String("evidence", "", "the record, base64url JSON (dispatch)")
	capTok := fs.String("capability", "", "the principal's capability (dispatch)")
	body := fs.String("body", "", "a file with the pull request body (pull)")
	repo := fs.String("repository", os.Getenv("GITHUB_REPOSITORY"), "owner/repo")
	did := fs.String("did", "https://abovebeyond.ai/.well-known/did.json", "the DID document")
	mirror := fs.String("mirror", "https://raw.githubusercontent.com/abovebeyond-ai/control-evidence/main/store/attestation.json", "the mirror's current attestation; empty skips the measurement check")
	maxAge := fs.Duration("max-age", 3*time.Hour, "how old a dispatched record may be")
	_ = fs.Parse(os.Args[2:])
	if *repo == "" {
		usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	keys, err := relying.ResolveKeys(ctx, *did, "control-gateway", "portal")
	fail(err)
	o := relying.Options{Repository: *repo, Now: time.Now()}
	switch mode {
	case "dispatch":
		o.Kind, o.MaxAge = "workflow.dispatch", *maxAge
	case "pull":
		o.Kind = "pull.open"
		raw, err := os.ReadFile(*body)
		fail(err)
		e, c, err := relying.FromBody(string(raw))
		fail(err)
		evidenceB64, capTok = &e, &c
	default:
		usage()
	}
	if *mirror != "" {
		req, _ := http.NewRequestWithContext(ctx, "GET", *mirror, nil)
		if res, err := http.DefaultClient.Do(req); err == nil && res.StatusCode == 200 {
			var rec struct {
				MRTD string `json:"mrtd"`
			}
			_ = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&rec)
			res.Body.Close()
			o.MRTD = rec.MRTD
		} else {
			fmt.Println("note   the mirror's attestation could not be read; the measurement is not checked against it")
		}
	}
	tok, err := relying.DecodeToken(*evidenceB64)
	fail(err)
	r := relying.Check(tok, *capTok, keys, o)
	if r.OK {
		fmt.Printf("holds  %s step %d: %s by %s on %s, task %v, measurement %s\n", o.Kind, r.Step, r.Verdict, r.Agent, o.Repository, r.Task, short(r.Measured))
		return
	}
	for _, reason := range r.Reasons {
		fmt.Printf("REFUSE %s\n", reason)
	}
	os.Exit(1)
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: relying dispatch --evidence B64 --capability TOKEN --repository owner/repo | relying pull --body FILE --repository owner/repo")
	os.Exit(2)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "REFUSE", err)
		os.Exit(1)
	}
}
