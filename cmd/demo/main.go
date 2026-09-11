// demo writes a small evidence chain into a directory: an allowed dispatch
// with verified premises, a proposal, a refused merge, and a dispatch whose
// premises fail, each as the three records the service writes (request, effect,
// result; row 7.1.2). The cross-check in tools/crosscheck.py then replays it with
// the standard's own validator and reference verifier, and the premises with
// the ProveML package, with nothing of this repository loaded.
//
//	go run ./cmd/demo <dir>
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
	proveml "github.com/abovebeyond-ai/proveml-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: demo <dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	store, err := log.Open(filepath.Join(dir, "store"))
	fail(err)
	seed, _ := hex.DecodeString(strings.Repeat("22", 32))
	key := ed25519.NewKeyFromSeed(seed)
	agent := "did:webvh:QmTest:example.org#agent-fix"
	g, err := gateway.Open(gateway.Config{
		Issuer: "https://gateway.example/control", Agent: agent,
		Policy: policy.Policy{Grant: policy.Grant{Principal: "did:webvh:QmTest:example.org", Kinds: []string{"workflow.dispatch", "pull.open"}, Resources: []string{"x/y"}, MaxPerKind: 1, PremisesFor: []string{"workflow.dispatch"}}, PathAware: true},
		Store:  store, Key: key, AgbomDigest: strings.Repeat("a", 64),
	})
	fail(err)
	good := material(1)
	bad := material(0)
	principal := "did:webvh:QmTest:example.org"
	act := func(a policy.Action, ext map[string]any, prem *premises.Material) {
		v := g.Submit(a, principal, ext, prem)
		fmt.Println(v.Verdict)
		// As the service does: an effect record and a result record follow every request,
		// a refusal included, so a verifier can tell allowed-but-never-done from done.
		var outcome map[string]any
		var reason string
		if v.Allowed() {
			outcome, reason = map[string]any{"performed": true, "demo": true}, "effect performed"
		} else {
			outcome, reason = map[string]any{"performed": false, "why": "refused"}, "not performed: the request was refused"
		}
		fail(errOf(g.Follow("", v.ActionID, gateway.PhaseEffect, a, principal, v.Verdict, reason, outcome)))
		answer := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "action": v.ActionID, "effect": outcome}
		fail(errOf(g.Follow("", v.ActionID, gateway.PhaseResult, a, principal, v.Verdict, "result returned", answer)))
	}
	act(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "elixir-fix.yml", "ref": "main", "packages": 1}}, map[string]any{"project": "demo"}, good)
	act(policy.Action{Kind: "pull.open", Resource: "x/y", Params: map[string]any{"branch": "elixir/security-2026-09-07", "base": "main"}}, nil, nil)
	act(policy.Action{Kind: "pull.merge", Resource: "x/y"}, nil, nil)
	act(policy.Action{Kind: "workflow.dispatch", Resource: "x/y", Params: map[string]any{"workflow": "w", "ref": "main"}}, nil, bad)
	cp, err := g.Checkpoint()
	fail(err)
	raw, _ := json.MarshalIndent(cp, "", " ")
	fail(os.WriteFile(filepath.Join(dir, "checkpoint.json"), raw, 0o644))
	fail(os.WriteFile(filepath.Join(dir, "public-key.hex"), []byte(hex.EncodeToString(g.PublicKey())+"\n"), 0o644))
	fail(os.WriteFile(filepath.Join(dir, "measurement.hex"), []byte(g.Measurement()+"\n"), 0o644))
	fmt.Println("public key", hex.EncodeToString(g.PublicKey()))
}

func material(safe int) *premises.Material {
	return &premises.Material{
		Certificate:      "@[package:tar]{tar} moves from %[from]{7.13.1} to %[to]{7.14.2}, closing %[advisories]{2} advisories, ?[safe: FIX_WITHIN_SEMVER]{within semver}.",
		Store:            map[string]any{"package:tar.name": "tar", "package:tar.from": "7.13.1", "package:tar.to": "7.14.2", "package:tar.advisories": 2, "package:tar.semverSafe": safe},
		Registry:         proveml.Registry{"FIX_WITHIN_SEMVER": {Field: "semverSafe", Op: "eq", Value: 1, Label: "the update stays within semver"}},
		Provenance:       map[string]string{"package:tar.name": "inferred", "package:tar.from": "inferred", "package:tar.to": "inferred", "package:tar.advisories": "inferred", "package:tar.semverSafe": "gateway"},
		RequiredControls: []string{"FIX_WITHIN_SEMVER"}, RequiredGrades: map[string]string{"from": "inferred", "to": "inferred", "advisories": "inferred", "semverSafe": "gateway"},
	}
}

func errOf(v gateway.Verdict) error {
	if v.Verdict == "FAIL_CLOSED" {
		return fmt.Errorf("record not written: %s", v.Reason)
	}
	return nil
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
