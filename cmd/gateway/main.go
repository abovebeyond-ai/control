// gateway is the control gateway as a service: hands propose over HTTP, the
// gateway judges, writes the evidence and performs the effect with credentials
// the hands never see. Anchors, witnesses and verifiers read the signed
// checkpoint; nothing of theirs runs here.
//
//	gateway --config config.json
//
// config.json:
//
//	{
//	  "listen": "127.0.0.1:8471",
//	  "issuer": "https://portal.example/control",
//	  "store": "/var/lib/control/store",
//	  "secrets": "/etc/control/secrets",
//	  "agents": {
//	    "did:webvh:...#agent-fix": {
//	      "grant": { "principal": "did:webvh:...", "kinds": ["workflow.dispatch", "pull.open"], "resources": ["owner/repo"], "max_per_kind": 1, "premises_for": ["workflow.dispatch"] }
//	    }
//	  }
//	}
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
)

type config struct {
	Listen  string `json:"listen"`
	Issuer  string `json:"issuer"`
	Store   string `json:"store"`
	Secrets string `json:"secrets"`
	Agents  map[string]struct {
		Grant policy.Grant `json:"grant"`
	} `json:"agents"`
	// Dry means: judge and record, perform nothing. For a first deployment
	// beside an existing hand, so the evidence starts before the credentials move.
	Dry bool `json:"dry"`
	// ClientToken, when set, is what a hand must present as a bearer token to
	// submit. A gateway that is reached from another machine holds credentials
	// and judges within grants; without this, anyone who can reach the port can
	// make it act. The reading endpoints stay open: evidence is for strangers.
	ClientToken string `json:"client_token"`
	// Attestation is "software" (the default: the operator vouches) or "tdx":
	// the gateway asks the hardware for a quote binding its key at start and
	// refuses to run without one. A gateway configured to prove and unable to
	// must not judge, because its evidence would claim what it cannot show.
	Attestation string `json:"attestation"`
}

type service struct {
	cfg      config
	key      ed25519.PrivateKey
	attested *attest.Record
	store    *log.Store
	effects  effects.Registry
	mu       sync.Mutex
	gateways map[string]*gateway.Gateway
}

func main() {
	path := flag.String("config", "config.json", "configuration file")
	attestOnly := flag.Bool("attest", false, "acquire the hardware quote binding the key, write attestation.json beside the store, and exit; run as root before the service drops to its own user")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	fail(err)
	var cfg config
	fail(json.Unmarshal(raw, &cfg))
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8471"
	}
	store, err := log.Open(cfg.Store)
	fail(err)
	key, err := loadKey(filepath.Join(cfg.Secrets, "control-signing.key"))
	fail(err)
	if *attestOnly {
		r, err := acquire(cfg, key)
		fail(err)
		fmt.Fprintf(os.Stderr, "attested on %s via %s, MRTD %s\n", r.Platform, r.Provider, r.MRTD)
		return
	}
	s := &service{cfg: cfg, key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}}
	s.effects.Add(effects.GitHub{SecretsDir: cfg.Secrets})
	s.attested, err = attestation(cfg, key)
	fail(err)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", s.authed(s.submit))
	mux.HandleFunc("GET /v1/agents", s.agents)
	mux.HandleFunc("GET /v1/attachment", s.attachment)
	mux.HandleFunc("GET /v1/checkpoint", s.checkpoint)
	mux.HandleFunc("GET /v1/records", s.records)
	mux.HandleFunc("GET /v1/proof", s.proof)
	mux.HandleFunc("GET /v1/key", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"public_key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "issuer": cfg.Issuer, "platform": s.platform()})
	})
	mux.HandleFunc("GET /v1/attestation", s.attestation)
	fmt.Fprintf(os.Stderr, "control gateway on %s, %d agent(s), store %s, %s%s\n", cfg.Listen, len(cfg.Agents), cfg.Store, s.platform(), map[bool]string{true: ", dry", false: ""}[cfg.Dry])
	fail(http.ListenAndServe(cfg.Listen, mux))
}

// attestation is the hardware's record binding the key when the configuration
// says so: attestation.json beside the store, the one file a stranger needs
// together with the log to check that the key that signed lives in the
// measured environment. A record already there that binds this key is used;
// otherwise the quote is acquired now, which works only as root, because the
// kernel's configfs-tsm creates every report entry root-only (the older
// /dev/tdx_guest device no longer produces quotes on current kernels). The
// service therefore runs `--attest` as root in ExecStartPre and the gateway
// itself, under its own user, only accepts what binds its key.
func attestation(cfg config, key ed25519.PrivateKey) (*attest.Record, error) {
	switch cfg.Attestation {
	case "", "software":
		return nil, nil
	case "tdx":
		if r, err := stored(cfg, key); err == nil {
			return r, nil
		}
		r, err := acquire(cfg, key)
		if err != nil {
			return nil, fmt.Errorf("configured to attest on Intel TDX but cannot: %w", err)
		}
		return r, nil
	}
	return nil, fmt.Errorf("attestation %q: software or tdx", cfg.Attestation)
}

func stored(cfg config, key ed25519.PrivateKey) (*attest.Record, error) {
	raw, err := os.ReadFile(filepath.Join(cfg.Store, "attestation.json"))
	if err != nil {
		return nil, err
	}
	var r attest.Record
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	quoteRaw, err := base64.StdEncoding.DecodeString(r.QuoteB64)
	if err != nil {
		return nil, err
	}
	quote, err := attest.Parse(quoteRaw)
	if err != nil {
		return nil, err
	}
	if !attest.BindsKey(quote, key.Public().(ed25519.PublicKey)) {
		return nil, errors.New("attestation.json binds another key")
	}
	return &r, nil
}

func acquire(cfg config, key ed25519.PrivateKey) (*attest.Record, error) {
	r, err := attest.Acquire(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.Store, "attestation.json"), append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *service) platform() string {
	if s.attested == nil {
		return attest.PlatformSoftware
	}
	return s.attested.Platform
}

func (s *service) attestation(w http.ResponseWriter, r *http.Request) {
	if s.attested == nil {
		writeJSON(w, 404, map[string]any{"platform": attest.PlatformSoftware, "error": "this gateway attests in software: the operator vouches for the measurement"})
		return
	}
	writeJSON(w, 200, s.attested)
}

// loadKey reads the Ed25519 seed from the secrets directory, making it on first
// use with owner-only permissions. Under TDX the seed file lives on the trust
// domain's encrypted disk, the key is made there on first start, and the quote
// binds it: attestation() runs right after this.
func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s does not hold a 32-byte hex seed", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (s *service) gateway(agent string) (*gateway.Gateway, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.gateways[agent]; ok {
		return g, nil
	}
	a, ok := s.cfg.Agents[agent]
	if !ok {
		return nil, errors.New("unknown agent: no grant configured")
	}
	g, err := gateway.Open(gateway.Config{Issuer: s.cfg.Issuer, Agent: agent, Policy: policy.Policy{Grant: a.Grant, PathAware: true}, Store: s.store, Key: s.key, Attestation: s.attested})
	if err != nil {
		return nil, err
	}
	s.gateways[agent] = g
	return g, nil
}

type submitRequest struct {
	Run       string             `json:"run"` // the hand's run; path limits are per run
	Agent     string             `json:"agent"`
	Principal string             `json:"principal"`
	Action    policy.Action      `json:"action"`
	Extension map[string]any     `json:"extension"`
	Premises  *premises.Material `json:"premises"`
}

func (s *service) submit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	g, err := s.gateway(req.Agent)
	if err != nil {
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	if req.Principal == "" {
		req.Principal = s.cfg.Agents[req.Agent].Grant.Principal
	}
	v := g.SubmitIn(req.Run, req.Action, req.Principal, req.Extension, req.Premises)
	if v.Verdict == "FAIL_CLOSED" {
		writeJSON(w, 503, map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "token": v.Token})
		return
	}
	principal := req.Principal
	if principal == "" {
		principal = s.cfg.Agents[req.Agent].Grant.Principal
	}
	// The effect, as performed, is the second record of the action; a refusal or a dry
	// run records that nothing was performed and why, so every action has all three.
	var outcome any
	var effectReason string
	switch {
	case !v.Allowed():
		outcome, effectReason = map[string]any{"performed": false, "why": "refused"}, "not performed: the request was refused"
	case s.cfg.Dry:
		outcome, effectReason = map[string]any{"performed": false, "why": "dry"}, "not performed: dry"
	default:
		adapter, ok := s.effects[req.Action.Kind]
		if !ok {
			o := effects.Outcome{Error: effects.ErrNoAdapter.Error()}
			outcome, effectReason = o, "not performed: "+o.Error
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			o := adapter.Perform(ctx, req.Action)
			cancel()
			outcome = o
			if o.OK {
				effectReason = "effect performed"
			} else {
				effectReason = "effect failed: " + o.Error
			}
		}
	}
	e := g.Follow(req.Run, v.ActionID, gateway.PhaseEffect, req.Action, principal, v.Verdict, effectReason, outcome)
	if e.Verdict == "FAIL_CLOSED" {
		writeJSON(w, 503, map[string]any{"verdict": e.Verdict, "reason": "the effect record could not be written: " + e.Reason, "action": v.ActionID})
		return
	}
	out := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "action": v.ActionID, "token": v.Token, "effect": nil, "steps": []int{v.Step, e.Step}}
	if v.Allowed() && !s.cfg.Dry {
		out["effect"] = outcome
	}
	// The result, as handed back, is the third: its digest covers the answer above.
	answer := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "action": v.ActionID, "effect": outcome}
	rr := g.Follow(req.Run, v.ActionID, gateway.PhaseResult, req.Action, principal, v.Verdict, "result returned", answer)
	if rr.Verdict == "FAIL_CLOSED" {
		writeJSON(w, 503, map[string]any{"verdict": rr.Verdict, "reason": "the result record could not be written: " + rr.Reason, "action": v.ActionID})
		return
	}
	out["steps"] = []int{v.Step, e.Step, rr.Step}
	writeJSON(w, 200, out)
}

// authed refuses a submission without the client token when one is configured.
func (s *service) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.ClientToken != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.ClientToken)) != 1 {
				writeJSON(w, 401, map[string]any{"error": "a client token is required to submit"})
				return
			}
		}
		next(w, r)
	}
}

// agents lists the agents this gateway judges for, so a verifier that reaches
// it over the network knows which chains to ask for.
func (s *service) agents(w http.ResponseWriter, r *http.Request) {
	ids := make([]string, 0, len(s.cfg.Agents))
	for id := range s.cfg.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	writeJSON(w, 200, map[string]any{"agents": ids, "platform": s.platform(), "dry": s.cfg.Dry})
}

// attachment serves what was written beside a record: the premises material,
// the action. A verifier replays the premises from it.
func (s *service) attachment(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	if _, ok := s.cfg.Agents[agent]; !ok {
		writeJSON(w, 404, map[string]any{"error": "unknown agent"})
		return
	}
	step, err := strconv.Atoi(r.URL.Query().Get("step"))
	name := r.URL.Query().Get("name")
	if err != nil || (name != "premises" && name != "action") {
		writeJSON(w, 400, map[string]any{"error": "step must be a number and name premises or action"})
		return
	}
	var data any
	found, err := s.store.Attachment(agent, step, name, &data)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if !found {
		writeJSON(w, 404, map[string]any{"error": "no such attachment"})
		return
	}
	writeJSON(w, 200, data)
}

func (s *service) checkpoint(w http.ResponseWriter, r *http.Request) {
	g, err := s.gateway(r.URL.Query().Get("agent"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	cp, err := g.Checkpoint()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, cp)
}

func (s *service) records(w http.ResponseWriter, r *http.Request) {
	agent := r.URL.Query().Get("agent")
	if _, ok := s.cfg.Agents[agent]; !ok {
		writeJSON(w, 404, map[string]any{"error": "unknown agent"})
		return
	}
	records, err := s.store.Records(agent)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	from, _ := strconv.Atoi(r.URL.Query().Get("from"))
	if from < 0 || from > len(records) {
		from = 0
	}
	writeJSON(w, 200, map[string]any{"agent": agent, "from": from, "records": records[from:]})
}

func (s *service) proof(w http.ResponseWriter, r *http.Request) {
	g, err := s.gateway(r.URL.Query().Get("agent"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	step, err := strconv.Atoi(r.URL.Query().Get("step"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "step must be a number"})
		return
	}
	proof, size, root, err := g.InclusionProof(step)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"step": step, "tree_size": size, "root": root, "proof": proof})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
