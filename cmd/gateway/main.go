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
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

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
}

type service struct {
	cfg      config
	key      ed25519.PrivateKey
	store    *log.Store
	effects  effects.Registry
	mu       sync.Mutex
	gateways map[string]*gateway.Gateway
}

func main() {
	path := flag.String("config", "config.json", "configuration file")
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
	s := &service{cfg: cfg, key: key, store: store, effects: effects.Registry{}, gateways: map[string]*gateway.Gateway{}}
	s.effects.Add(effects.GitHub{SecretsDir: cfg.Secrets})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", s.submit)
	mux.HandleFunc("GET /v1/checkpoint", s.checkpoint)
	mux.HandleFunc("GET /v1/records", s.records)
	mux.HandleFunc("GET /v1/proof", s.proof)
	mux.HandleFunc("GET /v1/key", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"public_key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "issuer": cfg.Issuer})
	})
	fmt.Fprintf(os.Stderr, "control gateway on %s, %d agent(s), store %s%s\n", cfg.Listen, len(cfg.Agents), cfg.Store, map[bool]string{true: ", dry", false: ""}[cfg.Dry])
	fail(http.ListenAndServe(cfg.Listen, mux))
}

// loadKey reads the Ed25519 seed from the secrets directory, making it on first
// use with owner-only permissions. In an enclave this is where the key is
// generated inside and its digest goes into the attestation.
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
	g, err := gateway.Open(gateway.Config{Issuer: s.cfg.Issuer, Agent: agent, Policy: policy.Policy{Grant: a.Grant, PathAware: true}, Store: s.store, Key: s.key})
	if err != nil {
		return nil, err
	}
	s.gateways[agent] = g
	return g, nil
}

type submitRequest struct {
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
	v := g.Submit(req.Action, req.Principal, req.Extension, req.Premises)
	out := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "token": v.Token}
	if v.Allowed() && !s.cfg.Dry {
		adapter, ok := s.effects[req.Action.Kind]
		if !ok {
			out["effect"] = effects.Outcome{Error: effects.ErrNoAdapter.Error()}
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()
			out["effect"] = adapter.Perform(ctx, req.Action)
		}
	}
	if v.Verdict == "FAIL_CLOSED" {
		writeJSON(w, 503, out)
		return
	}
	writeJSON(w, 200, out)
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
