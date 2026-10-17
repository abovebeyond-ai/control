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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/effects"
	"github.com/abovebeyond-ai/control/evidence"
	"github.com/abovebeyond-ai/control/gateway"
	"github.com/abovebeyond-ai/control/log"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/premises"
	"github.com/abovebeyond-ai/control/registry"
	"github.com/abovebeyond-ai/control/relying"
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
	// Release names this gateway's own build, "v0.11.0 sha256:…", written by the boot
	// script from what it installed; every record carries it as control_gateway.
	Release string `json:"release"`
	// CarriedConfig is the file holding the configuration the operator carried, as the
	// attribute bytes: measured into RTMR3 before the quote (since v0.15.0), so a
	// reader can hold the quote to the policy the machine booted with.
	CarriedConfig string `json:"carried_config,omitempty"`
	// VeraBase is the Vera app the review hand publishes to (default https://vera.abovebeyond.ai).
	VeraBase string `json:"vera_base,omitempty"`
	// Reviewer is the GitHub login the gateway asks to review every pull request it opens
	// (since v0.24.1). With the App as author, a pull request no longer shows under the
	// owner's own pull requests; on 16 September 2026 two of them sat unnoticed for that
	// reason. A review request puts them where the owner looks, and it is the form GitHub
	// gives the person in the loop. Empty means: ask nobody.
	Reviewer string `json:"reviewer,omitempty"`
	// Systems maps a running system's resource to its base URL ("stocklist:platform":
	// "https://traders.stocklistdealer.eu"): where an action on it is carried, its evidence
	// attached, for the system to verify itself (docs/mandates.md). An address, not a secret.
	Systems map[string]string `json:"systems,omitempty"`
	// PolicyLog, when set, is where the gateway reads the signed versions of its grants after
	// this configuration (docs/working-set.md): forward only, a widening on the owner's token, a
	// narrowing from Elixir, each measured into RTMR3 before it is served.
	PolicyLog *policyLogConfig `json:"policy_log,omitempty"`
	// Revocations, when set, is where the gateway reads the capabilities the owner ended
	// before they expired (revoked.go); an action under one is refused.
	Revocations *revokedConfig `json:"revocations,omitempty"`
	// Orgs pins the root key of each organisation whose people speak for a hand (a grant's
	// org): the Ed25519 public key in hex at the start of every registry chain (docs/odoo-gate.md).
	Orgs map[string]string `json:"orgs,omitempty"`
	// Passkey is the relying party those people's passkeys are made for: its RP ID and the
	// origins an assertion may come from.
	Passkey capability.Party `json:"passkey,omitempty"`
	// RelayURL is where a write waiting for a person's word is announced (POST /api/requests);
	// RELAY_URL in the environment when this is empty, and nobody is told when both are.
	RelayURL string `json:"relay_url,omitempty"`
	// Odoo maps an instance, the first part of an odoo:<instance>/<model> resource, to its
	// address and database; its API key is odoo-key-<instance> in the secrets.
	Odoo map[string]effects.OdooInstance `json:"odoo,omitempty"`
	// AuditEnc is the organisation's audit key: every sealed receipt is sealed a second time to
	// it, under "<org>#audit", so the organisation's trail does not hang on one phone
	// (receipts.go). Its private half is the organisation's, never the operator's.
	AuditEnc *registry.EncKey `json:"audit_enc,omitempty"`

	// The versions applied since this configuration, and the head they lead to; read at start.
	applied []policy.SignedVersion
	head    *policy.Head
}

// defined are the kinds the served version defines (docs/kinds.md); none without a policy log.
func (c config) defined() policy.Kinds {
	if c.head == nil {
		return nil
	}
	return c.head.Kinds
}

// kinds is the table the gateway judges and performs by: the built-in kinds and the defined.
func (c config) kinds() policy.Kinds { return policy.Builtin.With(c.defined()) }

// orgKeys are the pinned root keys by organisation, and an error when one is not a key or a
// grant names an organisation without one, or without a relying party for its passkeys.
func (c config) orgKeys() (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for org, h := range c.Orgs {
		pub, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("orgs: the root key of %s is not 32 bytes of hex", org)
		}
		out[org] = ed25519.PublicKey(pub)
	}
	for agent, a := range c.Agents {
		org := a.Grant.Org
		if org == "" {
			continue
		}
		if _, ok := out[org]; !ok {
			return nil, fmt.Errorf("%s: the grant listens to %s, and no root key is pinned for it under orgs", agent, org)
		}
		if c.Passkey.RPID == "" || len(c.Passkey.Origins) == 0 {
			return nil, fmt.Errorf("%s: the grant listens to %s, and passkey names no rp_id and origins", agent, org)
		}
	}
	return out, nil
}

type service struct {
	cfg      config
	key      ed25519.PrivateKey
	attested *attest.Record
	store    *log.Store
	effects  effects.Registry
	mu       sync.Mutex
	gateways map[string]*gateway.Gateway
	revoked  *revokedList
	// The writes waiting for a person's word (pending.go).
	pendMu  sync.Mutex
	pending map[string]*pendingWord
	// allowMu holds a daily allowance's read, check and add together (settle).
	allowMu sync.Mutex
	// receipts is the outbox of sealed receipts (receipts.go); nil sends none.
	receipts *outbox
}

func main() {
	path := flag.String("config", "config.json", "configuration file")
	attestOnly := flag.Bool("attest", false, "acquire the hardware quote binding the key, write attestation.json beside the store, and exit; run as root before the service drops to its own user")
	pullOnly := flag.Bool("pull-policy", false, "read the policy versions after the one served, keep those that hold, and exit 3 when one was applied (the unit then restarts the gateway)")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	fail(err)
	var cfg config
	fail(json.Unmarshal(raw, &cfg))
	if cfg.PolicyLog != nil {
		carried, err := carriedBytes(cfg, *path)
		fail(err)
		if *pullOnly {
			took, err := pullPolicy(cfg, carried, &http.Client{Timeout: 30 * time.Second}, portalToken(cfg.Secrets), time.Now())
			if err != nil {
				fmt.Fprintf(os.Stderr, "policy log: %v\n", err)
			}
			if took > 0 {
				fmt.Fprintf(os.Stderr, "policy log: applied %d version(s)\n", took)
				os.Exit(pulledExit)
			}
			return
		}
		// A kept version that no longer holds stops the replay there: the gateway serves the
		// last version that did, and says why.
		head, applied, err := loadChain(cfg, carried, time.Now())
		if errors.Is(err, errPolicyState) {
			fail(err)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy log: %v\n", err)
		}
		cfg = withHead(cfg, head)
		cfg.applied, cfg.head = applied, &head
	} else if *pullOnly {
		return
	}
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
	if cfg.Revocations != nil {
		s.revoked = newRevokedList(time.Now)
		s.revoked.follow(*cfg.Revocations, portalToken(cfg.Secrets))
	}
	s.effects.Add(effects.GitHub{SecretsDir: cfg.Secrets, Reviewer: cfg.Reviewer})
	s.effects.Add(effects.Vera{SecretsDir: cfg.Secrets, Base: cfg.VeraBase})
	s.effects.Add(effects.Portal{SecretsDir: cfg.Secrets})
	s.effects.Add(effects.Forge{SecretsDir: cfg.Secrets})
	s.effects.Add(effects.System{Bases: cfg.Systems, Table: cfg.kinds()})
	s.effects.Add(effects.Odoo{SecretsDir: cfg.Secrets, Instances: cfg.Odoo})
	_, err = cfg.orgKeys()
	fail(err)
	s.attested, err = attestation(cfg, key)
	fail(err)
	// Every agent's chain is opened now, not at its first request: an action the last
	// run was stopped in the middle of gets its closing records at boot.
	for agent := range cfg.Agents {
		if _, err := s.gateway(agent); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", agent, err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/submit", s.authed(s.submit))
	mux.HandleFunc("POST /v1/pending/{id}/word", s.authed(s.word))
	mux.HandleFunc("POST /v1/pending/{id}/refuse", s.authed(s.refuse))
	mux.HandleFunc("GET /v1/pending/{id}", s.authed(s.pendingState))
	go s.sweepPending(time.Minute)
	s.receipts = &outbox{kick: make(chan struct{}, 1)}
	go s.deliverReceipts()
	mux.HandleFunc("GET /v1/github/read-token", s.authed(s.readToken))
	mux.HandleFunc("GET /v1/agents", s.accessed("agents", s.agents))
	mux.HandleFunc("GET /v1/policy", s.accessed("policy", s.policy))
	mux.HandleFunc("GET /v1/attachment", s.accessed("attachment", s.attachment))
	mux.HandleFunc("GET /v1/checkpoint", s.accessed("checkpoint", s.checkpoint))
	mux.HandleFunc("GET /v1/checkpoints", s.accessed("checkpoints", s.checkpoints))
	mux.HandleFunc("GET /v1/consistency", s.accessed("consistency", s.consistency))
	mux.HandleFunc("GET /v1/records", s.accessed("records", s.records))
	mux.HandleFunc("GET /v1/proof", s.accessed("proof", s.proof))
	// The seal key of the review hand (#vera) is made now, so the register can name it
	// before the first review is sealed; it is published beside the gateway's own key.
	veraKey, err := effects.Vera{SecretsDir: cfg.Secrets}.SealKey()
	fail(err)
	mux.HandleFunc("GET /v1/key", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"public_key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "issuer": cfg.Issuer, "platform": s.platform(),
			"keys": map[string]string{"control-gateway": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "vera": hex.EncodeToString(veraKey.Public().(ed25519.PublicKey))}})
	})
	mux.HandleFunc("GET /v1/attestation", s.accessed("attestation", s.attestation))
	mux.HandleFunc("GET /v1/attestations", s.accessed("attestations", s.attestations))
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

// rtmr3Inputs: the running binary and the carried configuration, when there is one.
func rtmr3Inputs(cfg config) []attest.Input {
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return nil
	}
	inputs := []attest.Input{attest.InputOf("control-gateway-linux-amd64", exe)}
	if cfg.CarriedConfig != "" {
		if raw, err := os.ReadFile(cfg.CarriedConfig); err == nil {
			inputs = append(inputs, attest.InputWithContent("carried-config", raw))
		}
	}
	// Then every policy version applied since, in order: the quote taken after a new version
	// covers what the gateway serves, not only what it booted with (row 6.1.3).
	return append(inputs, policyInputs(cfg.applied)...)
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
	// Our own layer first (since v0.15.0): the binary that will serve and the
	// configuration the operator carried go into RTMR3 before the quote is taken, so
	// the quote itself binds the release. A kernel without the door, or a register
	// that holds something else, leaves the record without inputs, and the verifier
	// says so; the quote is still taken.
	inputs := rtmr3Inputs(cfg)
	measured := false
	if len(inputs) > 0 {
		if err := attest.ExtendRTMR3(inputs); err != nil {
			fmt.Fprintf(os.Stderr, "RTMR3 not extended: %v\n", err)
		} else {
			measured = true
		}
	}
	r, err := attest.Acquire(key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if measured {
		r.RTMR3Inputs = inputs
	}
	r.Release = cfg.Release
	r.WithBootLog()
	raw, _ := json.MarshalIndent(r, "", "  ")
	if err := os.WriteFile(filepath.Join(cfg.Store, "attestation.json"), append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	// Every quote is kept, named by its digest: a checkpoint anchored under an earlier
	// quote (the daily retake, a reboot) must remain resolvable, or the anchor could not
	// be checked against the attestation it committed to (found on 10 September 2026:
	// two reboots after an anchor, and the anchored quote was gone).
	if quote, err := base64.StdEncoding.DecodeString(r.QuoteB64); err == nil {
		dir := filepath.Join(cfg.Store, "attestations")
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, canonical.SHA256(quote)+".json"), append(raw, '\n'), 0o644)
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
	if d := r.URL.Query().Get("digest"); d != "" {
		// An earlier quote by its digest, for an anchor that committed to it.
		_, hexDigest, err := canonical.UntagAny(d)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "digest must be a tagged sha-256"})
			return
		}
		raw, err := os.ReadFile(filepath.Join(s.cfg.Store, "attestations", hexDigest+".json"))
		if err != nil {
			writeJSON(w, 404, map[string]any{"error": "no attestation with that digest is kept here"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	}
	if s.attested == nil {
		writeJSON(w, 404, map[string]any{"platform": attest.PlatformSoftware, "error": "this gateway attests in software: the operator vouches for the measurement"})
		return
	}
	writeJSON(w, 200, s.attested)
}

// attestations lists the digests of every quote kept, oldest file first.
func (s *service) attestations(w http.ResponseWriter, r *http.Request) {
	entries, _ := os.ReadDir(filepath.Join(s.cfg.Store, "attestations"))
	out := []string{}
	for _, e := range entries {
		if n := strings.TrimSuffix(e.Name(), ".json"); n != e.Name() {
			out = append(out, canonical.Tag(n))
		}
	}
	writeJSON(w, 200, map[string]any{"attestations": out})
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
	served := ""
	if s.cfg.head != nil {
		served = policyClaim(*s.cfg.head)
	}
	orgs, err := s.cfg.orgKeys()
	if err != nil {
		return nil, err
	}
	gcfg := gateway.Config{Issuer: s.cfg.Issuer, Agent: agent, Policy: policy.Policy{Grant: a.Grant, PathAware: true, Defined: s.cfg.defined()}, Store: s.store, Key: s.key, Attestation: s.attested, Release: s.cfg.Release, PolicyVersion: served,
		Orgs: orgs, Passkey: s.cfg.Passkey}
	if s.revoked != nil {
		gcfg.Revoked = s.revoked.Revoked
	}
	g, err := gateway.Open(gcfg)
	if err != nil {
		return nil, err
	}
	s.gateways[agent] = g
	return g, nil
}

type submitRequest struct {
	Run        string             `json:"run"`        // the hand's run; path limits are per run
	Capability string             `json:"capability"` // the principal's token for this task, when the grant asks for one
	Agent      string             `json:"agent"`
	Principal  string             `json:"principal"`
	Action     policy.Action      `json:"action"`
	Extension  map[string]any     `json:"extension"`
	Premises   *premises.Material `json:"premises"`
	// Files of a branch.push: the runner's change, handed back instead of pushed. Bound to
	// the judged parameters by params.files_sha256, checked before the judgement so a
	// refusal names a mismatch, and kept beside the record as the material was.
	Files []effects.FileChange `json:"files,omitempty"`
	// Agbom is the hand's bill of materials in force for this step (C1.2 of the standard):
	// what software, which commit, which runner, which model if any. Its canonical digest
	// is the record's agbom_digest; the document is kept beside the record so the digest
	// resolves to a manifest, as row 1.1.1 asks.
	Agbom map[string]any `json:"agbom,omitempty"`
	// Chain is the registry chain behind a passkey capability, root first, under a grant that
	// names an organisation; Holder, the person to ask for a word when the grant's default
	// (Grant.Asks) is not the one (docs/odoo-gate.md).
	Chain  []string `json:"chain,omitempty"`
	Holder string   `json:"holder,omitempty"`
	// asked is the holder whose word was asked for this action, set when a waiting write is
	// decided (pending.go); the receipt says so and goes to them.
	asked string
}

// maxSubmission is what one submission may weigh. Eight MiB was the first number, sized for
// a branch.push with its lockfiles. A review page is a different animal: Vera's paper page is
// 8.4 MB of HTML with its readings, which is 11.2 MB once it travels as base64 inside the
// JSON, and the gateway refused it with "request body too large" on 13 September 2026, the
// evening Vera became a hand. The limit exists to keep a sealed machine from being filled by
// whoever can reach the port, so it stays, at a size that fits the work the hands actually do.
const maxSubmission = 32 << 20

func (s *service) submit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSubmission))
	if err != nil {
		// A body over the limit reads as a network error unless it is named; a hand that
		// cannot tell "too large" from "connection lost" retries what will never fit.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, 413, map[string]any{"error": fmt.Sprintf("the submission is larger than %d MiB", maxSubmission>>20)})
			return
		}
		writeJSON(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	var req submitRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	// The hand's signature over exactly these bytes, hex, in Control-Signature.
	var signature []byte
	if h := r.Header.Get("Control-Signature"); h != "" {
		if signature, err = hex.DecodeString(h); err != nil {
			writeJSON(w, 400, map[string]any{"error": "Control-Signature is not hex"})
			return
		}
	}
	g, err := s.gateway(req.Agent)
	if err != nil {
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	if req.Principal == "" {
		req.Principal = s.cfg.Agents[req.Agent].Grant.Principal
	}
	// A push binds its files, a publication its page, a share its document, an expense its
	// invoice, to the judged parameters by digest before any judgement: what does not match is
	// refused unrecorded. The kind table names the parameter (Kind.Files), so a kind that takes
	// files cannot be added without saying so: the first share on 13 October 2026 was judged
	// and allowed, and the adapter found no file, because a list here did not name the kind.
	kind := s.cfg.kinds()[req.Action.Kind]
	_, mustBind := kind.Required[kind.Files]
	if param := kind.Files; param != "" && (mustBind || len(req.Files) > 0 || req.Action.Params[param] != nil) {
		want, _ := req.Action.Params[param].(string)
		got, _ := effects.FilesDigest(req.Files)
		if len(req.Files) == 0 || want == "" || got != want {
			writeJSON(w, 400, map[string]any{"error": req.Action.Kind + " needs the files attached and params." + param + " equal to their canonical digest"})
			return
		}
		if req.Action.Attached == nil {
			req.Action.Attached = map[string]any{}
		}
		req.Action.Attached["files"] = req.Files
	}
	if req.Agbom != nil {
		digest, err := canonical.Digest(req.Agbom)
		if err != nil {
			writeJSON(w, 400, map[string]any{"error": "the bill of materials cannot be canonicalised: " + err.Error()})
			return
		}
		if req.Extension == nil {
			req.Extension = map[string]any{}
		}
		req.Extension["agbom_digest"] = canonical.Tag(digest)
	}
	// A write that needs a person's word and came without one waits for it (pending.go).
	if s.asksWord(w, g, req, body, signature) {
		return
	}
	v := g.SubmitChained(req.Run, req.Action, req.Principal, req.Extension, req.Premises, body, signature, req.Capability, req.Chain)
	status, out := s.settle(r.Context(), g, req, v)
	writeJSON(w, status, out)
}

// settle is what follows a judgement: what the hand handed in kept beside the request record,
// the effect performed when allowed, and the effect and result records, so every action has
// all three. It answers the status and the body the hand receives.
func (s *service) settle(ctx context.Context, g *gateway.Gateway, req submitRequest, v gateway.Verdict) (int, map[string]any) {
	if v.Verdict == "FAIL_CLOSED" {
		return 503, map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "token": v.Token}
	}
	if req.Agbom != nil {
		if err := s.store.Attach(req.Agent, v.Step, "agbom", req.Agbom); err != nil {
			return 503, map[string]any{"verdict": "FAIL_CLOSED", "reason": "the bill of materials could not be kept beside the record: " + err.Error(), "step": v.Step}
		}
	}
	if req.Capability != "" && v.Allowed() {
		// The capability as presented, beside the record that names its digest: a stranger
		// can then re-verify the principal's word against the key the identity log publishes,
		// instead of taking the gateway's verification on trust (row 4.1.6: the exact content
		// the human approved is the capability's own payload). A passkey word comes with the
		// registry chain that vouches for its key, kept with it for the same reason.
		kept := map[string]any{"capability": req.Capability}
		if len(req.Chain) > 0 {
			kept["chain"] = req.Chain
		}
		if err := s.store.Attach(req.Agent, v.Step, "capability", kept); err != nil {
			return 503, map[string]any{"verdict": "FAIL_CLOSED", "reason": "the capability could not be kept beside the record: " + err.Error(), "step": v.Step}
		}
	}
	if len(req.Files) > 0 {
		// What was pushed, beside the record that allowed it, as the working is.
		if err := s.store.Attach(req.Agent, v.Step, "files", req.Files); err != nil {
			return 503, map[string]any{"verdict": "FAIL_CLOSED", "reason": "the files could not be kept beside the record: " + err.Error(), "step": v.Step}
		}
	}
	principal := req.Principal
	if principal == "" {
		principal = s.cfg.Agents[req.Agent].Grant.Principal
	}
	if v.Signer != nil {
		// The person whose word allowed it, as the request record names them.
		principal = v.Signer.ID
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
			ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			// The far end gets the evidence with the effect (row 8.3.5): a dispatch
			// carries the signed record and the capability as inputs, a pull request
			// carries them in its footer, so a runner or a merge check can refuse
			// what nobody judged. The hand's parameters stay as recorded; this is
			// the gateway's own addition, and the outcome names it.
			kind := s.cfg.kinds()[req.Action.Kind]
			// A signer with a daily allowance: the day's sum is read, held and added under one
			// lock, so two writes at once cannot both fit in what is left for one.
			day, spent, dayErr := "", int64(0), error(nil)
			if kind.Adapter == policy.OdooAdapter && v.Signer != nil && v.Signer.DailyEUR > 0 {
				s.allowMu.Lock()
				day = log.AllowanceDay(time.Now())
				spent, dayErr = s.store.SpentOn(v.Signer.ID, day)
			}
			var o effects.Outcome
			if dayErr != nil {
				o = effects.Outcome{Error: "the day's allowance could not be read: " + dayErr.Error()}
			} else {
				o = adapter.Perform(ctx, withOdooAgent(withCeiling(withEvidence(req.Action, kind.Adapter, v.Token, req.Capability), kind.Adapter, v.Signer, spent), kind.Adapter, req.Agent))
			}
			cancel()
			outcome = o
			if o.OK {
				effectReason = "effect performed"
			} else {
				effectReason = "effect failed: " + o.Error
			}
			if day != "" {
				if o.OK && o.Counted != 0 {
					if err := s.store.AddSpent(v.Signer.ID, day, o.Counted, v.ActionID); err != nil {
						effectReason += "; the day's allowance could not be updated: " + err.Error()
					}
				}
				s.allowMu.Unlock()
			}
		}
	}
	e := g.Follow(req.Run, v.ActionID, gateway.PhaseEffect, req.Action, principal, v.Verdict, effectReason, outcome)
	if e.Verdict == "FAIL_CLOSED" {
		return 503, map[string]any{"verdict": e.Verdict, "reason": "the effect record could not be written: " + e.Reason, "action": v.ActionID}
	}
	out := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "action": v.ActionID, "token": v.Token, "effect": nil, "steps": []int{v.Step, e.Step}}
	if v.Allowed() && !s.cfg.Dry {
		out["effect"] = handed(outcome)
	}
	// The result, as handed back, is the third: its digest covers the answer above, with what
	// an outcome keeps private named by its digest only.
	answer := map[string]any{"verdict": v.Verdict, "reason": v.Reason, "step": v.Step, "action": v.ActionID, "effect": outcome}
	rr := g.Follow(req.Run, v.ActionID, gateway.PhaseResult, req.Action, principal, v.Verdict, "result returned", answer)
	if rr.Verdict == "FAIL_CLOSED" {
		return 503, map[string]any{"verdict": rr.Verdict, "reason": "the result record could not be written: " + rr.Reason, "action": v.ActionID}
	}
	out["steps"] = []int{v.Step, e.Step, rr.Step}
	s.receipt(g, req, []gateway.Verdict{v, e, rr}, outcome)
	return 200, out
}

// handed is the outcome as the hand receives it: with what it keeps off the record (the rows
// of a read) put back beside the detail.
func handed(outcome any) any {
	o, ok := outcome.(effects.Outcome)
	if !ok || o.Private == nil {
		return outcome
	}
	out := map[string]any{"ok": o.OK}
	if o.Detail != nil {
		out["detail"] = o.Detail
	}
	if o.Error != "" {
		out["error"] = o.Error
	}
	for k, v := range o.Private {
		out[k] = v
	}
	return out
}

// withCeiling adds to an Odoo action the ceiling of the person whose word allowed it, from the
// registry entry the gateway verified: the adapter holds the order's total to it, and refuses
// a write that comes without one. When the entry has a daily allowance, that and what the
// signer's orders came to today (cents) come along, and the adapter holds the day to it too.
func withCeiling(a policy.Action, adapter string, signer *registry.Entry, spentToday int64) policy.Action {
	if adapter != policy.OdooAdapter || signer == nil {
		return a
	}
	params := map[string]any{}
	for k, v := range a.Params {
		params[k] = v
	}
	params[effects.OdooCeilingParam] = signer.CeilingEUR
	if signer.DailyEUR > 0 {
		params[effects.OdooDailyParam] = signer.DailyEUR
		params[effects.OdooSpentParam] = spentToday
		params[effects.OdooSignerParam] = signer.ID
	}
	return policy.Action{Kind: a.Kind, Resource: a.Resource, Params: params, Classification: a.Classification, Attached: a.Attached}
}

// withOdooAgent adds to an Odoo action which agent it acts for: the fragment of the agent's
// identifier, lower case. The adapter then calls Odoo as that agent's own user when Acme gave it
// one, so Odoo itself shows which agent did what (effects.OdooAgentParam).
func withOdooAgent(a policy.Action, adapter, agent string) policy.Action {
	if adapter != policy.OdooAdapter {
		return a
	}
	_, frag, ok := strings.Cut(agent, "#")
	if !ok || frag == "" {
		return a
	}
	params := map[string]any{}
	for k, v := range a.Params {
		params[k] = v
	}
	params[effects.OdooAgentParam] = strings.ToLower(frag)
	return policy.Action{Kind: a.Kind, Resource: a.Resource, Params: params, Classification: a.Classification, Attached: a.Attached}
}

// accessed writes an access record for every read of evidence (row 7.6.4): what
// was asked, by which address, when. Reading stays open; it is no longer silent.
func (s *service) accessed(what string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		info := map[string]any{"read": what, "from": r.RemoteAddr, "agent": q.Get("agent")}
		if v := q.Get("step"); v != "" {
			info["step"] = v
		}
		if v := q.Get("name"); v != "" {
			info["name"] = v
		}
		if v := q.Get("from"); v != "" {
			info["records_from"] = v
		}
		if err := s.store.RecordAccess(info); err != nil {
			_ = s.store.RecordFailure(map[string]any{"error": "access not recorded: " + err.Error(), "read": what})
		}
		next(w, r)
	}
}

// withEvidence adds the signed request record and the capability to the effect
// the far end receives: as workflow inputs for a dispatch, as a footer for a pull
// request. Other kinds carry nothing extra.
func withEvidence(a policy.Action, adapter string, tok evidence.Token, capTok string) policy.Action {
	params := map[string]any{}
	for k, v := range a.Params {
		params[k] = v
	}
	switch a.Kind {
	case "workflow.dispatch":
		inputs := map[string]any{}
		if in, ok := params["inputs"].(map[string]any); ok {
			for k, v := range in {
				inputs[k] = v
			}
		}
		inputs["evidence"] = relying.EncodeToken(tok)
		inputs["capability"] = capTok
		params["inputs"] = inputs
	case "pull.open":
		body, _ := params["body"].(string)
		params["body"] = body + relying.Footer(relying.EncodeToken(tok), capTok)
	case "branch.push":
		// The commit message carries the same footer as a pull request body: the record
		// and the capability that allowed this change to exist.
		message, _ := params["message"].(string)
		params["message"] = message + relying.Footer(relying.EncodeToken(tok), capTok)
	case "issue.open":
		// An issue the gateway opened says so, like a pull request does: the record and the
		// capability in the footer, so a reader can tell a mirrored finding from a human one.
		body, _ := params["body"].(string)
		params["body"] = body + relying.Footer(relying.EncodeToken(tok), capTok)
	}
	if adapter == "portal" || adapter == policy.SystemAdapter {
		// Portal and a running system take the record and the capability as headers on the
		// write (Control-Evidence, Control-Capability); the adapter reads them from here.
		params["evidence"] = relying.EncodeToken(tok)
		params["capability"] = capTok
	}
	return policy.Action{Kind: a.Kind, Resource: a.Resource, Params: params, Classification: a.Classification, Attached: a.Attached}
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

// readToken hands the box a read-only GitHub token for one owner, minted from the App
// (effects.GitHub.ReadToken). Behind the client token like a submission; not an effect,
// so not judged and not recorded. The owner must be one the grants name: the gateway
// mints for the fleet it serves, not for any account the App happens to be installed on.
func (s *service) readToken(w http.ResponseWriter, r *http.Request) {
	owner := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("owner")))
	if owner == "" {
		writeJSON(w, 400, map[string]any{"error": "owner is required"})
		return
	}
	known := false
	for _, a := range s.cfg.Agents {
		for _, res := range a.Grant.Resources {
			if o, _, ok := strings.Cut(res, "/"); ok && strings.ToLower(o) == owner && !strings.HasPrefix(res, "vera/") {
				known = true
			}
		}
	}
	if !known {
		writeJSON(w, 403, map[string]any{"error": "no grant names a repository of " + owner})
		return
	}
	gh, ok := s.effects.GitHub()
	if !ok {
		writeJSON(w, 501, map[string]any{"error": "no GitHub adapter"})
		return
	}
	token, expires, err := gh.ReadToken(r.Context(), owner)
	if err != nil {
		writeJSON(w, 502, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"owner": owner, "token": token, "expires_at": expires.UTC().Format(time.RFC3339), "permissions": effects.ReadPermissions})
}

// agents lists the agents this gateway judges for, so a verifier that reaches
// it over the network knows which chains to ask for.
func (s *service) agents(w http.ResponseWriter, r *http.Request) {
	ids := make([]string, 0, len(s.cfg.Agents))
	for id := range s.cfg.Agents {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// And what each one may touch, as a digest. A gateway carries the configuration it was
	// given until an operator carries over a new one, and nothing told the hands which
	// version that was: on 14 September 2026 a new project sat in the configuration on the
	// box for an hour while the VM still served the grant from before it, and the only sign
	// was a hand being refused with "resource not in grant". A digest per grant is enough to
	// see the difference and says nothing a reader of the records could not already see.
	grants := make(map[string]any, len(ids))
	for _, id := range ids {
		grants[id] = map[string]any{
			"kinds":     digestOf(s.cfg.Agents[id].Grant.Kinds),
			"resources": digestOf(s.cfg.Agents[id].Grant.Resources),
		}
	}
	// And the kind table (docs/kinds.md): every kind this gateway performs, its schema, adapter,
	// radius and words, the built-in and the defined, so Portal, Elixir and the hand read one
	// table instead of keeping their own.
	out := map[string]any{"agents": ids, "grants": grants, "kinds": s.kindTable(), "platform": s.platform(), "dry": s.cfg.Dry, "failures": s.store.Failures()}
	// The version served, so Elixir drafts the next one on it and a reader sees which it is.
	if s.cfg.head != nil {
		out["policy"] = map[string]any{"version": s.cfg.head.Version, "hash": s.cfg.head.Hash, "formats": policy.Formats, "fields": policy.Fields}
	}
	writeJSON(w, 200, out)
}

// kindTable is the kind table as served: each kind with where its definition comes from, the
// release or the policy version.
func (s *service) kindTable() map[string]any {
	defined := s.cfg.defined()
	out := map[string]any{}
	for k, v := range s.cfg.kinds() {
		source := "release"
		if _, ok := defined[k]; ok {
			source = "policy"
		}
		out[k] = struct {
			policy.Kind
			Source string `json:"source"`
		}{v, source}
	}
	return out
}

// digestOf names a set without spelling it out: sorted, newline-joined, sha-256. Anyone
// holding the same list computes the same digest, and nobody learns the list from it.
func digestOf(values []string) string {
	sorted := append([]string{}, values...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))

	return "sha-256:" + hex.EncodeToString(sum[:])
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
	if err != nil || (name != "premises" && name != "action" && name != "outcome" && name != "grant" && name != "capability") {
		writeJSON(w, 400, map[string]any{"error": "step must be a number and name one of premises, action, outcome, grant, capability"})
		return
	}
	var data any
	found, err := s.store.Attachment(agent, step, name, &data)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	// A capability is served only when it is a passkey word (wa1) with its chain: what a
	// receipt needs to show who allowed the act. Other tokens stay beside the record unserved.
	if found && name == "capability" {
		kept, _ := data.(map[string]any)
		tok, _ := kept["capability"].(string)
		found = strings.HasPrefix(tok, "wa1.")
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

// checkpoints is GET /v1/checkpoints?agent=&after=N: the signed checkpoint at the end of every
// action after tree size N, and the current one, at most 500. An anchor takes these and needs
// no record: every sealed receipt names one of them.
func (s *service) checkpoints(w http.ResponseWriter, r *http.Request) {
	g, err := s.gateway(r.URL.Query().Get("agent"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	if after < 0 {
		after = 0
	}
	cps, err := g.ActionEnds(after, 500)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if cps == nil {
		cps = []gateway.Checkpoint{}
	}
	writeJSON(w, 200, map[string]any{"agent": r.URL.Query().Get("agent"), "after": after, "checkpoints": cps})
}

// consistency is GET /v1/consistency?agent=&m=&n=: the proof that the tree of size n extends
// the tree of size m, so an anchor holds the gate to an append-only log without its records.
func (s *service) consistency(w http.ResponseWriter, r *http.Request) {
	g, err := s.gateway(r.URL.Query().Get("agent"))
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	m, err1 := strconv.Atoi(r.URL.Query().Get("m"))
	n, err2 := strconv.Atoi(r.URL.Query().Get("n"))
	if err1 != nil || err2 != nil {
		writeJSON(w, 400, map[string]any{"error": "m and n are tree sizes"})
		return
	}
	proof, err := g.Consistency(m, n)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": err.Error()})
		return
	}
	if proof == nil {
		proof = []string{}
	}
	writeJSON(w, 200, map[string]any{"m": m, "n": n, "proof": proof})
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
