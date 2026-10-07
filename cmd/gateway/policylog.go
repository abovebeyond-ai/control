package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/policy"
)

// policyLogConfig is where the gateway reads the versions of its policy after the one it booted
// with (docs/working-set.md, "The gateway reads its policy"), and whose signatures it takes. It
// sits in the carried configuration, so the keys it trusts are measured into RTMR3 with it.
type policyLogConfig struct {
	// URL answers GET ?after=<version> with {"versions": [token, ...]}, oldest first.
	URL string `json:"url"`
	// Signers: the owner's token keys may sign any version, Elixir's only one that takes away.
	Signers policy.Signers `json:"signers"`
	// State is the file holding the versions applied since the carried configuration.
	State string `json:"state,omitempty"`
}

// pulledExit is the exit status of --pull-policy when it applied a version: the unit that runs
// it then restarts the gateway, whose ExecStartPre measures the version into RTMR3 and takes a
// fresh quote before the first action under it (row 6.1.3).
const pulledExit = 3

type policyState struct {
	Tokens []string `json:"tokens"`
}

func (p *policyLogConfig) statePath() string {
	if p.State != "" {
		return p.State
	}
	return "/var/lib/control/policy-log.json"
}

// carriedBytes is what the first version names as its predecessor: the configuration the
// operator carried, as RTMR3 measures it.
func carriedBytes(cfg config, path string) ([]byte, error) {
	if cfg.CarriedConfig != "" {
		return os.ReadFile(cfg.CarriedConfig)
	}
	return os.ReadFile(path)
}

// bootHead is the head before any version: the grants and systems the gateway booted with.
func bootHead(cfg config, carried []byte) policy.Head {
	agents := make(map[string]policy.HandGrant, len(cfg.Agents))
	for id, a := range cfg.Agents {
		agents[id] = policy.HandGrant{Grant: a.Grant}
	}
	return policy.Head{Version: 0, Hash: policy.HashOf(carried), Agents: agents, Systems: cfg.Systems}
}

// loadChain replays the versions kept on disk from the boot head, each judged again as when it
// arrived. A chain that does not start at this carried configuration belongs to an earlier
// carry-over and is set aside: the carried configuration is the newer word.
func loadChain(cfg config, carried []byte, now time.Time) (policy.Head, []policy.SignedVersion, error) {
	head := bootHead(cfg, carried)
	raw, err := os.ReadFile(cfg.PolicyLog.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return head, nil, nil
	}
	if err != nil {
		return head, nil, err
	}
	var st policyState
	if err := json.Unmarshal(raw, &st); err != nil {
		return head, nil, fmt.Errorf("policy state: %w", err)
	}
	var applied []policy.SignedVersion
	for i, token := range st.Tokens {
		s, err := policy.ParseVersion(token)
		if err == nil && i == 0 && s.Version.Prev != head.Hash {
			fmt.Fprintf(os.Stderr, "policy log: the kept versions follow another carried configuration; serving the carried one\n")
			return head, nil, nil
		}
		if err == nil {
			head, err = policy.Next(head, s, cfg.PolicyLog.Signers, now)
		}
		if err != nil {
			return head, applied, fmt.Errorf("kept version %d: %w", i+1, err)
		}
		applied = append(applied, s)
	}
	return head, applied, nil
}

// withHead is the configuration as the head says it: its grants and systems.
func withHead(cfg config, head policy.Head) config {
	cfg.Agents = make(map[string]struct {
		Grant policy.Grant `json:"grant"`
	}, len(head.Agents))
	for id, a := range head.Agents {
		cfg.Agents[id] = struct {
			Grant policy.Grant `json:"grant"`
		}{Grant: a.Grant}
	}
	cfg.Systems = head.Systems
	return cfg
}

// policyInputs are the applied versions as RTMR3 measures them, after the binary and the
// carried configuration, in the order they were applied.
func policyInputs(applied []policy.SignedVersion) []attest.Input {
	inputs := make([]attest.Input, 0, len(applied))
	for _, s := range applied {
		inputs = append(inputs, attest.InputWithContent("policy-version-"+strconv.Itoa(s.Version.Version), []byte(s.Token)))
	}
	return inputs
}

// pullPolicy asks for the versions after the head, judges each, and keeps those that hold. The
// first that does not stops the pull: the gateway never skips one, so a refused version blocks
// every later one until a version that follows the head arrives.
func pullPolicy(cfg config, carried []byte, client *http.Client, token string, now time.Time) (int, error) {
	head, applied, err := loadChain(cfg, carried, now)
	if err != nil {
		return 0, err
	}
	u, err := url.Parse(cfg.PolicyLog.URL)
	if err != nil {
		return 0, err
	}
	q := u.Query()
	q.Set("after", strconv.Itoa(head.Version))
	u.RawQuery = q.Encode()
	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("policy log answered %d", resp.StatusCode)
	}
	var page struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return 0, fmt.Errorf("policy log: %w", err)
	}
	took := 0
	var refusal error
	for _, t := range page.Versions {
		s, err := policy.ParseVersion(t)
		if err == nil {
			head, err = policy.Next(head, s, cfg.PolicyLog.Signers, now)
		}
		if err != nil {
			refusal = fmt.Errorf("refused: %w", err)
			break
		}
		applied = append(applied, s)
		took++
	}
	if took > 0 {
		st := policyState{}
		for _, s := range applied {
			st.Tokens = append(st.Tokens, s.Token)
		}
		if err := writeAtomic(cfg.PolicyLog.statePath(), st); err != nil {
			return 0, err
		}
	}
	return took, refusal
}

func writeAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// policyClaim names the version the gateway serves, on every record: "v3 sha-256:…", the
// carried configuration being v0.
func policyClaim(head policy.Head) string {
	return "v" + strconv.Itoa(head.Version) + " " + head.Hash
}

// portalToken is the token the gateway already holds for Portal's writes (effects.Portal); the
// policy log is served by Portal to the gateway and to a verifier with access, never in public.
func portalToken(secrets string) string {
	raw, err := os.ReadFile(filepath.Join(secrets, "portal-token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// policy serves the version the gateway judges under, whole: its number, its hash, every hand's
// grant and the systems. Elixir drafts the next version on it and decides whether its change
// only takes away; a reader sees what each record's control_policy names. The same grants are
// readable already, as the attachment beside the first record judged under each.
func (s *service) policy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.head == nil {
		writeJSON(w, 404, map[string]any{"error": "this gateway reads no policy log"})
		return
	}
	writeJSON(w, 200, map[string]any{"version": s.cfg.head.Version, "hash": s.cfg.head.Hash, "agents": s.cfg.head.Agents, "systems": s.cfg.head.Systems})
}
