package main

// The gateway in Google Confidential Space (attestation "confidential-space"). The image holds
// the binary and the configuration, so the image digest Google signs into the attestation token
// covers the policy too. What differs from a gateway on its own machine:
//
//   - the record key is made in memory at start and never written: a restart is a new key, a
//     new log, and a new token binding it; the organisation signs its gate entry again;
//   - the launcher gives the token (POST /v1/token on its unix socket), with the hex SHA-256 of
//     the record key as its nonce, and the gateway takes a new one every day;
//   - the Odoo keys come from the organisation, sealed to a key the record key signs
//     (provision.go), and stay in memory;
//   - the launcher writes the container's environment into the attestation token, which is
//     public, so no secret goes there: the client token comes as its SHA-256
//     (CLIENT_TOKEN_SHA256, which the launch policy lets the operator set), and the relay token
//     is provisioned like the Odoo keys, by the relay's operator (provisioners, "relay-token").

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/abovebeyond-ai/control/attest"
	"github.com/abovebeyond-ai/control/canonical"
)

const attestationCS = "confidential-space"

// csRefresh is how often a gateway in Confidential Space takes a new token.
var csRefresh = 24 * time.Hour

// envOverrides takes the tokens the operator may set at launch, when set.
func envOverrides(cfg *config) {
	if v := os.Getenv("CLIENT_TOKEN"); v != "" {
		cfg.ClientToken = v
	}
	if v := os.Getenv("CLIENT_TOKEN_SHA256"); v != "" {
		cfg.ClientTokenSHA256 = v
	}
	if v := os.Getenv("RELAY_TOKEN"); v != "" {
		cfg.RelayToken = v
	}
}

// relayDo sends a call to the relay with the relay token, when there is one: the relay's gate
// door is on the internet once the gate runs away from the box.
func (s *service) relayDo(req *http.Request) (*http.Response, error) {
	if t := s.relayToken(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	return http.DefaultClient.Do(req)
}

// relayToken is the configured one, else the one the relay's operator provisioned.
func (s *service) relayToken() string {
	if s.cfg.RelayToken != "" {
		return s.cfg.RelayToken
	}
	if s.prov != nil {
		if v, ok := s.prov.key(relayTokenFile); ok {
			return string(v)
		}
	}
	return ""
}

// memoryKey is a record key made now and held only in memory.
func memoryKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// csStore is the store directory of one key: a restart writes a new log beside the old one
// instead of on top of a chain another key signed.
func csStore(base string, pub ed25519.PublicKey) string {
	return filepath.Join(base, hex.EncodeToString(pub)[:16])
}

// tokenSource asks for a token binding the key; the launcher in production, a fake in tests.
type tokenSource func(ctx context.Context, audience string, nonces []string) (string, error)

func launcherTokens(ctx context.Context, audience string, nonces []string) (string, error) {
	return attest.RequestToken(ctx, attest.TeeServerSocket, audience, nonces)
}

// csAttest takes a token for the key and keeps it beside the store, named by its digest, so an
// anchored checkpoint that names it can be resolved later.
func csAttest(cfg config, key ed25519.PrivateKey, tokens tokenSource) (*attest.Record, error) {
	pub := key.Public().(ed25519.PublicKey)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := tokens(ctx, cfg.Issuer, []string{attest.KeyNonce(pub)})
	if err != nil {
		return nil, fmt.Errorf("configured for Confidential Space but the launcher gave no token: %w", err)
	}
	r, err := attest.CSRecord(tok, pub, cfg.Release)
	if err != nil {
		return nil, err
	}
	raw, _ := json.MarshalIndent(r, "", "  ")
	dir := filepath.Join(cfg.Store, "attestations")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(cfg.Store, "attestation.json"), append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, canonical.SHA256([]byte(r.Token))+".json"), append(raw, '\n'), 0o644); err != nil {
		return nil, err
	}
	return r, nil
}

// refreshAttestation takes a new token every day and hands it to every agent's chain, so the
// records name a token Google's keys still verify.
func (s *service) refreshAttestation(tokens tokenSource) {
	for range time.Tick(csRefresh) {
		r, err := csAttest(s.cfg, s.key, tokens)
		if err != nil {
			fmt.Fprintf(os.Stderr, "attestation: %v; the records keep naming the token before\n", err)
			continue
		}
		if err := s.setAttestation(r); err != nil {
			fmt.Fprintf(os.Stderr, "attestation: %v\n", err)
		}
	}
}

func (s *service) setAttestation(r *attest.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.gateways {
		if err := g.SetAttestation(r); err != nil {
			return err
		}
	}
	s.attested = r
	return nil
}

// errNoClientToken: a gateway reached over a tunnel must not take submissions from anyone.
var errNoClientToken = errors.New("confidential-space: no client token (CLIENT_TOKEN_SHA256): refusing to take submissions from anyone who reaches the port")

// errClientTokenInEnv: the launcher would publish it in the attestation token.
var errClientTokenInEnv = errors.New("confidential-space: a client token in the clear would be published in the attestation token; give its SHA-256 (CLIENT_TOKEN_SHA256)")
