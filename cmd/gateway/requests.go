package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/capability"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

// Sealed requests (docs/odoo-gate.md): when a write waits for a person's word, the gateway reads
// from Odoo what the person needs to decide (the display), and seals it with the action and the
// agent's reason to the person's phone and to the organisation's audit key. The relay is told
// only who is asked, until when, and the bytes the passkey is to sign, which name the act by
// its digest alone. It carries the envelopes; it reads no order, product, price or reason.

// requestInfo is HPKE's info for a sealed request.
const requestInfo = "bextrust request v1"

// sealedRequest is one envelope of a request for one key.
type sealedRequest struct {
	Holder  string `json:"holder"`
	Pending string `json:"pending"`
	Exp     int64  `json:"exp"`
	Kid     string `json:"kid"`
	Enc     string `json:"enc"`
	CT      string `json:"ct"`
}

// displayer is an adapter that can show a write from the far end's own data.
type displayer interface {
	Display(ctx context.Context, a policy.Action) (map[string]any, error)
}

// requestPlaintext is what the person's phone opens: the act, Odoo's display of it, the agent's
// reason and reasoning as the agent's, and the digest of the payload the passkey signs, signed by the gateway.
func (s *service) requestPlaintext(ctx context.Context, p *pendingWord) map[string]any {
	plain := map[string]any{
		"v": 1, "pending": p.ID, "holder": p.Holder, "exp": p.Expires.Unix(), "agent": p.Req.Agent,
		"action":         map[string]any{"kind": p.Req.Action.Kind, "resource": p.Req.Action.Resource, "params": orEmptyParams(p.Req.Action.Params)},
		"act":            capability.ActDigest(p.Req.Action),
		"payload_digest": canonical.Tag(hex.EncodeToString(sha256Of(p.Payload))),
		"gate_key":       hex.EncodeToString(s.key.Public().(ed25519.PublicKey)),
	}
	if r := strings.TrimSpace(p.Req.Reason); r != "" {
		plain["reason"] = r
	}
	if len(p.Req.Reasoning) > 0 {
		plain["reasoning"] = p.Req.Reasoning.list()
	}
	display := map[string]any{}
	if a, ok := s.effects[p.Req.Action.Kind].(displayer); ok {
		dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		d, err := a.Display(dctx, p.Req.Action)
		cancel()
		if err != nil {
			display["error"] = "the gate could not read this from Odoo: " + err.Error()
		} else {
			display = d
		}
	}
	plain["display"] = display
	return plain
}

func orEmptyParams(p map[string]any) map[string]any {
	if p == nil {
		return map[string]any{}
	}
	return p
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// announceSealed tells the relay a word is wanted, with the request sealed to the person's phone
// (their entry's enc, from their chain at the relay, verified from the pinned root) and to the
// audit key. A person without a key still gets asked; their phone then has only the payload.
func (s *service) announceSealed(p *pendingWord) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plain := s.requestPlaintext(ctx, p)
	var envs []sealedRequest
	org, _, _ := strings.Cut(p.Holder, "#")
	if key := s.holderKey(p.Holder); key != nil {
		if e, err := s.sealRequest(*key, p.Holder, p, plain); err == nil {
			envs = append(envs, e)
		} else {
			fmt.Fprintf(os.Stderr, "request %s: could not be sealed for %s: %v\n", p.ID, p.Holder, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "request %s: %s has no encryption key; the phone gets the payload only\n", p.ID, p.Holder)
	}
	if s.cfg.AuditEnc != nil {
		if e, err := s.sealRequest(*s.cfg.AuditEnc, org+"#audit", p, plain); err == nil {
			envs = append(envs, e)
		}
	}
	if envs == nil {
		envs = []sealedRequest{}
	}
	s.announce(map[string]any{"pending": p.ID, "holder": p.Holder, "exp": p.Expires.Unix(),
		"payload": base64.RawURLEncoding.EncodeToString(p.Payload), "challenge": capability.Challenge(p.Payload), "sealed": envs})
}

// sealRequest signs the plaintext for one recipient and seals it to their key.
func (s *service) sealRequest(key registry.EncKey, recipient string, p *pendingWord, base map[string]any) (sealedRequest, error) {
	plain := map[string]any{}
	for k, v := range base {
		plain[k] = v
	}
	plain["recipient"] = recipient
	// Through JSON, so what is signed is what the phone decodes.
	raw, _ := json.Marshal(plain)
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return sealedRequest{}, err
	}
	body, err := canonical.Encode(m)
	if err != nil {
		return sealedRequest{}, err
	}
	m["sig"] = hex.EncodeToString(ed25519.Sign(s.key, body))
	out, err := canonical.Encode(m)
	if err != nil {
		return sealedRequest{}, err
	}
	exp := p.Expires.Unix()
	aad, err := canonical.Encode(map[string]any{"holder": recipient, "pending": p.ID, "exp": exp, "kid": key.Kid})
	if err != nil {
		return sealedRequest{}, err
	}
	enc, ct, err := hpkeSeal(key, requestInfo, aad, out)
	if err != nil {
		return sealedRequest{}, err
	}
	b := base64.RawURLEncoding.EncodeToString
	return sealedRequest{Holder: recipient, Pending: p.ID, Exp: exp, Kid: key.Kid, Enc: b(enc), CT: b(ct)}, nil
}

// holderKey is the enc of the holder's current entry: their chain at the relay, verified from the
// pinned root and not revoked. nil when there is none to seal to.
func (s *service) holderKey(holder string) *registry.EncKey {
	toks, err := s.relayChain(holder)
	if err != nil || len(toks) == 0 {
		return nil
	}
	roots, err := s.cfg.orgKeys()
	if err != nil {
		return nil
	}
	entries, err := registry.VerifyChain(toks, roots, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "request: %s's chain at the relay does not hold: %v\n", holder, err)
		return nil
	}
	var lookup func(string) string
	if s.revoked != nil {
		lookup = s.revoked.RevokedEntry
	}
	if why := registry.Revoked(toks, entries, roots, lookup); why != "" {
		fmt.Fprintf(os.Stderr, "request: %s\n", why)
		return nil
	}
	if leaf := entries[len(entries)-1]; leaf.ID == holder {
		return leaf.Enc
	}
	return nil
}
