package main

// Attested provisioning (docs/odoo-gate.md, Confidential Space). A gateway in Confidential
// Space holds no secret when it starts: the operator chose only the image, and the image carries
// no key. The organisation whose Odoo it calls hands it the API keys itself, and only after
// checking Google's attestation: the token names the image the organisation checked and binds
// the record key, and the record key signs the provisioning key below. What is sealed to that
// key opens only inside the attested workload, and stays in its memory.
//
//	GET  /v1/provision-key  {"key": <P-256 JWK>, "record_key": <hex>, "sig": <hex>, "provisioned": [...]}
//	POST /v1/provision      {"kid", "enc", "ct"}  HPKE as receipts, info "bextrust provision v1",
//	                        aad the canonical JSON of {"kid"}; plaintext {"v":1,"files":{name: text}}

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/abovebeyond-ai/control/canonical"
	"github.com/abovebeyond-ai/control/policy"
	"github.com/abovebeyond-ai/control/registry"
)

const (
	provisionInfo    = "bextrust provision v1"
	provisionPurpose = "bextrust provision key v1"
)

// An organisation provisions Odoo API keys: odoo-key-<instance> or odoo-key-<instance>-<agent>;
// and the state key its gate's state is sealed under (stateKeyFile, state.go).
var provisionName = regexp.MustCompile(`^odoo-key-[a-z0-9][a-z0-9-]{0,62}$`)

// relayTokenFile is the relay's door token, provisioned by the relay's operator.
const relayTokenFile = "relay-token"

// provisionerConfig is a party other than an organisation that may provision named files.
type provisionerConfig struct {
	Key   string   `json:"key"`
	Files []string `json:"files"`
}

// provisioner holds the provisioning key and what was provisioned, in memory only.
type provisioner struct {
	priv *ecdh.PrivateKey
	pub  registry.EncKey
	mu   sync.RWMutex
	keys map[string][]byte
}

func newProvisioner() (*provisioner, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	point := priv.PublicKey().Bytes()
	b64 := base64.RawURLEncoding.EncodeToString
	// The uncompressed point is 0x04 || X || Y, 32 bytes each.
	pub := registry.EncKey{Kty: "EC", Crv: "P-256", X: b64(point[1:33]), Y: b64(point[33:65]), Kid: registry.EncKid(point)}
	return &provisioner{priv: priv, pub: pub, keys: map[string][]byte{}}, nil
}

// key answers a provisioned file by name: the Odoo adapter reads here first.
func (p *provisioner) key(name string) ([]byte, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	v, ok := p.keys[name]
	return v, ok
}

func (p *provisioner) names() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.keys))
	for n := range p.keys {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// provisionKeyBytes is what the record key signs over the provisioning key.
func provisionKeyBytes(k registry.EncKey) ([]byte, error) {
	return canonical.Encode(map[string]any{"purpose": provisionPurpose,
		"key": map[string]any{"kty": k.Kty, "crv": k.Crv, "x": k.X, "y": k.Y, "kid": k.Kid}})
}

func (s *service) provisionKey(w http.ResponseWriter, r *http.Request) {
	in, err := provisionKeyBytes(s.prov.pub)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"key": s.prov.pub, "record_key": hex.EncodeToString(s.key.Public().(ed25519.PublicKey)),
		"sig": hex.EncodeToString(ed25519.Sign(s.key, in)), "provisioned": s.prov.names()})
}

// provisionEnvelope is one sealed provisioning, signed by the organisation's root key: the
// gateway takes keys only from an organisation it pins, so nobody else who reaches the port can
// swap them for another Odoo user's.
type provisionEnvelope struct {
	Org string `json:"org"`
	Kid string `json:"kid"`
	Enc string `json:"enc"`
	CT  string `json:"ct"`
	Sig string `json:"sig"`
}

// provisionSigned is what the organisation's root key signs over an envelope.
func provisionSigned(e provisionEnvelope) ([]byte, error) {
	return canonical.Encode(map[string]any{"purpose": provisionInfo, "org": e.Org, "kid": e.Kid, "enc": e.Enc, "ct": e.CT})
}

// signedBy checks the envelope's signature under the org's pinned root key, or the named
// provisioner's key, and says which files that signer may provision.
func (e provisionEnvelope) signedBy(roots map[string]ed25519.PublicKey, others map[string]provisionerConfig) (func(string) bool, error) {
	root, ok := roots[e.Org]
	allowed := func(n string) bool { return provisionName.MatchString(n) || n == stateKeyFile }
	if !ok {
		p, isProv := others[e.Org]
		raw, err := hex.DecodeString(p.Key)
		if !isProv || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("no root key is pinned for %q and no provisioner has that name", e.Org)
		}
		root = ed25519.PublicKey(raw)
		allowed = func(n string) bool {
			for _, f := range p.Files {
				if f == n {
					return true
				}
			}
			return false
		}
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil {
		return nil, errors.New("sig is not hex")
	}
	in, err := provisionSigned(e)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(root, in, sig) {
		return nil, fmt.Errorf("the envelope is not signed by %s's key", e.Org)
	}
	return allowed, nil
}

// openProvision opens one envelope with the provisioning key and reads its files.
func (p *provisioner) open(e provisionEnvelope, allowed func(string) bool) (map[string][]byte, error) {
	if e.Kid != p.pub.Kid {
		return nil, fmt.Errorf("sealed to key %q, this gateway's provisioning key is %q (restarted since?)", e.Kid, p.pub.Kid)
	}
	enc, err1 := base64.RawURLEncoding.DecodeString(e.Enc)
	ct, err2 := base64.RawURLEncoding.DecodeString(e.CT)
	if err1 != nil || err2 != nil {
		return nil, errors.New("the envelope is not base64url")
	}
	k, err := hpke.NewDHKEMPrivateKey(p.priv)
	if err != nil {
		return nil, err
	}
	aad, _ := canonical.Encode(map[string]any{"kid": e.Kid})
	rcp, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.AES128GCM(), []byte(provisionInfo))
	if err != nil {
		return nil, errors.New("the envelope does not open")
	}
	plain, err := rcp.Open(aad, ct)
	if err != nil {
		return nil, errors.New("the envelope does not open")
	}
	var body struct {
		V     int               `json:"v"`
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(plain, &body); err != nil || body.V != 1 || len(body.Files) == 0 {
		return nil, errors.New("the sealed content is not a provisioning of version 1 with files")
	}
	out := map[string][]byte{}
	for name, v := range body.Files {
		if !allowed(name) {
			return nil, fmt.Errorf("%q is not a file %s may provision", name, e.Org)
		}
		v = strings.TrimSpace(v)
		if v == "" {
			return nil, fmt.Errorf("%s is empty", name)
		}
		if name == stateKeyFile {
			if _, err := parseStateKey([]byte(v)); err != nil {
				return nil, err
			}
		}
		out[name] = []byte(v)
	}
	return out, nil
}

// provision takes an envelope, keeps its files in memory, and writes one record of it under
// every agent: which files, sealed to which key, and no secret.
func (s *service) provision(w http.ResponseWriter, r *http.Request) {
	var e provisionEnvelope
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&e); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	roots, err := s.cfg.orgKeys()
	var allowed func(string) bool
	if err == nil {
		allowed, err = e.signedBy(roots, s.cfg.Provisioners)
	}
	if err != nil {
		writeJSON(w, 403, map[string]any{"error": err.Error()})
		return
	}
	files, err := s.prov.open(e, allowed)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.prov.mu.Lock()
	for n, v := range files {
		s.prov.keys[n] = v
	}
	s.prov.mu.Unlock()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	recorded := map[string]int{}
	for agent := range s.cfg.Agents {
		g, err := s.gateway(agent)
		if err != nil {
			continue
		}
		outcome := map[string]any{"files": names, "sealed_to": e.Kid, "by": e.Org, "envelope": canonical.Tag(canonical.SHA256([]byte(e.Enc + "." + e.CT)))}
		v := g.Event("provision", policy.Action{Kind: "control.provision", Resource: "control:secrets", Params: map[string]any{"files": names}},
			e.Org, "provisioned in memory by "+e.Org+" after checking the attestation; no secret in this record", outcome)
		if v.Token != nil {
			recorded[agent] = v.Step
		}
	}
	fmt.Fprintf(os.Stderr, "provisioned %s\n", strings.Join(names, ", "))
	// A state key, or the relay token it needs, may be what was missing to restore the state.
	s.startState()
	writeJSON(w, 200, map[string]any{"provisioned": s.prov.names(), "records": recorded})
}
