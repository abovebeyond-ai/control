// Package premises is the reason-as-evidence profile: a hand states the
// premises of an action as a ProveML certificate, the gateway verifies it
// against a snapshot, a registry and a provenance map before the grant is
// consulted, and the digests ride in the token as the profile's seven claims.
// The certificate language is ProveML through proveml-go; another language
// would be another implementation of Checker.
package premises

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/abovebeyond-ai/control/canonical"
	proveml "github.com/abovebeyond-ai/proveml-go"
)

// Material is what the digests cover, supplied by the hand and kept beside the record.
type Material struct {
	Certificate      string            `json:"certificate"`
	Store            map[string]any    `json:"store"`
	Registry         proveml.Registry  `json:"registry"`
	Provenance       map[string]string `json:"provenance"`
	RequiredControls []string          `json:"requiredControls"`
	RequiredGrades   map[string]string `json:"requiredGrades"`
	Verified         bool              `json:"verified"`
	Errors           []string          `json:"errors"`
}

var rank = map[string]int{"absent": 0, "inferred": 1, "gateway": 2, "inferred:signed": 2, "attested": 3, "presented": 4, "ledger": 4, "policy": 4}

var judgement = regexp.MustCompile(`\?\[[^:\]]+:\s*([A-Z][A-Z0-9_]*)[^\]]*\]`)

// Check verifies the material and fills Verified and Errors: every construct
// verified by the ProveML judge in certificate coverage, every required
// control argued by at least one judgement, every bound fact at the grade
// the policy requires.
func Check(m *Material) {
	m.Errors = nil
	if strings.TrimSpace(m.Certificate) == "" {
		m.Errors = append(m.Errors, "the certificate is empty")
	}
	res, err := proveml.Verify(m.Certificate, proveml.Store(m.Store), &proveml.Options{Thresholds: m.Registry, Coverage: "certificate"})
	if err != nil {
		m.Errors = append(m.Errors, err.Error())
	} else {
		m.Errors = append(m.Errors, res.Errors...)
		if res.Total == 0 && m.Certificate != "" {
			m.Errors = append(m.Errors, "the certificate makes no claim")
		}
		for _, u := range res.Unmarked {
			m.Errors = append(m.Errors, u.Value+" in the certificate is not a claim")
		}
	}
	argued := map[string]bool{}
	for _, match := range judgement.FindAllStringSubmatch(m.Certificate, -1) {
		argued[match[1]] = true
	}
	for _, control := range m.RequiredControls {
		if !argued[control] {
			m.Errors = append(m.Errors, "the certificate does not argue "+control)
		}
	}
	for path, grade := range m.Provenance {
		field := path[strings.LastIndex(path, ".")+1:]
		if need, ok := m.RequiredGrades[field]; ok && rank[grade] < rank[need] {
			m.Errors = append(m.Errors, fmt.Sprintf("%s is %s, the policy requires %s", path, grade, need))
		}
	}
	// Every fact the certificate binds must have a grade; a path without one is absent.
	if res != nil {
		for _, d := range res.Details {
			if p, ok := d["path"].(string); ok && d["type"] == "fact" {
				if _, has := m.Provenance[p]; !has {
					m.Errors = append(m.Errors, p+" has no provenance")
				}
			}
		}
	}
	sort.Strings(m.Errors)
	m.Verified = len(m.Errors) == 0
}

// Claims are the profile's seven claims for the token's extension point.
func Claims(m *Material) (map[string]any, error) {
	store, err := canonical.Digest(m.Store)
	if err != nil {
		return nil, err
	}
	registry, err := canonical.Digest(m.Registry)
	if err != nil {
		return nil, err
	}
	prov := map[string]any{}
	for k, v := range m.Provenance {
		prov[k] = v
	}
	provenance, err := canonical.Digest(prov)
	if err != nil {
		return nil, err
	}
	controls := make([]any, len(m.RequiredControls))
	for i, c := range m.RequiredControls {
		controls[i] = c
	}
	return map[string]any{
		"proveml_certificate_hash":  canonical.Tag(canonical.SHA256([]byte(m.Certificate))),
		"proveml_store_hash":        canonical.Tag(store),
		"proveml_registry_hash":     canonical.Tag(registry),
		"proveml_required_controls": controls,
		"proveml_verified":          m.Verified,
		"proveml_provenance_hash":   canonical.Tag(provenance),
		"proveml_provenance":        prov,
	}, nil
}

// Replay recomputes the digests and the check from stored material and
// compares both with what a record claims.
func Replay(claims map[string]any, m Material) error {
	Check(&m)
	want, err := Claims(&m)
	if err != nil {
		return err
	}
	for _, k := range []string{"proveml_certificate_hash", "proveml_store_hash", "proveml_registry_hash", "proveml_provenance_hash"} {
		if claims[k] != want[k] {
			return fmt.Errorf("%s does not recompute from the stored material", k)
		}
	}
	if v, _ := claims["proveml_verified"].(bool); v != m.Verified {
		return fmt.Errorf("the check replayed over the material gives %v, the record claims the opposite", m.Verified)
	}
	if !m.Verified && claims["verdict"] != "DENY" {
		return fmt.Errorf("the premises do not verify, yet the verdict is not DENY")
	}
	return nil
}
