// Package policy is the deterministic policy over (action, path summary):
// the same inputs give the same verdict, with no lookup a stranger cannot
// repeat. The grant is data; the bundle hash names exactly which policy
// judged, so a verdict can be re-derived.
package policy

import (
	"sort"

	"github.com/abovebeyond-ai/control/canonical"
)

const Version = "control-1"

// Action is a proposed effect at the interception point.
type Action struct {
	Kind           string         `json:"kind"`
	Resource       string         `json:"resource"`
	Params         map[string]any `json:"params"`
	Classification string         `json:"classification"`
	// Attached carries material that is too large for the judged parameters and is bound
	// to them by digest (the files of a branch.push). Never part of the snapshot: ToMap
	// leaves it out, and the record names it only through the digest in Params.
	Attached map[string]any `json:"-"`
}

// ToMap is the action as the snapshot commits to it.
func (a Action) ToMap() map[string]any {
	params := a.Params
	if params == nil {
		params = map[string]any{}
	}
	class := a.Classification
	if class == "" {
		class = "public"
	}
	return map[string]any{"kind": a.Kind, "resource": a.Resource, "params": params, "classification": class}
}

// Grant is the authority a hand holds: who granted it, which verbs, on which
// resources, how many of each in one path, and which kinds must carry a
// certificate of premises.
type Grant struct {
	Principal      string   `json:"principal"`
	Kinds          []string `json:"kinds"`
	Resources      []string `json:"resources"`
	MaxPerKind     int      `json:"max_per_kind"`
	PremisesFor    []string `json:"premises_for"`
	MaxSensitivity string   `json:"max_sensitivity_egress,omitempty"`
	// SubmitterKey, when set, is the hand's own Ed25519 public key (hex): every
	// submission must be signed by it, and the record says so (row 5.1.2). The key
	// is the one the DID log publishes for the agent, so a stranger can check it.
	SubmitterKey string `json:"submitter_key,omitempty"`
	// PrincipalKey, when set, is the principal's Ed25519 public key (hex): every
	// submission must then carry a capability the principal signed for this task,
	// naming the agent, this gateway, the kinds and the resources, with an expiry
	// (rows 4.2.1, 5.1.3). The gateway takes the intersection of grant and
	// capability, so a capability narrows and never widens (row 4.2.3).
	PrincipalKey string `json:"principal_key,omitempty"`
}

// PathSummary is bounded path state: counts per kind and the resources
// touched, so a composed sequence of permitted actions can still be refused.
type PathSummary struct {
	Steps     int            `json:"steps"`
	PerKind   map[string]int `json:"per_kind"`
	Resources []string       `json:"resources"`
}

const Bound = 8

// Fold returns the summary after an action with a verdict; a refusal
// advances the step counter only.
func (p PathSummary) Fold(a Action, verdict string) PathSummary {
	next := PathSummary{Steps: p.Steps + 1, PerKind: map[string]int{}, Resources: append([]string{}, p.Resources...)}
	for k, v := range p.PerKind {
		next.PerKind[k] = v
	}
	if verdict != "ALLOW" {
		return next
	}
	next.PerKind[a.Kind]++
	seen := false
	for _, r := range next.Resources {
		if r == a.Resource {
			seen = true
		}
	}
	if !seen {
		next.Resources = append(next.Resources, a.Resource)
		sort.Strings(next.Resources)
		if len(next.Resources) > Bound {
			next.Resources = next.Resources[:Bound]
		}
	}
	return next
}

// Digest of the summary, hex.
func (p PathSummary) Digest() string {
	perKind := map[string]any{}
	for k, v := range p.PerKind {
		perKind[k] = v
	}
	res := p.Resources
	if res == nil {
		res = []string{}
	}
	d, _ := canonical.Digest(map[string]any{"steps": p.Steps, "per_kind": perKind, "resources": res})
	return d
}

// Policy evaluates a grant, path-aware.
type Policy struct {
	Grant     Grant
	PathAware bool
}

// BundleHash names the policy: grant, rule and version.
func (p Policy) BundleHash() string {
	kinds := append([]string{}, p.Grant.Kinds...)
	resources := append([]string{}, p.Grant.Resources...)
	premises := append([]string{}, p.Grant.PremisesFor...)
	sort.Strings(kinds)
	sort.Strings(resources)
	sort.Strings(premises)
	d, _ := canonical.Digest(p.Bundle())
	return d
}

// Bundle is the policy as a document: the grant, the parameter schemas, the rule
// and the version. It is what the hash names and what is written beside the first
// record judged under it (row 4.1.1).
func (p Policy) Bundle() map[string]any {
	kinds := append([]string{}, p.Grant.Kinds...)
	resources := append([]string{}, p.Grant.Resources...)
	premises := append([]string{}, p.Grant.PremisesFor...)
	sort.Strings(kinds)
	sort.Strings(resources)
	sort.Strings(premises)
	return map[string]any{
		"principal": p.Grant.Principal, "kinds": kinds, "resources": resources,
		"max_per_kind": p.Grant.MaxPerKind, "premises_for": premises,
		"path_aware": p.PathAware, "version": Version, "schemas": schemaDocument(),
		"submitter_key": p.Grant.SubmitterKey, "principal_key": p.Grant.PrincipalKey,
		"expiry": "none: a standing grant, replaced by a new bundle when it changes",
	}
}

// Evaluate returns verdict and reason.
func (p Policy) Evaluate(a Action, phi PathSummary) (string, string) {
	if !contains(p.Grant.Kinds, a.Kind) {
		return "DENY", "kind not in grant"
	}
	if err := Validate(a); err != nil {
		return "DENY", "out of schema: " + err.Error()
	}
	if !contains(p.Grant.Resources, a.Resource) {
		return "DENY", "resource not in grant"
	}
	if p.PathAware && p.Grant.MaxPerKind > 0 && phi.PerKind[a.Kind]+1 > p.Grant.MaxPerKind {
		return "DENY", "a second " + a.Kind + " in one run: the first already ran"
	}
	return "ALLOW", "within grant"
}

// RequiresPremises says whether a kind must carry a certificate.
func (p Policy) RequiresPremises(kind string) bool { return contains(p.Grant.PremisesFor, kind) }

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
