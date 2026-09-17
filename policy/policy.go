// Package policy is the deterministic policy over (action, path summary):
// the same inputs give the same verdict, with no lookup a stranger cannot
// repeat. The grant is data; the bundle hash names exactly which policy
// judged, so a verdict can be re-derived.
package policy

import (
	"sort"
	"strings"

	"github.com/abovebeyond-ai/control/canonical"
)

const Version = "control-1"

// The preview kinds and the one branch the first of them may set. A preview site on Forge
// tracks a fixed branch; a hand moves that branch to a pull request's head and asks Forge
// to deploy. The branch is named here and nowhere else, so a grant cannot widen it: a
// forced update of any other branch would be a push without a pull request.
const (
	PreviewPushKind = "preview.push"
	ForgeDeployKind = "forge.deploy"
	PreviewBranch   = "preview"
)

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
	// PrincipalKeys names further keys of the principal by DID fragment (the operator's
	// own, "did:webvh:…#operator" on a hardware token, and its counterpart "#operator-2"
	// on the second token): a capability whose issuer is one of them is verified against
	// that key. Until 2026-09-13 every capability was signed by Portal's key, so the
	// operator's word was whatever the Portal application chose to sign; with the
	// operator's keys named here, the capability is a signature only the person holding
	// the token could have made, and the record names which key spoke.
	PrincipalKeys map[string]string `json:"principal_keys,omitempty"`
	// PerAction names the kinds whose capability must name the act itself (Payload.Act):
	// the word is then spent on one action and cannot be reused inside its window. Reserve
	// it for what a person cannot undo, since every kind listed here costs the operator a
	// touch of the key per action; a push and a pull request end in a review, an invitation
	// is mail already sent and a seal is anchored.
	PerAction []string `json:"per_action,omitempty"`
	// Judgements names the controls a certificate of premises may argue for this grant.
	// A working is only as good as the rule it argues: a permit that accepts "within
	// semver" must not be satisfied by a working that argues something else. Empty means
	// the one judgement the fleet has used since 7 September 2026, FIX_WITHIN_SEMVER.
	// A grant that lets an agent cross a major version names MAJOR_UNDER_TESTS here, and
	// the working then has to argue tests before and after the change.
	Judgements []string `json:"judgements,omitempty"`
	// Tasks, when set, narrows the grant per task the principal's capability names.
	// One hand that runs several playbooks under one key is one agent, not several:
	// the key is what a stranger can check, and four agent ids on one key would claim
	// a boundary that does not exist. So the agent holds one grant, and the playbook
	// the capability names selects the task's own verbs, premises and judgements out
	// of it (a task never widens: its kinds are met with the grant's). A capability
	// naming a task the grant does not have is refused, and so is a submission
	// without a capability when the grant is per task.
	Tasks map[string]TaskGrant `json:"tasks,omitempty"`
}

// TaskGrant is what one task under an agent's grant may do: its verbs (within the
// grant's), which of them carry a certificate, and which judgements that certificate
// may argue.
type TaskGrant struct {
	Kinds       []string `json:"kinds"`
	PremisesFor []string `json:"premises_for,omitempty"`
	Judgements  []string `json:"judgements,omitempty"`
}

// PerTask says whether the grant is narrowed per task.
func (p Policy) PerTask() bool { return len(p.Grant.Tasks) > 0 }

// ForTask is the policy as it applies to one task: the grant with the task's verbs
// (intersected with its own), premises and judgements in place of the agent-wide
// ones. A grant without tasks is returned as it is. The second value is the reason
// when the task is not one the grant names.
func (p Policy) ForTask(playbook string) (Policy, string) {
	if !p.PerTask() {
		return p, ""
	}
	t, ok := p.Grant.Tasks[playbook]
	if !ok {
		if playbook == "" {
			return p, "the grant is per task and the capability names none"
		}
		return p, "the grant names no task " + playbook
	}
	q := p
	q.Grant.Kinds = nil
	for _, k := range t.Kinds {
		if contains(p.Grant.Kinds, k) {
			q.Grant.Kinds = append(q.Grant.Kinds, k)
		}
	}
	q.Grant.PremisesFor = append([]string{}, t.PremisesFor...)
	q.Grant.Judgements = append([]string{}, t.Judgements...)
	q.Grant.Tasks = nil
	return q, ""
}

// DefaultJudgements is what a grant accepts when it names none.
var DefaultJudgements = []string{"FIX_WITHIN_SEMVER"}

// Accepted says whether every control a certificate argues is one the grant accepts;
// the first that is not is returned.
func (p Policy) Accepted(required []string) (string, bool) {
	accepted := p.Grant.Judgements
	if len(accepted) == 0 {
		accepted = DefaultJudgements
	}
	for _, c := range required {
		if !contains(accepted, c) {
			return c, false
		}
	}
	if len(required) == 0 {
		return "", false
	}
	return "", true
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
	doc := map[string]any{
		"principal": p.Grant.Principal, "kinds": kinds, "resources": resources,
		"max_per_kind": p.Grant.MaxPerKind, "premises_for": premises, "judgements": append([]string{}, p.Grant.Judgements...),
		"path_aware": p.PathAware, "version": Version, "schemas": schemaDocument(),
		"submitter_key": p.Grant.SubmitterKey, "principal_key": p.Grant.PrincipalKey,
		"expiry": "none: a standing grant, replaced by a new bundle when it changes",
	}
	// Only a grant that is per task carries the key, so a bundle without tasks hashes
	// as it did before tasks existed.
	if len(p.Grant.Tasks) > 0 {
		doc["tasks"] = tasksDocument(p.Grant.Tasks)
	}
	// Likewise the operator's keys: a bundle without them hashes as before.
	if len(p.Grant.PrincipalKeys) > 0 {
		keys := map[string]any{}
		for k, v := range p.Grant.PrincipalKeys {
			keys[k] = v
		}
		doc["principal_keys"] = keys
	}
	return doc
}

// tasksDocument is the per-task narrowing as the bundle carries it, sorted so the
// hash is stable.
func tasksDocument(tasks map[string]TaskGrant) []map[string]any {
	names := make([]string, 0, len(tasks))
	for n := range tasks {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		t := tasks[n]
		kinds := append([]string{}, t.Kinds...)
		premises := append([]string{}, t.PremisesFor...)
		judgements := append([]string{}, t.Judgements...)
		sort.Strings(kinds)
		sort.Strings(premises)
		sort.Strings(judgements)
		out = append(out, map[string]any{"task": n, "kinds": kinds, "premises_for": premises, "judgements": judgements})
	}
	return out
}

// Evaluate returns verdict and reason.
func (p Policy) Evaluate(a Action, phi PathSummary) (string, string) {
	if !contains(p.Grant.Kinds, a.Kind) {
		return "DENY", "kind not in grant"
	}
	if err := Validate(a); err != nil {
		return "DENY", "out of schema: " + err.Error()
	}
	if !ResourceCovered(p.Grant.Resources, a.Resource) {
		return "DENY", "resource not in grant"
	}
	if p.PathAware && p.Grant.MaxPerKind > 0 && phi.PerKind[a.Kind]+1 > p.Grant.MaxPerKind {
		return "DENY", "a second " + a.Kind + " in one run: the first already ran"
	}
	if verdict, reason, held := previewRule(a, phi); held {
		return verdict, reason
	}
	return "ALLOW", "within grant"
}

// previewRule is the path-aware rule of the preview kinds, over and above the grant's
// counts: preview.push sets the branch named preview and no other, once per run (a second
// would move the preview under a reviewer's feet, whatever max_per_kind says); forge.deploy
// follows a preview.push in the same run, since a deploy of what was not set is a deploy
// of whatever the branch held. Deterministic over (action, path summary) like the rest.
func previewRule(a Action, phi PathSummary) (string, string, bool) {
	switch a.Kind {
	case PreviewPushKind:
		if branch, _ := a.Params["branch"].(string); branch != PreviewBranch {
			return "DENY", PreviewPushKind + " sets the branch named " + PreviewBranch + " and no other", true
		}
		if phi.PerKind[PreviewPushKind] >= 1 {
			return "DENY", "a second " + PreviewPushKind + " in one run: the preview was already set", true
		}
	case ForgeDeployKind:
		if phi.PerKind[PreviewPushKind] == 0 {
			return "DENY", ForgeDeployKind + " before a " + PreviewPushKind + " in this run: nothing was set to deploy", true
		}
	}
	return "", "", false
}

// RequiresPremises says whether a kind must carry a certificate.
func (p Policy) RequiresPremises(kind string) bool { return contains(p.Grant.PremisesFor, kind) }

// ResourceCovered: a grant names resources exactly ("owner/repo") or by prefix, an
// entry ending in "/*" ("vera/hoet/*", since 13 September 2026: a review is made under
// a project and its id is not known when the permit is written). A prefix entry covers
// what lies under it and nothing beside it: "vera/hoet/*" covers "vera/hoet/paper1",
// not "vera/hoet" and not "vera/hoetx/paper1".
func ResourceCovered(list []string, resource string) bool {
	for _, x := range list {
		if x == resource {
			return true
		}
		if strings.HasSuffix(x, "/*") && strings.HasPrefix(resource, strings.TrimSuffix(x, "*")) && len(resource) > len(x)-1 {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
