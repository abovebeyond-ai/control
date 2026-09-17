package policy

import (
	"strings"
	"testing"
)

// A grant names a resource exactly or by prefix; a prefix covers what lies under it and
// nothing beside it.
func TestAResourcePrefixCoversWhatLiesUnderItOnly(t *testing.T) {
	list := []string{"x/y", "vera/hoet/*"}
	for _, ok := range []string{"x/y", "vera/hoet/paper1", "vera/hoet/a/b"} {
		if !ResourceCovered(list, ok) {
			t.Errorf("%s must be covered", ok)
		}
	}
	for _, no := range []string{"x/z", "vera/hoet", "vera/hoet/", "vera/hoetx/paper1", "vera/cabrio/paper1", "vera"} {
		if ResourceCovered(list, no) {
			t.Errorf("%s must not be covered", no)
		}
	}
}

// The preview kinds carry a rule of their own beside the grant's counts: preview.push sets
// the branch named preview and no other, once per run; forge.deploy only after it.
func TestThePreviewIsSetOnceOnItsOwnBranchAndDeployedOnlyAfter(t *testing.T) {
	p := Policy{Grant: Grant{Kinds: []string{PreviewPushKind, ForgeDeployKind}, Resources: []string{"o/r", "forge:demo"}}, PathAware: true}
	sha := "0123456789abcdef0123456789abcdef01234567"
	push := func(branch string) Action {
		return Action{Kind: PreviewPushKind, Resource: "o/r", Params: map[string]any{"branch": branch, "sha": sha, "pull": 511}}
	}
	deploy := Action{Kind: ForgeDeployKind, Resource: "forge:demo", Params: map[string]any{"sha": sha, "pull": 511}}
	fresh := PathSummary{PerKind: map[string]int{}}

	if v, r := p.Evaluate(push("main"), fresh); v != "DENY" || r != "preview.push sets the branch named preview and no other" {
		t.Errorf("another branch: %s %s", v, r)
	}
	if v, r := p.Evaluate(deploy, fresh); v != "DENY" || r != "forge.deploy before a preview.push in this run: nothing was set to deploy" {
		t.Errorf("deploy first: %s %s", v, r)
	}
	if v, r := p.Evaluate(push("preview"), fresh); v != "ALLOW" {
		t.Errorf("the preview: %s %s", v, r)
	}
	after := fresh.Fold(push("preview"), "ALLOW")
	if v, r := p.Evaluate(deploy, after); v != "ALLOW" {
		t.Errorf("deploy after the push: %s %s", v, r)
	}
	// A second push is refused by this rule even when the grant counts nothing (max_per_kind 0).
	if v, r := p.Evaluate(push("preview"), after); v != "DENY" || r != "a second preview.push in one run: the preview was already set" {
		t.Errorf("second push: %s %s", v, r)
	}
	// A short commit id is out of schema: the far end would resolve it, not the judgement.
	short := push("preview")
	short.Params["sha"] = "0123456"
	if v, r := p.Evaluate(short, fresh); v != "DENY" || !strings.Contains(r, "commit id") {
		t.Errorf("short sha: %s %s", v, r)
	}
}
