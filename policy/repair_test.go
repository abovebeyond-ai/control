package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

const portal = "did:x#portal"

func repairKeys(t *testing.T) (ed25519.PrivateKey, Signers) {
	t.Helper()
	k := newLogKeys(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	k.signers.Repair = map[string]string{portal: hex.EncodeToString(pub)}
	return priv, k.signers
}

// changed is the boot head's grants with one change made to the shed's grant.
func changed(head Head, change func(g *Grant)) map[string]HandGrant {
	g := head.Agents[shed].Grant
	g.Kinds = append([]string{}, g.Kinds...)
	g.Resources = append([]string{}, g.Resources...)
	change(&g)
	return map[string]HandGrant{shed: {Grant: g}}
}

func TestPortalsKeyAddsAReversibleKindOrAResource(t *testing.T) {
	key, signers := repairKeys(t)
	head := bootHead()
	for name, agents := range map[string]map[string]HandGrant{
		"a listed kind": changed(head, func(g *Grant) { g.Kinds = append(g.Kinds, "observatory.trend_edit", "observatory.trend_site") }),
		"a resource":    changed(head, func(g *Grant) { g.Resources = append(g.Resources, "observatory:pipeline") }),
		"both": changed(head, func(g *Grant) {
			g.Kinds = append(g.Kinds, "issue.open")
			g.Resources = append(g.Resources, "abovebeyond-ai/control")
		}),
		"only taking away": changed(head, func(g *Grant) { g.Resources = g.Resources[:1] }),
	} {
		v := sign(t, key, version(head, portal, agents, head.Systems))
		if _, err := Next(head, v, signers, now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPortalsKeyAddsNothingElse(t *testing.T) {
	key, signers := repairKeys(t)
	head := bootHead()
	elixirHand := map[string]HandGrant{"did:x#agent-elixir": {Grant: Grant{Principal: "did:x", Kinds: []string{"branch.push"}, Resources: []string{"a/b"}}}}
	for name, c := range map[string]struct {
		agents  map[string]HandGrant
		systems map[string]string
		reason  string
	}{
		"an unlisted kind": {changed(head, func(g *Grant) { g.Kinds = append(g.Kinds, "review.invite") }), head.Systems, "adds the kind review.invite"},
		"a merge":          {changed(head, func(g *Grant) { g.Kinds = append(g.Kinds, "pull.merge") }), head.Systems, "adds the kind pull.merge"},
		"a new hand": {func() map[string]HandGrant {
			a := changed(head, func(*Grant) {})
			a["did:x#agent-elixir"] = elixirHand["did:x#agent-elixir"]
			return a
		}(), head.Systems, "adds the hand did:x#agent-elixir"},
		"a new system":     {head.Agents, map[string]string{"stocklist:platform": "https://traders.example", "observatory:pipeline": "https://observatory.example"}, "adds the system observatory:pipeline"},
		"a system moved":   {head.Agents, map[string]string{"stocklist:platform": "https://elsewhere.example"}, "moves the system stocklist:platform"},
		"a key changed":    {changed(head, func(g *Grant) { g.SubmitterKey = "ab" }), head.Systems, "changes who speaks for it"},
		"a principal key":  {changed(head, func(g *Grant) { g.PrincipalKeys = map[string]string{"#operator": "ab"} }), head.Systems, "changes who speaks for it"},
		"a higher count":   {changed(head, func(g *Grant) { g.MaxPerKind = 2 }), head.Systems, "raises the count per kind"},
		"premises dropped": {changed(head, func(g *Grant) { g.PremisesFor = nil }), head.Systems, "drops the certificate for pull.open"},
		"a judgement":      {changed(head, func(g *Grant) { g.Judgements = []string{"MAJOR_UNDER_TESTS"} }), head.Systems, "accepts the judgement MAJOR_UNDER_TESTS"},
	} {
		v := sign(t, key, version(head, portal, c.agents, c.systems))
		_, err := Next(head, v, signers, now)
		if err == nil || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: want a refusal naming %q, got %v", name, c.reason, err)
		}
	}
}

func TestANewResourceDoesNotReachAKindThatIsNotReversible(t *testing.T) {
	head := bootHead()
	g := head.Agents[shed].Grant
	g.Kinds = append(append([]string{}, g.Kinds...), "review.invite")
	head.Agents = map[string]HandGrant{shed: {Grant: g}}
	next := changed(head, func(g *Grant) { g.Resources = append(g.Resources, "vera/other/*") })
	if reason := RepairOnly(head.Agents, head.Systems, next, head.Systems); !strings.Contains(reason, "holds review.invite") {
		t.Fatalf("a resource added beside review.invite: %q", reason)
	}
}

func TestARepairAddsAListedKindToATaskButNoTask(t *testing.T) {
	head := bootHead()
	g := head.Agents[shed].Grant
	g.Kinds = []string{"branch.push", "pull.open", "issue.open"}
	g.Tasks = map[string]TaskGrant{"maintenance": {Kinds: []string{"branch.push"}}}
	head.Agents = map[string]HandGrant{shed: {Grant: g}}
	add := changed(head, func(g *Grant) {
		g.Tasks = map[string]TaskGrant{"maintenance": {Kinds: []string{"branch.push", "issue.open"}}}
	})
	if reason := RepairOnly(head.Agents, head.Systems, add, head.Systems); reason != "" {
		t.Fatalf("a listed kind added to a task: %s", reason)
	}
	task := changed(head, func(g *Grant) {
		g.Tasks = map[string]TaskGrant{"maintenance": {Kinds: []string{"branch.push"}}, "headers": {Kinds: []string{"issue.open"}}}
	})
	if reason := RepairOnly(head.Agents, head.Systems, task, head.Systems); !strings.Contains(reason, "adds the task headers") {
		t.Fatalf("a task added: %q", reason)
	}
}

func TestNoKindThatReachesAPersonIsARepairKind(t *testing.T) {
	for _, k := range []string{"review.invite", "review.sign", "review.publish", "pull.merge", "pull.ready", "branch.delete", "workflow.dispatch", "stocklist.resend", "stocklist.transport_price"} {
		if IsRepairKind(k) {
			t.Errorf("%s is on the repair list", k)
		}
	}
	for k, radius := range RepairKinds {
		if !strings.HasPrefix(radius, "B1: ") && !strings.HasPrefix(radius, "B2: ") {
			t.Errorf("%s names no radius of B1 or B2: %q", k, radius)
		}
	}
}
