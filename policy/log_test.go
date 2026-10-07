package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	owner  = "did:x#operator"
	elixir = "did:x#agent-elixir"
	shed   = "did:x#agent-workbench-shed"
)

type logKeys struct {
	owner, elixir ed25519.PrivateKey
	signers       Signers
}

func newLogKeys(t *testing.T) logKeys {
	t.Helper()
	opub, opriv, _ := ed25519.GenerateKey(rand.Reader)
	epub, epriv, _ := ed25519.GenerateKey(rand.Reader)
	return logKeys{owner: opriv, elixir: epriv, signers: Signers{
		Widen:  map[string]string{owner: hex.EncodeToString(opub)},
		Narrow: map[string]string{elixir: hex.EncodeToString(epub)},
	}}
}

func sign(t *testing.T, key ed25519.PrivateKey, v LogVersion) SignedVersion {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))
	s, err := ParseVersion(token)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var now = time.Unix(1_791_400_000, 0)

func bootHead() Head {
	return Head{Version: 0, Hash: HashOf([]byte(`{"agents":{}}`)), Agents: map[string]HandGrant{
		shed: {Grant: Grant{Principal: "did:x", Kinds: []string{"branch.push", "pull.open"}, Resources: []string{"abovebeyond-ai/portal", "abovebeyond-ai/portal-cli"}, MaxPerKind: 1, PremisesFor: []string{"pull.open"}}},
	}, Systems: map[string]string{"stocklist:platform": "https://traders.example"}}
}

func version(head Head, iss string, agents map[string]HandGrant, systems map[string]string) LogVersion {
	return LogVersion{Type: VersionType, Iss: iss, Version: head.Version + 1, Prev: head.Hash, Iat: now.Unix(), Agents: agents, Systems: systems, Change: []string{"the change in words"}}
}

func withResources(head Head, resources ...string) map[string]HandGrant {
	g := head.Agents[shed].Grant
	g.Resources = resources
	return map[string]HandGrant{shed: {Grant: g}}
}

func TestTheOwnerWidensAndTheChainMovesForward(t *testing.T) {
	k := newLogKeys(t)
	head := bootHead()
	v1 := sign(t, k.owner, version(head, owner, withResources(head, "abovebeyond-ai/portal", "abovebeyond-ai/portal-cli", "abovebeyond-ai/portal-android"), head.Systems))
	next, err := Next(head, v1, k.signers, now)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version != 1 || next.Hash != v1.Hash() || !contains(next.Agents[shed].Grant.Resources, "abovebeyond-ai/portal-android") {
		t.Fatalf("head after version 1: %+v", next)
	}

	// A second version follows the first; the first, replayed, is refused, and so is a
	// version that skips a number or names another predecessor.
	v2 := sign(t, k.owner, version(next, owner, withResources(next, "abovebeyond-ai/portal"), next.Systems))
	if _, err := Next(next, v1, k.signers, now); err == nil || !strings.Contains(err.Error(), "does not follow") {
		t.Fatalf("a replayed version must be refused, got %v", err)
	}
	skip := version(next, owner, next.Agents, next.Systems)
	skip.Version = 3
	if _, err := Next(next, sign(t, k.owner, skip), k.signers, now); err == nil {
		t.Fatal("a skipped number must be refused")
	}
	fork := version(next, owner, next.Agents, next.Systems)
	fork.Prev = head.Hash
	if _, err := Next(next, sign(t, k.owner, fork), k.signers, now); err == nil || !strings.Contains(err.Error(), "names") {
		t.Fatalf("a version naming another predecessor must be refused, got %v", err)
	}
	if _, err := Next(next, v2, k.signers, now); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyAKnownKeyWithAHoldingSignatureSpeaks(t *testing.T) {
	k := newLogKeys(t)
	head := bootHead()
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Next(head, sign(t, stranger, version(head, "did:x#someone", head.Agents, head.Systems)), k.signers, now); err == nil {
		t.Fatal("an unknown issuer must be refused")
	}
	// The owner's name on a signature made by another key.
	if _, err := Next(head, sign(t, stranger, version(head, owner, head.Agents, head.Systems)), k.signers, now); err == nil || !strings.Contains(err.Error(), "does not hold") {
		t.Fatalf("a forged signature must be refused, got %v", err)
	}
	// A working set is signed by the same key in the same form, and is not a policy.
	ws := version(head, owner, head.Agents, head.Systems)
	ws.Type = "working-set"
	if _, err := Next(head, sign(t, k.owner, ws), k.signers, now); err == nil {
		t.Fatal("a token of another type must be refused")
	}
	future := version(head, owner, head.Agents, head.Systems)
	future.Iat = now.Add(time.Hour).Unix()
	if _, err := Next(head, sign(t, k.owner, future), k.signers, now); err == nil {
		t.Fatal("a version from the future must be refused")
	}
	silent := version(head, owner, head.Agents, head.Systems)
	silent.Change = nil
	if _, err := Next(head, sign(t, k.owner, silent), k.signers, now); err == nil {
		t.Fatal("a version that does not say its change must be refused")
	}
}

func TestElixirOnlyTakesAway(t *testing.T) {
	k := newLogKeys(t)
	head := bootHead()
	narrower := version(head, elixir, withResources(head, "abovebeyond-ai/portal"), map[string]string{})
	if _, err := Next(head, sign(t, k.elixir, narrower), k.signers, now); err != nil {
		t.Fatalf("a removed repository and system is narrower: %v", err)
	}

	g := head.Agents[shed].Grant
	cases := map[string]func(g *Grant, agents map[string]HandGrant, systems map[string]string){
		"adds the resource": func(g *Grant, _ map[string]HandGrant, _ map[string]string) {
			g.Resources = append(g.Resources, "client/secret-repo")
		},
		"adds the kind":    func(g *Grant, _ map[string]HandGrant, _ map[string]string) { g.Kinds = append(g.Kinds, "pull.merge") },
		"raises the count": func(g *Grant, _ map[string]HandGrant, _ map[string]string) { g.MaxPerKind = 0 },
		"drops the certificate": func(g *Grant, _ map[string]HandGrant, _ map[string]string) {
			g.PremisesFor = nil
		},
		"changes who speaks": func(g *Grant, _ map[string]HandGrant, _ map[string]string) {
			g.PrincipalKeys = map[string]string{"did:x#elixir-own": "00"}
		},
		"accepts the judgement": func(g *Grant, _ map[string]HandGrant, _ map[string]string) {
			g.Judgements = []string{"MAJOR_UNDER_TESTS"}
		},
		"adds the hand": func(_ *Grant, agents map[string]HandGrant, _ map[string]string) {
			agents["did:x#agent-new"] = HandGrant{Grant: Grant{Kinds: []string{"pull.open"}}}
		},
		"adds the system": func(_ *Grant, _ map[string]HandGrant, systems map[string]string) {
			systems["observatory:pipeline"] = "https://observatory.example"
		},
		"moves the system": func(_ *Grant, _ map[string]HandGrant, systems map[string]string) {
			systems["stocklist:platform"] = "https://elsewhere.example"
		},
	}
	for want, change := range cases {
		grant := g
		grant.Kinds = append([]string{}, g.Kinds...)
		grant.Resources = append([]string{}, g.Resources...)
		agents := map[string]HandGrant{}
		systems := map[string]string{"stocklist:platform": "https://traders.example"}
		change(&grant, agents, systems)
		agents[shed] = HandGrant{Grant: grant}
		_, err := Next(head, sign(t, k.elixir, version(head, elixir, agents, systems)), k.signers, now)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: Elixir must be refused, got %v", want, err)
		}
		// The same version from the owner's token is a widening he may sign.
		if _, err := Next(head, sign(t, k.owner, version(head, owner, agents, systems)), k.signers, now); err != nil {
			t.Errorf("%s: the owner may sign it: %v", want, err)
		}
	}
}

func TestATaskNarrowingIsNarrowerAndDroppingItIsNot(t *testing.T) {
	cur := bootHead().Agents
	g := cur[shed].Grant
	g.Tasks = map[string]TaskGrant{"workbench": {Kinds: []string{"pull.open"}, PremisesFor: []string{"pull.open"}}}
	tasked := map[string]HandGrant{shed: {Grant: g}}
	if reason := Narrower(cur, nil, tasked, nil); reason != "" {
		t.Fatalf("narrowing a grant per task is narrower: %s", reason)
	}
	if reason := Narrower(tasked, nil, cur, nil); !strings.Contains(reason, "per task") {
		t.Fatalf("dropping the narrowing per task widens, got %q", reason)
	}
	wider := g
	wider.Tasks = map[string]TaskGrant{"workbench": {Kinds: []string{"pull.open", "branch.push"}, PremisesFor: []string{"pull.open"}}}
	if reason := Narrower(tasked, nil, map[string]HandGrant{shed: {Grant: wider}}, nil); !strings.Contains(reason, "to the task") {
		t.Fatalf("a kind added to a task widens, got %q", reason)
	}
	// A task's premises replace the grant's (ForTask), so a task without them drops the certificate.
	bare := g
	bare.Tasks = map[string]TaskGrant{"workbench": {Kinds: []string{"pull.open"}}}
	if reason := Narrower(cur, nil, map[string]HandGrant{shed: {Grant: bare}}, nil); !strings.Contains(reason, "drops the certificate") {
		t.Fatalf("a task without the grant's certificate widens, got %q", reason)
	}
}

func TestATokenThatIsNotAVersionDoesNotParse(t *testing.T) {
	for _, token := range []string{"", "one-part", "a.b.c", "!!.!!"} {
		if _, err := ParseVersion(token); err == nil {
			t.Errorf("%q parsed", token)
		}
	}
	unknown := base64.RawURLEncoding.EncodeToString([]byte(`{"type":"policy-version","widen_everything":true}`)) + ".AA"
	if _, err := ParseVersion(unknown); err == nil {
		t.Error("a payload with a field the gateway does not know must not parse")
	}
}
