package policy

import (
	"fmt"
	"reflect"
	"sort"
)

// Kind is one row of the kind table: what an action of this kind may carry (its schema), which
// adapter performs it, how far it reaches (its radius), which parameter binds attached files,
// and the words the owner reads it in. The table is the one place a kind is described: the
// gateway judges by it, serves it on /v1/agents, and Portal, Elixir and the hand read it there
// instead of keeping lists of their own (docs/kinds.md).
type Kind struct {
	// Adapter performs the kind: github, portal, forge, system, or gateway for the run kinds
	// the gateway performs itself.
	Adapter string `json:"adapter"`
	// Radius is B1 or B2 for a kind a repair key may add and a working set may admit, empty for
	// one that only the owner's token grants (it reaches a person or cannot be called back).
	Radius string `json:"radius,omitempty"`
	// Why says what bounds the radius, in the words the owner signs.
	Why string `json:"why,omitempty"`
	// Files names the parameter that binds the attached files by digest: the files must be
	// attached and match it when the parameter is required, and when it or a file is present
	// otherwise. Empty: the kind takes no files.
	Files string `json:"files,omitempty"`
	// On names the running systems a system kind acts on, by resource ("stocklist:platform"):
	// the gateway refuses it on any other, whatever the grant covers. Empty for a kind whose
	// adapter is code, which knows its own resources.
	On []string `json:"on,omitempty"`
	// Place and Words: the kind as the owner reads it, under its type of action.
	Place string `json:"place"`
	Words string `json:"words"`
	Schema
}

// Kinds is the kind table by name.
type Kinds map[string]Kind

// SystemAdapter is the adapter a kind defined in the policy performs through: it carries the
// action to the running system, which verifies the capability and the record itself. It is
// the only adapter whose kinds need no code in this gateway, so the only one a policy version
// may name (docs/kinds.md).
const SystemAdapter = "system"

// GatewayAdapter performs the run kinds: the gateway itself, nothing beyond its own record.
const GatewayAdapter = "gateway"

// Builtin are the kinds whose effect is code in this release. A kind performed by code keeps
// its description beside that code: a schema in the policy for an effect the binary carries out
// would be two things that must agree. Kinds on a running system may be defined in the policy
// instead (LogVersion.Kinds); the four below came before that and stay until the owner signs a
// version that carries them.
var Builtin = Kinds{
	// The GitHub kinds, on owner/repo resources.
	"workflow.dispatch": {Adapter: "github", Place: "Runs a repair in CI", Words: "start a repair workflow on the repository",
		Schema: Schema{Required: map[string]string{"workflow": "string", "ref": "string"}, Optional: map[string]string{"packages": "int", "plan_sha256": "hex64", "inputs": "strings"}}},
	// The gateway creates the branch itself (since v0.11.0): from base_sha, with the files the
	// hand attached, whose canonical digest is files_sha256, so the judged parameters bind what
	// is pushed. Required since the kind table: the gateway already refused a push without it.
	"branch.push": {Adapter: "github", Radius: "B2", Why: "a branch nobody has merged", Files: "files_sha256", Place: "Proposes code", Words: "push a branch",
		Schema: Schema{Required: map[string]string{"branch": "string", "files_sha256": "hex64"}, Optional: map[string]string{"packages": "int", "base_sha": "string", "message": "string"}}},
	// A branch the gateway pushed and whose tests never went green: removed, on the record, so
	// nothing half-done stays behind in a client's repository.
	"branch.delete": {Adapter: "github", Place: "Proposes code", Words: "delete a branch of its own that never went green",
		Schema: Schema{Required: map[string]string{"branch": "string"}, Optional: map[string]string{"reason": "string"}}},
	// draft (since v0.14.0): opened as a draft, for a change whose only judge is the pull
	// request's own checks; pull.ready turns it into a proposal on green.
	"pull.open": {Adapter: "github", Radius: "B2", Why: "a pull request that waits for the owner's merge", Place: "Proposes code", Words: "open a pull request",
		Schema: Schema{Required: map[string]string{"branch": "string", "base": "string"}, Optional: map[string]string{"title": "string", "body": "string", "packages": "int", "draft": "bool"}}},
	// A draft the gateway opened, marked ready once its checks went green, with the body
	// rewritten to say so; the footer stays, so the merge check still finds the record.
	"pull.ready": {Adapter: "github", Place: "Proposes code", Words: "mark its pull request ready once the tests pass",
		Schema: Schema{Required: map[string]string{"number": "int"}, Optional: map[string]string{"body": "string"}}},
	// issue.open (19 September 2026): the mirror of a finding that lives in the repository; the
	// body carries the path of the finding, so the issue never becomes a second truth.
	"issue.open": {Adapter: "github", Radius: "B2", Why: "an issue on the owner's own repository, closed in one step", Place: "Proposes code", Words: "open an issue",
		Schema: Schema{Required: map[string]string{"title": "string"}, Optional: map[string]string{"body": "string", "labels": "[]string", "finding": "string"}}},
	// The preview (17 September 2026): preview.push sets the one branch a preview site tracks,
	// named preview and no other, to the head of a pull request (optionally onto base, GitHub's
	// test merge); forge.deploy asks Forge to deploy that site, with the tokenless trigger URL
	// held in the gateway's secrets as forge-deploy-<slug>.
	PreviewPushKind: {Adapter: "github", Radius: "B2", Why: "moves the branch named preview, which only a preview site tracks", Place: "Shows a preview", Words: "put a pull request on the preview site",
		Schema: Schema{Required: map[string]string{"branch": "string", "sha": "hex40"}, Optional: map[string]string{"pull": "int", "head": "string", "base": "hex40"}}},
	ForgeDeployKind: {Adapter: "forge", Radius: "B2", Why: "deploys the preview site, which the next preview replaces", Place: "Shows a preview", Words: "deploy that preview",
		Schema: Schema{Required: map[string]string{}, Optional: map[string]string{"sha": "hex40", "pull": "int"}}},

	// The Portal kinds (since v0.17.0), on the resource portal:<slug>: every field Portal's
	// ingest accepts, and nothing else, since the adapter forwards a kind's own parameters only.
	"portal.update": {Adapter: "portal", Radius: "B2", Why: "one update in Portal, edited or deleted there", Place: "Records in Portal", Words: "post an update",
		Schema: Schema{Required: map[string]string{"title": "string"}, Optional: map[string]string{"date": "string", "clientVisible": "bool", "body": "list"}}},
	"portal.time_entry": {Adapter: "portal", Radius: "B2", Why: "one time entry in Portal, edited or deleted there", Place: "Records in Portal", Words: "log hours",
		Schema: Schema{Required: map[string]string{"hours": "number"}, Optional: map[string]string{"date": "string", "note": "string", "billable": "bool"}}},
	// files_sha256 (since v0.18.0): the invoice travels attached, one file, bound like a push's.
	"portal.expense": {Adapter: "portal", Radius: "B2", Why: "one expense in Portal, edited or deleted there", Files: "files_sha256", Place: "Records in Portal", Words: "log an expense",
		Schema: Schema{Required: map[string]string{"vendor": "string", "amount": "number"}, Optional: map[string]string{"currency": "string", "date": "string", "description": "string", "invoiceNumber": "string", "rebillable": "bool", "files_sha256": "hex64"}}},
	// Every field optional, at least one present (the adapter checks); clearNextAction empties
	// the next action, since a null cannot be typed here.
	"portal.project.patch": {Adapter: "portal", Radius: "B2", Why: "project fields in Portal, set back in one step", Place: "Steers in Portal", Words: "change project settings",
		Schema: Schema{Required: map[string]string{}, Optional: map[string]string{"status": "string", "nextAction": "string", "clearNextAction": "bool", "summary": "string", "milestones": "records", "stack": "list", "links": "records", "replaceLinks": "bool", "elixir": "bool", "productionTheirs": "bool"}}},
	"portal.task": {Adapter: "portal", Radius: "B2", Why: "a task's state in Portal, set back in one step", Place: "Steers in Portal", Words: "set a task",
		Schema: Schema{Required: map[string]string{"key": "string", "state": "string"}, Optional: map[string]string{"note": "string", "url": "string"}}},
	"portal.measure": {Adapter: "portal", Radius: "B1", Why: "queues a measurement; nothing changes but a reading", Place: "Steers in Portal", Words: "ask for a measurement",
		Schema: Schema{Required: map[string]string{}, Optional: map[string]string{"only": "string"}}},
	"portal.playbook": {Adapter: "portal", Radius: "B2", Why: "queues a playbook, whose own actions are judged one by one", Place: "Steers in Portal", Words: "start a playbook",
		Schema: Schema{Required: map[string]string{"playbook": "string"}, Optional: map[string]string{}}},
	// A document behind a link and a passphrase (portal#399): the document attached and digest
	// bound, the passphrase only as its hash (optional since v0.40.0: without it the link is
	// the key, and every open is still on record).
	"portal.share": {Adapter: "portal", Radius: "B2", Why: "one share in Portal, ended there in one step", Files: "files_sha256", Place: "Records in Portal", Words: "share a document behind a passphrase",
		Schema: Schema{Required: map[string]string{"title": "string", "files_sha256": "hex64"}, Optional: map[string]string{"days": "int", "passphrase_hash": "string"}}},

	// The review hand's kinds (review.publish, review.invite, review.sign, since 13 September
	// 2026) left with the Vera app in October 2026. Their records stay checkable: a record
	// carries its own action and parameters, and nothing in the chain reads this table back.

	// The run kinds (docs/run-lifecycle.md): a hand's own word on its run, judged under a
	// grant's lifecycle and performed by the gateway, whose record is the whole effect.
	RunOpenKind: {Adapter: GatewayAdapter, Place: "Works in runs", Words: "start a run, or take over one handed on",
		Schema: Schema{Required: map[string]string{}, Optional: map[string]string{"goal": "string", "continues": "string"}}},
	RunCheckpointKind: {Adapter: GatewayAdapter, Place: "Works in runs", Words: "say where a run stands",
		Schema: Schema{Required: map[string]string{"summary": "string"}, Optional: map[string]string{"next": "list", "state": "strings"}}},
	RunCloseKind: {Adapter: GatewayAdapter, Place: "Works in runs", Words: "end a run as done, handed over or abandoned",
		Schema: Schema{Required: map[string]string{"outcome": "string", "summary": "string"}, Optional: map[string]string{"next": "list", "checks": "records", "state": "strings"}}},

	// Actions on a running system (docs/mandates.md), one kind per action, never a generic
	// command. The photo repair of one car on Stocklist: without apply it only reports.
	"stocklist.photos_repair": {Adapter: SystemAdapter, On: []string{"stocklist:platform"}, Radius: "B2", Why: "writes derived photo sizes a later run can write again", Place: "Repairs a live system", Words: "repair the photos of one car on Stocklist, a dry run first and the repair only on a separate yes",
		Schema: Schema{Required: map[string]string{"vehicle": "int"}, Optional: map[string]string{"apply": "bool"}}},
	// A research brief for the Gentells desk; only an editor approves, in the Studio.
	"studio.research_draft": {Adapter: SystemAdapter, On: []string{"observatory:pipeline"}, Radius: "B2", Why: "one brief for review; an editor approves or dismisses it", Place: "Writes to a live system", Words: "set out a research brief for the Gentells desk, ready for review; an editor approves it in the Studio",
		Schema: Schema{Required: map[string]string{"title": "string", "description": "string"}, Optional: map[string]string{"context": "string", "sources": "records", "status": "string"}}},
	"observatory.trend_edit": {Adapter: SystemAdapter, On: []string{"observatory:pipeline"}, Radius: "B2", Why: "rewrites one trend's text; the text before is kept, one step undoes it", Place: "Writes to a live system", Words: "rewrite one trend's headline or reading, undone in one step",
		Schema: Schema{Required: map[string]string{"trend": "string", "field": "string", "text": "string"}, Optional: map[string]string{}}},
	"observatory.trend_site": {Adapter: SystemAdapter, On: []string{"observatory:pipeline"}, Radius: "B2", Why: "puts one trend on the site or takes it off; deciding again reverses it", Place: "Writes to a live system", Words: "put one trend on gentells.com or take it off",
		Schema: Schema{Required: map[string]string{"trend": "string", "action": "string"}, Optional: map[string]string{}}},
}

// With is the table with the kinds a policy version defines added to the built-in ones.
func (t Kinds) With(defined Kinds) Kinds {
	if len(defined) == 0 {
		return t
	}
	out := make(Kinds, len(t)+len(defined))
	for k, v := range t {
		out[k] = v
	}
	for k, v := range defined {
		out[k] = v
	}
	return out
}

// Of lists the kinds an adapter performs, sorted.
func (t Kinds) Of(adapter string) []string {
	out := []string{}
	for k, v := range t {
		if v.Adapter == adapter {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Acts says why the kind is not performed on the resource, or "": a system kind acts only on
// the systems its row names.
func (t Kinds) Acts(kind, resource string) string {
	d := t[kind]
	if d.Adapter == SystemAdapter && !containsString(d.On, resource) {
		return kind + " acts on " + listed(d.On) + ", not on " + resource
	}
	return ""
}

func listed(xs []string) string {
	if len(xs) == 0 {
		return "no system"
	}
	out := xs[0]
	for _, x := range xs[1:] {
		out += ", " + x
	}
	return out
}

// IsRepair says whether a repair key may add the kind: it has a radius of B1 or B2.
func (t Kinds) IsRepair(kind string) bool {
	return t[kind].Radius != ""
}

// Layers are the radii a repair key and a working set reach, lowest first.
var Layers = []string{"B1", "B2"}

// CheckDefined holds the kinds a policy version defines to what a definition may say: a kind on
// a running system (the system adapter), not a name the release already performs, a radius of
// B1 or B2 or none with what bounds it, the words the owner reads, and a schema of known types.
func CheckDefined(defined Kinds) error {
	names := make([]string, 0, len(defined))
	for k := range defined {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		d := defined[k]
		if _, ok := Builtin[k]; ok {
			return fmt.Errorf("the kind %s is performed by this release and is not defined in a policy", k)
		}
		if d.Adapter != SystemAdapter {
			return fmt.Errorf("the kind %s names the adapter %q; a policy defines kinds on a running system only", k, d.Adapter)
		}
		if d.Files != "" {
			return fmt.Errorf("the kind %s binds files; an action on a running system carries none", k)
		}
		if len(d.On) == 0 {
			return fmt.Errorf("the kind %s names no running system it acts on", k)
		}
		switch {
		case d.Radius == "" && d.Why != "":
			return fmt.Errorf("the kind %s says what bounds a radius it does not have", k)
		case d.Radius != "" && !containsString(Layers, d.Radius):
			return fmt.Errorf("the kind %s has the radius %q, not B1 or B2", k, d.Radius)
		case d.Radius != "" && d.Why == "":
			return fmt.Errorf("the kind %s does not say what bounds its radius", k)
		}
		if d.Place == "" || d.Words == "" {
			return fmt.Errorf("the kind %s has no words for the owner to read", k)
		}
		if d.Required == nil || d.Optional == nil {
			return fmt.Errorf("the kind %s needs a required and an optional set, empty or not", k)
		}
		for _, set := range []map[string]string{d.Required, d.Optional} {
			for key, typ := range set {
				if !containsString(schemaTypes, typ) {
					return fmt.Errorf("the kind %s gives %q the unknown type %q", k, key, typ)
				}
			}
		}
		for key := range d.Required {
			if _, both := d.Optional[key]; both {
				return fmt.Errorf("the kind %s names %q both required and optional", k, key)
			}
		}
	}
	return nil
}

// definedNarrower says why next defines more than cur, or "": a version that takes away may
// drop a definition and change nothing else, since a changed schema, radius or set of words is
// something the owner signs.
func definedNarrower(cur, next Kinds) string {
	names := make([]string, 0, len(next))
	for k := range next {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		was, ok := cur[k]
		if !ok {
			return "defines the kind " + k
		}
		if !reflect.DeepEqual(was, next[k]) {
			return "changes the definition of the kind " + k
		}
	}
	return ""
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
