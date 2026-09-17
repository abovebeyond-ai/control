package policy

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Schema is what a kind's parameters may be (row 4.1.4): every key named with its
// type, required or not; a key the schema does not name is out of schema and the
// call is refused. The registry is part of the policy bundle, so a record names
// the schema it was validated against.
type Schema struct {
	Required map[string]string `json:"required"`
	Optional map[string]string `json:"optional"`
}

// Types: "string", "hex64" (a sha-256 in hex), "hex40" (a git commit id in hex), "int" (a
// whole number), "number" (any finite number), "bool", "strings" (an object whose values
// are strings), "list" (an array of strings), "records" (an array of objects whose values
// are strings).
var Schemas = map[string]Schema{
	// The Portal kinds (since v0.17.0): what a hand writes to the operator's dashboard,
	// on the resource portal:<slug>. Every field Portal's ingest validation accepts is
	// named here with its type, and nothing else: the adapter forwards a kind's own
	// parameters only, so a key outside the schema is refused here rather than dropped
	// there while the record says it was written.
	"portal.update": {
		Required: map[string]string{"title": "string"},
		Optional: map[string]string{"date": "string", "clientVisible": "bool", "body": "list"},
	},
	"portal.time_entry": {
		Required: map[string]string{"hours": "number"},
		Optional: map[string]string{"date": "string", "note": "string", "billable": "bool"},
	},
	"portal.expense": {
		Required: map[string]string{"vendor": "string", "amount": "number"},
		// files_sha256 (since v0.18.0): the invoice travels attached, one file, digest bound like a push's files.
		Optional: map[string]string{"currency": "string", "date": "string", "description": "string", "invoiceNumber": "string", "rebillable": "bool", "files_sha256": "hex64"},
	},
	"portal.project.patch": {
		// Every field is optional and at least one must be present (the adapter checks);
		// clearNextAction empties the next action, since a null cannot be typed here.
		Required: map[string]string{},
		Optional: map[string]string{"status": "string", "nextAction": "string", "clearNextAction": "bool", "summary": "string", "milestones": "records", "stack": "list", "links": "records", "replaceLinks": "bool", "elixir": "bool", "productionTheirs": "bool"},
	},
	"portal.task": {
		Required: map[string]string{"key": "string", "state": "string"},
		Optional: map[string]string{"note": "string", "url": "string"},
	},
	"portal.measure": {
		Required: map[string]string{},
		Optional: map[string]string{"only": "string"},
	},
	"portal.playbook": {
		Required: map[string]string{"playbook": "string"},
		Optional: map[string]string{},
	},
	"workflow.dispatch": {
		Required: map[string]string{"workflow": "string", "ref": "string"},
		Optional: map[string]string{"packages": "int", "plan_sha256": "hex64", "inputs": "strings"},
	},
	"branch.push": {
		// The gateway creates the branch itself (since v0.11.0): from base_sha, with the
		// files the hand attached, whose canonical digest is files_sha256, so the judged
		// parameters bind what is pushed.
		Required: map[string]string{"branch": "string"},
		Optional: map[string]string{"packages": "int", "base_sha": "string", "message": "string", "files_sha256": "hex64"},
	},
	"branch.delete": {
		// A branch the gateway pushed and whose tests never went green: removed, on the
		// record, so nothing half-done stays behind in a client's repository.
		Required: map[string]string{"branch": "string"},
		Optional: map[string]string{"reason": "string"},
	},
	"pull.open": {
		// draft (since v0.14.0): opened as a draft, for a change whose only judge is the
		// pull request's own checks; pull.ready turns it into a proposal on green.
		Required: map[string]string{"branch": "string", "base": "string"},
		Optional: map[string]string{"title": "string", "body": "string", "packages": "int", "draft": "bool"},
	},
	// The review hand (13 September 2026): a page published, a person invited, a root
	// sealed. The page travels attached and digest-bound like a push's files; the root is
	// a sha-256 tag; a judgement is never a verb.
	"review.publish": {
		Required: map[string]string{"page_sha256": "hex64"},
		Optional: map[string]string{"title": "string", "by": "string"},
	},
	"review.invite": {
		// An empty optional set, not a nil one: the bundle beside the record is read back
		// through JSON, and a nil map would not digest to what the claims name.
		Required: map[string]string{"email": "string"},
		Optional: map[string]string{},
	},
	"review.sign": {
		Required: map[string]string{"root": "string"},
		Optional: map[string]string{"readings": "int", "judged": "int"},
	},
	// The preview (17 September 2026): a pull request put on a preview site through the
	// gateway, in one run of two steps. preview.push sets the one branch a preview site
	// tracks, named "preview" and no other (the policy holds it to that name), to the head
	// of the pull request; the number and the head are in the record, and since v0.27.0
	// optionally the base (params.base): the preview then shows GitHub's test merge of
	// the pull request onto that commit, what one gets after merging, and the record says
	// onto what. forge.deploy then
	// asks Forge to deploy that site, on the resource forge:<slug>, with the tokenless
	// trigger URL Forge gives per site, held in the gateway's secrets as forge-deploy-<slug>.
	// Until then the design had a Forge API token on the operator's laptop, which is the
	// one place a session's credential may not be.
	PreviewPushKind: {
		Required: map[string]string{"branch": "string", "sha": "hex40"},
		Optional: map[string]string{"pull": "int", "head": "string", "base": "hex40"},
	},
	ForgeDeployKind: {
		Required: map[string]string{},
		Optional: map[string]string{"sha": "hex40", "pull": "int"},
	},
	"pull.ready": {
		// A draft the gateway opened, marked ready for review once the pull request's
		// checks went green, with the body rewritten to say so; the footer the draft was
		// born with stays, so the merge check still finds the record that made it.
		Required: map[string]string{"number": "int"},
		Optional: map[string]string{"body": "string"},
	},
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Validate holds an action's parameters to the schema of its kind.
func Validate(a Action) error {
	s, ok := Schemas[a.Kind]
	if !ok {
		return fmt.Errorf("no parameter schema is registered for %s", a.Kind)
	}
	for key := range a.Params {
		if _, r := s.Required[key]; !r {
			if _, o := s.Optional[key]; !o {
				return fmt.Errorf("parameter %q is not in the schema of %s", key, a.Kind)
			}
		}
	}
	for key, typ := range s.Required {
		v, present := a.Params[key]
		if !present {
			return fmt.Errorf("parameter %q is required for %s", key, a.Kind)
		}
		if err := checkType(key, typ, v); err != nil {
			return err
		}
	}
	for key, typ := range s.Optional {
		if v, present := a.Params[key]; present {
			if err := checkType(key, typ, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkType(key, typ string, v any) error {
	switch typ {
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("parameter %q must be a string", key)
		}
	case "hex64":
		s, ok := v.(string)
		if !ok || !hex64.MatchString(s) {
			return fmt.Errorf("parameter %q must be a sha-256 in lowercase hex", key)
		}
	case "hex40":
		s, ok := v.(string)
		if !ok || !hex40.MatchString(s) {
			return fmt.Errorf("parameter %q must be a git commit id in lowercase hex", key)
		}
	case "int":
		switch n := v.(type) {
		case int:
		case int64:
		case float64:
			if n != math.Trunc(n) {
				return fmt.Errorf("parameter %q must be a whole number", key)
			}
		default:
			return fmt.Errorf("parameter %q must be a whole number", key)
		}
	case "bool":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("parameter %q must be true or false", key)
		}
	case "number":
		switch n := v.(type) {
		case int, int64:
		case float64:
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return fmt.Errorf("parameter %q must be a finite number", key)
			}
		default:
			return fmt.Errorf("parameter %q must be a number", key)
		}
	case "list":
		xs, ok := v.([]any)
		if !ok {
			return fmt.Errorf("parameter %q must be a list of strings", key)
		}
		for i, x := range xs {
			if _, ok := x.(string); !ok {
				return fmt.Errorf("parameter %q[%d] must be a string", key, i)
			}
		}
	case "records":
		xs, ok := v.([]any)
		if !ok {
			return fmt.Errorf("parameter %q must be a list of records", key)
		}
		for i, x := range xs {
			m, ok := x.(map[string]any)
			if !ok {
				return fmt.Errorf("parameter %q[%d] must be an object of strings", key, i)
			}
			for k, y := range m {
				if _, ok := y.(string); !ok {
					return fmt.Errorf("parameter %q[%d].%s must be a string", key, i, k)
				}
			}
		}
	case "strings":
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("parameter %q must be an object of strings", key)
		}
		for k, x := range m {
			if _, ok := x.(string); !ok {
				return fmt.Errorf("parameter %q.%s must be a string", key, k)
			}
		}
	default:
		return fmt.Errorf("unknown schema type %s", typ)
	}
	return nil
}

// schemaDocument is the registry in a canonical shape for the bundle.
func schemaDocument() map[string]any {
	out := map[string]any{}
	kinds := make([]string, 0, len(Schemas))
	for k := range Schemas {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := Schemas[k]
		out[k] = map[string]any{"required": s.Required, "optional": s.Optional}
	}
	return out
}

// Matched names the permission an allowed action matched (row 4.1.2).
func Matched(a Action, phi PathSummary, g Grant) string {
	n := phi.PerKind[a.Kind] + 1
	limit := "no limit"
	if g.MaxPerKind > 0 {
		limit = fmt.Sprintf("%d", g.MaxPerKind)
	}
	return strings.TrimSpace(fmt.Sprintf("%s on %s, %d of %s this run", a.Kind, a.Resource, n, limit))
}
