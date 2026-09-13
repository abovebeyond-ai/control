package effects

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// Portal performs what a hand writes to Portal: an update on a project, hours, a cost, a
// project field, the state of a task, a request to measure or to run a playbook. Until
// 13 September 2026 these went straight from a session's machine to Portal's ingest API
// on the owner's token, so Portal could not tell the operator's hand from a session's and
// nothing recorded which was which. Here the token lives in the gateway's secrets
// (portal-token), the hand proposes, and every write on Portal is a record like a push.
//
// The resource of every kind is "portal:<slug>", the project as Portal names it; the
// prefix keeps a project apart from an owner/repo in the same grant.
type Portal struct {
	SecretsDir string
	Client     *http.Client
	Base       string // https://portal.abovebeyond.ai
}

// PortalResourcePrefix is what a Portal resource starts with.
const PortalResourcePrefix = "portal:"

func (p Portal) Kinds() []string {
	return []string{"portal.update", "portal.time_entry", "portal.expense", "portal.project.patch", "portal.task", "portal.measure", "portal.playbook"}
}

// projectFields are the fields a project patch may carry: the same list lib/portal.mjs on
// the operator's machine refuses everything outside of, so an unknown field is refused
// here rather than dropped by Portal's validation and reported as written.
var projectFields = map[string]bool{"status": true, "nextAction": true, "milestones": true, "summary": true, "stack": true, "links": true, "replaceLinks": true, "elixir": true, "productionTheirs": true}

func (p Portal) token() (string, error) {
	raw, err := os.ReadFile(filepath.Join(p.SecretsDir, "portal-token"))
	if err != nil {
		return "", fmt.Errorf("no Portal token in the gateway's secrets")
	}
	return strings.TrimSpace(string(raw)), nil
}

// PortalSlug reads the project out of a Portal resource.
func PortalSlug(resource string) (string, bool) {
	slug, ok := strings.CutPrefix(resource, PortalResourcePrefix)
	if !ok || slug == "" || strings.ContainsAny(slug, "/ ?#") {
		return "", false
	}
	return slug, true
}

func (p Portal) Perform(ctx context.Context, a policy.Action) Outcome {
	slug, ok := PortalSlug(a.Resource)
	if !ok {
		return Outcome{Error: "resource is not portal:<slug>"}
	}
	token, err := p.token()
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	base := p.Base
	if base == "" {
		base = "https://portal.abovebeyond.ai"
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	str := func(k string) string { s, _ := a.Params[k].(string); return s }
	call := func(method, path string, body map[string]any) (int, map[string]any, error) {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, base+"/api/ingest/"+path, &buf)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		// The evidence travels with the effect (row 8.3.5), as a dispatch carries it in
		// its inputs and a pull request in its footer: Portal can keep the record and
		// the capability beside what was written, and refuse what nobody judged.
		if ev := str("evidence"); ev != "" {
			req.Header.Set("Control-Evidence", ev)
		}
		if capTok := str("capability"); capTok != "" {
			req.Header.Set("Control-Capability", capTok)
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return res.StatusCode, out, nil
	}
	answered := func(status int, body map[string]any) string {
		msg := body["message"]
		if r, ok := body["refused"]; ok {
			msg = r
		}
		return fmt.Sprintf("Portal answered %d: %v", status, msg)
	}
	// Only the parameters a kind names go to Portal: the evidence fields the gateway
	// added ride in the headers, and a stray field never becomes a write.
	pick := func(keys ...string) map[string]any {
		out := map[string]any{"project": slug}
		for _, k := range keys {
			if v, ok := a.Params[k]; ok && v != nil {
				out[k] = v
			}
		}
		return out
	}
	switch a.Kind {
	case "portal.update":
		if str("title") == "" {
			return Outcome{Error: "portal.update needs params.title"}
		}
		status, body, err := call("POST", "update", pick("title", "date", "clientVisible", "body"))
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "title": str("title"), "clientVisible": a.Params["clientVisible"] == true}}
	case "portal.time_entry":
		if _, ok := a.Params["hours"].(float64); !ok {
			return Outcome{Error: "portal.time_entry needs params.hours"}
		}
		status, body, err := call("POST", "time-entry", pick("date", "hours", "note", "billable"))
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "hours": a.Params["hours"]}}
	case "portal.expense":
		if _, ok := a.Params["amount"].(float64); !ok || str("vendor") == "" {
			return Outcome{Error: "portal.expense needs params.vendor and params.amount"}
		}
		// A file (an invoice) is not carried yet: it is an attachment, and it comes with
		// the same digest binding a branch.push's files have. Until then a cost goes in
		// without its document and the person attaches it in Portal.
		status, body, err := call("POST", "expense", pick("vendor", "amount", "currency", "date", "description", "invoiceNumber", "rebillable"))
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "vendor": str("vendor"), "amount": a.Params["amount"]}}
	case "portal.project.patch":
		fields, _ := a.Params["fields"].(map[string]any)
		if len(fields) == 0 {
			return Outcome{Error: "portal.project.patch needs params.fields"}
		}
		for k := range fields {
			if !projectFields[k] {
				return Outcome{Error: "portal.project.patch does not carry the field " + k}
			}
		}
		status, body, err := call("PATCH", "project/"+slug, fields)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		names := make([]string, 0, len(fields))
		for k := range fields {
			names = append(names, k)
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "fields": names}}
	case "portal.task":
		key, state := str("key"), str("state")
		if key == "" || state == "" || strings.ContainsAny(key, "/ ?#") {
			return Outcome{Error: "portal.task needs params.key and params.state"}
		}
		payload := map[string]any{"state": state}
		for _, k := range []string{"note", "url"} {
			if v := str(k); v != "" {
				payload[k] = v
			}
		}
		status, body, err := call("POST", "tasks/"+slug+"/"+key, payload)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "key": key, "state": state}}
	case "portal.measure":
		payload := map[string]any{}
		if only := str("only"); only != "" {
			payload["only"] = only
		}
		status, body, err := call("POST", "measure/"+slug, payload)
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "queued": body["queued"], "only": str("only")}}
	case "portal.playbook":
		playbook := str("playbook")
		if playbook == "" || strings.ContainsAny(playbook, "/ ?#") {
			return Outcome{Error: "portal.playbook needs params.playbook"}
		}
		status, body, err := call("POST", "playbooks/"+playbook+"/"+slug, map[string]any{})
		if err != nil {
			return Outcome{Error: err.Error()}
		}
		if status/100 != 2 {
			return Outcome{Error: answered(status, body)}
		}
		return Outcome{OK: true, Detail: map[string]any{"project": slug, "playbook": playbook, "queued": body["queued"]}}
	}
	return Outcome{Error: "no adapter for " + a.Kind}
}
