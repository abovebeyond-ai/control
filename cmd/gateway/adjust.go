package main

// Adjusting is a word on a changed act (docs/odoo-gate.md, the conversation carries everything).
// The person changes a value the view offers before giving their word; the relay brings the
// change to the gate:
//
//	POST /v1/pending/{id}/adjust  {"holder", "changes": [{"path", "value"}]}
//
// The gate checks each change against what the view offered (the path, whole, within its
// bounds), makes the changed act a new waiting word with a new payload and a new sealed request,
// and marks the old one replaced. The agent's submission stays as it signed it; the record says
// the act was changed by the person, from what to what (control_adjusted), and so does the
// receipt. The agent asking for the old id hears {"state":"replaced","by":<new id>}.
//
// The relay carries the adjustment and its answer, so neither says what the act is: the answer
// is {"state":"replaced","replaced":<old id>,"by":<new id>,"pending":<new id>}, and the new
// request, with its labels, values and bounds, reaches the phone sealed in its announcement. A
// change the gate does not take is answered with a code and a generic text; the detail (which
// line, its label, the bounds the budget gives) goes only into "sealed", an envelope for the
// holder's key (HPKE as a sealed request, info "bextrust adjust refusal v1", aad canonical
// {"holder","pending","kid"}, plaintext {"v","pending","holder","recipient","code","detail","sig"},
// sig the gate key's Ed25519 over the canonical plaintext without sig).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// adjustChange is one change the person made: which parameter, its label, from what to what.
type adjustChange struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	From  int64  `json:"from"`
	To    int64  `json:"to"`
}

func changesList(cs []adjustChange) []any {
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = map[string]any{"path": c.Path, "label": c.Label, "from": c.From, "to": c.To}
	}
	return out
}

// adjustedRecord is what the receipt says of the person's change, nil when there was none.
func adjustedRecord(p *pendingWord) map[string]any {
	if len(p.Adjusted) == 0 {
		return nil
	}
	return map[string]any{"from_pending": p.Replaces, "by": p.Holder, "changes": changesList(p.Adjusted)}
}

// adjustedExtension is the submission's extension with the gate's own account of an adjustment:
// whatever a submission put under control_adjusted is not taken.
func adjustedExtension(ext map[string]any, p *pendingWord) map[string]any {
	out := map[string]any{}
	for k, v := range ext {
		if k != "control_adjusted" {
			out[k] = v
		}
	}
	if a := adjustedRecord(p); a != nil {
		out["control_adjusted"] = a
	}
	return out
}

// mergeChanges keeps the first value a path had, across adjustments of adjustments.
func mergeChanges(before, now []adjustChange) []adjustChange {
	out := append([]adjustChange{}, before...)
	for _, c := range now {
		merged := false
		for i := range out {
			if out[i].Path == c.Path {
				out[i].To, merged = c.To, true
			}
		}
		if !merged {
			out = append(out, c)
		}
	}
	return out
}

// applyChange sets one adjustable parameter on a copy of the params: "qty", or "lines.<i>.qty".
func applyChange(params map[string]any, path string, v int64) error {
	if path == "qty" {
		params["qty"] = float64(v)
		return nil
	}
	parts := strings.Split(path, ".")
	if len(parts) != 3 || parts[0] != "lines" || parts[2] != "qty" {
		return fmt.Errorf("%s is not a parameter the gate changes", path)
	}
	i, err := strconv.Atoi(parts[1])
	lines, _ := params["lines"].([]any)
	if err != nil || i < 0 || i >= len(lines) {
		return fmt.Errorf("%s names no line", path)
	}
	line, ok := lines[i].(map[string]any)
	if !ok {
		return fmt.Errorf("%s names no line", path)
	}
	line["qty"] = float64(v)
	return nil
}

func (s *service) adjust(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Holder  string `json:"holder"`
		Changes []struct {
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"changes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || len(in.Changes) == 0 {
		writeJSON(w, 400, map[string]any{"error": "an adjustment is {holder, changes: [{path, value}]}"})
		return
	}
	p, status, view := s.claim(r.PathValue("id"))
	if p == nil {
		writeJSON(w, status, view)
		return
	}
	refuse := func(status int, code, detail string) {
		s.release(p)
		out := map[string]any{"error": adjustRefusals[code], "code": code}
		if detail != "" && in.Holder == p.Holder {
			if env := s.sealedRefusal(p, code, detail); env != nil {
				out["sealed"] = []sealedRequest{*env}
			}
		}
		writeJSON(w, status, out)
	}
	if in.Holder != p.Holder {
		refuse(403, "not_holder", "")
		return
	}
	s.pendMu.Lock()
	specs := append([]adjustSpec{}, p.Adjust...)
	s.pendMu.Unlock()
	if len(specs) == 0 {
		refuse(409, "not_adjustable", "")
		return
	}
	// The params through JSON, so the copy shares nothing with the waiting act.
	raw, _ := json.Marshal(p.Req.Action.Params)
	var params map[string]any
	_ = json.Unmarshal(raw, &params)
	var changes []adjustChange
	seen := map[string]bool{}
	for _, c := range in.Changes {
		var spec *adjustSpec
		for i := range specs {
			if specs[i].Path == c.Path {
				spec = &specs[i]
			}
		}
		if spec == nil || seen[c.Path] {
			refuse(400, "outside_view", fmt.Sprintf("%q is not something this act lets you adjust, or named twice", c.Path))
			return
		}
		seen[c.Path] = true
		v, err := strconv.ParseInt(strings.TrimSpace(string(c.Value)), 10, 64)
		if err != nil {
			refuse(400, "outside_view", fmt.Sprintf("%s takes a whole number", spec.Label))
			return
		}
		if v < spec.Min || v > spec.Max || (spec.Step > 1 && (v-spec.Min)%spec.Step != 0) {
			refuse(400, "outside_view", fmt.Sprintf("%s goes from %d to %d", spec.Label, spec.Min, spec.Max))
			return
		}
		if v == spec.Value {
			continue
		}
		if err := applyChange(params, c.Path, v); err != nil {
			refuse(400, "outside_view", err.Error())
			return
		}
		changes = append(changes, adjustChange{Path: c.Path, Label: spec.Label, From: spec.Value, To: v})
	}
	if len(changes) == 0 {
		refuse(400, "nothing_changed", "")
		return
	}
	g, err := s.gateway(p.Req.Agent)
	if err != nil {
		refuse(403, "grant", err.Error())
		return
	}
	req := p.Req
	req.Action = policy.Action{Kind: p.Req.Action.Kind, Resource: p.Req.Action.Resource, Params: params, Classification: p.Req.Action.Classification, Attached: p.Req.Action.Attached}
	if verdict, why := g.Precheck(req.Run, req.Action); verdict != "ALLOW" {
		refuse(403, "grant", "the grant does not allow the changed act: "+why)
		return
	}
	// The agent's reasoning as it gave it, and a line for what the person changed.
	req.Reasoning = append(reasoning{}, p.Req.Reasoning...)
	for _, c := range changes {
		req.Reasoning = append(req.Reasoning, fmt.Sprintf("%s changed %s from %d to %d.", p.Holder, c.Label, c.From, c.To))
	}
	q, err := s.newPending(req, p.Body, p.Signature, p.Holder, s.cfg.Agents[p.Req.Agent].Grant.Org)
	if err != nil {
		refuse(429, "busy", "")
		return
	}
	s.pendMu.Lock()
	q.Replaces, q.Adjusted = p.ID, mergeChanges(p.Adjusted, changes)
	p.busy, p.State, p.ReplacedBy, p.Done = false, "replaced", q.ID, time.Now()
	s.pendMu.Unlock()
	s.stateChanged()
	// The new request is sealed and announced before the answer, so the relay has it when it
	// tells the phone the old one was replaced.
	s.announceSealed(q)
	writeJSON(w, 200, map[string]any{"state": "replaced", "replaced": p.ID, "by": q.ID, "pending": q.ID})
}

// adjustRefusals are the texts the relay may carry of a change the gate did not take: they name
// no line, label, value or bound.
var adjustRefusals = map[string]string{
	"not_holder":      "only the person asked may adjust this act",
	"not_adjustable":  "nothing of this act may be adjusted",
	"outside_view":    "the change is outside what the view allows",
	"nothing_changed": "the change leaves the act as it was",
	"grant":           "the grant does not allow the changed act",
	"busy":            "too many writes wait for a word; ask again later",
}

// adjustRefusalInfo is HPKE's info for the detail of a refused adjustment.
const adjustRefusalInfo = "bextrust adjust refusal v1"

// sealedRefusal seals why a change was not taken to the holder's key, signed by the gate; nil
// when the holder has no key the gate can verify.
func (s *service) sealedRefusal(p *pendingWord, code, detail string) *sealedRequest {
	entry := s.holderEntry(p.Holder)
	if entry == nil || entry.Enc == nil {
		return nil
	}
	plain := map[string]any{"v": 1, "pending": p.ID, "holder": p.Holder, "code": code, "detail": detail}
	env, err := s.sealFor(*entry.Enc, p.Holder, adjustRefusalInfo, p.ID, 0, plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "adjust %s: the refusal could not be sealed: %v\n", p.ID, err)
		return nil
	}
	return &env
}
