package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abovebeyond-ai/control/policy"
)

func (r *stateRig) post(handler func(w *httptest.ResponseRecorder, id string, body []byte), id string, body any) (int, map[string]any) {
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	handler(rec, id, raw)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (r *stateRig) adjust(s *service, id string, body any) (int, map[string]any) {
	return r.post(func(w *httptest.ResponseRecorder, id string, raw []byte) {
		req := httptest.NewRequest("POST", "/v1/pending/x/adjust", bytes.NewReader(raw))
		req.SetPathValue("id", id)
		s.adjust(w, req)
	}, id, body)
}

// The person changes a quantity before their word: the gate checks it against what the view
// offered, makes the changed act a new word and marks the old one replaced; the agent asking
// for the old id learns which took its place; the word on the new one drafts the changed
// quantity, and the record and the receipt say who changed what, from what to what.
func TestAnAdjustedActIsANewWord(t *testing.T) {
	r := newStateRig(t)
	s := r.gate()
	id, oldPayload := r.ask(s)
	waitFor(t, "the request announced", func() bool { return r.announcedFor(id) == 1 })
	s.pendMu.Lock()
	adj := s.pending[id].Adjust
	s.pendMu.Unlock()
	// Shane's ceiling is 5000 and a desk costs 600 at cost: at most 8.
	if len(adj) != 1 || adj[0].Path != "lines.0.qty" || adj[0].Value != 2 || adj[0].Min != 1 || adj[0].Max != 8 || adj[0].Label != "Corner Desk" {
		t.Fatalf("%+v", adj)
	}
	for _, bad := range []map[string]any{
		{"holder": "acme#tom", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 5}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 9}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.product_id", "value": 20}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 2.5}}},
		{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 2}}},
	} {
		if code, out := r.adjust(s, id, bad); code/100 == 2 {
			t.Fatalf("%v taken: %v", bad, out)
		}
	}
	code, out := r.adjust(s, id, map[string]any{"holder": "acme#shane", "changes": []any{map[string]any{"path": "lines.0.qty", "value": 5}}})
	if code != 200 || out["state"] != "replaced" || out["replaced"] != id || out["by"] == nil || out["by"] != out["pending"] {
		t.Fatalf("%d %v", code, out)
	}
	newID := out["by"].(string)
	// The relay has the new request, which names the one it replaces.
	r.mu.Lock()
	var ann map[string]any
	for _, a := range r.announce {
		if a["pending"] == newID {
			ann = a
		}
	}
	r.mu.Unlock()
	if ann == nil || ann["replaces"] != id {
		t.Fatalf("%v", ann)
	}
	// The agent asking for the old id hears which took its place; a word on it is refused.
	st := httptest.NewRequest("GET", "/v1/pending/"+id, nil)
	st.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	s.pendingState(rec, st)
	if !strings.Contains(rec.Body.String(), `"state":"replaced"`) || !strings.Contains(rec.Body.String(), `"by":"`+newID+`"`) {
		t.Fatalf("%s", rec.Body.String())
	}
	if old := r.word(s, id, oldPayload); old != nil {
		t.Fatalf("a word on the replaced act: %v", old)
	}
	s.pendMu.Lock()
	q := s.pending[newID]
	if q.Req.Action.Params["lines"].([]any)[0].(map[string]any)["qty"] != float64(5) || len(q.Req.Reasoning) != 3 ||
		q.Req.Reasoning[2] != "acme#shane changed Corner Desk from 2 to 5." || q.Req.Reason != "Desks are short" {
		t.Fatalf("%+v", q.Req)
	}
	s.pendMu.Unlock()

	payload, _ := base64.RawURLEncoding.DecodeString(out["payload"].(string))
	rec2 := r.word(s, newID, payload)
	if rec2["verdict"] != "ALLOW" || rec2["effect"].(map[string]any)["ok"] != true {
		t.Fatalf("%v", rec2)
	}
	if len(r.createdQty) != 1 || r.createdQty[0] != 5 || r.creates[0] != "bextrust:"+newID {
		t.Fatalf("%v %v", r.createdQty, r.creates)
	}
	// The record keeps the gate's account of the change.
	records, err := s.store.Records(r.agent)
	if err != nil || len(records) == 0 {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(records[len(records)-3].Claims())
	if !strings.Contains(string(claims), `"control_adjusted"`) || !strings.Contains(string(claims), `"from_pending":"`+id+`"`) {
		t.Fatalf("the request record: %s", claims)
	}
	// The receipt says so.
	s.flushReceipts()
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	for _, e := range r.receipts {
		plain, err := openReceipt(r.audit, e)
		if err != nil {
			t.Fatal(err)
		}
		var p map[string]any
		_ = json.Unmarshal(plain, &p)
		if a, ok := p["adjusted"].(map[string]any); ok {
			c := a["changes"].([]any)[0].(map[string]any)
			if a["from_pending"] != id || a["by"] != "acme#shane" || c["from"] != float64(2) || c["to"] != float64(5) {
				t.Fatalf("%v", a)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no receipt says the act was adjusted")
	}
}

// A submission cannot claim an adjustment: control_adjusted comes from the gate only.
func TestASubmissionCannotClaimAnAdjustment(t *testing.T) {
	p := &pendingWord{Holder: "acme#shane"}
	ext := adjustedExtension(map[string]any{"control_adjusted": "forged", "x": 1}, p)
	if _, ok := ext["control_adjusted"]; ok || ext["x"] != 1 {
		t.Fatalf("%v", ext)
	}
	p.Adjusted, p.Replaces = []adjustChange{{Path: "qty", Label: "Hops", From: 62, To: 80}}, "old"
	if a := adjustedExtension(nil, p)["control_adjusted"].(map[string]any); a["from_pending"] != "old" {
		t.Fatalf("%v", a)
	}
}

// Every Odoo kind has a view any app draws from the display alone; the draft and the quantity
// change offer their quantities within the holder's ceiling and what is left of the day.
func TestEveryOdooKindHasAView(t *testing.T) {
	order := map[string]any{"order": "P00031", "state": "draft", "partner": "Mouterij De Schelde", "partner_id": int64(77), "currency": "EUR",
		"date_order": "2026-10-18", "date_planned": "2026-10-21",
		"lines":   []any{map[string]any{"product_id": int64(71), "name": "[BEER-MALT-PALE] Pale malt", "code": "BEER-MALT-PALE", "qty": int64(90), "uom": "bag", "unit_price": "21.50", "subtotal": "1935.00"}},
		"untaxed": "1935.00", "tax": "406.35", "total": "2341.35"}
	b := budget{known: true, ceiling: 500000, daily: true, leftDay: 300000}

	draft := policy.Action{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(77), "lines": []any{map[string]any{"product_id": float64(71), "qty": float64(90)}}}}
	v, adj := buildView(draft, map[string]any{"partner": "Mouterij De Schelde", "partner_id": int64(77), "currency": "EUR", "date_planned": "2026-10-21", "total_at_cost": "1935.00",
		"lines": []any{map[string]any{"product_id": int64(71), "name": "[BEER-MALT-PALE] Pale malt", "qty": int64(90), "uom": "bag", "unit_cost": "21.50", "subtotal": "1935.00", "last_price": "21.00", "last_date": "2026-09-30"}}}, b)
	raw, _ := json.Marshal(v)
	// The day leaves 3000.00: 139 bags of 21.50.
	if v["title"] != "Draft an order at Mouterij De Schelde" || len(adj) != 1 || adj[0].Max != 139 || adj[0].Label != "[BEER-MALT-PALE] Pale malt, bag" ||
		!strings.Contains(string(raw), `"90 bag"`) || !strings.Contains(string(raw), `"21.00 on 2026-09-30"`) || !strings.Contains(string(raw), `"1935.00 EUR"`) {
		t.Fatalf("%s %+v", raw, adj)
	}

	lineSet := map[string]any{}
	for k, x := range order {
		lineSet[k] = x
	}
	lineSet["line"] = map[string]any{"product": "[BEER-MALT-PALE] Pale malt", "qty_now": int64(90), "qty": int64(100), "unit_price": "21.50"}
	lineSet["total_after_estimate"] = "2150.00"
	v, adj = buildView(policy.Action{Kind: "odoo.order_line_set", Params: map[string]any{"order": float64(31), "line": float64(5), "qty": float64(100)}}, lineSet, b)
	raw, _ = json.Marshal(v)
	// Ceiling: 90 + (5000.00 - 2341.35) / 21.50 = 213; the day: 90 + 3000.00 / 21.50 = 229.
	if v["title"] != "Change a quantity on P00031" || len(adj) != 1 || adj[0].Path != "qty" || adj[0].Value != 100 || adj[0].Max != 213 ||
		!strings.Contains(string(raw), "Pale malt: 90 to 100") || !strings.Contains(string(raw), `"2341.35 EUR"`) {
		t.Fatalf("%s %+v", raw, adj)
	}

	for kind, title := range map[string]string{"odoo.order_cancel": "Cancel P00031", "odoo.order_request_approval": "Ask for approval of P00031"} {
		v, adj := buildView(policy.Action{Kind: kind, Params: map[string]any{"order": float64(31)}}, order, b)
		raw, _ := json.Marshal(v)
		if v["title"] != title || adj != nil || v["adjust"] != nil || !strings.Contains(string(raw), `"406.35 EUR"`) || !strings.Contains(string(raw), `"2026-10-21"`) {
			t.Fatalf("%s: %s", kind, raw)
		}
	}
	v, adj = buildView(policy.Action{Kind: "odoo.read", Params: map[string]any{"model": "stock.quant", "limit": float64(5)}}, map[string]any{}, b)
	if v["title"] != "Read stock.quant" || adj != nil {
		t.Fatalf("%v", v)
	}
	// Without the holder's entry no bound can be given, and nothing is adjustable.
	if _, adj := buildView(draft, map[string]any{"partner": "x", "total_at_cost": "10.00", "lines": []any{map[string]any{"product_id": int64(71), "unit_cost": "1.00"}}}, budget{}); adj != nil {
		t.Fatalf("%+v", adj)
	}
	// When Odoo could not be read, the view says so and offers nothing.
	v, adj = buildView(draft, map[string]any{"error": "the gate could not read this from Odoo: down"}, b)
	if adj != nil || !strings.Contains(fmt.Sprint(v), "down") {
		t.Fatalf("%v", v)
	}
}
