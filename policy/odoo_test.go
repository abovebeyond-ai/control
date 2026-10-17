package policy

import (
	"strings"
	"testing"
)

// An Odoo action is judged on its face before Odoo is asked anything: a model of the list, a
// read of the model its resource names with plain fields and a bounded limit, a domain of plain
// terms, a write on purchase orders with whole ids and quantities above zero.
func TestAnOdooActionIsHeldToTheModelsAndPlainTerms(t *testing.T) {
	p := Policy{Grant: Grant{Kinds: Builtin.Of(OdooAdapter), Resources: []string{"odoo:acme/*"}}}
	read := func(model string, params map[string]any) Action {
		return Action{Kind: "odoo.read", Resource: "odoo:acme/" + model, Params: params}
	}
	allowed := []Action{
		read("purchase.order", map[string]any{"model": "purchase.order", "domain": []any{[]any{"state", "=", "draft"}, "|", []any{"partner_id", "in", []any{float64(8), float64(11)}}, []any{"name", "ilike", "P0"}}, "fields": []any{"name", "amount_total"}, "limit": float64(20)}),
		read("stock.quant", map[string]any{"model": "stock.quant"}),
		{Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2)}}}},
		{Kind: "odoo.order_line_set", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7), "line": float64(15), "qty": float64(3)}},
		{Kind: "odoo.order_cancel", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7)}},
		{Kind: "odoo.order_request_approval", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7)}},
	}
	for _, a := range allowed {
		if v, r := p.Evaluate(a, PathSummary{}); v != "ALLOW" {
			t.Errorf("%s %v: %s", a.Kind, a.Params, r)
		}
	}
	refused := map[string]Action{
		"a model off the list":          read("res.users", map[string]any{"model": "res.users"}),
		"a model other than the named":  read("purchase.order", map[string]any{"model": "res.partner"}),
		"a field into another model":    read("purchase.order", map[string]any{"model": "purchase.order", "fields": []any{"partner_id.email"}}),
		"a domain into another model":   read("purchase.order", map[string]any{"model": "purchase.order", "domain": []any{[]any{"partner_id.bank_ids.acc_number", "ilike", "BE"}}}),
		"a domain with any":             read("purchase.order", map[string]any{"model": "purchase.order", "domain": []any{[]any{"order_line", "any", []any{[]any{"qty", ">", float64(1)}}}}}),
		"a fractional value":            read("purchase.order", map[string]any{"model": "purchase.order", "domain": []any{[]any{"amount_total", ">", 10.5}}}),
		"a term of two":                 read("purchase.order", map[string]any{"model": "purchase.order", "domain": []any{[]any{"state", "draft"}}}),
		"a limit too high":              read("purchase.order", map[string]any{"model": "purchase.order", "limit": float64(5000)}),
		"no instance":                   {Kind: "odoo.read", Resource: "odoo:/purchase.order", Params: map[string]any{"model": "purchase.order"}},
		"a write on another model":      {Kind: "odoo.order_cancel", Resource: "odoo:acme/res.partner", Params: map[string]any{"order": float64(7)}},
		"a quantity of zero":            {Kind: "odoo.order_line_set", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7), "line": float64(15), "qty": float64(0)}},
		"a fractional quantity":         {Kind: "odoo.order_line_set", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7), "line": float64(15), "qty": 1.5}},
		"a line with a price":           {Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(19), "qty": float64(2), "price_unit": float64(1)}}}},
		"no lines":                      {Kind: "odoo.order_draft", Resource: "odoo:acme/purchase.order", Params: map[string]any{"partner_id": float64(8), "lines": []any{}}},
		"a resource outside the grant":  {Kind: "odoo.order_cancel", Resource: "odoo:other/purchase.order", Params: map[string]any{"order": float64(7)}},
		"an approval, which is no kind": {Kind: "odoo.order_approve", Resource: "odoo:acme/purchase.order", Params: map[string]any{"order": float64(7)}},
	}
	for name, a := range refused {
		if v, _ := p.Evaluate(a, PathSummary{}); v != "DENY" {
			t.Errorf("%s: must be refused", name)
		}
	}
	if _, _, ok := OdooResource("odoo:acme/purchase.order/x"); ok {
		t.Fatal("a resource with a path beyond the model")
	}
	// Nothing that cannot be called back has a kind.
	for k := range Builtin {
		if strings.HasPrefix(k, "odoo.") && (strings.Contains(k, "approve") && !strings.Contains(k, "approval") || strings.Contains(k, "send") || strings.Contains(k, "pay")) {
			t.Fatalf("the kind %s reaches what cannot be called back", k)
		}
	}
}
