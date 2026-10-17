package effects

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// Display reads from Odoo, with the instance's own key and only reading, what a person needs to
// decide on a write: the supplier's name, each product's name, code and cost, and for a change to
// an existing order its name, state and current total. The gateway seals it to the person's phone
// (docs/odoo-gate.md, sealed requests), so the screen they approve on is Odoo's word, not the
// agent's, and the relay that carries it reads none of it.
func (o Odoo) Display(ctx context.Context, a policy.Action) (map[string]any, error) {
	instance, _, ok := policy.OdooResource(a.Resource)
	if !ok {
		return nil, fmt.Errorf("resource is not odoo:<instance>/<model>")
	}
	inst, ok := o.Instances[instance]
	if !ok || inst.Base == "" || inst.DB == "" {
		return nil, fmt.Errorf("no Odoo is configured for %s", instance)
	}
	raw, err := o.key(instance, nil)
	if err != nil {
		return nil, err
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	if inst.Currency == "" {
		inst.Currency = "EUR"
	}
	c := odooClient{base: strings.TrimRight(inst.Base, "/"), db: inst.DB, key: strings.TrimSpace(string(raw)), client: client, currency: inst.Currency}
	switch a.Kind {
	case "odoo.order_draft":
		return c.displayDraft(ctx, a.Params)
	case "odoo.order_line_set":
		return c.displayLineSet(ctx, a.Params)
	case "odoo.order_cancel", "odoo.order_request_approval":
		id, _ := wholeParam(a.Params, "order")
		ord, err := c.order(ctx, id)
		if err != nil {
			return nil, err
		}
		d := map[string]any{"order": ord.Name, "state": ord.State, "total": money(ord.Total), "currency": ord.Currency}
		if name, err := c.partnerName(ctx, ord.Partner); err == nil && name != "" {
			d["partner"] = name
		}
		return d, nil
	}
	return map[string]any{}, nil
}

func (c odooClient) partnerName(ctx context.Context, id int64) (string, error) {
	if id == 0 {
		return "", nil
	}
	var rows []map[string]any
	if _, err := c.call(ctx, "res.partner", "read", map[string]any{"ids": []int64{id}, "fields": []string{"name"}}, &rows); err != nil || len(rows) != 1 {
		if err == nil {
			err = fmt.Errorf("Odoo has no partner %d", id)
		}
		return "", err
	}
	return odooStr(rows[0]["name"]), nil
}

// displayDraft names the supplier and each line at the products' cost, with the total at cost:
// the figure the ceiling is checked against before anything is created.
func (c odooClient) displayDraft(ctx context.Context, params map[string]any) (map[string]any, error) {
	partner, _ := wholeParam(params, "partner_id")
	lines, _ := params["lines"].([]any)
	var productIDs []int64
	qty := map[int64]int64{}
	for _, l := range lines {
		m, _ := l.(map[string]any)
		p, _ := wholeParam(m, "product_id")
		q, _ := wholeParam(m, "qty")
		if _, seen := qty[p]; !seen {
			productIDs = append(productIDs, p)
		}
		qty[p] += q
	}
	var products []map[string]any
	if _, err := c.call(ctx, "product.product", "read", map[string]any{"ids": productIDs, "fields": []string{"display_name", "default_code", "standard_price"}}, &products); err != nil {
		return nil, err
	}
	byID := map[int64]map[string]any{}
	for _, p := range products {
		id, _ := whole64(p["id"])
		byID[id] = p
	}
	var out []any
	var total int64
	for _, id := range productIDs {
		p := byID[id]
		if p == nil {
			return nil, fmt.Errorf("Odoo has no product %d", id)
		}
		unit := cents(p["standard_price"])
		total += unit * qty[id]
		out = append(out, map[string]any{"product_id": id, "name": odooStr(p["display_name"]), "code": odooStr(p["default_code"]),
			"qty": qty[id], "unit_cost": money(unit), "subtotal": money(unit * qty[id])})
	}
	d := map[string]any{"lines": out, "total_at_cost": money(total), "currency": c.currency}
	name, err := c.partnerName(ctx, partner)
	if err != nil {
		return nil, err
	}
	d["partner"], d["partner_id"] = name, partner
	return d, nil
}

// displayLineSet names the order, the line's product, the quantity now and asked, and the total
// now and as estimated at the line's price.
func (c odooClient) displayLineSet(ctx context.Context, params map[string]any) (map[string]any, error) {
	id, _ := wholeParam(params, "order")
	line, _ := wholeParam(params, "line")
	q, _ := wholeParam(params, "qty")
	ord, err := c.order(ctx, id)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if _, err := c.call(ctx, "purchase.order.line", "read", map[string]any{"ids": []int64{line}, "fields": []string{"product_id", "product_qty", "price_unit"}}, &rows); err != nil || len(rows) != 1 {
		if err == nil {
			err = fmt.Errorf("Odoo has no line %d", line)
		}
		return nil, err
	}
	_, product := many2one(rows[0]["product_id"])
	was, _ := rows[0]["product_qty"].(float64)
	unit := cents(rows[0]["price_unit"])
	d := map[string]any{"order": ord.Name, "state": ord.State, "total": money(ord.Total), "currency": ord.Currency,
		"line":                 map[string]any{"product": product, "qty_now": number(was), "qty": q, "unit_price": money(unit)},
		"total_after_estimate": money(ord.Total + unit*(q-int64(was)))}
	if name, err := c.partnerName(ctx, ord.Partner); err == nil && name != "" {
		d["partner"] = name
	}
	return d, nil
}
