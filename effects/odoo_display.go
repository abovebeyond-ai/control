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
// decide on a write: for a draft the supplier's name and each product's name, code, unit, cost
// and the supplier's last price; for a change to an existing order the whole order as Odoo has
// it, lines, dates, tax and total. The gateway seals it to the person's phone
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
		return c.displayOrder(ctx, id)
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
// the figure the ceiling is checked against before anything is created. Each line carries its
// unit and, when Odoo has one, the supplier's last price for it; the draft carries the date
// Odoo will plan it for when the supplier has a lead time.
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
	if _, err := c.call(ctx, "product.product", "read", map[string]any{"ids": productIDs, "fields": []string{"display_name", "default_code", "standard_price", "uom_id", "product_tmpl_id"}}, &products); err != nil {
		return nil, err
	}
	byID := map[int64]map[string]any{}
	for _, p := range products {
		id, _ := whole64(p["id"])
		byID[id] = p
	}
	var out []any
	var total int64
	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	lead := int64(-1)
	for _, id := range productIDs {
		p := byID[id]
		if p == nil {
			return nil, fmt.Errorf("Odoo has no product %d", id)
		}
		unit := cents(p["standard_price"])
		total += unit * qty[id]
		line := map[string]any{"product_id": id, "name": odooStr(p["display_name"]), "code": odooStr(p["default_code"]),
			"qty": qty[id], "unit_cost": money(unit), "subtotal": money(unit * qty[id])}
		if _, uom := many2one(p["uom_id"]); uom != "" {
			line["uom"] = uom
		}
		template, _ := many2one(p["product_tmpl_id"])
		// The last price is a help, not the decision: a lookup Odoo does not answer leaves it
		// out rather than the whole screen.
		last, _ := c.supplierPrice(ctx, partner, id, template, qty[id], today)
		if last.found {
			line["last_price"] = money(last.price)
			if last.day != "" {
				line["last_date"] = last.day
			}
			if last.order != "" {
				line["last_order"] = last.order
			}
		}
		// Odoo plans each line at the order date plus its supplier's lead time, and the order
		// at the earliest of its lines.
		if last.delay >= 0 && (lead < 0 || last.delay < lead) {
			lead = last.delay
		}
		out = append(out, line)
	}
	d := map[string]any{"lines": out, "total_at_cost": money(total), "currency": c.currency}
	if lead >= 0 {
		d["date_planned"] = now.AddDate(0, 0, int(lead)).Format("2006-01-02")
	}
	name, err := c.partnerName(ctx, partner)
	if err != nil {
		return nil, err
	}
	d["partner"], d["partner_id"] = name, partner
	return d, nil
}

// displayLineSet is the whole order, with the line's product, the quantity now and asked, and
// the total as estimated at the line's price.
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
	d, err := c.displayOrder(ctx, id)
	if err != nil {
		return nil, err
	}
	d["line"] = map[string]any{"product": product, "qty_now": number(was), "qty": q, "unit_price": money(unit)}
	d["total_after_estimate"] = money(ord.Total + unit*(q-int64(was)))
	return d, nil
}

// displayOrder is the whole order as Odoo has it: name, state, supplier, currency, dates, every
// line with its product, quantity, unit, price and subtotal, and the untaxed amount, the tax and
// the total. A person approves an order, not a step, so every word asked on an order shows this.
func (c odooClient) displayOrder(ctx context.Context, id int64) (map[string]any, error) {
	var rows []map[string]any
	if _, err := c.call(ctx, policy.OdooOrderModel, "read", map[string]any{"ids": []int64{id}, "fields": []string{
		"name", "state", "partner_id", "currency_id", "date_order", "date_planned", "amount_untaxed", "amount_tax", "amount_total", "order_line"}}, &rows); err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("Odoo has no purchase order %d", id)
	}
	r := rows[0]
	partner, partnerName := many2one(r["partner_id"])
	if partnerName == "" && partner != 0 {
		name, err := c.partnerName(ctx, partner)
		if err != nil {
			return nil, err
		}
		partnerName = name
	}
	_, currency := many2one(r["currency_id"])
	d := map[string]any{"order": odooStr(r["name"]), "state": odooStr(r["state"]), "partner": partnerName, "partner_id": partner,
		"currency": currency, "untaxed": money(cents(r["amount_untaxed"])), "tax": money(cents(r["amount_tax"])), "total": money(cents(r["amount_total"]))}
	for _, k := range []string{"date_order", "date_planned"} {
		if day := odooDay(r[k]); day != "" {
			d[k] = day
		}
	}
	lines, err := c.orderLines(ctx, ids(r["order_line"]))
	if err != nil {
		return nil, err
	}
	d["lines"] = lines
	return d, nil
}

// orderLines reads an order's lines with their products' codes; section and note lines, which
// carry no product, are left out.
func (c odooClient) orderLines(ctx context.Context, lineIDs []int64) ([]any, error) {
	out := []any{}
	if len(lineIDs) == 0 {
		return out, nil
	}
	var rows []map[string]any
	if _, err := c.call(ctx, "purchase.order.line", "read", map[string]any{"ids": lineIDs, "fields": []string{
		"product_id", "name", "product_qty", "product_uom_id", "price_unit", "price_subtotal", "display_type"}}, &rows); err != nil {
		return nil, err
	}
	var productIDs []int64
	for _, l := range rows {
		if p, _ := many2one(l["product_id"]); p != 0 && !containsID(productIDs, p) {
			productIDs = append(productIDs, p)
		}
	}
	codes := map[int64]string{}
	if len(productIDs) > 0 {
		var products []map[string]any
		if _, err := c.call(ctx, "product.product", "read", map[string]any{"ids": productIDs, "fields": []string{"default_code"}}, &products); err != nil {
			return nil, err
		}
		for _, p := range products {
			id, _ := whole64(p["id"])
			codes[id] = odooStr(p["default_code"])
		}
	}
	for _, l := range rows {
		product, productName := many2one(l["product_id"])
		if product == 0 || odooStr(l["display_type"]) != "" {
			continue
		}
		name := odooStr(l["name"])
		if name == "" {
			name = productName
		}
		qty, _ := l["product_qty"].(float64)
		_, uom := many2one(l["product_uom_id"])
		out = append(out, map[string]any{"product_id": product, "name": name, "code": codes[product], "qty": number(qty), "uom": uom,
			"unit_price": money(cents(l["price_unit"])), "subtotal": money(cents(l["price_subtotal"]))})
	}
	return out, nil
}

// odooDay is the date part of an Odoo date or datetime ("2026-10-18 09:12:00"), or "".
func odooDay(v any) string {
	s := odooStr(v)
	if len(s) < 10 {
		return ""
	}
	return s[:10]
}

// lastPrice is what the supplier last asked for a product: its price list entry
// (product.supplierinfo) when there is one that holds for this quantity today, else the last
// confirmed order line for that product from that supplier. delay is the entry's lead time in
// days, -1 without an entry.
type lastPrice struct {
	price      int64
	day, order string
	found      bool
	delay      int64
}

func (c odooClient) supplierPrice(ctx context.Context, partner, product, template, qty int64, today string) (lastPrice, error) {
	lp := lastPrice{delay: -1}
	if partner == 0 {
		return lp, nil
	}
	var infos []map[string]any
	if _, err := c.call(ctx, "product.supplierinfo", "search_read", map[string]any{
		"domain": []any{[]any{"partner_id", "=", partner}, []any{"product_tmpl_id", "=", template}},
		"fields": []string{"product_id", "price", "min_qty", "date_start", "date_end", "delay"},
		"order":  "sequence, min_qty DESC, price, id"}, &infos); err != nil {
		return lp, err
	}
	for _, s := range infos {
		if p, _ := many2one(s["product_id"]); p != 0 && p != product {
			continue
		}
		if start := odooDay(s["date_start"]); start != "" && start > today {
			continue
		}
		if end := odooDay(s["date_end"]); end != "" && end < today {
			continue
		}
		if m, _ := s["min_qty"].(float64); m > float64(qty) {
			continue
		}
		lp.price, lp.found = cents(s["price"]), true
		lp.day = odooDay(s["date_start"])
		if d, ok := whole64(s["delay"]); ok {
			lp.delay = d
		}
		return lp, nil
	}
	var lines []map[string]any
	if _, err := c.call(ctx, "purchase.order.line", "search_read", map[string]any{
		"domain": []any{[]any{"product_id", "=", product}, []any{"partner_id", "=", partner}, []any{"state", "in", []string{"purchase", "done"}}, []any{"display_type", "=", false}},
		"fields": []string{"price_unit", "order_id", "date_order"},
		"order":  "id desc", "limit": 1}, &lines); err != nil {
		return lp, err
	}
	if len(lines) == 1 {
		lp.price, lp.found = cents(lines[0]["price_unit"]), true
		lp.day = odooDay(lines[0]["date_order"])
		_, lp.order = many2one(lines[0]["order_id"])
	}
	return lp, nil
}
