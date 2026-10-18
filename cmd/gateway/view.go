package main

// The view (docs/odoo-gate.md, the conversation carries everything): beside the kind's display,
// every sealed request carries a view any app can draw without knowing the kind: a title,
// labelled fields, a table, totals, and what the person may adjust before giving their word,
// with bounds from policy. Every label and value is text the gate wrote from Odoo's display.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/abovebeyond-ai/control/policy"
)

// adjustSpec is one parameter the person may change, as the view names it and the gate checks
// a change against it.
type adjustSpec struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	Value int64  `json:"value"`
	Min   int64  `json:"min"`
	Max   int64  `json:"max"`
	Step  int64  `json:"step"`
}

// budget is what the holder may still spend on this act, in cents: their ceiling per order and,
// when they have one, what is left of their day. Zero values mean unknown, and then nothing is
// adjustable, since no bound can be given.
type budget struct {
	known   bool
	ceiling int64 // cents
	daily   bool
	leftDay int64 // cents
}

// within is the most the act may come to at cost.
func (b budget) within() int64 {
	if b.daily && b.leftDay < b.ceiling {
		return b.leftDay
	}
	return b.ceiling
}

// unboundedQty caps a quantity whose unit costs nothing, which no budget bounds.
func unboundedQty(q int64) int64 {
	if 10*q > 100 {
		return 10 * q
	}
	return 100
}

// parseCents reads an amount as the display writes it ("1519.00").
func parseCents(v any) (int64, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	whole, frac, _ := strings.Cut(s, ".")
	for len(frac) < 2 {
		frac += "0"
	}
	w, err1 := strconv.ParseInt(whole, 10, 64)
	f, err2 := strconv.ParseInt(frac[:2], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	c := w*100 + f
	if neg {
		c = -c
	}
	return c, true
}

func text(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}

func field(label string, v any) map[string]any {
	return map[string]any{"label": label, "value": text(v)}
}

func withCurrency(amount any, currency any) string {
	if c := text(currency); c != "" {
		return text(amount) + " " + c
	}
	return text(amount)
}

func qtyText(q, uom any) string {
	if u := text(uom); u != "" {
		return text(q) + " " + u
	}
	return text(q)
}

func floorDiv(a, b int64) int64 {
	if b <= 0 {
		return 0
	}
	if a < 0 {
		return -((-a + b - 1) / b)
	}
	return a / b
}

// clampMax keeps a bound at least the minimum.
func clampMax(max int64) int64 {
	if max < 1 {
		return 1
	}
	return max
}

// buildView writes the view of an act from its display, and what the person may adjust.
func buildView(a policy.Action, d map[string]any, b budget) (map[string]any, []adjustSpec) {
	words := policy.Builtin[a.Kind].Words
	v := map[string]any{"title": capitalize(words), "fields": []any{}}
	if errText, ok := d["error"].(string); ok {
		v["fields"] = []any{field("Odoo", errText)}
		return v, nil
	}
	switch a.Kind {
	case "odoo.order_draft":
		return draftView(a, d, b)
	case "odoo.order_line_set":
		v, adj := orderView("Change a quantity on", d)
		lineSetView(v, a, d, b, &adj)
		return v, adj
	case "odoo.order_cancel":
		v, _ := orderView("Cancel", d)
		return v, nil
	case "odoo.order_request_approval":
		v, _ := orderView("Ask for approval of", d)
		return v, nil
	case "odoo.read":
		model := text(a.Params["model"])
		v["title"] = "Read " + model
		fields := []any{field("Model", model)}
		if f, ok := a.Params["fields"].([]any); ok && len(f) > 0 {
			names := make([]string, 0, len(f))
			for _, x := range f {
				names = append(names, text(x))
			}
			fields = append(fields, field("Fields", strings.Join(names, ", ")))
		}
		if l, ok := a.Params["limit"]; ok {
			fields = append(fields, field("At most", l))
		}
		v["fields"] = fields
		return v, nil
	}
	return v, nil
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// draftView: the supplier, delivery, each line at cost with the supplier's last price, the total
// at cost; each line's quantity adjustable between 1 and what keeps the total at cost within the
// holder's ceiling and what is left of their day.
func draftView(a policy.Action, d map[string]any, b budget) (map[string]any, []adjustSpec) {
	partner := text(d["partner"])
	fields := []any{field("Supplier", partner)}
	if dp := text(d["date_planned"]); dp != "" {
		fields = append(fields, field("Delivery", dp))
	}
	lines, _ := d["lines"].([]any)
	byProduct := map[string]map[string]any{}
	withLast := false
	for _, l := range lines {
		m, _ := l.(map[string]any)
		byProduct[text(m["product_id"])] = m
		if m["last_price"] != nil {
			withLast = true
		}
	}
	columns := []any{"Product", "Qty", "Unit cost", "Subtotal"}
	if withLast {
		columns = append(columns, "Last price")
	}
	rows := []any{}
	for _, l := range lines {
		m, _ := l.(map[string]any)
		row := []any{text(m["name"]), qtyText(m["qty"], m["uom"]), text(m["unit_cost"]), text(m["subtotal"])}
		if withLast {
			last := text(m["last_price"])
			if dt := text(m["last_date"]); last != "" && dt != "" {
				last += " on " + dt
			}
			row = append(row, last)
		}
		rows = append(rows, row)
	}
	v := map[string]any{"title": "Draft an order at " + partner, "fields": fields,
		"table":  map[string]any{"columns": columns, "rows": rows},
		"totals": []any{field("Total at cost", withCurrency(d["total_at_cost"], d["currency"]))}}
	total, ok := parseCents(d["total_at_cost"])
	if !ok || !b.known {
		return v, nil
	}
	var adj []adjustSpec
	params, _ := a.Params["lines"].([]any)
	for i, l := range params {
		m, _ := l.(map[string]any)
		q, _ := whole(m["qty"])
		p := byProduct[text(m["product_id"])]
		if p == nil {
			continue
		}
		unit, ok := parseCents(p["unit_cost"])
		if !ok {
			continue
		}
		max := unboundedQty(q)
		if unit > 0 {
			max = clampMax(floorDiv(b.within()-(total-unit*q), unit))
		}
		label := text(p["name"])
		if u := text(p["uom"]); u != "" {
			label += ", " + u
		}
		adj = append(adj, adjustSpec{Path: fmt.Sprintf("lines.%d.qty", i), Label: label, Value: q, Min: 1, Max: max, Step: 1})
	}
	if len(adj) > 0 {
		v["adjust"] = adj
	}
	return v, adj
}

// orderView is the whole order as the display carries it.
func orderView(verb string, d map[string]any) (map[string]any, []adjustSpec) {
	order := text(d["order"])
	fields := []any{field("Supplier", d["partner"]), field("Order", order), field("State", d["state"])}
	for _, k := range []struct{ key, label string }{{"date_order", "Order date"}, {"date_planned", "Delivery"}} {
		if s := text(d[k.key]); s != "" {
			fields = append(fields, field(k.label, s))
		}
	}
	rows := []any{}
	lines, _ := d["lines"].([]any)
	for _, l := range lines {
		m, _ := l.(map[string]any)
		rows = append(rows, []any{text(m["name"]), qtyText(m["qty"], m["uom"]), text(m["unit_price"]), text(m["subtotal"])})
	}
	totals := []any{}
	for _, k := range []struct{ key, label string }{{"untaxed", "Untaxed"}, {"tax", "Tax"}, {"total", "Total"}} {
		if d[k.key] != nil {
			totals = append(totals, field(k.label, withCurrency(d[k.key], d["currency"])))
		}
	}
	return map[string]any{"title": verb + " " + order, "fields": fields,
		"table":  map[string]any{"columns": []any{"Product", "Qty", "Unit price", "Subtotal"}, "rows": rows},
		"totals": totals}, nil
}

// lineSetView adds the change itself and its quantity, adjustable between 1 and what keeps the
// estimated total within the holder's ceiling and the increase within what is left of the day.
func lineSetView(v map[string]any, a policy.Action, d map[string]any, b budget, adj *[]adjustSpec) {
	line, _ := d["line"].(map[string]any)
	if line == nil {
		return
	}
	product := text(line["product"])
	v["fields"] = append(v["fields"].([]any), field("Change", fmt.Sprintf("%s: %s to %s", product, text(line["qty_now"]), text(line["qty"]))))
	if d["total_after_estimate"] != nil {
		v["totals"] = append(v["totals"].([]any), field("Total after the change (estimate)", withCurrency(d["total_after_estimate"], d["currency"])))
	}
	q, _ := whole(a.Params["qty"])
	now, _ := whole(line["qty_now"])
	unit, ok1 := parseCents(line["unit_price"])
	total, ok2 := parseCents(d["total"])
	if !ok1 || !ok2 || !b.known {
		return
	}
	max := unboundedQty(q)
	if unit > 0 {
		max = now + floorDiv(b.ceiling-total, unit)
		if b.daily {
			if byDay := now + floorDiv(b.leftDay, unit); byDay < max {
				max = byDay
			}
		}
		max = clampMax(max)
	}
	*adj = []adjustSpec{{Path: "qty", Label: product, Value: q, Min: 1, Max: max, Step: 1}}
	v["adjust"] = *adj
}

// whole reads a whole number as the parameters or the display carry it.
func whole(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return int64(x), true
		}
	case int64:
		return x, true
	case int:
		return int64(x), true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}
