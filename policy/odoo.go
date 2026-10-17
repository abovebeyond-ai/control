package policy

import (
	"fmt"
	"math"
	"strings"
)

// OdooAdapter performs the Odoo kinds: calls on a client's Odoo through its JSON-2 API, with
// the API key the gateway holds (effects/odoo.go, docs/odoo-gate.md).
const OdooAdapter = "odoo"

// OdooModels are the models an Odoo kind may touch: what a procurement agent reads to buy
// well (orders, suppliers, products, stock), and no accounting, payroll or users. A model
// outside the list is refused at the judgement, whatever the grant and the mandate cover.
var OdooModels = []string{"purchase.order", "purchase.order.line", "res.partner", "product.product", "product.template", "stock.quant"}

// OdooOrderModel is the model every Odoo write acts on.
const OdooOrderModel = "purchase.order"

// OdooMaxLimit bounds how many records one read returns.
const OdooMaxLimit = 200

// OdooResource splits a resource "odoo:<instance>/<model>" into its instance and model.
func OdooResource(resource string) (instance, model string, ok bool) {
	rest, found := strings.CutPrefix(resource, "odoo:")
	if !found {
		return "", "", false
	}
	instance, model, found = strings.Cut(rest, "/")
	if !found || instance == "" || model == "" || strings.Contains(model, "/") {
		return "", "", false
	}
	return instance, model, true
}

// odooRule says why an Odoo action is refused on its face, or "": the resource names an
// instance and a model of the list, a read reads the model its resource names, with plain
// field names and a bounded limit, and a write acts on purchase orders. Deterministic over the
// action, like the rest of the judgement; what needs Odoo's own state (the order's total, its
// state) the adapter checks before it acts.
func odooRule(a Action) string {
	if Builtin[a.Kind].Adapter != OdooAdapter {
		return ""
	}
	_, model, ok := OdooResource(a.Resource)
	if !ok {
		return a.Kind + " acts on odoo:<instance>/<model>, not on " + a.Resource
	}
	if !containsString(OdooModels, model) {
		return "the model " + model + " is not one an Odoo kind may touch"
	}
	if a.Kind != "odoo.read" {
		if model != OdooOrderModel {
			return a.Kind + " acts on " + OdooOrderModel + ", not on " + model
		}
		// An id or a quantity of zero or less is no record and no quantity.
		for _, k := range []string{"partner_id", "order", "line", "qty"} {
			if v, present := a.Params[k]; present && !positiveWhole(v) {
				return k + " must be a whole number above zero"
			}
		}
		return ""
	}
	if m, _ := a.Params["model"].(string); m != model {
		return "odoo.read reads the model its resource names, " + model + ", not " + m
	}
	if fields, ok := a.Params["fields"].([]any); ok {
		for _, f := range fields {
			if s, _ := f.(string); !plainField(s) {
				return fmt.Sprintf("the field %q is not a plain field name", s)
			}
		}
	}
	if v, ok := a.Params["limit"]; ok {
		if n, whole := wholeNumber(v); !whole || n < 1 || n > OdooMaxLimit {
			return fmt.Sprintf("odoo.read returns between 1 and %d records", OdooMaxLimit)
		}
	}
	return ""
}

// plainField is a field of the model itself: no path into another model ("partner_id.email"),
// which would let a read filter on, and so learn about, a model outside the list.
func plainField(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// odooOperators are the comparison operators a domain term may use: none that takes a domain
// of its own (any, not any) or walks a hierarchy (child_of, parent_of).
var odooOperators = []string{"=", "!=", ">", ">=", "<", "<=", "in", "not in", "like", "ilike", "not like", "not ilike", "=like", "=ilike"}

// checkDomain holds an Odoo search domain to plain terms: at most 20 elements, each "&", "|",
// "!" or [field, operator, value], the field a plain name, the value a string, a whole number,
// true or false, null, or a list of at most 100 of those. A fractional number has no
// canonical form in the record, so it is refused here rather than at the digest.
func checkDomain(key string, v any) error {
	terms, ok := v.([]any)
	if !ok {
		return fmt.Errorf("parameter %q must be an Odoo domain, a list of terms", key)
	}
	if len(terms) > 20 {
		return fmt.Errorf("parameter %q takes at most twenty terms", key)
	}
	for i, t := range terms {
		if op, ok := t.(string); ok {
			if op != "&" && op != "|" && op != "!" {
				return fmt.Errorf("parameter %q[%d] is %q, not &, | or !", key, i, op)
			}
			continue
		}
		term, ok := t.([]any)
		if !ok || len(term) != 3 {
			return fmt.Errorf("parameter %q[%d] must be [field, operator, value]", key, i)
		}
		field, _ := term[0].(string)
		if !plainField(field) {
			return fmt.Errorf("parameter %q[%d] names %q, not a plain field name", key, i, field)
		}
		if op, _ := term[1].(string); !containsString(odooOperators, op) {
			return fmt.Errorf("parameter %q[%d] uses the operator %v, which a domain here does not take", key, i, term[1])
		}
		if list, ok := term[2].([]any); ok {
			if len(list) > 100 {
				return fmt.Errorf("parameter %q[%d] compares with more than a hundred values", key, i)
			}
			for _, x := range list {
				if !domainScalar(x) {
					return fmt.Errorf("parameter %q[%d] compares with %v, not a string, a whole number, a boolean or null", key, i, x)
				}
			}
		} else if !domainScalar(term[2]) {
			return fmt.Errorf("parameter %q[%d] compares with %v, not a string, a whole number, a boolean or null", key, i, term[2])
		}
	}
	return nil
}

func domainScalar(v any) bool {
	switch x := v.(type) {
	case nil, string, bool, int, int64:
		return true
	case float64:
		return x == math.Trunc(x) && math.Abs(x) < 1<<53
	}
	return false
}

// checkOrderLines holds the lines of a draft order: one to fifty, each exactly a product id
// and a quantity, both whole numbers above zero.
func checkOrderLines(key string, v any) error {
	lines, ok := v.([]any)
	if !ok || len(lines) == 0 {
		return fmt.Errorf("parameter %q must be a list of order lines", key)
	}
	if len(lines) > 50 {
		return fmt.Errorf("parameter %q takes at most fifty lines", key)
	}
	for i, l := range lines {
		m, ok := l.(map[string]any)
		if !ok || len(m) != 2 {
			return fmt.Errorf("parameter %q[%d] must be {product_id, qty}", key, i)
		}
		for _, f := range []string{"product_id", "qty"} {
			if !positiveWhole(m[f]) {
				return fmt.Errorf("parameter %q[%d].%s must be a whole number above zero", key, i, f)
			}
		}
	}
	return nil
}

func positiveWhole(v any) bool {
	n, ok := wholeNumber(v)
	return ok && n > 0
}

// wholeNumber reads a whole number as JSON decodes it (a float64) or as Go code passes it.
func wholeNumber(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x), true
		}
	}
	return 0, false
}
