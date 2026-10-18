package effects

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// fakeOdoo answers the JSON-2 calls the adapter makes, with Odoo's own rules where they
// matter: button_confirm approves at once when the company approves in one step, under the
// threshold, or for a manager, and leaves the order "to approve" otherwise.
type fakeOdoo struct {
	mu        sync.Mutex
	calls     []string
	orders    map[int64]*fakeOrder
	lines     map[int64]*fakeLine
	products  map[int64]fakeProduct
	twoStep   bool
	threshold float64
	manager   bool
	currency  string
	sellers   []fakeSeller
	tax       float64 // the tax rate on every line, 0 unless a test sets it
	nextOrder int64
	nextLine  int64
}

type fakeOrder struct {
	state, currency string
	lines           []int64
	partner         int64
}

// fakeSeller is a supplier's price list entry, product.supplierinfo.
type fakeSeller struct {
	partner, product int64
	price, minQty    float64
	delay            int64
}

type fakeLine struct {
	order, product int64
	qty, price     float64
}

type fakeProduct struct {
	name         string
	cost, seller float64 // standard_price, and the supplier's price Odoo puts on a line
	purchasable  bool
}

func newFakeOdoo() *fakeOdoo {
	return &fakeOdoo{
		orders:   map[int64]*fakeOrder{7: {state: "draft", currency: "EUR", lines: []int64{15}, partner: 8}, 12: {state: "to approve", currency: "EUR", lines: []int64{24}, partner: 8}, 11: {state: "purchase", currency: "EUR", lines: []int64{22}, partner: 9}},
		lines:    map[int64]*fakeLine{15: {order: 7, product: 31, qty: 5, price: 130.5}, 24: {order: 12, product: 31, qty: 1, price: 198}, 22: {order: 11, product: 31, qty: 1, price: 900}},
		products: map[int64]fakeProduct{19: {name: "Corner Desk", cost: 600, seller: 600, purchasable: true}, 21: {name: "Storage Box", cost: 14, seller: 14, purchasable: true}, 31: {name: "Office Chair", cost: 120, seller: 130.5, purchasable: true}, 40: {name: "Cheap on paper", cost: 10, seller: 900, purchasable: true}, 41: {name: "Not for sale", cost: 1, seller: 1}},
		twoStep:  true, currency: "EUR", nextOrder: 100, nextLine: 1000,
	}
}

func (f *fakeOdoo) total(id int64) float64 {
	t := 0.0
	for _, l := range f.orders[id].lines {
		t += f.lines[l].qty * f.lines[l].price
	}
	return t
}

func (f *fakeOdoo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "bearer the-key" || r.Header.Get("X-Odoo-Database") != "acme" {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"name":"AccessDenied","message":"Access Denied"}`))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/json/2/")
	f.calls = append(f.calls, path)
	var args map[string]any
	_ = json.NewDecoder(r.Body).Decode(&args)
	idsOf := func() []int64 {
		var out []int64
		for _, x := range args["ids"].([]any) {
			out = append(out, int64(x.(float64)))
		}
		return out
	}
	answer := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch path {
	case "purchase.order/search_read":
		rows := []any{}
		for id, o := range f.orders {
			rows = append(rows, map[string]any{"id": id, "state": o.state, "amount_total": f.total(id)})
		}
		answer(rows)
	case "res.partner/read":
		rows := []any{}
		for _, id := range idsOf() {
			rows = append(rows, map[string]any{"id": id, "name": fmt.Sprintf("Supplier %d", id)})
		}
		answer(rows)
	case "product.product/read":
		rows := []any{}
		for _, id := range idsOf() {
			if p, ok := f.products[id]; ok {
				rows = append(rows, map[string]any{"id": id, "display_name": p.name, "default_code": fmt.Sprintf("P-%d", id), "standard_price": p.cost, "purchase_ok": p.purchasable,
					"uom_id": []any{1, "Units"}, "product_tmpl_id": []any{id + 1000, p.name}})
			}
		}
		answer(rows)
	case "purchase.order/create":
		vals := args["vals_list"].([]any)[0].(map[string]any)
		f.nextOrder++
		o := &fakeOrder{state: "draft", currency: f.currency, partner: int64(vals["partner_id"].(float64))}
		for _, c := range vals["order_line"].([]any) {
			l := c.([]any)[2].(map[string]any)
			f.nextLine++
			p := int64(l["product_id"].(float64))
			f.lines[f.nextLine] = &fakeLine{order: f.nextOrder, product: p, qty: l["product_qty"].(float64), price: f.products[p].seller}
			o.lines = append(o.lines, f.nextLine)
		}
		f.orders[f.nextOrder] = o
		answer([]int64{f.nextOrder})
	case "purchase.order/read":
		rows := []any{}
		for _, id := range idsOf() {
			if o, ok := f.orders[id]; ok {
				t := f.total(id)
				rows = append(rows, map[string]any{"id": id, "name": fmt.Sprintf("P%05d", id), "state": o.state, "amount_total": t + t*f.tax, "amount_untaxed": t, "amount_tax": t * f.tax,
					"currency_id": []any{1, o.currency}, "company_id": []any{1, "Acme"}, "order_line": o.lines,
					"partner_id": []any{o.partner, fmt.Sprintf("Supplier %d", o.partner)}, "date_order": "2026-10-18 09:12:00", "date_planned": "2026-10-21 10:00:00"})
			}
		}
		answer(rows)
	case "purchase.order.line/read":
		rows := []any{}
		for _, id := range idsOf() {
			if l, ok := f.lines[id]; ok {
				rows = append(rows, map[string]any{"id": id, "product_id": []any{l.product, f.products[l.product].name}, "name": "[P-" + fmt.Sprint(l.product) + "] " + f.products[l.product].name,
					"product_qty": l.qty, "product_uom_id": []any{1, "Units"}, "price_unit": l.price, "price_subtotal": l.qty * l.price, "price_total": l.qty * l.price, "display_type": false})
			}
		}
		answer(rows)
	case "product.supplierinfo/search_read":
		domain := args["domain"].([]any)
		partner := int64(domain[0].([]any)[2].(float64))
		template := int64(domain[1].([]any)[2].(float64))
		rows := []any{}
		for _, sl := range f.sellers {
			if sl.partner == partner && sl.product+1000 == template {
				rows = append(rows, map[string]any{"product_id": false, "price": sl.price, "min_qty": sl.minQty, "date_start": false, "date_end": false, "delay": sl.delay})
			}
		}
		answer(rows)
	case "purchase.order.line/search_read":
		domain := args["domain"].([]any)
		product := int64(domain[0].([]any)[2].(float64))
		partner := int64(domain[1].([]any)[2].(float64))
		rows := []any{}
		var best int64
		for id, l := range f.lines {
			o := f.orders[l.order]
			if l.product == product && o.partner == partner && (o.state == "purchase" || o.state == "done") && id > best {
				best = id
			}
		}
		if best != 0 {
			l := f.lines[best]
			rows = append(rows, map[string]any{"id": best, "price_unit": l.price, "order_id": []any{l.order, fmt.Sprintf("P%05d", l.order)}, "date_order": "2026-09-30 08:00:00"})
		}
		answer(rows)
	case "purchase.order.line/write":
		for _, id := range idsOf() {
			l := f.lines[id]
			l.qty = args["vals"].(map[string]any)["product_qty"].(float64)
			if l.qty > 100 {
				l.price *= 2 // a supplier who charges more for a large quantity
			}
		}
		answer(true)
	case "purchase.order/button_cancel":
		for _, id := range idsOf() {
			f.orders[id].state = "cancel"
		}
		answer(true)
	case "purchase.order/button_confirm":
		for _, id := range idsOf() {
			o := f.orders[id]
			if !f.twoStep || f.total(id) < f.threshold || f.manager {
				o.state = "purchase"
			} else {
				o.state = "to approve"
			}
		}
		answer(true)
	case "res.company/read":
		step := "one_step"
		if f.twoStep {
			step = "two_step"
		}
		answer([]any{map[string]any{"id": 1, "po_double_validation": step, "po_double_validation_amount": f.threshold, "currency_id": []any{1, f.currency}}})
	case "res.users/context_get":
		answer(map[string]any{"uid": 7, "lang": "en_US"})
	case "res.users/has_group":
		answer(f.manager)
	default:
		w.WriteHeader(404)
		answer(map[string]any{"name": "NotFound", "message": "The method '" + path + "' does not exist", "debug": "Traceback ..."})
	}
}

func (f *fakeOdoo) wrote() bool {
	for _, c := range f.calls {
		if strings.HasSuffix(c, "/create") || strings.HasSuffix(c, "/write") || strings.Contains(c, "/button_") {
			return true
		}
	}
	return false
}

func odooFor(t *testing.T, f *fakeOdoo) Odoo {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "odoo-key-acme"), []byte("the-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return Odoo{SecretsDir: dir, Instances: map[string]OdooInstance{"acme": {Base: srv.URL + "/", DB: "acme"}}}
}

func act(kind string, params map[string]any) policy.Action {
	return policy.Action{Kind: kind, Resource: "odoo:acme/purchase.order", Params: params}
}

// A read goes out as search_read with the key the gateway holds; the rows come back to the
// hand, and the record keeps only their count and digest.
func TestAnOdooReadKeepsTheRowsOffTheRecord(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	out := o.Perform(context.Background(), policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order", "domain": []any{[]any{"state", "=", "draft"}}}})
	if !out.OK || out.Detail["count"] != 3 || len(out.Private["records"].([]any)) != 3 || len(out.Detail["records_sha256"].(string)) != 64 {
		t.Fatalf("%+v", out)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "records\"") || strings.Contains(string(raw), "amount_total") {
		t.Fatalf("the rows must not be in the outcome as recorded: %s", raw)
	}
	if out := (Odoo{SecretsDir: t.TempDir(), Instances: o.Instances}).Perform(context.Background(), policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order"}}); out.OK || !strings.Contains(out.Error, "no Odoo key") {
		t.Fatalf("without the key nothing is called: %+v", out)
	}
	if out := o.Perform(context.Background(), policy.Action{Kind: "odoo.read", Resource: "odoo:other/purchase.order", Params: map[string]any{"model": "purchase.order"}}); out.OK || !strings.Contains(out.Error, "no Odoo is configured") {
		t.Fatalf("an instance nobody configured: %+v", out)
	}
}

// A draft is priced at the products' cost first and refused above the ceiling before anything
// is created; a draft Odoo prices above it after all is cancelled at once. Under it, the draft
// stands, and the outcome carries no fractional number.
func TestADraftIsHeldToTheSignersCeiling(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	line := func(p, q float64) []any { return []any{map[string]any{"product_id": p, "qty": q}} }

	out := o.Perform(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": line(19, 10), OdooCeilingParam: int64(5000)}))
	if out.OK || !strings.Contains(out.Error, "6000.00 at the products' cost") || f.wrote() {
		t.Fatalf("over the ceiling at cost, nothing may be created: %+v %v", out, f.calls)
	}
	out = o.Perform(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": line(40, 10), OdooCeilingParam: int64(5000)}))
	if out.OK || !strings.Contains(out.Error, "so it was cancelled") || f.orders[101].state != "cancel" {
		t.Fatalf("priced over the ceiling by Odoo, the draft is cancelled: %+v", out)
	}
	out = o.Perform(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(31), "qty": float64(3)}, map[string]any{"product_id": float64(21), "qty": float64(5)}}, OdooCeilingParam: int64(5000)}))
	if !out.OK || out.Detail["state"] != "draft" || out.Detail["amount_total"] != "461.50" || out.Detail[OdooCeilingParam] != int64(5000) {
		t.Fatalf("%+v", out)
	}
	if out := o.Perform(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": line(41, 1), OdooCeilingParam: int64(5000)})); out.OK || !strings.Contains(out.Error, "cannot be purchased") {
		t.Fatalf("%+v", out)
	}
	// No ceiling, no write: the gateway adds it from the registry entry, and a write without
	// one did not come through that road.
	if out := o.Perform(context.Background(), act("odoo.order_cancel", map[string]any{"order": float64(7)})); out.OK || !strings.Contains(out.Error, "ceiling") {
		t.Fatalf("%+v", out)
	}
	// An order in another currency than the one the ceiling is compared in is refused.
	f.currency = "USD"
	if out := o.Perform(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": line(21, 1), OdooCeilingParam: int64(5000)})); out.OK || !strings.Contains(out.Error, "in USD") {
		t.Fatalf("%+v", out)
	}
}

// A quantity changes only on a draft, only on a line of that order, and is set back when Odoo's
// price for the new quantity takes the order over the ceiling.
func TestALineQuantityChangesOnlyOnADraftAndWithinTheCeiling(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	set := func(order, line, qty float64) Outcome {
		return o.Perform(context.Background(), act("odoo.order_line_set", map[string]any{"order": order, "line": line, "qty": qty, OdooCeilingParam: int64(30000)}))
	}
	if out := set(7, 15, 8); !out.OK || out.Detail["qty"] != int64(8) || out.Detail["was"] != int64(5) || out.Detail["amount_total"] != "1044.00" {
		t.Fatalf("%+v", out)
	}
	if out := set(12, 24, 2); out.OK || !strings.Contains(out.Error, "to approve") {
		t.Fatalf("not a draft: %+v", out)
	}
	if out := set(7, 24, 2); out.OK || !strings.Contains(out.Error, "not on") {
		t.Fatalf("a line of another order: %+v", out)
	}
	if out := set(7, 15, 400); out.OK || !strings.Contains(out.Error, "nothing was changed") || f.lines[15].qty != 8 {
		t.Fatalf("over the ceiling at the line's price: %+v", out)
	}
	if out := set(7, 15, 150); out.OK || !strings.Contains(out.Error, "so it was set back") || f.lines[15].qty != 8 {
		t.Fatalf("over the ceiling at Odoo's price: %+v %v", out, f.lines[15])
	}
}

// Cancel takes a draft or an order waiting for approval, never an approved one.
func TestCancelTakesOnlyWhatNobodyApproved(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	cancel := func(id float64) Outcome {
		return o.Perform(context.Background(), act("odoo.order_cancel", map[string]any{"order": id, OdooCeilingParam: int64(5000)}))
	}
	if out := cancel(12); !out.OK || out.Detail["state"] != "cancel" || out.Detail["was"] != "to approve" {
		t.Fatalf("%+v", out)
	}
	if out := cancel(11); out.OK || !strings.Contains(out.Error, "purchase") || f.orders[11].state != "purchase" {
		t.Fatalf("an approved order stays: %+v", out)
	}
}

// Asking for approval never approves: when Odoo would approve at once (one step, under the
// threshold, a manager's key) the call is refused before it is made.
func TestAskingForApprovalNeverApproves(t *testing.T) {
	ask := func(f *fakeOdoo) Outcome {
		return odooFor(t, f).Perform(context.Background(), act("odoo.order_request_approval", map[string]any{"order": float64(7), OdooCeilingParam: int64(5000)}))
	}
	f := newFakeOdoo()
	if out := ask(f); !out.OK || out.Detail["state"] != "to approve" {
		t.Fatalf("%+v", out)
	}
	cases := map[string]func(f *fakeOdoo){
		"one step":            func(f *fakeOdoo) { f.twoStep = false },
		"under the threshold": func(f *fakeOdoo) { f.threshold = 1000 },
		"a manager's key":     func(f *fakeOdoo) { f.manager = true },
	}
	for name, change := range cases {
		f := newFakeOdoo()
		change(f)
		if out := ask(f); out.OK || f.orders[7].state != "draft" {
			t.Errorf("%s: asking must be refused and the order left a draft: %+v", name, out)
		}
	}
	f = newFakeOdoo()
	if out := odooFor(t, f).Perform(context.Background(), act("odoo.order_request_approval", map[string]any{"order": float64(7), OdooCeilingParam: int64(500)})); out.OK || !strings.Contains(out.Error, "above the signer's ceiling") {
		t.Fatalf("over the ceiling: %+v", out)
	}
}

// Against the Odoo on this machine, when asked: CONTROL_ODOO_IT=1, with CONTROL_ODOO_URL,
// CONTROL_ODOO_DB, CONTROL_ODOO_KEY_FILE and CONTROL_ODOO_CURRENCY overriding the defaults
// (http://127.0.0.1:8069, acme, /home/bench/work/odoo-demo/gate.key, the database's own
// currency). It reads, drafts an order, changes its quantity, asks for approval and cancels
// it, so it leaves one cancelled order behind.
func TestAgainstALocalOdoo(t *testing.T) {
	if os.Getenv("CONTROL_ODOO_IT") == "" {
		t.Skip("set CONTROL_ODOO_IT=1 to run against a local Odoo")
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	key, err := os.ReadFile(env("CONTROL_ODOO_KEY_FILE", "/home/bench/work/odoo-demo/gate.key"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "odoo-key-acme"), key, 0o600)
	o := Odoo{SecretsDir: dir, Instances: map[string]OdooInstance{"acme": {Base: env("CONTROL_ODOO_URL", "http://127.0.0.1:8069"), DB: env("CONTROL_ODOO_DB", "acme")}}}
	ctx := context.Background()
	read := func(model string, params map[string]any) Outcome {
		params["model"] = model
		return o.Perform(ctx, policy.Action{Kind: "odoo.read", Resource: "odoo:acme/" + model, Params: params})
	}
	for _, m := range policy.OdooModels {
		if out := read(m, map[string]any{"limit": float64(3)}); !out.OK {
			t.Fatalf("%s: %s", m, out.Error)
		}
	}
	// The ceiling is compared in the database's currency; a demo database may not run in euros.
	orders := read("purchase.order", map[string]any{"limit": float64(1), "fields": []any{"currency_id", "partner_id"}})
	row := orders.Private["records"].([]any)[0].(map[string]any)
	_, cur := many2one(row["currency_id"])
	partner, _ := many2one(row["partner_id"])
	inst := o.Instances["acme"]
	inst.Currency = env("CONTROL_ODOO_CURRENCY", cur)
	o.Instances["acme"] = inst
	products := read("product.product", map[string]any{"domain": []any{[]any{"purchase_ok", "=", true}, []any{"standard_price", ">", float64(0)}}, "limit": float64(1), "fields": []any{"id"}})
	product := products.Private["records"].([]any)[0].(map[string]any)["id"].(float64)

	draft := o.Perform(ctx, act("odoo.order_draft", map[string]any{"partner_id": float64(partner), "lines": []any{map[string]any{"product_id": product, "qty": float64(1)}}, OdooCeilingParam: int64(100000)}))
	if !draft.OK {
		t.Fatal(draft.Error)
	}
	id := float64(draft.Detail["order"].(int64))
	t.Logf("drafted %v at %v %v", draft.Detail["name"], draft.Detail["amount_total"], draft.Detail["currency"])
	lines := read("purchase.order.line", map[string]any{"domain": []any{[]any{"order_id", "=", id}}, "fields": []any{"id"}})
	line := lines.Private["records"].([]any)[0].(map[string]any)["id"].(float64)
	if out := o.Perform(ctx, act("odoo.order_line_set", map[string]any{"order": id, "line": line, "qty": float64(2), OdooCeilingParam: int64(100000)})); !out.OK {
		t.Fatal(out.Error)
	}
	approval := o.Perform(ctx, act("odoo.order_request_approval", map[string]any{"order": id, OdooCeilingParam: int64(100000)}))
	t.Logf("request approval: ok=%v %v %v", approval.OK, approval.Detail["state"], approval.Error)
	if out := o.Perform(ctx, act("odoo.order_cancel", map[string]any{"order": id, OdooCeilingParam: int64(100000)})); !out.OK || out.Detail["state"] != "cancel" {
		t.Fatalf("%+v", out)
	}
}

// An agent with its own Odoo user goes to Odoo with its own key; an agent without one, or a name
// that is not a plain slug, goes with the instance's key.
func TestOdooKeyPerAgent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "odoo-key-acme"), []byte("instance"), 0o600)
	os.WriteFile(filepath.Join(dir, "odoo-key-acme-supplier-scout"), []byte("scout"), 0o600)
	o := Odoo{SecretsDir: dir}
	for agent, want := range map[string]string{"supplier-scout": "scout", "procurement-agent": "instance", "../acme": "instance", "": "instance"} {
		raw, err := o.key("acme", map[string]any{OdooAgentParam: agent})
		if err != nil || string(raw) != want {
			t.Errorf("agent %q: got %q, %v; want %q", agent, raw, err, want)
		}
	}
}

// With a daily allowance, a draft or a larger quantity that takes the signer's day over it is
// refused, named by the signer; what stands is counted, and the detail says how far the day is.
func TestAnOrderIsHeldToTheSignersDailyAllowance(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	day := func(spent int64) map[string]any {
		return map[string]any{OdooCeilingParam: int64(5000), OdooDailyParam: int64(1000), OdooSpentParam: spent, OdooSignerParam: "acme#shane"}
	}
	draft := func(p, q float64, spent int64) Outcome {
		params := day(spent)
		params["partner_id"], params["lines"] = float64(8), []any{map[string]any{"product_id": p, "qty": q}}
		return o.Perform(context.Background(), act("odoo.order_draft", params))
	}
	// 3 chairs cost 360 and Odoo prices them at 391.50; 700 already spent today is over at cost.
	if out := draft(31, 3, 70000); out.OK || !strings.Contains(out.Error, "over acme#shane's daily allowance: EUR 1060.00 of 1000.00") || f.wrote() {
		t.Fatalf("over the day at cost, nothing may be created: %+v %v", out, f.calls)
	}
	if out := draft(31, 3, 62000); out.OK || !strings.Contains(out.Error, "is over acme#shane's daily allowance: EUR 1011.50 of 1000.00") || !strings.Contains(out.Error, "so it was cancelled") {
		t.Fatalf("over the day at Odoo's price, the draft is cancelled: %+v", out)
	}
	out := draft(31, 3, 50000)
	if !out.OK || out.Counted != 39150 || out.Detail["spent_today_eur"] != "891.50" || out.Detail[OdooDailyParam] != int64(1000) {
		t.Fatalf("%+v", out)
	}
	// A quantity change counts by how much the order moved.
	set := func(qty float64, spent int64) Outcome {
		params := day(spent)
		params["order"], params["line"], params["qty"] = float64(7), float64(15), qty
		return o.Perform(context.Background(), act("odoo.order_line_set", params))
	}
	if out := set(8, 70000); out.OK || !strings.Contains(out.Error, "daily allowance") || f.lines[15].qty != 5 {
		t.Fatalf("over the day with the new quantity: %+v", out)
	}
	if out := set(8, 0); !out.OK || out.Counted != 39150 || out.Detail["spent_today_eur"] != "391.50" {
		t.Fatalf("%+v", out)
	}
	if out := set(2, 99000); !out.OK || out.Counted != -78300 {
		t.Fatalf("going down is never over the day: %+v", out)
	}
}

// What a person sees before a draft is Odoo's own: the supplier's name, each product's name,
// code and cost, the total at cost; for a change to an order, its name, state and total.
func TestTheDisplayIsOdoosWord(t *testing.T) {
	f := newFakeOdoo()
	o := odooFor(t, f)
	d, err := o.Display(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(31), "qty": float64(3)}}}))
	if err != nil {
		t.Fatal(err)
	}
	lines := d["lines"].([]any)
	l := lines[0].(map[string]any)
	if d["total_at_cost"] != "360.00" || l["name"] != "Office Chair" || l["unit_cost"] != "120.00" || l["qty"] != int64(3) {
		t.Fatalf("%v", d)
	}
	d, err = o.Display(context.Background(), act("odoo.order_cancel", map[string]any{"order": float64(7)}))
	if err != nil || d["state"] != "draft" || d["total"] == "" {
		t.Fatalf("%v %v", d, err)
	}
	if f.wrote() {
		t.Fatal("the display wrote to Odoo")
	}
}

// Every word asked on an order shows the whole order as Odoo has it: supplier, dates, each line
// with its unit, price and subtotal, and the untaxed amount, the tax and the total.
func TestEveryWordOnAnOrderShowsTheWholeOrder(t *testing.T) {
	f := newFakeOdoo()
	f.tax = 0.2
	o := odooFor(t, f)
	want := map[string]any{"order": "P00007", "state": "draft", "partner": "Supplier 8", "partner_id": int64(8), "currency": "EUR",
		"date_order": "2026-10-18", "date_planned": "2026-10-21", "untaxed": "652.50", "tax": "130.50", "total": "783.00"}
	wantLine := map[string]any{"product_id": int64(31), "name": "[P-31] Office Chair", "code": "P-31", "qty": int64(5), "uom": "Units", "unit_price": "130.50", "subtotal": "652.50"}
	for _, kind := range []string{"odoo.order_cancel", "odoo.order_request_approval", "odoo.order_line_set"} {
		d, err := o.Display(context.Background(), act(kind, map[string]any{"order": float64(7), "line": float64(15), "qty": float64(8)}))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		for k, v := range want {
			if d[k] != v {
				t.Fatalf("%s: %s is %v, want %v (%v)", kind, k, d[k], v, d)
			}
		}
		lines := d["lines"].([]any)
		if len(lines) != 1 {
			t.Fatalf("%s: %v", kind, lines)
		}
		for k, v := range wantLine {
			if got := lines[0].(map[string]any)[k]; got != v {
				t.Fatalf("%s: line %s is %v, want %v", kind, k, got, v)
			}
		}
		if kind == "odoo.order_line_set" {
			// What the current screen reads stays where it was.
			l := d["line"].(map[string]any)
			if l["qty_now"] != int64(5) || l["qty"] != int64(8) || d["total_after_estimate"] == nil {
				t.Fatalf("%v", d)
			}
		}
	}
	if f.wrote() {
		t.Fatal("the display wrote to Odoo")
	}
}

// A draft's lines carry their unit and the supplier's last price: the price list entry when one
// holds for the quantity, else the last confirmed order line, else nothing; and the draft the
// date Odoo plans it for from the supplier's lead time.
func TestADraftShowsTheSuppliersLastPriceAndLeadTime(t *testing.T) {
	f := newFakeOdoo()
	f.sellers = []fakeSeller{{partner: 9, product: 19, price: 580, delay: 3}, {partner: 9, product: 21, price: 11, minQty: 50, delay: 1}}
	o := odooFor(t, f)
	d, err := o.Display(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(9), "lines": []any{
		map[string]any{"product_id": float64(19), "qty": float64(2)},
		map[string]any{"product_id": float64(31), "qty": float64(1)},
		map[string]any{"product_id": float64(21), "qty": float64(4)},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	lines := d["lines"].([]any)
	desk, chair, box := lines[0].(map[string]any), lines[1].(map[string]any), lines[2].(map[string]any)
	if desk["uom"] != "Units" || desk["last_price"] != "580.00" || desk["last_order"] != nil || desk["last_date"] != nil {
		t.Fatalf("from the price list: %v", desk)
	}
	if chair["last_price"] != "900.00" || chair["last_order"] != "P00011" || chair["last_date"] != "2026-09-30" {
		t.Fatalf("from the last confirmed order: %v", chair)
	}
	if _, ok := box["last_price"]; ok {
		t.Fatalf("a price list entry for 50 does not hold for 4, and nothing was ordered: %v", box)
	}
	if want := time.Now().UTC().AddDate(0, 0, 3).Format("2006-01-02"); d["date_planned"] != want {
		t.Fatalf("date_planned %v, want %s", d["date_planned"], want)
	}
	if d["total_at_cost"] != "1376.00" || d["partner_id"] != int64(9) {
		t.Fatalf("%v", d)
	}
	// Without any lead time there is no planned date.
	d, err = o.Display(context.Background(), act("odoo.order_draft", map[string]any{"partner_id": float64(8), "lines": []any{map[string]any{"product_id": float64(31), "qty": float64(1)}}}))
	if err != nil || d["date_planned"] != nil {
		t.Fatalf("%v %v", d, err)
	}
	if f.wrote() {
		t.Fatal("the display wrote to Odoo")
	}
}

// The display against a local Odoo, only reading (CONTROL_ODOO_IT=1, as TestAgainstALocalOdoo):
// the fields asked for exist in this Odoo, and the last order's display is whole.
func TestTheDisplayAgainstALocalOdoo(t *testing.T) {
	if os.Getenv("CONTROL_ODOO_IT") == "" {
		t.Skip("set CONTROL_ODOO_IT=1 to run against a local Odoo")
	}
	keyFile := os.Getenv("CONTROL_ODOO_KEY_FILE")
	if keyFile == "" {
		keyFile = "/home/bench/work/odoo-demo/gate.key"
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	base := os.Getenv("CONTROL_ODOO_URL")
	if base == "" {
		base = "http://127.0.0.1:8069"
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "odoo-key-acme"), key, 0o600)
	o := Odoo{SecretsDir: dir, Instances: map[string]OdooInstance{"acme": {Base: base, DB: "acme"}}}
	ctx := context.Background()
	orders := o.Perform(ctx, policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order", Params: map[string]any{"model": "purchase.order",
		"limit": float64(1), "order": "id desc", "domain": []any{[]any{"state", "=", "purchase"}}, "fields": []any{"partner_id", "order_line"}}})
	if !orders.OK {
		t.Fatal(orders.Error)
	}
	row := orders.Private["records"].([]any)[0].(map[string]any)
	id := row["id"].(float64)
	partner, _ := many2one(row["partner_id"])
	for _, kind := range []string{"odoo.order_cancel", "odoo.order_request_approval"} {
		d, err := o.Display(ctx, act(kind, map[string]any{"order": id}))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if ls, _ := d["lines"].([]any); len(ls) == 0 || d["untaxed"] == nil || d["tax"] == nil || d["total"] == nil || d["date_order"] == nil {
			t.Fatalf("%s: not the whole order: %v", kind, d)
		}
		b, _ := json.Marshal(d)
		t.Logf("%s: %s", kind, b)
	}
	lines := o.Perform(ctx, policy.Action{Kind: "odoo.read", Resource: "odoo:acme/purchase.order.line", Params: map[string]any{"model": "purchase.order.line",
		"domain": []any{[]any{"order_id", "=", id}, []any{"display_type", "=", false}}, "fields": []any{"product_id"}, "limit": float64(1)}})
	if !lines.OK {
		t.Fatal(lines.Error)
	}
	l := lines.Private["records"].([]any)[0].(map[string]any)
	product, _ := many2one(l["product_id"])
	d, err := o.Display(ctx, act("odoo.order_line_set", map[string]any{"order": id, "line": l["id"], "qty": float64(3)}))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	t.Logf("line_set: %s", b)
	d, err = o.Display(ctx, act("odoo.order_draft", map[string]any{"partner_id": float64(partner), "lines": []any{map[string]any{"product_id": float64(product), "qty": float64(3)}}}))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(d)
	t.Logf("draft: %s", b)
}
