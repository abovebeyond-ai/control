package effects

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// Odoo performs the Odoo kinds on a client's Odoo through its own JSON-2 API, unchanged:
// POST {base}/json/2/<model>/<method> with the API key as a bearer token and the database in
// X-Odoo-Database. The key lives in the gateway's secrets as odoo-key-<instance>; the agent
// never sees it, and nothing else calls Odoo (docs/odoo-gate.md).
//
// The resource is "odoo:<instance>/<model>". The judgement already held the model to the list
// and a write to purchase orders (policy.odooRule); what needs Odoo's own state is checked
// here, before the call that changes anything: an order's state, and its total against the
// ceiling the registry gives the person whose word the write carries (ceiling_eur, added by
// the gateway from the verified entry, never by the hand).
type Odoo struct {
	SecretsDir string
	Instances  map[string]OdooInstance
	Client     *http.Client
}

// OdooInstance is where one client's Odoo is: an address and a database, configuration and
// not a secret.
type OdooInstance struct {
	Base string `json:"base"` // https://acme.odoo.com
	DB   string `json:"db"`
	// Currency is the currency an order's total must be in for the ceiling to be compared with
	// it, EUR unless a demo database runs in another; an order in any other currency is refused.
	Currency string `json:"currency,omitempty"`
}

// OdooAgentParam is the parameter the gateway adds to every Odoo action: which agent it acts
// for, as the fragment of the agent's identifier. When the secrets hold odoo-key-<instance>-<it>,
// the action goes to Odoo as that agent's own Odoo user, so Odoo shows which agent did what;
// otherwise as the instance's one user. Each such user has the same narrow rights in Odoo.
const OdooAgentParam = "odoo_agent"

// OdooCeilingParam is the parameter the gateway adds to an Odoo write: the signer's ceiling in
// whole euros, from the registry entry it verified.
const OdooCeilingParam = "ceiling_eur"

// The parameters the gateway adds when the signer's entry carries a daily allowance: the
// allowance in whole euros, what the signer's orders already came to today in cents, and who
// the signer is, for the refusal to name. Without them only the ceiling per order holds.
const (
	OdooDailyParam  = "daily_eur"
	OdooSpentParam  = "spent_today_cents"
	OdooSignerParam = "signer"
)

// limits are what an order's total is held to: the signer's ceiling per order and, when the
// entry has one, the day's allowance and what was spent against it already.
type limits struct {
	ceiling, daily, spent int64
	signer                string
}

// day says why adding cents to the signer's day goes over the allowance, or "".
func (l limits) day(add int64) string {
	if l.daily <= 0 || add <= 0 || l.spent+add <= l.daily*100 {
		return ""
	}
	who := l.signer
	if who == "" {
		who = "the signer"
	}
	return fmt.Sprintf("over %s's daily allowance: EUR %s of %s would be used", who, money(l.spent+add), money(l.daily*100))
}

// key is the Odoo API key an action goes with: the agent's own user's when the secrets hold one,
// else the instance's. The agent's name is the gateway's addition, never the hand's, and is
// held to letters, digits and dashes before it becomes part of a file name.
func (o Odoo) key(instance string, params map[string]any) ([]byte, error) {
	if agent, _ := params[OdooAgentParam].(string); agent != "" && odooSlug.MatchString(agent) {
		if raw, err := os.ReadFile(filepath.Join(o.SecretsDir, "odoo-key-"+instance+"-"+agent)); err == nil {
			return raw, nil
		}
	}
	return os.ReadFile(filepath.Join(o.SecretsDir, "odoo-key-"+instance))
}

var odooSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (o Odoo) Kinds() []string { return policy.Builtin.Of(policy.OdooAdapter) }

// odooDefaultFields are read when a read names no fields: enough to buy with, and never the
// binary fields (images, attachments) that Odoo returns when asked for everything.
var odooDefaultFields = map[string][]string{
	"purchase.order":      {"name", "state", "partner_id", "date_order", "amount_untaxed", "amount_total", "currency_id", "order_line"},
	"purchase.order.line": {"order_id", "product_id", "product_qty", "price_unit", "price_subtotal", "price_total"},
	"res.partner":         {"name", "is_company", "ref", "city", "country_id"},
	"product.product":     {"display_name", "default_code", "standard_price", "qty_available", "uom_id"},
	"product.template":    {"name", "default_code", "standard_price", "list_price"},
	"stock.quant":         {"product_id", "location_id", "quantity", "reserved_quantity"},
}

func (o Odoo) Perform(ctx context.Context, a policy.Action) Outcome {
	instance, model, ok := policy.OdooResource(a.Resource)
	if !ok {
		return Outcome{Error: "resource is not odoo:<instance>/<model>"}
	}
	inst, ok := o.Instances[instance]
	if !ok || inst.Base == "" || inst.DB == "" {
		return Outcome{Error: "no Odoo is configured for " + instance}
	}
	raw, err := o.key(instance, a.Params)
	if err != nil {
		return Outcome{Error: "no Odoo key for " + instance + " in the gateway's secrets"}
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if inst.Currency == "" {
		inst.Currency = "EUR"
	}
	c := odooClient{base: strings.TrimRight(inst.Base, "/"), db: inst.DB, key: strings.TrimSpace(string(raw)), client: client, currency: inst.Currency}
	if a.Kind == "odoo.read" {
		return c.read(ctx, model, a.Params)
	}
	ceiling, ok := wholeParam(a.Params, OdooCeilingParam)
	if !ok || ceiling < 0 {
		return Outcome{Error: "an Odoo write needs the ceiling of the person whose word it carries, and none came with it"}
	}
	lim := limits{ceiling: ceiling}
	if daily, ok := wholeParam(a.Params, OdooDailyParam); ok && daily > 0 {
		lim.daily = daily
		lim.spent, _ = wholeParam(a.Params, OdooSpentParam)
		lim.signer, _ = a.Params[OdooSignerParam].(string)
	}
	var out Outcome
	switch a.Kind {
	case "odoo.order_draft":
		out = c.draft(ctx, a.Params, lim)
	case "odoo.order_line_set":
		out = c.lineSet(ctx, a.Params, lim)
	case "odoo.order_cancel":
		out = c.cancel(ctx, a.Params)
	case "odoo.order_request_approval":
		out = c.requestApproval(ctx, a.Params, ceiling)
	default:
		return Outcome{Error: "the Odoo adapter does not perform " + a.Kind}
	}
	if out.Detail != nil {
		out.Detail["resource"] = a.Resource
		out.Detail[OdooCeilingParam] = ceiling
		if lim.daily > 0 {
			out.Detail[OdooDailyParam] = lim.daily
			out.Detail["spent_today_eur"] = money(lim.spent + out.Counted)
		}
	}
	return out
}

type odooClient struct {
	base, db, key, currency string
	client                  *http.Client
}

// call is one JSON-2 request; the answer is decoded into out and returned as Odoo sent it.
func (c odooClient) call(ctx context.Context, model, method string, args map[string]any, out any) ([]byte, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/json/2/"+model+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "bearer "+c.key)
	req.Header.Set("X-Odoo-Database", c.db)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if res.StatusCode/100 != 2 {
		// Odoo's error carries a traceback in debug; only its message comes back.
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
			if len(e.Message) > 200 {
				e.Message = e.Message[:200]
			}
		}
		return raw, fmt.Errorf("Odoo answered %d on %s/%s: %s", res.StatusCode, model, method, e.Message)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("Odoo's answer on %s/%s does not parse: %w", model, method, err)
		}
	}
	return raw, nil
}

// read is odoo.read: search_read on the model, the rows back to the hand and only their digest
// and count on the record.
func (c odooClient) read(ctx context.Context, model string, params map[string]any) Outcome {
	args := map[string]any{"domain": []any{}, "limit": 80}
	if d, ok := params["domain"]; ok {
		args["domain"] = d
	}
	if f, ok := params["fields"].([]any); ok && len(f) > 0 {
		args["fields"] = f
	} else {
		args["fields"] = odooDefaultFields[model]
	}
	if n, ok := wholeParam(params, "limit"); ok {
		args["limit"] = n
	}
	var rows []any
	raw, err := c.call(ctx, model, "search_read", args, &rows)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	sum := sha256.Sum256(raw)
	return Outcome{OK: true,
		Detail:  map[string]any{"model": model, "count": len(rows), "records_sha256": hex.EncodeToString(sum[:])},
		Private: map[string]any{"records": rows}}
}

// order is what the adapter reads of a purchase order before it acts on one.
type order struct {
	ID       int64
	Name     string
	State    string
	Total    int64 // amount_total in cents
	Currency string
	Company  int64
	Lines    []int64
}

func (c odooClient) order(ctx context.Context, id int64) (order, error) {
	var rows []map[string]any
	if _, err := c.call(ctx, policy.OdooOrderModel, "read", map[string]any{"ids": []int64{id}, "fields": []string{"name", "state", "amount_total", "currency_id", "company_id", "order_line"}}, &rows); err != nil {
		return order{}, err
	}
	if len(rows) != 1 {
		return order{}, fmt.Errorf("Odoo has no purchase order %d", id)
	}
	r := rows[0]
	o := order{ID: id, Name: odooStr(r["name"]), State: odooStr(r["state"]), Total: cents(r["amount_total"]), Lines: ids(r["order_line"])}
	_, o.Currency = many2one(r["currency_id"])
	o.Company, _ = many2one(r["company_id"])
	return o, nil
}

// held says why an order's total may not carry this word, or "": in the instance's currency
// and no higher than the ceiling.
func (c odooClient) held(total int64, currency string, ceiling int64) string {
	if currency != c.currency {
		return "the order is in " + currency + ", and the ceiling is compared in " + c.currency
	}
	if total > ceiling*100 {
		return fmt.Sprintf("the order total of %s %s is above the signer's ceiling of %d", money(total), currency, ceiling)
	}
	return ""
}

func (o order) detail() map[string]any {
	return map[string]any{"order": o.ID, "name": o.Name, "state": o.State, "amount_total": money(o.Total), "currency": o.Currency}
}

// draft is odoo.order_draft: the lines priced at the products' cost first, refused above the
// ceiling before anything is created; then the order in draft, and its total as Odoo computed
// it (from the supplier's price) held to the ceiling again. A draft Odoo priced above it is
// cancelled at once, and the outcome says so.
func (c odooClient) draft(ctx context.Context, params map[string]any, lim limits) Outcome {
	ceiling := lim.ceiling
	partner, _ := wholeParam(params, "partner_id")
	lines, _ := params["lines"].([]any)
	productIDs := make([]int64, 0, len(lines))
	qty := map[int64]int64{}
	commands := make([]any, 0, len(lines))
	for _, l := range lines {
		m, _ := l.(map[string]any)
		p, _ := wholeParam(m, "product_id")
		q, _ := wholeParam(m, "qty")
		if _, twice := qty[p]; !twice {
			productIDs = append(productIDs, p)
		}
		qty[p] += q
		commands = append(commands, []any{0, 0, map[string]any{"product_id": p, "product_qty": q}})
	}
	var products []map[string]any
	if _, err := c.call(ctx, "product.product", "read", map[string]any{"ids": productIDs, "fields": []string{"standard_price", "purchase_ok", "display_name"}}, &products); err != nil {
		return Outcome{Error: err.Error()}
	}
	if len(products) != len(productIDs) {
		return Outcome{Error: "not every product of the order exists in Odoo"}
	}
	var estimate int64
	for _, p := range products {
		if p["purchase_ok"] != true {
			return Outcome{Error: fmt.Sprintf("the product %v cannot be purchased", p["display_name"])}
		}
		id, _ := whole64(p["id"])
		estimate += cents(p["standard_price"]) * qty[id]
	}
	if estimate > ceiling*100 {
		return Outcome{Error: fmt.Sprintf("the order comes to %s at the products' cost, above the signer's ceiling of %d; nothing was created", money(estimate), ceiling)}
	}
	if reason := lim.day(estimate); reason != "" {
		return Outcome{Error: "at the products' cost the order is " + reason + "; nothing was created"}
	}
	var created []int64
	if _, err := c.call(ctx, policy.OdooOrderModel, "create", map[string]any{"vals_list": []any{map[string]any{"partner_id": partner, "order_line": commands}}}, &created); err != nil {
		return Outcome{Error: err.Error()}
	}
	if len(created) != 1 {
		return Outcome{Error: "Odoo created no purchase order"}
	}
	o, err := c.order(ctx, created[0])
	if err != nil {
		return Outcome{Error: fmt.Sprintf("purchase order %d was created, and reading it back failed: %v", created[0], err)}
	}
	reason := c.held(o.Total, o.Currency, ceiling)
	if day := lim.day(o.Total); reason == "" && day != "" {
		reason = "is " + day
	}
	if reason != "" {
		_, cerr := c.call(ctx, policy.OdooOrderModel, "button_cancel", map[string]any{"ids": []int64{o.ID}}, nil)
		if cerr != nil {
			return Outcome{Error: fmt.Sprintf("%s was created as a draft and %s; cancelling it failed: %v", o.Name, reason, cerr), Detail: o.detail()}
		}
		o.State = "cancel"
		return Outcome{Error: fmt.Sprintf("%s was created as a draft and %s, so it was cancelled", o.Name, reason), Detail: o.detail()}
	}
	return Outcome{OK: true, Detail: o.detail(), Counted: o.Total}
}

// lineSet is odoo.order_line_set: one line's quantity on a draft order, the new total
// estimated at the line's own price and refused above the ceiling, then held again as Odoo
// computed it, and set back when Odoo's price for the new quantity crosses it.
func (c odooClient) lineSet(ctx context.Context, params map[string]any, lim limits) Outcome {
	ceiling := lim.ceiling
	id, _ := wholeParam(params, "order")
	line, _ := wholeParam(params, "line")
	q, _ := wholeParam(params, "qty")
	o, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	if o.State != "draft" {
		return Outcome{Error: fmt.Sprintf("%s is %s; a quantity changes only on a draft", o.Name, o.State)}
	}
	if !containsID(o.Lines, line) {
		return Outcome{Error: fmt.Sprintf("line %d is not on %s", line, o.Name)}
	}
	var rows []map[string]any
	if _, err := c.call(ctx, "purchase.order.line", "read", map[string]any{"ids": []int64{line}, "fields": []string{"product_qty", "price_unit", "price_total"}}, &rows); err != nil || len(rows) != 1 {
		if err == nil {
			err = fmt.Errorf("Odoo has no line %d", line)
		}
		return Outcome{Error: err.Error()}
	}
	was, _ := rows[0]["product_qty"].(float64)
	lineTotal := cents(rows[0]["price_total"])
	estimate := o.Total + cents(rows[0]["price_unit"])*q
	if was > 0 {
		estimate = o.Total - lineTotal + int64(math.Round(float64(lineTotal)*float64(q)/was))
	}
	if reason := c.held(estimate, o.Currency, ceiling); reason != "" {
		return Outcome{Error: "with that quantity " + reason + "; nothing was changed"}
	}
	if reason := lim.day(estimate - o.Total); reason != "" {
		return Outcome{Error: "with that quantity the order is " + reason + "; nothing was changed"}
	}
	setQty := func(n any) error {
		_, err := c.call(ctx, "purchase.order.line", "write", map[string]any{"ids": []int64{line}, "vals": map[string]any{"product_qty": n}}, nil)
		return err
	}
	if err := setQty(q); err != nil {
		return Outcome{Error: err.Error()}
	}
	after, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: fmt.Sprintf("the quantity on %s was set, and reading the order back failed: %v", o.Name, err)}
	}
	reason := c.held(after.Total, after.Currency, ceiling)
	if reason == "" {
		if day := lim.day(after.Total - o.Total); day != "" {
			reason = "the order is " + day
		}
	}
	if reason != "" {
		if err := setQty(was); err != nil {
			return Outcome{Error: fmt.Sprintf("the quantity on %s was set and %s; setting it back failed: %v", o.Name, reason, err), Detail: after.detail()}
		}
		return Outcome{Error: fmt.Sprintf("the quantity on %s was set and %s, so it was set back", o.Name, reason)}
	}
	d := after.detail()
	d["line"], d["qty"], d["was"] = line, q, number(was)
	return Outcome{OK: true, Detail: d, Counted: after.Total - o.Total}
}

// cancel is odoo.order_cancel: only an order nobody has received or approved, a draft or one
// waiting for approval.
func (c odooClient) cancel(ctx context.Context, params map[string]any) Outcome {
	id, _ := wholeParam(params, "order")
	o, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	if o.State != "draft" && o.State != "to approve" {
		return Outcome{Error: fmt.Sprintf("%s is %s; only a draft or an order waiting for approval is cancelled here", o.Name, o.State)}
	}
	if _, err := c.call(ctx, policy.OdooOrderModel, "button_cancel", map[string]any{"ids": []int64{id}}, nil); err != nil {
		return Outcome{Error: err.Error()}
	}
	after, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: fmt.Sprintf("%s was cancelled, and reading it back failed: %v", o.Name, err)}
	}
	d := after.detail()
	d["was"] = o.State
	return Outcome{OK: true, Detail: d}
}

// requestApproval is odoo.order_request_approval: button_confirm, which Odoo turns into an
// approval at once when the company approves in one step, when the total is under the
// company's threshold, or when the gateway's own Odoo user may approve. Each of those would
// make this kind approve an order, which no kind may, so each is checked first and the call
// refused when any holds; the state after the call is checked again.
func (c odooClient) requestApproval(ctx context.Context, params map[string]any, ceiling int64) Outcome {
	id, _ := wholeParam(params, "order")
	o, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	if o.State != "draft" && o.State != "sent" {
		return Outcome{Error: fmt.Sprintf("%s is %s; approval is requested for a draft", o.Name, o.State)}
	}
	if reason := c.held(o.Total, o.Currency, ceiling); reason != "" {
		return Outcome{Error: reason}
	}
	var companies []map[string]any
	if _, err := c.call(ctx, "res.company", "read", map[string]any{"ids": []int64{o.Company}, "fields": []string{"po_double_validation", "po_double_validation_amount", "currency_id"}}, &companies); err != nil || len(companies) != 1 {
		if err == nil {
			err = fmt.Errorf("Odoo has no company %d", o.Company)
		}
		return Outcome{Error: err.Error()}
	}
	co := companies[0]
	_, coCurrency := many2one(co["currency_id"])
	switch {
	case co["po_double_validation"] != "two_step":
		return Outcome{Error: "the company approves orders in one step, so asking for approval would approve " + o.Name}
	case coCurrency != o.Currency:
		return Outcome{Error: "the order is in " + o.Currency + " and the approval threshold in " + coCurrency + "; the gateway does not convert"}
	case o.Total < cents(co["po_double_validation_amount"]):
		return Outcome{Error: fmt.Sprintf("%s is under the company's approval threshold of %s, so asking for approval would approve it", o.Name, money(cents(co["po_double_validation_amount"])))}
	}
	var ctxInfo struct {
		UID int64 `json:"uid"`
	}
	if _, err := c.call(ctx, "res.users", "context_get", map[string]any{}, &ctxInfo); err != nil {
		return Outcome{Error: err.Error()}
	}
	var manager bool
	if _, err := c.call(ctx, "res.users", "has_group", map[string]any{"ids": []int64{ctxInfo.UID}, "group_ext_id": "purchase.group_purchase_manager"}, &manager); err != nil {
		return Outcome{Error: err.Error()}
	}
	if manager {
		return Outcome{Error: "the gateway's Odoo user may approve orders, so asking for approval would approve " + o.Name}
	}
	if _, err := c.call(ctx, policy.OdooOrderModel, "button_confirm", map[string]any{"ids": []int64{id}}, nil); err != nil {
		return Outcome{Error: err.Error()}
	}
	after, err := c.order(ctx, id)
	if err != nil {
		return Outcome{Error: fmt.Sprintf("approval of %s was requested, and reading it back failed: %v", o.Name, err)}
	}
	if after.State != "to approve" {
		return Outcome{Error: fmt.Sprintf("Odoo left %s as %s after the request, not waiting for approval", o.Name, after.State), Detail: after.detail()}
	}
	return Outcome{OK: true, Detail: after.detail()}
}

// cents reads an amount as Odoo sends it (a float) in whole cents.
func cents(v any) int64 {
	f, _ := v.(float64)
	return int64(math.Round(f * 100))
}

// money writes cents as an amount with two decimals: a string, since the record's canonical
// form has no fractional numbers.
func money(c int64) string {
	sign := ""
	if c < 0 {
		sign, c = "-", -c
	}
	return fmt.Sprintf("%s%d.%02d", sign, c/100, c%100)
}

// number is a quantity for the record: whole when it is, else written out.
func number(f float64) any {
	if f == math.Trunc(f) && math.Abs(f) < 1<<53 {
		return int64(f)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func odooStr(v any) string { s, _ := v.(string); return s }

// many2one reads Odoo's [id, "name"] (or false).
func many2one(v any) (int64, string) {
	pair, ok := v.([]any)
	if !ok || len(pair) != 2 {
		return 0, ""
	}
	id, _ := whole64(pair[0])
	return id, odooStr(pair[1])
}

func ids(v any) []int64 {
	list, _ := v.([]any)
	out := make([]int64, 0, len(list))
	for _, x := range list {
		if n, ok := whole64(x); ok {
			out = append(out, n)
		}
	}
	return out
}

func containsID(list []int64, id int64) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func wholeParam(params map[string]any, key string) (int64, bool) { return whole64(params[key]) }

// whole64 is wholeNumber for ids and amounts, which Odoo keeps in 64 bits.
func whole64(v any) (int64, bool) {
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
