package policy

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Schema is what a kind's parameters may be (row 4.1.4): every key named with its
// type, required or not; a key the schema does not name is out of schema and the
// call is refused. The registry is part of the policy bundle, so a record names
// the schema it was validated against.
type Schema struct {
	Required map[string]string `json:"required"`
	Optional map[string]string `json:"optional"`
}

// Types: "string", "hex64" (a sha-256 in hex), "hex40" (a git commit id in hex), "int" (a
// whole number), "number" (any finite number), "bool", "strings" (an object whose values
// are strings), "list" (an array of strings), "records" (an array of objects whose values
// are strings), "[]string" (a short list of short words).
var schemaTypes = []string{"string", "hex64", "hex40", "int", "number", "bool", "strings", "list", "records", "[]string"}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Validate holds an action's parameters to the schema of its kind among the built-in kinds.
func Validate(a Action) error { return Builtin.Validate(a) }

// Validate holds an action's parameters to the schema of its kind in the table.
func (t Kinds) Validate(a Action) error {
	k, ok := t[a.Kind]
	s := k.Schema
	if !ok {
		return fmt.Errorf("no parameter schema is registered for %s", a.Kind)
	}
	for key := range a.Params {
		if _, r := s.Required[key]; !r {
			if _, o := s.Optional[key]; !o {
				return fmt.Errorf("parameter %q is not in the schema of %s", key, a.Kind)
			}
		}
	}
	for key, typ := range s.Required {
		v, present := a.Params[key]
		if !present {
			return fmt.Errorf("parameter %q is required for %s", key, a.Kind)
		}
		if err := checkType(key, typ, v); err != nil {
			return err
		}
	}
	for key, typ := range s.Optional {
		if v, present := a.Params[key]; present {
			if err := checkType(key, typ, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkType(key, typ string, v any) error {
	switch typ {
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("parameter %q must be a string", key)
		}
	case "hex64":
		s, ok := v.(string)
		if !ok || !hex64.MatchString(s) {
			return fmt.Errorf("parameter %q must be a sha-256 in lowercase hex", key)
		}
	case "hex40":
		s, ok := v.(string)
		if !ok || !hex40.MatchString(s) {
			return fmt.Errorf("parameter %q must be a git commit id in lowercase hex", key)
		}
	case "int":
		switch n := v.(type) {
		case int:
		case int64:
		case float64:
			if n != math.Trunc(n) {
				return fmt.Errorf("parameter %q must be a whole number", key)
			}
		default:
			return fmt.Errorf("parameter %q must be a whole number", key)
		}
	case "bool":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("parameter %q must be true or false", key)
		}
	case "[]string":
		// A list of short words (labels on an issue): every element a string, and the list
		// bounded, because a parameter that can grow without end is a parameter nobody reads.
		list, ok := v.([]any)
		if !ok {
			return fmt.Errorf("parameter %q must be a list of words", key)
		}
		if len(list) > 10 {
			return fmt.Errorf("parameter %q takes at most ten words", key)
		}
		for _, item := range list {
			s, ok := item.(string)
			if !ok || s == "" {
				return fmt.Errorf("parameter %q must be a list of words", key)
			}
			if len(s) > 50 {
				return fmt.Errorf("parameter %q has a word longer than fifty characters", key)
			}
		}
	case "number":
		switch n := v.(type) {
		case int, int64:
		case float64:
			if math.IsNaN(n) || math.IsInf(n, 0) {
				return fmt.Errorf("parameter %q must be a finite number", key)
			}
		default:
			return fmt.Errorf("parameter %q must be a number", key)
		}
	case "list":
		xs, ok := v.([]any)
		if !ok {
			return fmt.Errorf("parameter %q must be a list of strings", key)
		}
		for i, x := range xs {
			if _, ok := x.(string); !ok {
				return fmt.Errorf("parameter %q[%d] must be a string", key, i)
			}
		}
	case "records":
		xs, ok := v.([]any)
		if !ok {
			return fmt.Errorf("parameter %q must be a list of records", key)
		}
		for i, x := range xs {
			m, ok := x.(map[string]any)
			if !ok {
				return fmt.Errorf("parameter %q[%d] must be an object of strings", key, i)
			}
			for k, y := range m {
				if _, ok := y.(string); !ok {
					return fmt.Errorf("parameter %q[%d].%s must be a string", key, i, k)
				}
			}
		}
	case "strings":
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("parameter %q must be an object of strings", key)
		}
		for k, x := range m {
			if _, ok := x.(string); !ok {
				return fmt.Errorf("parameter %q.%s must be a string", key, k)
			}
		}
	default:
		return fmt.Errorf("unknown schema type %s", typ)
	}
	return nil
}

// schemaDocument is the table's schemas in a canonical shape for the bundle.
func (t Kinds) schemaDocument() map[string]any {
	out := map[string]any{}
	kinds := make([]string, 0, len(t))
	for k := range t {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := t[k]
		out[k] = map[string]any{"required": s.Required, "optional": s.Optional}
	}
	return out
}

// Matched names the permission an allowed action matched (row 4.1.2).
func Matched(a Action, phi PathSummary, g Grant) string {
	n := phi.PerKind[a.Kind] + 1
	limit := "no limit"
	if g.MaxPerKind > 0 {
		limit = fmt.Sprintf("%d", g.MaxPerKind)
	}
	return strings.TrimSpace(fmt.Sprintf("%s on %s, %d of %s this run", a.Kind, a.Resource, n, limit))
}
