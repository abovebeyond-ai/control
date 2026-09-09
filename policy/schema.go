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

// Types: "string", "hex64" (a sha-256 in hex), "int" (a whole number), "strings"
// (an object whose values are strings).
var Schemas = map[string]Schema{
	"workflow.dispatch": {
		Required: map[string]string{"workflow": "string", "ref": "string"},
		Optional: map[string]string{"packages": "int", "plan_sha256": "hex64", "inputs": "strings"},
	},
	"branch.push": {
		Required: map[string]string{"branch": "string"},
		Optional: map[string]string{"packages": "int"},
	},
	"pull.open": {
		Required: map[string]string{"branch": "string", "base": "string"},
		Optional: map[string]string{"title": "string", "body": "string", "packages": "int"},
	},
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate holds an action's parameters to the schema of its kind.
func Validate(a Action) error {
	s, ok := Schemas[a.Kind]
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

// schemaDocument is the registry in a canonical shape for the bundle.
func schemaDocument() map[string]any {
	out := map[string]any{}
	kinds := make([]string, 0, len(Schemas))
	for k := range Schemas {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := Schemas[k]
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
