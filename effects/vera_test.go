package effects

import (
	"strings"
	"testing"
)

// A refusal has to say why. Vera answers a 404 without a JSON "error", and the adapter
// printed "<nil>", so the record of a refused run carried no reason at all.
func TestTheAppsRefusalIsSaidInWords(t *testing.T) {
	for _, c := range []struct {
		status int
		res    map[string]any
		want   string
	}{
		{404, map[string]any{}, "no such review"},
		{401, nil, "does not open this"},
		{400, map[string]any{"error": "page must be armed"}, "page must be armed"},
		{500, map[string]any{}, "without saying why"},
	} {
		if got := said(c.status, c.res); !strings.Contains(got, c.want) {
			t.Fatalf("%d: %q does not say %q", c.status, got, c.want)
		}
	}
}
