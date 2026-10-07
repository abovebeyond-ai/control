package effects

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/abovebeyond-ai/control/policy"
)

// SystemKinds are the actions on a running system (docs/mandates.md): one kind per action,
// never a generic command, each with its own schema and its own blast radius. The first is
// Stocklist's photo repair (B2: it writes derived sizes a later run can write again). The second
// is a research draft on the Gentells pipeline (B2: one brief for the desk, ready for review,
// which any editor edits, approves or dismisses; nothing is published).
var SystemKinds = []string{"stocklist.photos_repair", "studio.research_draft", "observatory.trend_edit", "observatory.trend_site"}

// System carries an action to the control endpoint of a running system, the evidence
// attached. It holds no credential: the system verifies the owner's capability and this
// gateway's signed request record itself (relying's checks), and refuses what nobody judged
// or what the owner did not mandate. Bases maps a resource ("stocklist:platform") to the
// system's base URL; an address is configuration, not a secret.
type System struct {
	Bases  map[string]string
	Client *http.Client
}

func (System) Kinds() []string { return SystemKinds }

// IsSystemKind says whether the gateway attaches the evidence for a system to this kind.
func IsSystemKind(kind string) bool {
	for _, k := range SystemKinds {
		if k == kind {
			return true
		}
	}
	return false
}

func (s System) Perform(ctx context.Context, a policy.Action) Outcome {
	base := strings.TrimRight(s.Bases[a.Resource], "/")
	if base == "" {
		return Outcome{Error: fmt.Sprintf("no system is configured for %s", a.Resource)}
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	str := func(k string) string { v, _ := a.Params[k].(string); return v }
	// Only the kind's own parameters go in the body; the evidence rides in the headers, as
	// on a Portal write, so a field the gateway added never becomes part of the action.
	params := map[string]any{}
	for k, v := range a.Params {
		if k != "evidence" && k != "capability" {
			params[k] = v
		}
	}
	body, _ := json.Marshal(map[string]any{"kind": a.Kind, "resource": a.Resource, "params": params})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/control/act", bytes.NewReader(body))
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Control-Evidence", str("evidence"))
	req.Header.Set("Control-Capability", str("capability"))
	res, err := client.Do(req)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if res.StatusCode/100 != 2 {
		reason := out["refused"]
		if reason == nil {
			reason = out["error"]
		}
		if reason == nil {
			reason = strings.TrimSpace(string(raw))
		}
		return Outcome{Error: fmt.Sprintf("%s answered %d: %v", a.Resource, res.StatusCode, reason)}
	}
	if out == nil {
		out = map[string]any{}
	}
	out["resource"] = a.Resource
	return Outcome{OK: true, Detail: out}
}
