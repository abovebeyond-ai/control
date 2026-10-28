package policy

import (
	"fmt"
	"sort"
	"strings"
)

// The run kinds (docs/run-lifecycle.md): what a hand says about its own run, never an effect at a
// far end. run.open starts a run and may name the run it continues; run.checkpoint keeps where
// the work stands; run.close ends the run as done, handed over or abandoned. They are judged only
// under a grant or task that carries a Lifecycle, and the gateway performs them itself: the
// record is the effect, and the one thing handed back is a predecessor's handover.
const (
	RunOpenKind       = "run.open"
	RunCheckpointKind = "run.checkpoint"
	RunCloseKind      = "run.close"
)

// IsRunKind says whether the kind is one of the run's own signals.
func IsRunKind(kind string) bool {
	return kind == RunOpenKind || kind == RunCheckpointKind || kind == RunCloseKind
}

// The outcomes a run.close may state.
const (
	OutcomeDone      = "done"
	OutcomeHandover  = "handover"
	OutcomeAbandoned = "abandoned"
)

// Lifecycle is what a grant or a task asks of a run: how it ends (Done, Checks) and how long it
// may go on without ending (MaxMinutes, MaxRequests, CheckpointEvery, MaxHandovers). A zero limit
// is no limit. The owner writes it once per task; the hand cannot loosen it, since it lives in
// the bundle the record names.
type Lifecycle struct {
	// Done names the kinds a run must have performed before it may close as done: for a coding
	// task branch.push and pull.open, so "done" always ends in a pull request a person reviews.
	Done []string `json:"done,omitempty"`
	// Checks names the checks the hand must report as passed when it closes as done ("tests",
	// "lint"). The gateway cannot run them: it holds the hand to saying so, on the record, and a
	// close that leaves one out or reports it failed is refused. The pull request's own CI and
	// the reviewer remain the judges of whether they really passed.
	Checks []string `json:"checks,omitempty"`
	// MaxMinutes is how long after its first request a run may act. Past it only run.close is
	// judged, so a stuck hand hands over instead of carrying on.
	MaxMinutes int `json:"max_minutes,omitempty"`
	// MaxRequests is how many requests a run may make, refused ones included: a hand looping on
	// a refusal reaches it as surely as one looping on effects. Past it only run.close.
	MaxRequests int `json:"max_requests,omitempty"`
	// CheckpointEvery is how many effects a run may perform before it must say where it stands
	// with a run.checkpoint. The checkpoint is also what a follow-on reads if this run stalls.
	CheckpointEvery int `json:"checkpoint_every,omitempty"`
	// MaxHandovers is how long a chain of runs continuing one another may grow. A task that has
	// been handed on this many times waits for a person, not for one more agent.
	MaxHandovers int `json:"max_handovers,omitempty"`
}

// Document is the lifecycle as the bundle carries it, sorted so the hash is stable.
func (l Lifecycle) Document() map[string]any {
	done := append([]string{}, l.Done...)
	checks := append([]string{}, l.Checks...)
	sort.Strings(done)
	sort.Strings(checks)
	return map[string]any{"done": done, "checks": checks, "max_minutes": l.MaxMinutes, "max_requests": l.MaxRequests,
		"checkpoint_every": l.CheckpointEvery, "max_handovers": l.MaxHandovers}
}

// RunState is where one run stands in its lifecycle: bounded, folded from the run's own records,
// and written on each record judged under a lifecycle (control_lifecycle) so a reader can repeat
// the verdict from the record alone.
type RunState struct {
	// Opened is the time of the run's first request, unix seconds; Resource what it was on.
	Opened   int64  `json:"opened"`
	Resource string `json:"resource"`
	// Requests counts every request, refused ones included; Effects those allowed, and
	// SinceCheckpoint those allowed since the last run.checkpoint.
	Requests        int `json:"requests"`
	Effects         int `json:"effects"`
	SinceCheckpoint int `json:"since_checkpoint"`
	// Closed is the outcome of the run.close, or empty while the run is open.
	Closed string `json:"closed,omitempty"`
	// Continues names the run this one took over, Depth how many handovers led here, and
	// ContinuedBy the run that took this one over: a run is continued once.
	Continues   string `json:"continues,omitempty"`
	Depth       int    `json:"depth"`
	ContinuedBy string `json:"continued_by,omitempty"`
	// Handover is what a follow-on receives: the parameters of the closing handover, or of the
	// last checkpoint while the run has not closed. Never part of the claims, only its presence.
	Handover map[string]any `json:"-"`
	// Life is the lifecycle the run was judged under, nil for a run under a grant without one.
	Life *Lifecycle `json:"-"`
}

// Claims is the state as a record carries it.
func (r RunState) Claims() map[string]any {
	c := map[string]any{"opened": r.Opened, "requests": r.Requests, "effects": r.Effects, "since_checkpoint": r.SinceCheckpoint, "depth": r.Depth}
	for k, v := range map[string]string{"closed": r.Closed, "continues": r.Continues, "continued_by": r.ContinuedBy} {
		if v != "" {
			c[k] = v
		}
	}
	return c
}

// Stalled says whether the run went past its time or its requests without closing.
func (l Lifecycle) Stalled(r RunState, now int64) bool {
	if r.Closed != "" || r.Requests == 0 {
		return false
	}
	return (l.MaxMinutes > 0 && now >= r.Opened+int64(l.MaxMinutes)*60) || (l.MaxRequests > 0 && r.Requests >= l.MaxRequests)
}

// Waiting says whether a follow-on may continue the run: it was handed over, or it stalled with
// a checkpoint to hand over, and nobody has taken it yet.
func (l Lifecycle) Waiting(r RunState, now int64) bool {
	if r.ContinuedBy != "" {
		return false
	}
	return r.Closed == OutcomeHandover || (l.Stalled(r, now) && r.Handover != nil)
}

// Judge is the lifecycle's verdict on the next request of a run, before the grant is read: the
// run's path (with the runs it continues, for the definition of done) and lifecycle state as
// they stand, the time of the request, and, for a run.open that continues another, that
// run's state (nil when it names one the gateway has never seen). Empty means the lifecycle has
// no objection. Deterministic over its inputs like Evaluate.
func (l Lifecycle) Judge(run string, a Action, phi PathSummary, r RunState, now int64, prev *RunState) (string, string) {
	if run == "" {
		return "DENY", "a run under a lifecycle must have a name"
	}
	if r.Closed != "" {
		return "DENY", "the run was closed as " + r.Closed + "; a new run starts the next piece of work"
	}
	if a.Kind == RunOpenKind && r.Requests > 0 {
		return "DENY", "run.open comes first in a run, and this run has already acted"
	}
	// Past time or past budget only the close is judged: the way out is always open.
	if a.Kind != RunCloseKind && r.Requests > 0 {
		if l.MaxMinutes > 0 && now >= r.Opened+int64(l.MaxMinutes)*60 {
			return "DENY", fmt.Sprintf("the run is past its %d minutes; close it, with a handover if work remains", l.MaxMinutes)
		}
		if l.MaxRequests > 0 && r.Requests >= l.MaxRequests {
			return "DENY", fmt.Sprintf("the run has made its %d requests; close it, with a handover if work remains", l.MaxRequests)
		}
	}
	if !IsRunKind(a.Kind) && l.CheckpointEvery > 0 && r.SinceCheckpoint >= l.CheckpointEvery {
		return "DENY", fmt.Sprintf("%d effects since the last checkpoint; say where the run stands with run.checkpoint first", r.SinceCheckpoint)
	}
	if IsRunKind(a.Kind) {
		if err := HandoverSafe(a.Params); err != nil {
			return "DENY", err.Error()
		}
	}
	switch a.Kind {
	case RunOpenKind:
		prevName, _ := a.Params["continues"].(string)
		if prevName == "" {
			return "", ""
		}
		switch {
		case prevName == run:
			return "DENY", "a run cannot continue itself"
		case prev == nil:
			return "DENY", "there is no run " + prevName + " to continue"
		case prev.ContinuedBy != "":
			return "DENY", "the run " + prevName + " was already continued by " + prev.ContinuedBy
		case prev.Closed == OutcomeDone || prev.Closed == OutcomeAbandoned:
			return "DENY", "the run " + prevName + " closed as " + prev.Closed + " and hands nothing over"
		case !l.Waiting(*prev, now):
			return "DENY", "the run " + prevName + " is still running; it hands over when it closes or stalls with a checkpoint"
		case prev.Resource != a.Resource:
			return "DENY", "the run " + prevName + " worked on " + prev.Resource + ", not on " + a.Resource
		case l.MaxHandovers > 0 && prev.Depth+1 > l.MaxHandovers:
			return "DENY", fmt.Sprintf("this work was handed over %d times; a person looks at it before another run takes it on", prev.Depth)
		}
	case RunCloseKind:
		outcome, _ := a.Params["outcome"].(string)
		switch outcome {
		case OutcomeDone:
			if missing := l.DoneMissing(phi); missing != "" {
				return "DENY", "not done: " + missing
			}
			if missing := l.missingChecks(a.Params["checks"]); missing != "" {
				return "DENY", "not done: " + missing
			}
		case OutcomeHandover:
			if next, _ := a.Params["next"].([]any); len(next) == 0 {
				return "DENY", "a handover names what remains in next"
			}
		case OutcomeAbandoned:
		default:
			return "DENY", "a run closes as done, handover or abandoned, not as " + outcome
		}
	}
	return "", ""
}

// DoneMissing names the first kind of the definition of done the path has not performed.
func (l Lifecycle) DoneMissing(phi PathSummary) string {
	for _, k := range l.Done {
		if phi.PerKind[k] == 0 {
			return "the run has no " + k + " yet"
		}
	}
	return ""
}

// missingChecks names the first required check the close does not report as passed.
func (l Lifecycle) missingChecks(v any) string {
	reported := map[string]string{}
	list, _ := v.([]any)
	for _, item := range list {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		result, _ := m["result"].(string)
		reported[name] = result
	}
	for _, c := range l.Checks {
		switch result, ok := reported[c]; {
		case !ok:
			return "the check " + c + " is not reported"
		case result != "passed":
			return "the check " + c + " reports " + result
		}
	}
	return ""
}

// Fold is the state after a request with a verdict, at a time.
func (r RunState) Fold(a Action, verdict string, at int64) RunState {
	next := r
	if next.Requests == 0 {
		next.Opened, next.Resource = at, a.Resource
	}
	next.Requests++
	if verdict != "ALLOW" {
		return next
	}
	switch a.Kind {
	case RunOpenKind:
		if prev, _ := a.Params["continues"].(string); prev != "" {
			next.Continues = prev
		}
	case RunCheckpointKind:
		next.SinceCheckpoint = 0
		next.Handover = a.Params
	case RunCloseKind:
		next.Closed, _ = a.Params["outcome"].(string)
		if next.Closed == OutcomeHandover {
			next.Handover = a.Params
		}
	default:
		next.Effects++
		next.SinceCheckpoint++
	}
	return next
}

// The bounds of what a run says about itself. A handover is read by the next agent as its
// starting context, so it is held small: long enough for a summary and a list of what remains,
// too short to carry a repository, and refused when it looks like it carries a credential.
const (
	maxHandoverText  = 4000
	maxHandoverItems = 30
)

// credentialMarks are the openings of the credentials a coding hand is most likely to paste by
// mistake. Finding one is a refusal; not finding one proves nothing, which is why a handover
// carries no authority either way: the follow-on acts under its own capability.
var credentialMarks = []string{"-----BEGIN", "ghp_", "gho_", "ghs_", "github_pat_", "sk-ant-", "sk-proj-", "xoxb-", "xoxp-", "AKIA", "AIza"}

// HandoverSafe holds the parameters of a run kind to the bounds of a handover.
func HandoverSafe(params map[string]any) error {
	items := 0
	var check func(path string, v any) error
	check = func(path string, v any) error {
		switch x := v.(type) {
		case string:
			if len(x) > maxHandoverText {
				return fmt.Errorf("%s is longer than %d characters; a handover points at the work, it does not carry it", path, maxHandoverText)
			}
			for _, m := range credentialMarks {
				if strings.Contains(x, m) {
					return fmt.Errorf("%s looks like it carries a credential (%s…); a handover never does", path, m)
				}
			}
		case []any:
			items += len(x)
			if items > maxHandoverItems {
				return fmt.Errorf("the handover lists more than %d items", maxHandoverItems)
			}
			for i, y := range x {
				if err := check(fmt.Sprintf("%s[%d]", path, i), y); err != nil {
					return err
				}
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := check(path+"."+k, x[k]); err != nil {
					return err
				}
			}
		}
		return nil
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := check(k, params[k]); err != nil {
			return err
		}
	}
	return nil
}
