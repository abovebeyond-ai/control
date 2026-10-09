package policy

import (
	"sort"
)

// RepairKinds are the kinds a version signed by a repair key may add (docs/working-set.md,
// "A widening by passkey"): each B1 or B2, undone in one step or ending in a review nobody
// has merged, with its radius named. A kind that reaches a person or cannot be called back
// (review.invite, review.sign, pull.merge, anything B3) is not here and never will be: adding
// it takes the owner's token. The system kinds are effects.SystemKinds; a test there keeps
// every one of them named here or deliberately left out.
var RepairKinds = map[string]string{
	"branch.push":             "B2: a branch nobody has merged",
	"pull.open":               "B2: a pull request that waits for the owner's merge",
	"issue.open":              "B2: an issue on the owner's own repository, closed in one step",
	PreviewPushKind:           "B2: moves the branch named preview, which only a preview site tracks",
	ForgeDeployKind:           "B2: deploys the preview site, which the next preview replaces",
	"portal.update":           "B2: one update in Portal, edited or deleted there",
	"portal.time_entry":       "B2: one time entry in Portal, edited or deleted there",
	"portal.expense":          "B2: one expense in Portal, edited or deleted there",
	"portal.project.patch":    "B2: project fields in Portal, set back in one step",
	"portal.task":             "B2: a task's state in Portal, set back in one step",
	"portal.measure":          "B1: queues a measurement; nothing changes but a reading",
	"portal.playbook":         "B2: queues a playbook, whose own actions are judged one by one",
	"stocklist.photos_repair": "B2: writes derived photo sizes a later run can write again",
	"studio.research_draft":   "B2: one brief for review; an editor approves or dismisses it",
	"observatory.trend_edit":  "B2: rewrites one trend's text; the text before is kept, one step undoes it",
	"observatory.trend_site":  "B2: puts one trend on the site or takes it off; deciding again reverses it",
}

// IsRepairKind says whether a repair key may add the kind.
func IsRepairKind(kind string) bool {
	_, ok := RepairKinds[kind]
	return ok
}

// RepairOnly says why next is more than a repair of cur, or "" when it is not: against cur it
// may add kinds from RepairKinds (to a hand or to one of its tasks) and resources, and nothing
// else. No new hand, nothing about who speaks for a hand, no new system or system address, no
// higher count, no certificate or per-action word dropped: the rest is Narrower's. A resource
// is added only to a hand whose every kind is a repair kind, since a new resource reaches every
// kind the hand holds. A version that only takes away is a repair too.
func RepairOnly(cur map[string]HandGrant, curSystems map[string]string, next map[string]HandGrant, nextSystems map[string]string) string {
	agents := make([]string, 0, len(next))
	for a := range next {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	// The part a repair may add is taken off, and what is left must be narrower.
	trimmed := make(map[string]HandGrant, len(next))
	for _, a := range agents {
		was, ok := cur[a]
		if !ok {
			return "adds the hand " + a
		}
		g := next[a].Grant
		for _, k := range g.Kinds {
			if !contains(was.Grant.Kinds, k) && !IsRepairKind(k) {
				return "adds the kind " + k + " for " + a + ", which is not reversible in one step"
			}
		}
		if r := firstOutside(g.Resources, was.Grant.Resources); r != "" {
			for _, k := range g.Kinds {
				if !IsRepairKind(k) {
					return "adds the resource " + r + " for " + a + ", which holds " + k + ", not reversible in one step"
				}
			}
		}
		g.Kinds = alreadyIn(g.Kinds, was.Grant.Kinds)
		g.Resources = alreadyIn(g.Resources, was.Grant.Resources)
		if len(g.Tasks) > 0 {
			tasks := make(map[string]TaskGrant, len(g.Tasks))
			for name, t := range g.Tasks {
				if prev, ok := was.Grant.Tasks[name]; ok {
					for _, k := range t.Kinds {
						if !contains(prev.Kinds, k) && !IsRepairKind(k) {
							return "adds the kind " + k + " to the task " + name + " for " + a + ", which is not reversible in one step"
						}
					}
					t.Kinds = alreadyIn(t.Kinds, prev.Kinds)
				}
				tasks[name] = t
			}
			g.Tasks = tasks
		}
		trimmed[a] = HandGrant{Grant: g}
	}
	return Narrower(cur, curSystems, trimmed, nextSystems)
}

// alreadyIn is list without what it adds to was: the additions a repair may make are checked
// above, and what is left goes to Narrower.
func alreadyIn(list, was []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if contains(was, s) {
			out = append(out, s)
		}
	}
	return out
}
