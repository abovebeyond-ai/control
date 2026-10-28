package policy

import (
	"sort"
)

// RepairOnly says why next is more than a repair of cur, or "" when it is not: against cur it
// may add kinds with a radius in the kind table (to a hand or to one of its tasks) and
// resources, and nothing else. A kind that reaches a person or cannot be called back
// (branch.delete, pull.ready, pull.merge, anything B3) has no radius there: adding it takes
// the owner's token, and so does giving a kind a radius, since the table is the owner's. No new hand, nothing about who speaks for a hand, no new system or system address, no
// higher count, no certificate or per-action word dropped: the rest is Narrower's. A resource
// is added only to a hand whose every kind is a repair kind, since a new resource reaches every
// kind the hand holds. A version that only takes away is a repair too.
func RepairOnly(kinds Kinds, cur map[string]HandGrant, curSystems map[string]string, next map[string]HandGrant, nextSystems map[string]string) string {
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
			if !contains(was.Grant.Kinds, k) && !kinds.IsRepair(k) {
				return "adds the kind " + k + " for " + a + ", which is not reversible in one step"
			}
		}
		if r := firstOutside(g.Resources, was.Grant.Resources); r != "" {
			for _, k := range g.Kinds {
				if !kinds.IsRepair(k) {
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
						if !contains(prev.Kinds, k) && !kinds.IsRepair(k) {
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
