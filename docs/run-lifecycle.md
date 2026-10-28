# The run lifecycle

A run was a name a hand chose and the gateway counted against: one push and one pull request
per run, and nothing said when a run was over. A run that stopped halfway looked the same on the
record as one that finished, a session that took over had to be told by a person where the last
one left off, and a hand stuck in a loop kept submitting until something outside stopped it.

Since this release a grant, or a task within it, may carry a **lifecycle**: what a run must have
done to end as done, and how long it may go on without ending. Under it a run has a beginning, an
explicit end, a handover a follow-on can read without a person, and limits that turn a loop into a
refusal on the record. A grant without a lifecycle is judged exactly as before, and its bundle
hashes as before.

## What the owner writes

```json
"tasks": {
  "code": {
    "kinds": ["branch.push", "pull.open"],
    "lifecycle": {
      "done": ["branch.push", "pull.open"],
      "checks": ["tests"],
      "max_minutes": 120,
      "max_requests": 20,
      "checkpoint_every": 3,
      "max_handovers": 2
    }
  }
}
```

| field | what it holds a run to |
| --- | --- |
| `done` | the kinds the run, with the runs it continues, must have performed before it closes as done. For a coding task this is a push and a pull request, so done always ends in something a person reviews and merges. |
| `checks` | the checks the hand must report as `passed` when it closes as done. |
| `max_minutes` | how long after its first request the run may act. |
| `max_requests` | how many requests the run may make, refused ones included. |
| `checkpoint_every` | how many effects the run may perform before it must say where it stands. |
| `max_handovers` | how long a chain of runs continuing one another may grow. |

A zero is no limit. The lifecycle is part of the bundle the record names, so the hand cannot
loosen it and a reader sees which limits judged.

## What the hand says

Three kinds, admitted by the lifecycle itself: the owner's capability names effects and does not
have to list them. They reach no far end. The gateway performs them, and the record is the effect.

| kind | parameters | what it does |
| --- | --- | --- |
| `run.open` | `goal`, `continues` | starts the run. Optional, unless the run takes over another: then it names that run, and the answer carries its handover. |
| `run.checkpoint` | `summary`, `next`, `state` | says where the run stands. Resets the checkpoint count, and is what a follow-on receives if this run stalls. |
| `run.close` | `outcome`, `summary`, `next`, `checks`, `state` | ends the run as `done`, `handover` or `abandoned`. |

`state` is an object of strings (`branch`, `commit`, `pull`), `next` a list of what remains,
`checks` a list of `{name, result}`.

## How a request is judged

The grant and the capability judge first, as they always did. Then the lifecycle, in this order:

1. A run under a lifecycle has a name; the run of a hand that names none would be closed forever.
2. A closed run does nothing more. The next piece of work is a new run.
3. `run.open` comes first in its run.
4. Past `max_minutes` or `max_requests`, only `run.close` is judged. The way out stays open, so a
   stuck hand hands over instead of carrying on.
5. After `checkpoint_every` effects, only `run.checkpoint` and `run.close`.
6. Whatever a run kind says is held to the bounds of a handover (below).
7. `run.open` with `continues`: the run named must exist, not be this run, not have been taken
   over already, have closed as `handover` or stalled with a checkpoint, have worked on the same
   resource, and sit fewer than `max_handovers` handovers deep.
8. `run.close` as `done`: every kind in `done` performed in the chain, every check in `checks`
   reported `passed`. As `handover`: `next` is not empty. As `abandoned`: always.

Every record judged under a lifecycle carries `control_lifecycle`, the state of the run the verdict
was judged against (opened, requests, effects, effects since the last checkpoint, depth, closed,
continues, continued by), so the verdict can be repeated from the record. The state is folded again
from the records at start, like the path summary, so a restart forgets nothing.

## The handover

A follow-on finds work with `GET /v1/runs?agent=…&waiting=1`: runs that closed as a handover, or
stalled past their time or requests with a checkpoint, and that nobody has taken. It opens its own
run with `run.open {continues}` and the answer's effect carries the handover: the closing (or last
checkpoint's) summary, `next` and `state`, with where the run stood. The read of the handover is
itself an action on the record, and a run is taken over once.

What makes it safe to read as a starting context:

- **It carries no authority.** The follow-on acts under its own capability and its own run's
  limits. A handover crosses sessions of one hand, never hands, because carrying work from one
  grant to another is a widening no owner signed.
- **It is small.** Strings up to 4000 characters, at most 30 listed items. A handover points at the
  work (a branch, a commit, a pull request); it does not carry it.
- **It is refused when it looks like it carries a credential** (`ghp_`, `github_pat_`, `sk-ant-`,
  a PEM block and the like). Finding none proves nothing, which is why the first point matters more.
- **The chain is bounded.** After `max_handovers` the work waits for a person, not one more agent.

## What it does not prove

`checks` is the hand's word, on the record. The gateway cannot run the tests; it holds the hand to
saying, before it may call the work done, that it ran them and they passed, and it refuses a done
that leaves one out or reports one red. Whether they really passed is still for the pull request's
own CI and its reviewer, and `done` requires the pull request so that review is never skipped.
Nothing here merges.

## What a hand does

```
run.open {goal}                         s1
branch.push, run.checkpoint, ...        s1
run.close {outcome: handover, next}     s1   (or stops; past its time the checkpoint stands in)
GET /v1/runs?waiting=1                  s2   finds s1
run.open {continues: s1}                s2   receives the branch and what remains
pull.open                               s2
run.close {outcome: done, checks}       s2   allowed: push in s1, pull request in s2, tests green
```

`TestOneSessionHandsOverAndTheNextFinishesWithoutAPerson` in `cmd/gateway` is this sequence over
HTTP with a restart between the sessions, and `go run ./cmd/demo --lifecycle` writes it as a chain
the standard's validator and reference verifier replay in CI.
