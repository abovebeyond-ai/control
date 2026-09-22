# The halt

Row 8.3.3 of the Proof-of-Control standard asks for a halt that is mechanical: invalidate the
proof chain, or withhold a proof the claim requires, and the in-scope actions must stop. Row
8.3.4 asks that the halt conditions, the recovery and the tolerable outage be written down,
and that the recovery has been exercised. This is that page.

## What halts the gateway

Four conditions, all answered with `FAIL_CLOSED` and a reason, and none of them lets the
effect leave:

| Condition | Where it is caught | Since |
| --- | --- | --- |
| The store cannot be written | `Store.Append` fails, before release | v0.1.0 |
| The store cannot be read, or its last line is not a record | `tailHolds` before each judgement | 22 September 2026 |
| The store holds a different number of records than the gateway's step | the same | 22 September 2026 |
| The last record does not carry the head this gateway holds, or is not signed by its key | the same | 22 September 2026 |

On top of that the gateway refuses to **start** when the whole chain does not replay: a gap,
a break, a record judged under another measurement, or, since 22 September 2026, a record
whose signature does not hold. A log rewritten with recomputed links used to open as if it
held, because the replay read the links and not the signatures.

The two halves are deliberate. Replaying every record is the right check once, at start;
holding the tail to the head is the right check before each action, and it reads one record
rather than the log. Between them, a rewrite under a live gateway is caught at the next
action instead of at the next restart.

## What does not halt it, and why

A break deeper in the history than the tail is not caught while the gateway runs. It is
caught at the next start, by the daily replay (`elixir:control-verify`), and by the anchor:
the head of each chain goes to Hedera daily, so a rewritten history no longer matches a
posting that is already public. That is detection rather than prevention, and it is the
honest limit of this design.

An unreachable anchor does not halt the gateway either. Anchoring is periodic and after the
fact; making it a gate would put a public ledger in the path of every action.

## Recovery

A halt means the gateway will not act until its evidence is consistent again. There is no
flag to override it, by design: an operator-side switch that a compromised host could flip
is what row 8.3.5 exists to rule out.

1. **Read the reason.** The hand gets 503 with it; the service logs it. The four conditions
   above each name themselves.
2. **Replay the chain** with `cmd/verify` against the log and the published key. It names the
   record it breaks on.
3. **If the log was altered**, the chain is over. Rotate it: rename the log and its
   attachments, and let the gateway open a new chain. The retired chain still verifies on its
   own, and the anchor for its head stays valid; nothing is deleted.
4. **If the store was merely unreadable** (a full disk, a lost mount), fix that and the
   gateway resumes at the step it stood on.

**Tolerable outage.** The hands are asynchronous: a refused proposal is retried by a person
or by the next scheduled run, so a halt of up to a working day costs nothing that cannot be
redone. Nothing in the fleet depends on the gateway answering within a window.

**Exercised.** The rotation and the rebuild are rehearsed in `docs/rebuild.md`. The halt
itself is exercised by the tests in `gateway/gateway_test.go`: a log rewritten under a live
gateway, a store that cannot be read, and a record whose signature does not hold, each
asserted to stop an action that would otherwise have been allowed.
