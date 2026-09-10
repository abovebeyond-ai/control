# Availability under proof-gated operation (row 8.3.4)

A system that refuses to act without evidence also refuses to act when the evidence
cannot be produced. This names when that happens, what it costs, how it is recovered, and
which recoveries have been exercised.

## What the hands do, and how often

The hands propose repairs: a workflow dispatch, a branch push, a pull request. The fleet's
rounds run weekly (Monday measurements, Tuesday maintenance) and on request from Portal.
Nothing a hand does is time-critical: a repair that waits a day is a repair that waits a
day. Measurements (uptime, certificates, advisories) do not go through the gateway and keep
running when it halts. Elixir's daily jobs (verify, anchor, publish) report a halt to Portal
as an alert within their window.

**Maximum tolerable outage: 24 hours** for the gateway, after which a weekly round is missed
and the report says so. No client-facing service depends on the gateway.

## Halt conditions

| what stops | effect | detected by | recovery |
| --- | --- | --- | --- |
| the VM is down or unreachable | every submission fails closed in the hand (`FAIL_CLOSED`, "the control gateway could not be reached"); nothing is performed | the supervisor every minute (Portal: control-service NOT reachable, alert) | `rehearse.sh reboot`; if the instance is gone, reprovision (below) |
| the IAP tunnel on the box dies | same as above from the hands' side; the gateway itself is fine | the supervisor every minute | the supervisor reopens it; a stale tunnel after a VM reboot is killed and reopened |
| the daily quote retake fails (05:50 UTC) | the gateway is stopped on purpose: no attestation, no judging | control-service reports NOT reachable; the serial log says why | reboot; if the platform lost TDX, reprovision on a confidential machine |
| the evidence store cannot be written | that step is FAIL_CLOSED, the failure is recorded beside the store, later steps proceed when it recovers | the record and the failure log; the mirror's coverage counts it | disk: reprovision; permissions: reboot (the boot script restores them) |
| a chain does not replay at open | the gateway refuses to act on that agent's chain | the gateway log; control-verify reports BROKEN | the chain is rotated (archived, a fresh one starts), never repaired in place |
| Secret Manager unreachable at boot | the secrets already on disk stay; without any, the gateway has no client token and refuses to act | boot log (serial) | reboot when Secret Manager is back |
| DigiCert or Hedera unreachable | the anchor job alerts; the gateway keeps judging; the window in which truncation is undetectable grows by the outage | control-anchor alert in Portal | the next successful anchor closes the window; nothing to repair |
| Intel's collateral service unreachable | the verifier cannot check the quote's freshness; `--offline` still verifies signatures, chain and anchors | control-verify | wait; verify offline meanwhile |
| the far-end check refuses on a runner | that run stops before any package moves; the record of the refusal is on the gateway | the run's log; Portal's playbook status | fix the cause (a real refusal is the point), re-dispatch |
| GitHub is down | the effect fails; the record says "effect failed" | the effect record | re-dispatch later |

## Recovery procedures

**Reboot** (`deploy/gcp/rehearse.sh reboot`): a reset; the boot script installs the pinned
release, fetches the secrets, applies the policy, retakes the quote, restarts the gateway.
The disk and the key persist; the chains continue. Exercised: 9 September (stop and start,
same MRTD), 10 September at 14:28, 15:xx, 19:xx and 20:xx UTC (upgrades and configuration).
Every time the gateway was back within two minutes and the tunnel within one more, after
being reopened by the supervisor.

**Reprovision**: a new instance from the same boot script, with the same metadata and
service account. It generates a new key, so it starts new chains; the old instance's chains
stay in the mirror as history, its receipts beside them. The new key is published in the DID
log under `#control-gateway` and the old one retired, then the box's tunnel is pointed at
the new instance and the old instance deleted. **Not yet exercised.** Scheduled for the day
the DID update key moves to the hardware token, since the DID version that publishes the
new key should be signed by it. Until then, a lost instance means a manual reprovision with
the software update key, which the runbook covers.

**Chain rotation**: `archive/<date>-<reason>/` beside the store on the box, or on the VM by
reprovision; the anchor receipts of the retired chain move with it. Exercised twice on
9 September (measurement change; a certificate that did not replay).

## What is deliberately not high-availability

One gateway, one VM, one region. A second instance would be a second key and a second
chain, and the standard's rows are about evidence, not uptime; the tolerable outage above
is what justifies the choice. If the cadence ever tightens, the shape is two gateways with
two published keys and grants that name which repositories each judges, not a shared key.
