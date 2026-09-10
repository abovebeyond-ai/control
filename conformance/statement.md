# Conformance statement, Proof-of-Control draft v0.1

**Stage:** Self-Declared. No third party has assessed this system. (10.1.1)
**Standard:** Advanced AI Society, Proof-of-Control, draft v0.1. **Date of claim:** 9 September 2026. (10.1.5)
**Machine-readable form:** `statement.json` beside this file, same content. (10.1.7)
**Claims review:** `claims-review.md`, signed off by the operator. (7.5.2)

## System (10.1.4, 10.1.6)

Elixir's repair hands at Above Beyond: `security-fix` and `maintenance`, version the
deployed commit of `abovebeyond-ai/elixir` on the Hetzner box (167.233.221.164), and the
control gateway `abovebeyond-ai/control` v0.7.0, in service on an Intel TDX confidential VM
on Google Cloud (europe-west4) since 10 September 2026; the in-process gateway inside Elixir
is kept for comparison and writes no production records.

**Boundary.** Inside: the gateway process (policy, premises verifier, chain and tree,
signing key, evidence log, effect adapters), its configuration and its secrets. Outside:
Portal, the hands, the anchorer, the verifier, the timestamp authority, Hedera, Intel's
provisioning service, the did:webvh log, GitHub.

**In-scope action classes.** `workflow.dispatch` (start a repair workflow on a repository's
CI), `branch.push`, `pull.open`. **Excluded:** `pull.merge` (no hand holds a grant for it;
merging is a person's act or the automation rung earned in Portal's ledger, outside this
claim), reads of any kind (measurements do not change a repository), and anything a
person does with the same tokens by hand (not an agent action).

## Domains claimed (10.1.2)

C4 Authorization, C5 Identity, C7 Evidence generation and properties, C8 Verifiability
tiers, C10 Conformance and disclosure. Not claimed: C1 Provenance, C2 Privacy, C3
Portability, C6 Security, C9.

## Claims, tier reached, mechanism (10.1.3, 8.1.1 to 8.1.3)

The claim register is `register.json`. In short, for the records Elixir writes in production
today:

| claim | evidence | tier | why not higher |
| --- | --- | --- | --- |
| every in-scope action was judged before it happened | signed token per action, hash chain, Merkle tree, write before release; since 10 September 2026 14:20 UTC written and performed by the attested gateway on Google (service mode), with no login path to it since 14:45 UTC | 2 | the rows of the other chapters still open below (an outsider's recorded verification, 8.1.5, first among them); the branch push is still performed by the hand (7.1.4, see below) |
| the action carried a verified reason | ProveML certificate with its material beside the record; replayable by three independent verifiers | 2 | same boundary as above |
| the chain has not been rewritten below the anchored size | RFC 3161 timestamp and Hedera consensus time on the signed checkpoint, daily | 3 | Hedera testnet; mainnet before external use |
| the agent is who the record says | did:webvh with a signed key history; the agent is a fragment of it | 2 | no witness on the log yet |

Since 10 September 2026 14:20 UTC the attested gateway is the production gateway: the hands
propose through the tunnel with a signed submission and a client token, the gateway judges,
records and performs the workflow dispatch and the pull request with tokens that live only
inside the trust domain (7.1.1, 7.1.4 option a). One effect is not yet mediated inside the
boundary: a branch push, which is a git operation from the hand's checkout; projects that
carry the fix workflow do not push from the hand at all (the runner pushes under the token
GitHub issues for that run), and projects without it cannot push (read-only tokens), so the
exception is disclosed and bounded rather than silent. The in-process gateway in Elixir no
longer writes production records. Platform INTEL_TDX, the key generated inside the trust
domain and bound in the quote (7.2.4), the quote retaken daily (7.2.3). Since 14:45 UTC the
same day there is no login path to the VM: its secrets come from Secret Manager under its
own service account, its policy from an instance attribute, and both apply at boot; the
custody configuration in `key-custody.md` names the one path left, a disk snapshot by the
project's owner, which the audit log records (7.3.2).

The words "Proof-of-Control" are used for this system only as the standard it is built
against, not as a claim reached. (8.1.4)

## Authorization and identity rows (C4, C5), as they stand

Met: the grant is written beside every request record and its hash is a claim (4.1.1);
the record names the permission matched or the denial reason (4.1.2); out-of-scope actions
are refused with a record carrying the attempted action and parameters (4.1.3);
parameters are validated against a registered schema per kind, out-of-schema calls are
refused, and the validated parameter digest is a claim (4.1.4); evaluation is path-aware
per run (4.1.7); no tool output can raise the authorization state, the grant is standing
configuration (4.1.8); every record carries the agent and the principal (5.1.1).

Met since service mode (10 September 2026): the agent holds no standing token for the
effects the gateway performs, the gateway does (4.1.5); the record signer's key is bound to
the attested environment (5.1.4); the hand signs every submission with its own key, named
in the DID log, and the gateway refuses what it does not verify (5.1.2).

Met since 10 September 2026 evening: every submission carries a capability the principal
signed for the task, Portal signing on the principal's behalf behind the same gates as the
button (which hand, for which gateway, which verbs on which repository, valid two hours);
the gateway validates signature, audience, subject and time before execution, records the
token's digest and the task on the record, and takes the intersection with the standing
grant, so a capability narrows and never widens (4.2.1, 5.1.3, 4.2.3; the delegation is
one hop, principal to hand, 4.2.2). The principal's key is published in the DID log as
`#portal`.

Not applicable: human approval records (4.1.6: merging is a person's act in GitHub,
outside the claim); confidential delegation (4.2.4); agent-to-agent messages (5.2).

## Trust-assumption disclosure (7.4.1, C10.2)

| mechanism | what must be trusted |
| --- | --- |
| Ed25519 signatures, SHA-256, RFC 6962 tree, RFC 8785 canonical form | the mathematics |
| the gateway's key | Intel's attestation chain, Google's hypervisor and disk encryption, and that no project owner snapshotted the disk (the one path left; audit-logged; `key-custody.md`) |
| the anchors | DigiCert as a timestamp authority; Hedera's consensus and its mirror nodes |
| the identity | the domain abovebeyond.ai and its DNS; the self-certifying identifier binds the log to its first entry |
| the premises | the OSV advisory data the hands read, graded as inferred or gateway in the provenance |
| the effect | GitHub honours a token; it verifies nothing about the evidence |

## Anchoring interval and attestation refresh (7.6.6, 7.2.3)

Chain heads are anchored at least once a day (07:25 UTC); a missed anchor is an alert in
Portal. The hardware quote is retaken daily (05:50 UTC); a retake that fails stops the
gateway.

## Retention and access (7.6.5, 7.6.4)

Records are kept for as long as this claim is made and at least one year. The store on the
VM is readable by the gateway's user alone; every read through the gateway's endpoints
(records, attachments, checkpoints, proofs, attestation) writes an access record with what
was read, from where and when, to `access.jsonl` beside the chains (control v0.7.0). The
public mirror is a copy anyone may clone; clones of it are not individually recorded, and
the mirror's README says so.

## Inventory (10.1.8)

The declared inventory is Portal's project register; discovery is Elixir's repository
sync, which clones what the register names and measures nothing else. A project the
register does not switch on appears in the report as a blind spot rather than as silence,
and a repository that grants itself policy in its declaration is refused and recorded.

## The attestation, anchored (8.1.7)

The hardware attestation rests on Intel's root, a vendor. Since control v0.7.0 the signed
checkpoint carries the digest of the quote, so the daily anchors on DigiCert and Hedera
commit to the attestation as well, and the verifier holds the anchored digest to the
attestation presented.

## Coverage and the mirror (10.3.6, 8.1.5)

The service's evidence is mirrored daily to the public repository named below, with the
material beside each record, the attestation, the checkpoints, the anchor receipts and
`coverage.json`: request records divided by request records plus evidence writes that
failed closed, which are all the in-scope actions there were, because a hand cannot act
except through the gateway. On 10 September 2026 a fresh clone verified with the README's
command alone: attestation, chain, three records per action, the Hedera anchor. That run
was ours. `docs/verify-yourself.md` is the recipe for anyone else: the mirror, the
verifier from source, the key resolved from the DID log, one command, no credential of
ours. The recorded run by a party outside Above Beyond is still to come.

## Where to verify (8.1.8)

Tooling: `github.com/abovebeyond-ai/control`, `cmd/verify`, `tools/crosscheck.py`, and the
standard's own validator. Evidence: mirrored daily to `github.com/abovebeyond-ai/control-evidence`.
The key: the did:webvh log at `https://abovebeyond.ai/.well-known/did.jsonl`.

## Towards Tier 4: the far end (8.3.5, 8.3.2, 8.3.3)

Since 10 September 2026 20:07 UTC the gateway hands every dispatch its signed request
record and the principal's capability, and the fix workflow every repository under Elixir
calls runs the far-end check before any package moves: the record must be signed by the
gateway's key from the DID log, ALLOW for that repository and that verb, written on Intel
TDX under the measurement the public mirror attests, and named by the capability. The check
is the public action `abovebeyond-ai/control-verify-action`, built from `cmd/relying` at a
pinned release, and it runs in the repository's own workflow, where neither Elixir nor the
gateway can switch it off. Its first real run refused (the agent's DID form against the
document's alias) and the job stopped with nothing done, which is the halt the row asks for,
observed before it was rehearsed; the second run held and the work proceeded. The merge
check on pull requests, and the branch protection that requires it, are the next step; the
drills, the availability analysis and the inventory follow.

## Coverage reconciled, the validator and its window (10.3.2, 10.3.3, 10.3.4)

Coverage that counts records against records proves nothing. Daily, after the mirror is
published, `elixir:control-reconcile` counts what GitHub saw, dispatches of the fix workflow
and pull requests from the hands' branches, per repository, against the effect records the
gateway wrote as performed, over a window of seven days bounded by the start of service
mode, and writes `reconciliation.json` beside the mirror. Zero unexplained difference is the
claim; any difference is an alert in Portal. The first run, on 10 September 2026 at
20:50 UTC over the day of service mode, agreed on the one repository with activity, five
dispatches and one pull request on both sides, and named five repositories without the fix
workflow as unreadable, which the next version counts as zero. The validator of every record is
`elixir:control-verify`, daily at 07:20 UTC, a window of 24 hours; its results are the job's
runs in Portal, which is the log the row asks for. Alerts go to Portal's calm layer and by
mail on a transition. Portal keeps one episode per alert, opened by the run that turned
it on and closed by the run that cleared it, with the moment a person marked it seen and
by whom; the episodes with their seconds to acknowledgement are readable on the owner's
token (`GET ingest/acknowledgements`), which is the record of acknowledgment times. The
episodes begin at the deployment of that change (Portal pull request 245, evening of
10 September 2026); alerts before it have no acknowledgment record.

## Halt drills (7.6.3, 8.3.3) and the secondary log (7.6.1)

`tools/drills.sh` runs three drills against the gateway binary this checkout builds, the
same code as in production, and writes the record under `conformance/drills/`. The record
of 10 September 2026: an unwritable evidence store yields FAIL_CLOSED and nothing leaves,
and the failure is itself on record; a rewritten record makes the gateway refuse to act on
that chain; a gateway that must attest and cannot does not serve. The first run of the
first drill found that the failure log lived inside the store, so an unwritable store lost
its own failure record; since control v0.9.3 it lives beside the store. Three halts were
also observed in production before they were drilled, and the record names them.

