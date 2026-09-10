# Conformance statement, Proof-of-Control draft v0.1

**Stage:** Self-Declared. No third party has assessed this system. (10.1.1)
**Standard:** Advanced AI Society, Proof-of-Control, draft v0.1. **Date of claim:** 9 September 2026. (10.1.5)
**Machine-readable form:** `statement.json` beside this file, same content. (10.1.7)

## System (10.1.4, 10.1.6)

Elixir's repair hands at Above Beyond: `security-fix` and `maintenance`, version the
deployed commit of `abovebeyond-ai/elixir` on the Hetzner box (167.233.221.164), and the
control gateway `abovebeyond-ai/control` v0.4.0, in shadow on an Intel TDX confidential VM
on Google Cloud (europe-west4) and in process inside Elixir.

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
| every in-scope action was judged before it happened | signed token per action, hash chain, Merkle tree, write before release | 2 | the hands still hold their own credentials (7.1.1, 7.1.4); the key is a file the operator can read (7.3.2) |
| the action carried a verified reason | ProveML certificate with its material beside the record; replayable by three independent verifiers | 2 | same boundary as above |
| the chain has not been rewritten below the anchored size | RFC 3161 timestamp and Hedera consensus time on the signed checkpoint, daily | 3 | Hedera testnet; mainnet before external use |
| the agent is who the record says | did:webvh with a signed key history; the agent is a fragment of it | 2 | no witness on the log yet |

For the shadow records the attested gateway writes: platform INTEL_TDX, the key generated
inside the trust domain and bound in the quote (7.2.4), the quote retaken daily (7.2.3);
still dry, so the hands perform, and the claim above stays at Tier 2 until service mode.

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

Met at service mode: the agent holds no standing credential, the gateway does (4.1.5); the
agent's key is bound to the attested environment (5.1.4).

Open: a signed, per-task authorization token from the principal, validated by the gateway
before execution and recorded (4.2.1, 5.1.3, with 4.2.2 and 4.2.3 as the one-hop chain);
the hand authenticating with its own key rather than a bearer token (5.1.2).

Not applicable: human approval records (4.1.6: merging is a person's act in GitHub,
outside the claim); confidential delegation (4.2.4); agent-to-agent messages (5.2).

## Trust-assumption disclosure (7.4.1, C10.2)

| mechanism | what must be trusted |
| --- | --- |
| Ed25519 signatures, SHA-256, RFC 6962 tree, RFC 8785 canonical form | the mathematics |
| the gateway's key | in production: the operator (a file on the box). On the VM: Intel's attestation chain, Google's hypervisor and disk encryption, and that nobody with operator login copied the key |
| the anchors | DigiCert as a timestamp authority; Hedera's consensus and its mirror nodes |
| the identity | the domain abovebeyond.ai and its DNS; the self-certifying identifier binds the log to its first entry |
| the premises | the OSV advisory data the hands read, graded as inferred or gateway in the provenance |
| the effect | GitHub honours a token; it verifies nothing about the evidence |

## Anchoring interval and attestation refresh (7.6.6, 7.2.3)

Chain heads are anchored at least once a day (07:25 UTC); a missed anchor is an alert in
Portal. The hardware quote is retaken daily (05:50 UTC); a retake that fails stops the
gateway.

## Retention and access (7.6.5, 7.6.4)

Records are kept for as long as this claim is made and at least one year. The store is
readable by the gateway's user and the operator; reads are not yet individually logged.

## Coverage and the mirror (10.3.6, 8.1.5)

The service's evidence is mirrored daily to the public repository named below, with the
material beside each record, the attestation, the checkpoints, the anchor receipts and
`coverage.json`: request records divided by request records plus evidence writes that
failed closed, which are all the in-scope actions there were, because a hand cannot act
except through the gateway. On 10 September 2026 a fresh clone verified with the README's
command alone: attestation, chain, three records per action, the Hedera anchor. That run
was ours; the recorded run by a party outside Above Beyond is still to come.

## Where to verify (8.1.8)

Tooling: `github.com/abovebeyond-ai/control`, `cmd/verify`, `tools/crosscheck.py`, and the
standard's own validator. Evidence: mirrored daily to `github.com/abovebeyond-ai/control-evidence`.
The key: the did:webvh log at `https://abovebeyond.ai/.well-known/did.jsonl`.
