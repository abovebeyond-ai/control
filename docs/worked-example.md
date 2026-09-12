# A worked example: Proof-of-Control on a real fleet

Above Beyond, 8 September 2026. Written for the Advanced AI Society's Proof-of-Control
working group, as a deployment report rather than a proposal: everything below ran, and
every number names where it came from.

## What was deployed

Elixir is the agent that watches Above Beyond's client fleet: twenty-one projects under
its care, measured weekly, with two "hands" that change something outside it, a security
fix that updates vulnerable packages within semver and opens a pull request, and a
maintenance hand that does the same for anything behind. Since 6 September every effect of
those hands passes an Action Interception Gateway; since 7 September that gateway also
runs as a separate service, in shadow beside the in-process one, on the same machine, as
the same user, without root.

Three repositories carry it, all Apache-2.0 under `abovebeyond-ai`:

- **control**: the reference gateway service in Go, with the anchorer and the verifier
  as separate binaries, released as static Linux builds pinned by checksum
  (v0.1.1, 7 September).
- **proveml-go**: the ProveML verifier in Go, the third implementation after the
  JavaScript package and the PHP gate inside Elixir, tested against 81 vectors recorded
  from the JavaScript package's own suites and 5 certificates from the field.
- **elixir**: the fleet agent, first client of the service (`App\Control`).

## The boundary rule

Inside the trusted core lives only what can change a verdict or hold a credential: policy
evaluation, the evidence log, the signing key, the effect adapters, and the premises
verifier. Anchors, witnesses and verifiers live outside and need no trust. The gateway
publishes a signed checkpoint (tree size, root, chain head, signature); an anchorer that
never holds a key posts it and keeps the receipt; a missed anchor is what the verifier
detects. This is Certificate Transparency's shape, and what the standard's rows on
independent monitors (7.2.2, 7.3.3, 7.3.5, 8.1.6, 8.1.7) describe.

## One step, as it runs

1. A hand proposes: agent id, principal, action (kind, resource, params), and for a
   dispatch a certificate of premises in ProveML: per package the move from which version
   to which, how many advisories close, and the one judgement the policy requires, that the
   move stays within semver, named from a registry declared in advance, with a provenance
   grade per fact.
2. The gateway verifies the certificate inside the boundary (proveml-go) before it reads
   the grant. A kind that must carry premises and does not is a DENY; a certificate that
   does not verify is a DENY with the reason. The profile's seven claims ride in the token.
3. The grant, path-aware: kinds, resources, at most one of each kind per run. The second
   proposal in one run is refused; that rule is a bug from August turned into policy.
4. The snapshot is committed to a hash chain and an RFC 6962 tree; the token is the
   standard's claim set in its canonical form (RFC 8785), signed EdDSA.
5. The record is fsynced under a lock before the answer. An unwritable store answers
   FAIL_CLOSED and nothing leaves.
6. The effect, by an adapter holding the credential the hand never sees: a GitHub
   workflow dispatch, a pull request. In shadow the service records and performs nothing;
   the in-process gateway still acts, and the run's facts say whether the two agreed.

## Checked against what is not ours

- The standard's canonical vectors reproduce byte for byte; its published tokens re-sign
  identically under its published seed; the tree matches the RFC's recursive definition
  (control, `go test`).
- A chain the Go gateway wrote was replayed by the standard's Python validator and
  reference verifier, and every certificate re-verified by the ProveML JavaScript package
  as a second judge, on a clean CI runner (`tools/crosscheck.py`). An edited record fails
  on signature; an omitted one on sequence; an edited certificate on its digest.
- The same replay ran over the PHP in-process gateway's log with the same tools
  (`elixir/bin/control-replay`), so the three implementations of the verifier and the two
  of the gateway answer alike.

## Time and identity, from outside

- The service's checkpoint for both agents was pinned on 7 September at 19:56 UTC on two
  independent parties: DigiCert's RFC 3161 responder ("DigiCert SHA256 RSA4096 Timestamp
  Responder 2026 1", verified offline against the certificate in the token) and Hedera
  Consensus Service (at the time the testnet, topic 0.0.10275637; mainnet topic 0.0.10856156 since 12 September 2026, sequence 10, kept as the mirror node
  returned it). Two receipts per checkpoint; the verifier demands that the chain extend
  the anchored head.
- The agent is `did:webvh:QmdUpqNoPqt9txAjZbzUSshra31zYiTM8JebuN1uSzh5ZY:abovebeyond.ai#agent-security-fix`,
  a fragment of Above Beyond's identity, a DID with a signed, versioned history at
  `abovebeyond.ai/.well-known/did.jsonl`. Version 2 of that log added the evidence key;
  a record signed this month stays checkable against the key valid this month.
- What a verifier must still trust is published beside the evidence at
  `abovebeyond.ai/trust/keys/`.

## Against the standard's rows, honestly

| Row | State on 8 September |
| --- | --- |
| 7.1.1 gateway as a separate process the agent cannot bypass | Separate process, yes; the hands still hold their own credentials in shadow. Service mode moves them. |
| 7.1.3 evidence written before release | Yes, fsync under a lock; FAIL_CLOSED tested. |
| 7.1.4 effect channel mediated inside the boundary | Yes in service mode (adapters hold the credential); not yet live. |
| 7.2.1 contemporaneous records | Yes. |
| 7.2.2 timestamps anchored outside the operator | Yes, two backends, daily. Testnet on Hedera; mainnet before external use. |
| 7.2.3, 7.2.4 hardware attestation binding the key | **Demonstrated, not yet in production.** The production gateway is platform SOFTWARE and the standard's validator says "Tier 2 at most" on its tokens. The same binary ran attested on Intel TDX on 9 September 2026 (Google Cloud, c3, key generated inside, quote binding the key via REPORTDATA as the reference does it, MRTD `sha-384:c1ee9c16…8270a5` as the measurement); the verifier checked the quote against Intel's collateral from another machine, and the validator gave the record no notes. `docs/tier-3-rehearsal.md` has the findings. |
| 7.3.1 chain replayed on a schedule with results recorded | Yes, 07:20 UTC daily, reported to Portal, alert on a break. |
| 7.3.2 keys the operator cannot access | **No.** The key is a file the operator can read. |
| 7.3.3 equivocation resistance | Two independent anchors; no witness on the identity log yet. |
| 7.3.4, 7.3.5 inclusion and consistency proofs | Implemented and tested; the verifier compares the anchored root, not a count. |
| 7.5.1 no field asserts quality or intent | Yes; the profile's claims are digests and grades. |
| 7.6.1, 7.6.2, 7.6.3 failure log, sequence numbers, fail closed | Yes. |
| 7.6.6 declared anchoring interval, missed deadline alerts | One day; alert in Portal. |
| 7.7.1 to 7.7.5 schema, canonical form, tagged digests, vectors, duplicate keys | Yes; tested against the published vectors. |
| C10.2 trust-assumption disclosure | Published. |

So: Tier 2 in production, disclosed; Tier 3 demonstrated with the same binary on a
confidential VM, the key generated inside and bound in the attestation. The move changed
the `platform` claim and the measurement's width and nothing else in the design, which
was the claim to test. What the rehearsal did change is how the quote is taken: on a
current kernel it needs root, so the service acquires it in a privileged pre-step and
then drops to its own user, which accepts only a record binding its own key. The
production gateway moves to that machine after real traffic has gone through its shadow,
not before.

## What running it taught

- The first run of the anchorer on the real machine asked the gateway for the wrong agent:
  the agent id carries a `#`, which a URL reads as a fragment. No test had a real DID in it.
- The first start of the supervisor hung for as long as the gateway ran, because the
  child inherited a pipe. No test starts a real process.
- Elixir's report gate read a version like 7.13.1 as two numbers and refused a fact it had
  been handed. The certificate of premises was the first text with versions in it.

All three were found within hours of real traffic and none by a test we had written
beforehand. They are the argument for a reference *service* beside the reference
*library*: the library proves the protocol, the service meets the world.

Then the first real traffic, 9 September 2026, three maintenance runs and one security
run through both gateways at once, taught three more, in one afternoon:

4. **The measurement must name the code, not the policy.** Both gateways folded the policy
   bundle into the software measurement. Elixir's in-process grant names one repository
   per run, so its measurement changed with the project and the verifier reported its own
   chain broken at record 2, "judged by another policy". The policy is already a claim on
   every record; the measurement now names the engine alone. Corollary the standard
   implies but does not spell out: a chain is one measured environment, so an engine
   upgrade rotates the chain, and a gateway that finds a log judged under another
   measurement refuses to open it rather than hand the verifier a break.
5. **A path has a run.** The service kept one path summary per process. The second run of
   the day was refused as "a second dispatch in one run", correctly by its own reading and
   wrongly by anyone's. A hand now names its run; the gateway keeps a summary per run,
   writes run and action beside the record, and rebuilds them at open so a restart forgets
   nothing. Elixir's in-process gateway never had this problem because it is made per run,
   which is the kind of difference a shadow exists to find.
6. **Agreement is on the judgement, not the hashes.** Comparing the two chains, the verdict,
   the reason, the target, the principal and the seven premises claims were identical
   where both were right; the snapshot, path and policy hashes differed on every record,
   because two implementations encode an action map and a path summary differently. A
   comparison that expected equal hashes would have found two disagreeing gateways where
   there was one disagreeing design decision.
7. **The judgement must be the replayable one.** The next security run put js-yaml twice in
   one certificate, versions 3 and 4 from one lockfile, both as `package:js-yaml`. The
   hand's store kept the second's facts, the hand checked each line against its own facts
   and said verified, and the service, replaying the whole certificate against the whole
   store as any stranger would, said "%[from]{4.3.1} in package:js-yaml: should be
   3.15.1". The service was right and the hand had claimed something its own material
   could not reproduce. Repeated packages are now counted entities, and the hand judges
   with the same procedure the replayer uses. This is the profile's whole argument in one
   line: a certificate is evidence only if the material beside it gives the same verdict
   to anyone.

## What is offered

To the Society, as lab projects beside the reason-as-evidence profile: the gateway service
and its anchorer and verifier; the Go port of the ProveML verifier with its recorded
vectors; and this deployment as a worked example for the conformance chapter, at the tier
it honestly reaches. Under Apache-2.0, in the open, with the standard's Python code kept as
the independent judge in our CI rather than replaced.
