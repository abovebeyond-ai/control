# Interaction inventory (rows 8.3.1, 8.3.2)

Every system in the chain from a person's request to a change in a repository, each
interface between two of them, and which interfaces carry the evidence. Components that
operate below Tier 4 on their own (Portal, Elixir, GitHub) touch the chain only through
interfaces that do carry it.

| from | to | interface | evidence carried | halt if absent |
| --- | --- | --- | --- | --- |
| a person | Portal | the worklist button or the ingest API (owner token) | the request is a report with `requestedAt`; Portal signs a capability for the task (`#portal`) | Portal refuses behind the button's gates |
| Portal | Elixir | the request queue Elixir polls every ten seconds (fabric token) | the capability rides in the request payload | a request without one still starts, and the gateway then refuses (below) |
| Elixir's scheduler | Elixir's hands | the weekly rounds | the hand asks Portal for a capability first (`POST ingest/capability`) | Portal refuses behind the same gates; the gateway refuses a run without one |
| a hand | the gateway | `POST /v1/submit` through the IAP tunnel, client token, the submission signed with the hand's key (`#agent-*`), the capability in the body | the gateway judges, writes the signed request record, effect record and result record | any of: no token, unsigned, no capability, out of grant, out of schema, no premises: DENY, recorded |
| the gateway | GitHub | the effect: a workflow dispatch with `evidence` and `capability` inputs; a pull request with the evidence footer; performed with tokens only the gateway holds | the signed request record and the capability go with the effect | GitHub honours a token and verifies nothing (row 7.1.5 wording); the far end below does |
| GitHub | the repository's runner | the fix workflow, called at `abovebeyond-ai/elixir-fix@v1` | `abovebeyond-ai/control-verify-action` holds the record and the capability to the DID log and the mirror before any package moves | the run stops (exercised 10 September 2026) |
| the runner | GitHub | a branch pushed under the token GitHub issues for that run | none of ours: the runner's own token, scoped to that run | GitHub's own controls |
| a hand's pull request | a merge | the `evidence` workflow on pull requests from `elixir/*` branches, required in branch protection where the owner sets it | the footer is held to the DID log and the mirror | the merge is blocked where the check is required; elsewhere the check is visible but not binding |
| the gateway | the anchors | `cmd/anchor` on the box reads the signed checkpoint through the tunnel and pins it on DigiCert (RFC 3161) and Hedera daily | the checkpoint carries the tree root, the chain head and the attestation digest | a missed anchor is an alert; nothing halts |
| the gateway | the mirror | `elixir:control-publish` on the box copies records, attachments, quotes, checkpoints and receipts to `abovebeyond-ai/control-evidence` daily | everything a stranger needs | a missed publish is a failed job in Portal |
| anyone | the mirror and the DID log | `git clone`, `curl`; `docs/verify-yourself.md` | the whole chain, verifiable without us | none: reading halts nothing |

Below Tier 4 internally and touching the chain only through the interfaces above: Portal
(a Laravel application on the Hetzner box), Elixir (the hands, on the same box, as another
user), GitHub (the effect target and the runner host). The gateway on the confidential VM
is the one component whose own operation is attested.

What this inventory does not cover: the measurements Elixir takes (reads, not actions),
and anything a person does with the same tokens by hand, both excluded from the claim in
the statement.
