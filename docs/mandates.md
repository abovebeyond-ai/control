# Mandates by blast radius

A design note, not yet built. It describes how the owner's agents get to act on running
systems (the Stocklist platform, the Gentells Observatory) and not only propose code, without
weakening what holds today: no credential at the hand, every action judged and recorded,
merging and admitting the owner's alone.

## Why

Today an agent can do two kinds of things: propose a change to a repository (`branch.push`,
`pull.open`) and write to Portal (`portal.*`). Everything else on a running system takes the
owner at a terminal with a YubiKey: on 6 October 2026 that was reading view counts in tinker on
the Stocklist server and repairing the photos of one copied car with an artisan command. The
voice bridge (portal-cli `voice/`) makes the gap plain: the owner can start an agent from the
car, but the agent cannot retry a failed Observatory run or repair a car's photos.

One admission per project covers every kind the workbench has. That was right for proposals,
which all have the same blast radius (B2: a pull request nobody has merged). It is wrong for
acting on a running system, where reading a count, regenerating a thumbnail and putting a price
in front of a dealer are three different risks.

## Principles

These are PAC's (the `pac` plugin, `framework/pac.json`; Portal `App\Support\Pac`; Elixir
`App\Elixir\Blast` and `Autonomy`), applied to actions instead of playbooks.

1. **The mandate follows the blast radius, not the project.** One mandate per layer, each with
   its own duration and its own autonomy. A project is where a mandate applies, not what it is.
2. **One kind per action** (C5: restricted to what agents can do, not only blocked from what
   they cannot). The gateway knows `stocklist.photos_repair`, never `stocklist.artisan`. Each
   kind's schema bounds its parameters: one car per call, a price under a ceiling.
3. **Authority only decreases** (C2). An agent that starts another passes on at most its own
   mandate. The voice holds no mandate of its own: what it starts acts under the owner's.
4. **No credential at the hand, and none at the gateway either** (I5, made stronger). The system
   that acts verifies the owner's mandate and the gateway's record itself, the way the evidence
   check verifies a pull request. There is no API key for the system to leak or the gateway to
   hold: the authority is the owner's signature, and it ends when the mandate expires or the key
   is rotated in the DID log.
5. **Autonomy is earned per kind, never configured.** Elixir's thresholds per blast radius
   decide when a kind moves from A2 (the owner approves each action) to A3 or A4. The numbers
   are those in `Blast::threshold()`: lower bound of the reliability interval and judged runs,
   B1 0.80 over 10, B2 0.85 over 20, B3 0.92 over 40, B4 0.96 over 80. (The comment above that
   method speaks of 16, 22, 45 and 93 runs; the code is what decides, and the two should agree.)
6. **B3 and up are signed per action** (A2 with I4: a decision per action before it leaves).
   **B5 is not mandated**: make the action reversible first.

## The model

### The mandate

The capability the owner already signs (passkey in Portal, or the operator key on a YubiKey),
extended with what a layer needs:

| Field | Meaning |
|---|---|
| `iss` | the owner's key (`#portal` or `#operator`) |
| `sub` | the hand (`#agent-workbench-shed`, `#agent-elixir`) |
| `kinds` | only the kinds of one layer |
| `resource` | the system: `stocklist:platform`, `gentells:observatory` |
| `layer` | `B1`, `B2`, `B3` |
| `bounds` | per kind, where the schema needs the owner's number (a price ceiling) |
| `exp` | B1 up to 30 days, B2 the rest of the day, B3 minutes |
| `once` | B3 only: the exact parameters of one action, and a nonce; the mandate is spent when used |

### The flow

1. An agent asks: `hand.mjs act --kind stocklist.photos_repair --params '{"vehicle":23312,"apply":false}'`.
2. The gateway judges: the grant names the kind for this hand; the capability covers kind,
   resource, layer and bounds and has not expired; the parameters fit the schema. It records
   the verdict, as for every action.
3. The effect calls the system's control endpoint and attaches the evidence: the signed record
   and the capability.
4. The system verifies both (`relying dispatch`, or a native port of it), refuses on any
   mismatch, carries out the existing operation, and answers with what changed.
5. The gateway records the outcome. The agent reports it.

Reads take the short road: the system accepts requests signed by the hand's key from the DID log,
the way Portal accepts the workbench's reads since 5 October 2026 (`hand-read`). Nothing to
steal, nothing written.

### Admission in Portal

`/portal/werkbank` offers the layers apart for a project that has kinds on a running system:

- **Lezen** (B1): for 30 days.
- **Herstellen** (B2): for the rest of the day.
- **Per actie** (B3): nothing up front. When an agent needs one, the owner is asked to sign that
  one action, with its parameters shown before the passkey, in Portal or the Claude app.

## Commands, modelled on blast radius

An agent does not use screens. It uses commands: a name, typed parameters, the system's own
business logic behind it, and a blast radius that decides the approval. The owner no longer
decides about permissions, only about the actions that matter; the radius of a command says
which those are. A command is designed to keep its radius as low as it can be:

- **Narrow.** One car, one dealer, one source, one run. A bulk version is a command of its
  own, one layer higher, and most of them are not mandated at all.
- **A dry run by default.** The dry run sits in the lower layer; only `apply` carries the
  command's radius, and the owner decides on what the dry run showed.
- **Reversible where it can be.** A write that keeps its undo (the pipeline's `*_undo` tables)
  is B2; the same write without one is B3 or not mandated.
- **Read or write, never both.** A read is B1 and can go anywhere, the car included.
- **Through the app, not the database.** A read calls the system's own logic (Stocklist's
  `Measures`, the pipeline's `mix` and taxonomy), never free SQL: "handlings" or a cohort
  mean what the code says they mean.
- **Personal data is its own command.** An aggregate is B1. Rows that name people (a lead's
  phone, a reader's email, a login account) are not in the B1 set; when needed they get their
  own command, B3, and never through the voice, which speaks through a third party.
- **Answers stay with the owner.** A session that read a system's data has no write channel
  outside it in the same run (no pull request body, issue, Portal note or mail carrying it).
  What it found starts a new task, and the owner sees what that task takes along.

### The layers

| Layer | What it is | The owner's approval | From the car |
|---|---|---|---|
| B1 | a read; nothing changes | a mandate for 30 days | yes |
| B2 | a change that is redone or reversed, one item | for the rest of the day | starts it; `apply` waits |
| B3 | goes out at once and cannot be called back | per action, parameters shown | no, it waits for the owner |
| B4 | broad: many items at once | per action, after a dry run | no |
| B5 | irreversible | not mandated; make it reversible first | no |

## Stocklist

Behind each command: the existing service or artisan command. `ActionController::KINDS` and
the gateway's schema name the same parameters; a read calls the Support class directly.

| Command | Params | Layer | Behind it | Notes |
|---|---|---|---|---|
| `stocklist.insights` | `garage`, `window` (30d, 90d, 12m) | B1 | `DealerInsights` | views per channel, top cars, leads counted per source, stock age, days to sell, price drops, portals; no personal data |
| `stocklist.measures` | `measure` (handlings, edits, views, signins, ...), `from`, `to`, `by` (day, weekday, hour, channel) | B1 | `Measures::total/series/weekdays/matrix/channels` | the platform-wide numbers; `dealerTable` only with garage names, no people |
| `stocklist.stock` | `from`, `to` | B1 | `StockInsights` | age, selling time, prices; aggregates |
| `stocklist.shared_stock` | `date` | B1 | `stocklist_daily` (read, not the command that writes it) | shared stock per garage |
| `stocklist.checks` | `check` (transactions, duplicates, photos_missing), `days` | B1 | `check-transactions`, `duplicates`, `fotos-afgeleid --missing` without apply | counts only |
| `stocklist.photos_repair` | `vehicle`, `apply` | B2 | `fotos-afgeleid --missing --wagen` | built; additive, regenerating again is harmless |
| `stocklist.module` | `garage`, `module`, `on` | B2 | `update_module` | flip back to reverse; nothing is sent |
| `stocklist.resend` | `vehicle`, `to` (removals, updates, accident_flag), `apply` | B3 | the `resend-*` commands, one car | a partner receives it at once |
| `stocklist.transport_price` | `transport`, `amount` (≤ bound) | B3 | `TransportController::price` | the dealer is mailed at once |

Not mandated: users and invites (mail a person), API token rotation (breaks a partner), the
bulk resends and forced updates without a dry run (`forceUpdateWebhook`, `forceUpdateCarpass`,
`resendAllVehiclesToNederlandMobiel`, ...), deleting photo rows, catalogue merges and imports,
and the admin insights that return dealer names, emails and phone numbers
(`InsightsRepository::profiles`, `topDealers`, `dealersInBucket`). Those stay with a person.
Before any of them is ever mandated it needs a one-item form with a dry run.

## Gentells pipeline (the Observatory)

The reads exist already, behind a read-only door: the server's probe scope (a JWT that allows
GET and the named queries of `POST /store/query`, nothing else) and the Observatory MCP
(`bin/observatory-mcp.mjs`, read-only, `cohorts`, `signals`, `query`). A B1 mandate maps onto
that scope; the server verifies the mandate where it verifies a probe token today.

| Command | Params | Layer | Behind it | Notes |
|---|---|---|---|---|
| `observatory.status` | | B1 | `/pipeline-stats`, `/status`, `/workers`, `/supervisor`, `/monitor`, `/crons` | the last 24 hours, what runs, the judged whole, cron drift |
| `observatory.mix` | `by` (platform, source, region, cohort, ...), `days` | B1 | `/mix`, `core/mix.mjs` | intake, kept and cited per axis: "signals per source this week" |
| `observatory.cost` | | B1 | `/budget`, `/usage`, `/llm-health`, `/rate-limit` | spend and whether calls produce output; not `/accounts` (login emails) |
| `observatory.ask` | `tool` (cohorts, signals, query), its arguments | B1 | the Observatory MCP | the business logic of the taxonomy (`canonicalCohort`, `regionAndBelow`) |
| `observatory.retry_report` | `sourceId` | B2 | `POST /retry-report` | one report; a retry of a retry is harmless |
| `observatory.cron` | `id`, `enabled` | B2 | `POST /crons` | one job; switch it back, `crontab-install --apply` restores the file |
| `observatory.stop` | `phase` | B2 | `POST /stop/:phase` | stops one running phase; start it again to reverse |
| `observatory.run` | `phase` (collect, classify, enrich, promote, stats) | B2 | `POST /run/:phase` | one phase, refused while it runs; the dry phases (`enrich-dry`, `scout-list`) are B1 |
| `observatory.undo` | `script`, `ids` | B2 | the `--undo` of `plain-edit`, `widen-evidence`, `apply-ready`, `standard-migrate` | an undo is itself a narrow write |
| `observatory.edit` | `script`, `ids`, `apply` | B2 | `plain-edit`, `widen-evidence`, `apply-ready` | only scripts that keep an undo table; dry run first |
| `observatory.patch` | `record`, `fields` | B3 | `POST /store/patch` | one record, logged, but no undo |

Not mandated: model and plan configuration (every phase at once, plans push to the site),
deleting records, scripts that write without an undo (`link-trends`, `concept-fold`,
`fold-twins`, ...), deploys, and everything that touches people: reader accounts on the site,
team users, conversations, the login accounts behind `/accounts` and `/health`.

## What changes where

- **control:** the kinds and their schemas; `layer`, `bounds` and `once` in capability
  verification; a generic effect that calls a system's control endpoint with the evidence
  attached; `relying` able to verify a single action for a system, not only a pull request or a
  dispatch.
- **Portal:** admission per layer, per-action signing for B3 with the parameters shown, the
  kinds per layer in `Capability`, and the PAC profile per kind instead of per playbook only.
- **Elixir:** the catalogue names each kind with its `Blast` and its reversal, so `Autonomy`
  decides per kind.
- **the systems:** a control endpoint that verifies and then calls what exists; signed reads.
- **portal-cli and the voice:** one command per system for the agents; the voice knows what an
  agent can ask for, and that a B3 action waits for the owner's signature.

## Open questions

1. **Where do `bounds` come from?** In the mandate (the owner sets the ceiling when signing) or
   in the grant (configuration)? The first is closer to the owner's intent; the second is
   simpler to audit.
2. **Native verification or the `relying` binary?** Native in PHP for Stocklist follows Portal;
   the binary keeps one implementation of the rules. A conformance vector set would let both
   prove they agree.
3. **Revocation before expiry.** Today a mandate ends at `exp` or with a key rotation. A
   short-lived B2 (one day) may not need more; a 30-day B1 might want a revocation list the
   systems read.
4. **The client as owner.** For now the owner of these systems signs every mandate. When a
   client signs for their own system, `iss` becomes their key and the system verifies against
   their DID: the same model, a second principal.

## Order of work

1. Stocklist B1 reads and B2 `photos_repair` at A2, end to end: control kinds and effect, Portal
   admission per layer, the platform's endpoint, the agent command. That builds the whole
   mechanism at low risk.
2. The B1 reads of both systems, so a conversation (the car included) can ask what it needs;
   then the Observatory's B2 set, on the same mechanism.
3. B3 per-action signing (`stocklist.transport_price`), once the layers stand.
