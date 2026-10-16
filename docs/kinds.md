# The kind table

A kind is what a hand may ask the gateway to do: `pull.open`, `portal.share`,
`stocklist.photos_repair`. Until v0.43.0 a kind's name lived in nine places across four
repositories: the schema, the repair list, the adapter's own list, the files binding and the
evidence switch in control, plus copies in Portal, Elixir and the hand. Adding one kind took
seven pull requests in four repositories, two releases, a configuration transfer and three
reboots. A copy that fell behind was refused at the wrong moment: the first share was judged
and allowed, and then the adapter found no file.

The kind table is now the one place a kind is described. The gateway judges by it, performs by
it, and serves it.

## One row per kind

Each row (`policy.Kind`, `policy/kinds.go`) says:

| field | what it says |
|---|---|
| `adapter` | who performs it: `github`, `portal`, `forge`, `vera` or `system` |
| `radius` | `B1` or `B2` for a kind a repair key may add and a working set may admit; empty for a kind only the token grants |
| `why` | what bounds the radius, in the words the owner signs |
| `files` | the parameter that binds attached files by digest, if the kind takes files |
| `on` | for a system kind, the running systems it acts on, by resource; the gateway refuses it on any other |
| `place`, `words` | the kind as the owner reads it |
| `required`, `optional` | its schema |

The gateway reads every judgement from the row:

- the schema bounds the parameters;
- the radius caps a repair (`RepairOnly`) and a working set (`capability.InsideWorkingSet`);
- the files parameter is bound by digest before the judgement;
- a system kind is refused on a system its row does not name, whatever the grant covers;
- the adapter decides who performs the effect, and whether the record and capability travel as
  headers (Portal and the systems).

`/v1/agents` serves the whole table under `kinds`, each row with its `source`: `release` or
`policy`.

## Where a row lives

**A kind whose effect is code lives in the release** (`policy.Builtin`): the GitHub, Portal,
Forge and Vera kinds. Its row sits beside the code that performs it. A schema in the policy for
an effect the binary carries out would be two things that must agree, and then they don't.

**A kind on a running system may live in the policy.** The system adapter is generic. It
carries `{kind, resource, params}` to the system's `/control/act`, with the record and the
capability in the headers. The system verifies both itself (`relying`) and refuses what it does
not know. Such a kind needs no code in the gateway, so a policy version may define it, under
`kinds` in its body:

```json
"kinds": {
  "glk.worksheet_note": {
    "adapter": "system", "on": ["glk:transferor"],
    "radius": "B2", "why": "one note on a worksheet, deleted there in one step",
    "place": "Writes to a live system", "words": "add a note to a worksheet",
    "required": {"worksheet": "int", "text": "string"}, "optional": {}
  }
}
```

A new action on a running system is then a change in that system's own code plus one version
signed on the token. There is no gateway release, no configuration transfer and no reboot.

The four system kinds from before the table (`stocklist.photos_repair`, `studio.research_draft`,
`observatory.trend_edit`, `observatory.trend_site`) stay built in. They move to the policy once
the owner signs a version that carries them, followed by a release that drops them from
`policy.Builtin`.

## Who may change the table

The gateway checks this in `policy.Next` for every version:

- **Every definition** names the system adapter and the systems it acts on, no built-in name,
  no files, a radius of B1 or B2 with what bounds it (or none), the words, and a schema of
  known types (`CheckDefined`).
- **Defining a kind or changing a definition is a widening:** only the owner's token signs it.
  That includes the schema, the radius and the words. The radius is the owner's word that a
  kind is undone in one step, so a repair key must never be able to write it.
- **Dropping a definition is a narrowing:** Elixir may sign it. A hand that still holds the kind
  is then refused it as out of schema.
- **A repair (Portal's key, after a passkey) leaves the table exactly as it is.** It may grant a
  defined kind to a hand by the radius the owner signed, and never a kind without a radius.

The body field is announced in `fields` on `/v1/policy` and `/v1/agents` (`kinds`, beside
`working_set`). A body is decoded strictly, so a signer writes `kinds` only once the gateway
serves the field. `/v1/policy` serves the defined kinds as they stand, so that a signer copies
them into the next version. A version without them drops them.

## What reads the table

Portal, Elixir and the hand still keep lists of their own:

- Portal: `Capability::WORKBENCH_KINDS`, `Grants::KIND_WORDS`;
- Elixir: `PolicyLog::REPAIR_KINDS` and `KIND_WORDS`;
- the hand: `WORKBENCH_KINDS` in `lib/hand.mjs`.

Each of them moves to the served table once this release runs. Elixir reads it with the grants
and passes it to Portal on the grants report. The hand reads it through the door it already uses
for `/v1/agents`.

`Workbench::KINDS` in Elixir stays. It is not a description of kinds but the workbench's grant,
the policy Elixir drafts.

**Not in the table: the B1 reads on the systems** (`stocklist.read`, `glk.read`, ...). The
gateway does not carry them out. Portal signs those words for the systems, and each system
checks them itself.
