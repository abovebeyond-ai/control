# A pull request on a preview site, through the gateway

Since v0.26.0 (17 September 2026). A project may keep one extra site on Forge, the preview,
that runs a pull request on real data before it merges. Until this release the preview was
deployed with a Forge API token on the operator's laptop, read by a script any session on
that machine could run. That is the one credential a session's machine may not hold: a
session proposes, the gateway performs. So the preview became two kinds of the gateway,
in one run of two steps.

## The two kinds

| kind | resource | what | credential |
| --- | --- | --- | --- |
| `preview.push` | `owner/repo` | set the branch named `preview` to a commit (`params.sha`, the full id; `params.pull` and `params.head` say which pull request and which branch that was) | the GitHub App, or `github-token-<owner>` |
| `forge.deploy` | `forge:<slug>` | call the preview site's deployment trigger URL on Forge | `forge-deploy-<slug>` in the secrets: the URL itself |

The preview site on Forge tracks the fixed branch `preview`, quick deploy off. A forced
update is how the branch moves from one pull request's head to the next; it is allowed for
this kind only and for that branch only, held in the policy (`policy.PreviewBranch`) and
again in the adapter, so no grant and no parameter can turn it into a push elsewhere.

The rule, deterministic over the action and the run's path like the rest of the policy:

- `preview.push` sets the branch named `preview` and no other;
- a second `preview.push` in one run is refused, whatever `max_per_kind` says: the preview
  would move under the reviewer's feet;
- `forge.deploy` is refused before a `preview.push` in the same run: a deploy of what was
  not set is a deploy of whatever the branch held;
- both need the project's capability like `branch.push` does, and both kinds and both
  resources must be in the grant (Elixir's `App\Control\Workbench`) and in the capability
  (Portal's `Capability::WORKBENCH_KINDS`, with `forge:<slug>` beside `portal:<slug>`).

The record of the push carries the previous head, the new commit, the pull request number
and the head branch; the record of the deploy says Forge accepted the request. Forge deploys
in the background and reports nothing back to the gateway: whether the site runs the commit
is what the site says (`/.well-known/build.json`) and what Forge's deployment log says.
The trigger URL never appears in an outcome or a record, not even on a failure.

## The client

`node ~/Projects/.portal/hand.mjs preview --slug <slug> --repo owner/repo --pr 511` (or
`--branch <branch>`) on the operator's machine: it resolves the head with read-only `gh`,
asks Portal for the capability (or takes the operator's admission from the YubiKey), and
submits the two steps in one run. `hand.mjs propose` is untouched.

## What the operator does once per project

1. **Forge.** On the preview site: set the branch to `preview` (Git repository settings);
   quick deploy off. Copy the site's *Deployment Trigger URL* (Site, Deployments; it looks
   like `https://forge.laravel.com/servers/<server>/sites/<site>/deploy/http?token=…`).
2. **The box.** As `elixir` on the box, write that URL as one line to
   `/home/elixir/elixir-secrets/control/forge-deploy-<slug>` (mode 600). For the Stocklist
   platform the slug is `stocklistplatform-eu`, so the file is
   `forge-deploy-stocklistplatform-eu`.
3. **Secret Manager.** From the Mac, in the control checkout, with `CONTROL_GCP_PROJECT`
   set: `deploy/gcp/rehearse.sh tokens`. It reads the file from the box and creates
   `control-forge-deploy-<slug>` (or adds a version), readable by the VM's service account.
   Check with `gcloud secrets versions list control-forge-deploy-<slug>` that a version
   exists: a secret without one is a 404 at boot and the kind fails naming the missing file.
4. **The grant.** Once Elixir's `Workbench` names the kinds and the `forge:<slug>` resource
   (elixir), the box writes a new `control/config.json` within a minute; carry it:
   `scp elixir@167.233.221.164:control/config.json ~/control-config.json`, then
   `deploy/gcp/rehearse.sh config ~/control-config.json`. The boot script derives the
   secret names from the resources, so `forge:<slug>` in a grant is what makes the VM fetch
   `control-forge-deploy-<slug>`.
5. **The release.** Tag `v0.26.0` in control; the workflow builds the assets; pin the sha256
   of `control-gateway-linux-amd64` from `SHA256SUMS` in `deploy/gcp/startup.sh` (a PR,
   "The VM on v0.26.0"); then `deploy/gcp/rehearse.sh upgrade`. The upgrade reboots, and the
   boot fetches the new secret and applies the carried grant in the same pass. Steps 2 to 4
   can be done before the tag; nothing acts on them until the release that knows the kinds.

Then, in Portal, admit the workbench on the project as for any proposal, and run the client.

## What is deliberately not here

No Forge API token anywhere: the trigger URL deploys one site and nothing else, so what the
gateway holds can do exactly what the kind does. No polling of Forge: the trigger answers
at once, and a deploy that fails is visible where Forge shows it and on the site's build
stamp, which is what the reviewer looks at anyway. No branch other than `preview`, ever.
