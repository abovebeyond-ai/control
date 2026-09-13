# Rebuilding the sealed machine

What it takes to replace the production gateway with a fresh machine, written before the
first time it is needed (13 September 2026), from the code as it stands. The order matters
because two things are born inside the machine and cannot be carried: the seal key, and
the measurements.

## What a rebuild changes, and what it does not

- **The seal key is new.** It is made inside the machine on first start and never leaves.
  Every entry the old machine sealed verifies under the old key; every entry from now on
  under the new one. The identity log is the bridge: `#control-gateway` gets the new key
  with `replace-key`, and the old key stays in the log at the versions it held. The checker
  reads that history (`verify --did-log`, since v0.16.3) and uses, per chain, the key that
  signed it; the attestation must bind the current one.
- **The chains start anew.** The gateway refuses to append to a chain judged under another
  measurement or key. The old chains stay in the public copy, verifiable, anchored, ended;
  the new machine's chains begin at record 0. Nothing is lost, and the seam is visible.
- **The measurements are the same** if the image, the release and the carried configuration
  are the same: MRTD from Google's firmware, RTMR0 to RTMR2 from the pinned image, RTMR3
  from the release binary and the configuration. A new image or kernel changes the boot
  log, which the checker names.
- **The tokens, the client token and the configuration are carried**, not born: from
  Secret Manager and the instance attributes, at boot.

## The steps

1. On the Mac, with the control checkout on main and `CONTROL_GCP_PROJECT=elixir-508105`.
   Give the new machine a name of its own while the old one still serves:
   `CONTROL_GCP_NAME=control-gateway-2 deploy/gcp/rehearse.sh create`. The step sets the
   service account, the listen address, the pinned image and the boot script.
2. Carry the configuration the box generates (`deploy/gcp/rehearse.sh config <box's
   control/config.json>`) and the tokens (`tokens`; Secret Manager already holds them, this
   only re-adds versions), then `reboot`. The machine installs the pinned release, makes
   its key, measures itself, attests, serves.
3. Read the new key: through the tunnel later, or now from the serial log (`serial` prints
   the `/v1/key` line the boot script curls). Verify the fresh machine with
   `verify --gateway` once the tunnel points at it, or with `--key` against its store.
4. The register: `add`? No: `replace-key control-gateway <the new key's x>` in the site
   repository, a ceremony with both tokens (scripts/README.md there), merged and published;
   pin the version on the ledger (`elixir:control-anchor` does it within the day).
5. The box: the tunnel names the instance by name. Either the new machine takes the old
   name (delete the old, create the new under `control-gateway`), or the supervisor's
   tunnel target changes in Elixir's configuration. The first keeps every path as it is.
6. `lockdown` on the new machine: no login path. Then delete the old machine, or stop it
   and keep the disk for a week.
7. The public copy: the next mirror carries the new chains beside the old. The watcher
   reads keys from the identity log and needs nothing.

## What to rehearse before it is real

Steps 1 to 3 and 6 on a machine under another name, then delete it: the machine comes up,
attests, its layers hold, its key is new. Step 4 on a throwaway identity with SoftHSM
(scripts/README.md in the site repository). Step 5 is a change of one name and is not
rehearsed apart from the real thing.

## Rehearsed, 13 September 2026, 06:20 to 06:40 UTC

Steps 1 to 3 on `control-gateway-rehearsal`, from the pinned image and the v0.16.2 boot
script, with the production configuration carried and the machine set to dry: it came up in
under two minutes, made its own key (`7afec428…`, not the production key), fetched the
tokens from Secret Manager under the service account, measured itself, attested, served. A
checker through Google's tunnel from the operator's laptop read all layers as holds: the
same MRTD as production, RTMR0 to RTMR2 byte for byte the same as production (same image,
same kernel `7.0.0-1011-gcp`, the boot log's 112 events replaying), RTMR3 the release asset
plus the carried configuration (a different digest from production's, since the dry flag
is in the carried bytes). Then deleted. Cost: cents.

Two things the rehearsal found and fixed in the create step, both set by hand on the
production machine and absent from the script until then: the service account Secret
Manager trusts and the listen address (found writing this page), and the network tag the
firewall rule for the tunnel range names, without which the tunnel could not reach the
port (found in the rehearsal). A rebuild from the script now sets all three.

Not rehearsed: step 4 on the real identity (the key replacement is a ceremony with both
tokens), and step 5, the change of name.
