# The machine image: what the quote's registers are held to

Since 12 September 2026 (control v0.15.0). Before it the attestation record carried four
measurement registers and a verifier could say only "the same as yesterday". Each layer now
has a reference and a party whose word it rests on, named here so a reader knows where the
proof stops.

| register | holds | held to | rests on |
| --- | --- | --- | --- |
| MRTD | Google's virtual firmware for TDX | Google's signed launch endorsement for that exact measurement, verified under Google's root for confidential computing (pinned in `attest/GCE-cc-tcb-root_1.crt`, published at https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt) | Google's word for its firmware, signed |
| RTMR0 | firmware configuration, the secure boot variables | the boot event log, replayed | the event log, whose replay must land on the quote's value |
| RTMR1 | the partition table, shim, grub | the boot event log, replayed | same |
| RTMR2 | grub's configuration, the kernel and its command line, the initrd | the boot event log, replayed; the digests are those of the pinned public image | the image Google publishes under that name; Canonical's word for its contents |
| RTMR3 | ours: the gateway binary, then the carried configuration | the fold of the two inputs the record names, from zero; the binary's SHA-384 against the release asset, the configuration's bytes carried in the record | nobody's: the release is a public build on a GitHub runner, the configuration is public |

## How each is checked

`cmd/verify` prints one line per layer beside the attestation line:

```
holds  attestation: INTEL_TDX quote binds the key, MRTD c1ee9c16…
holds  firmware: MRTD is one Google signed for UEFI 53c558fe06714203… (endorsed 2026-05-21, svn 2)
holds  boot: 41 events replay to RTMR0 to RTMR2; secure boot true; kernel "BOOT_IMAGE=/vmlinuz-7.0.0-1011-gcp root=… ro console=ttyS0,115200 panic=-1"
       boot: EFI application <sha384 of shim> …
       boot: <sha384> /vmlinuz-7.0.0-1011-gcp …
holds  gateway: RTMR3 carries control-gateway-linux-amd64 <sha384>
holds  gateway: RTMR3 carries carried-config <sha384>
holds  gateway: the measured binary is the release asset
```

The firmware endorsement is fetched by the MRTD from Google's bucket
(`https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/<mrtd>.binarypb`), or
given with `--endorsement`; `--offline` skips it and says so. The event log travels in the
record (`event_log_table`, `event_log`, base64, as the kernel exposes the ACPI CCEL table
and the region it points at); the replay is Google's `go-eventlog`. The release asset's
SHA-384 is given with `--release-sha384`; the watcher computes it from the asset it downloads
at the pinned tag.

## The reference values

- Firmware: whatever Google endorses; the endorsement names the UEFI's SHA-384 and the day
  it was signed. Google rotates firmware, and a new MRTD with a valid endorsement is a
  change to read, not a break.
- Image: `ubuntu-os-cloud/ubuntu-2404-noble-amd64-v20260906`, pinned by name in
  `deploy/gcp/rehearse.sh create` (before 12 September the family `ubuntu-2404-lts-amd64`,
  which moves). The production machine was created from it on 10 September 2026.
- Kernel on the machine at the time of writing: `7.0.0-1011-gcp` (Ubuntu 7.0.0-1011.11~24.04.1).
  Ubuntu updates the kernel on the machine; after a reboot RTMR2 changes and the event log
  names the new kernel and initrd. That is a change to read. The reference for the OS layer
  is "the public image Google publishes under this name, with Canonical's updates", which
  is reproducible by booting it, not a build of ours.
- The gateway: the release asset `control-gateway-linux-amd64` at the tag `startup.sh`
  pins, built on a GitHub runner from the tagged commit (`.github/workflows/release.yml`);
  its SHA-256 is in the release's `SHA256SUMS` and in `startup.sh`, its SHA-384 is what
  RTMR3 carries.
- The carried configuration: the instance attribute `control-config` as the operator carried
  it, kept byte for byte at `/var/lib/control/carried-config.json` and travelling in the
  record as `rtmr3_inputs[1].content`.

## Reproduced once

On 13 September 2026 a second machine was created from the same image with the same boot
script and the production configuration carried (dry), verified through Google's tunnel,
and deleted (`docs/rebuild.md`). Its MRTD and its RTMR0 to RTMR2 were byte for byte the
production machine's, its RTMR3 carried the same release binary, and its key was its own.
That is the reference values reproduced by the one method this page claims for them,
booting the named image, once, by the operator; a reader with a Google project can do the
same with `deploy/gcp/rehearse.sh create` under a name of their choosing.

## What this does not reach

The quote proves what booted and what the gateway measured before it took the quote. It
does not prove that nothing else ran afterwards: a machine with no login path (see
`key-custody.md`) is the answer to that, and it is an operational claim, not a measured
one. RTMR3 is extended once per boot; the daily retake of the quote finds the register
already at the fold and leaves it. A register that holds something else at boot is left
alone and the record carries no inputs, which the verifier reports as a note, never as a
silent hold.
