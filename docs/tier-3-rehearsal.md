# Tier 3 rehearsal: the gateway in a confidential VM

What Tier 2 cannot show is that the operator could not have written the evidence
differently. Tier 3 shows it with hardware: the gateway runs in an Intel TDX trust domain,
its key is generated inside, and a quote signed by the CPU binds that key to the
measurement of the domain. A stranger checks the quote under Intel's roots and then
knows that whoever signed the records was this code on this hardware, not a person with
a file.

This is the rehearsal, not the move. The production gateway stays where it is until real
traffic has gone through its shadow; the rehearsal proves the code and the platform in an
afternoon, and the VM is stopped afterwards.

## Where

Google Cloud, machine type c3-standard-4, zone europe-west4-a (Netherlands), Confidential
VM type Intel TDX, Ubuntu 24.04. Chosen because the standard's reference used it, the
`attest` package targets it, and the confidential option is a flag on an ordinary VM
with the quote available from the kernel, no attestation service in between. About
130 EUR a month while running; stopped, only the 20 GB disk.

Not married to it: AMD SEV-SNP at another provider is a second backend for `attest`,
the same shape as Hedera beside the RFC 3161 timestamp.

## What Shane does

1. Create a Google Cloud project, attach billing, note the project id.
2. On the Mac, once:

```bash
gcloud auth login
gcloud config set project <project-id>
gcloud services enable compute.googleapis.com iap.googleapis.com
```

## What the scripts do

`deploy/gcp/startup.sh` runs as root on first boot: a system user `control`, the pinned
gateway binary (version and sha256 in the script, checked before install), a dry
configuration with one rehearsal agent, `"attestation": "tdx"`, a hardened systemd unit.
The gateway generates its key in `/var/lib/control/secrets` on that disk, asks the
hardware for a quote binding it, writes `attestation.json` beside the store, and serves
on localhost only. The VM has no public address; the Mac reaches it through IAP.

`deploy/gcp/rehearse.sh` from the Mac:

```bash
export CONTROL_GCP_PROJECT=<project-id>
deploy/gcp/rehearse.sh create     # the VM, with the startup script
deploy/gcp/rehearse.sh log        # did the quote come out? "INTEL_TDX" on /v1/key
deploy/gcp/rehearse.sh submit     # one dry pull.open, judged and recorded
deploy/gcp/rehearse.sh fetch      # attestation.json, the log, the key, the checkpoint
deploy/gcp/rehearse.sh verify     # on the Mac, collateral from Intel
deploy/gcp/rehearse.sh stop
```

## What verify must say

```
holds  attestation: INTEL_TDX quote binds the key, MRTD <96 hex>
holds  did_webvh_..._agent-rehearsal: chain verified: 1 records
holds  did_webvh_..._agent-rehearsal: checkpoint at size 1 matches the chain
```

and the standard's validator on the record, run with `tools/crosscheck.py`, must give no
note where it used to say "Tier 2 at most".

## What to write down afterwards

The MRTD, and whether it is the same after a stop and start (it should be: it measures
the image, not the run). Whether the key survived the stop (it is on the disk, so yes,
and that is a Tier 3 property, not Tier 4: Google can read that disk). The time from
create to the first quote. Anything the startup script had to do that this page does not
mention. Those go into the worked example and into the /trust/keys page, which then says
Tier 3 for the rehearsal gateway and still Tier 2 for the one in production, until the
move.
