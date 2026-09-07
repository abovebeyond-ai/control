#!/usr/bin/env python3
"""Replay a chain this gateway wrote with the standard's own code and the ProveML package.

Interoperability is the property the standard names, not one we assert about ourselves.
Nothing of this repository is loaded here: the standard's validator checks every token
(schema, canonical form, semantics, signature), its reference verifier replays the chain,
and the premises are re-verified with the ProveML JavaScript package as a second judge
beside the Go one that produced the record.

    tools/crosscheck.py <dir written by cmd/demo> [--standard PATH] [--proveml PATH to a node_modules with proveml]
"""
import hashlib, json, os, subprocess, sys, tempfile

args = [a for a in sys.argv[1:] if not a.startswith('--')]
opts = dict(a[2:].split('=', 1) for a in sys.argv[1:] if a.startswith('--') and '=' in a)
if not args:
    sys.exit(__doc__)
d = args[0]
standard = opts.get('standard') or os.environ.get('POC_STANDARD') or os.path.expanduser('~/Projects/ov-poc-standard')
sys.path.insert(0, os.path.join(standard, 'schema')); sys.path.insert(0, os.path.join(standard, 'impl'))
import validate
from poc.core import Verifier, untag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

public_key = open(os.path.join(d, 'public-key.hex')).read().strip()
measurement = open(os.path.join(d, 'measurement.hex')).read().strip()
logs = [f for f in os.listdir(os.path.join(d, 'store')) if f.endswith('.jsonl') and f != 'failures.jsonl']
if len(logs) != 1:
    sys.exit(f'expected one agent log, found {logs}')
log = os.path.join(d, 'store', logs[0])
records = [json.loads(l) for l in open(log, encoding='utf-8') if l.strip()]

for i, tok in enumerate(records):
    try:
        validate.validate(tok, public_key)
    except validate.ValidationError as e:
        sys.exit(f'record {i} rejected by the standard\'s validator: {e}')
print(f'validator: {len(records)} token(s) conform to the claim set, canonical form and signature')

ok, why = Verifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)), measurement).verify_chain(records)
print(f'reference verifier: {why}')
if not ok:
    sys.exit(1)

# The signed checkpoint must be the head the chain reaches.
cp = json.load(open(os.path.join(d, 'checkpoint.json')))
if cp['tree_size'] != len(records) or cp['chain_head'] != records[-1]['poc_claims']['chain_head'] or cp['root'] != records[-1]['poc_claims']['merkle_root']:
    sys.exit('the checkpoint does not match the chain head')
print('checkpoint: matches the last record')

node_dir = opts.get('proveml') or os.environ.get('PROVEML_NODE_DIR')
premises_dir = os.path.join(d, 'store', logs[0][:-len('.jsonl')], 'premises')
checked = 0
for i, tok in enumerate(records):
    c = tok['poc_claims']
    if 'proveml_certificate_hash' not in c:
        continue
    m = json.load(open(os.path.join(premises_dir, f'{i}.json'), encoding='utf-8'))
    digests = {
        'proveml_certificate_hash': 'sha-256:' + hashlib.sha256(m['certificate'].encode('utf-8')).hexdigest(),
        'proveml_store_hash': 'sha-256:' + hashlib.sha256(validate.jcs(m['store'])).hexdigest(),
        'proveml_registry_hash': 'sha-256:' + hashlib.sha256(validate.jcs(m['registry'])).hexdigest(),
        'proveml_provenance_hash': 'sha-256:' + hashlib.sha256(validate.jcs(m['provenance'])).hexdigest(),
    }
    for claim, expected in digests.items():
        if c.get(claim) != expected:
            sys.exit(f'record {i}: {claim} does not recompute from the stored material')
    if node_dir:
        with tempfile.TemporaryDirectory() as t:
            json.dump(m['store'], open(os.path.join(t, 's.json'), 'w')); json.dump(m['registry'], open(os.path.join(t, 'r.json'), 'w'))
            open(os.path.join(t, 'c.md'), 'w', encoding='utf-8').write(m['certificate'])
            r = subprocess.run(['node', '--input-type=module', '-e',
                "import { verifyProveml } from 'proveml/verify'; import { readFileSync } from 'node:fs';"
                "const [c, s, g] = process.argv.slice(1).map(f => readFileSync(f, 'utf8'));"
                "const r = verifyProveml(c, JSON.parse(s), { thresholds: JSON.parse(g), coverage: 'certificate' });"
                "console.log(JSON.stringify({ total: r.total, verified: r.verified, unmarked: r.unmarked.length }));",
                os.path.join(t, 'c.md'), os.path.join(t, 's.json'), os.path.join(t, 'r.json')], capture_output=True, text=True, cwd=node_dir)
        if r.returncode != 0:
            sys.exit(f'record {i}: the ProveML package did not run: {r.stderr[-300:]}')
        v = json.loads(r.stdout.strip().splitlines()[-1])
        controls = all(f'?[safe: {ctl}]' in m['certificate'] for ctl in m.get('requiredControls', []))
        second = v['total'] > 0 and v['verified'] == v['total'] and v['unmarked'] == 0 and controls
        if second != bool(c.get('proveml_verified')):
            sys.exit(f'record {i}: the ProveML package says {"verified" if second else "not verified"}, the record claims the opposite')
    if not c.get('proveml_verified') and c.get('verdict') != 'DENY':
        sys.exit(f'record {i}: premises do not verify, yet the verdict is not DENY')
    checked += 1
print(f'premises: {checked} record(s) replayed' + (' with the ProveML package as second verifier, all agree' if node_dir else ' on digests (no ProveML package given)'))
