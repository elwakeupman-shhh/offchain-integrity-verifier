# offchain-integrity-verifier — off-chain integrity proof toolkit

A small, dependency-light toolkit that proves a measurement / attestation
chain is **tamper-evident and honestly labeled** — without trusting the
producer. Built for anyone who needs to show "this result is real and was
not silently edited after the fact."

## Why it is useful
When one party hands you an integrity report ("we verified this"), you
usually have to take their word for it. This toolkit lets an **independent
verifier** re-derive every hash link and the head signature from the
chain's own embedded public key, and it **refuses** any event that claims
a "live measurement" without the proof fields to back it. Tampered chains
and fake-live chains both FAIL; honest chains PASS.

## What is inside
1. `cli.py` — the orchestrator. Run `python cli.py --selftest` to prove the
   engine is wired correctly (zero network, zero real IP).
2. `verify_cli.py` — an **independent verifier**: re-derives every hash link
   and head signature from the chain's own embedded public key, and refuses
   any event that claims a live measurement without proof fields.
3. `crypto_reference.py` — the crypto core: SHA-384 append-only hash chain,
   Ed25519 head signatures, multi-tenant envelope isolation, short-TTL
   workload credentials, and a signed baseline + canary set.
4. `egress_attestation.py` — a local-only egress-attestation module that
   measures its own egress source and REFUSES dishonest anonymity claims.
5. `config.py` / `recon.py` / `report.py` / `scanner.py` — supporting modules.

## Safety
- Pure local computation. No network calls in either self-test.
- No real IP, no private keys, no credentials touched.
- The crypto layer uses the standard `cryptography` library only.

## Requirements
- Python 3.8+
- `pip install cryptography`   (Ed25519 signing + AES-GCM envelope crypto)

## Run

Engine self-check:

    python cli.py --selftest

Independent verifier self-check (honest / tampered / fake-live):

    python verify_cli.py --selftest

### Example self-test output
    --- verify_cli self-test (zero real IP / zero network) ---
      [PASS] honest chain verifies PASS (exit 0)
      [PASS] tampered evidence FAILS (exit 1)
      [PASS] fake live-measurement FAILS (exit 1)
    SELF-TEST ALL PASS

## How to verify it yourself (self-test)
`verify_cli.py --selftest` builds an honest chain, verifies it (expect
PASS), then flips one evidence field and re-verifies (expect FAIL), then
labels an event as `live-measurement` with no proof fields and re-verifies
(expect FAIL). All of this runs **zero network, zero real IP**, so you can
re-run it anywhere to confirm the verifier's guarantees hold.

## License
MIT — see `LICENSE`.

## Contact
EL. (Inquiries: reach out via the platform you found this repository on.
No personal email is published here on purpose.)


## For your first client

This toolkit is built to be dropped into a real engagement and trusted by a paying client. It runs fully offline, leaves a verifiable evidence chain (self-test PASS), and ships with a signed integrity check (D2) so the client can re-verify the artifact they received was not tampered. Pricing/escrow via USDT-TRC20 is supported out of the box.
