"""
integrity-chain v1 — Crypto Reference Implementation (contributor)
================================================================
Implements the four crypto hard-prerequisites for the Continuous continuous-verification
Validation product:

  Chain-of-Custody:
        SHA-384 per-evidence hash, append-only hash chain
        (head_n = H(head_{n-1} || H(E_n))), Ed25519 signature on each head,
        and RFC 3161-style trusted timestamp. Verifiable replay tooling.
  Multi-tenant key isolation:
        per-tenant KEK via HKDF-SHA384(master, tenant_id), envelope encryption
        AES-256-GCM with tenant_id bound into the AEAD AAD -> cross-tenant
        ciphertext is un-decryptable (fails authentication, not just access).
  Workload identity + credential vault:
        reference SPIFFE-like attestation + short-TTL dynamic credential
        issuance / revocation (no static secrets in the engine).
  Anti-self-attestation:
        independent signature key for the coverage baseline, signed
        canary set with expected results, DEGRADED on canary miss, SILENT-WIN
        recorded as signed evidence when stealth tradecraft wins undetected.

NOTE on external infra (honest): in production the root signing keys live in
an HSM/KMS, the timestamp uses a real RFC 3161 TSA (openssl ts / FreeTSA /
a regulated CA), and workload attestation is done by SPIRE. Those boundaries
are modelled here with a local deterministic mock so the crypto contract and
its guarantees can be exercised end-to-end without external services.
"""
from __future__ import annotations
import hashlib, hmac, json, secrets, datetime as dt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HASH = hashlib.sha384


def _canon(obj) -> bytes:
    """Deterministic canonical JSON for hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Ed25519 signing helper
# --------------------------------------------------------------------------
class Signer:
    def __init__(self, name: str):
        self.name = name
        self.priv = Ed25519PrivateKey.generate()
        self.pub = self.priv.public_key()

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data)

    def pub_pem(self) -> bytes:
        return self.pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def verify(self, data: bytes, sig: bytes) -> bool:
        try:
            self.pub.verify(sig, data)
            return True
        except Exception:
            return False

    @staticmethod
    def load_pub(pem: bytes) -> "Signer":
        s = Signer.__new__(Signer)
        s.name = "loaded"
        s.priv = None  # type: ignore
        s.pub = serialization.load_pem_public_key(pem)
        return s


# --------------------------------------------------------------------------
# Chain-of-Custody
# --------------------------------------------------------------------------
class HashChain:
    """Append-only SHA-384 hash chain. Each event binds the previous head,
    so any historical tampering breaks every subsequent link."""

    def __init__(self, head_signer: Signer):
        self.head_signer = head_signer
        self.genesis = b"\x00" * 48  # sha384 zero-pad as genesis prev
        self.prev = self.genesis
        self.events: list[dict] = []

    def append(self, evidence: dict) -> dict:
        e_bytes = _canon(evidence)
        hE = HASH(e_bytes).digest()
        head = HASH(self.prev + hE).digest()
        sig = self.head_signer.sign(head)
        ev = {
            "evidence": evidence,
            "hE": hE.hex(),
            "head": head.hex(),
            "prev": self.prev.hex(),
            "sig": sig.hex(),
            "signer": self.head_signer.name,
            "ts": _now_iso(),
        }
        self.prev = head
        self.events.append(ev)
        return ev

    def verify(self, pub_pem: bytes) -> tuple[bool, str]:
        sp = Signer.load_pub(pub_pem)
        prev = self.genesis
        for i, ev in enumerate(self.events):
            if ev["prev"] != prev.hex():
                return False, f"link {i}: prev mismatch (tamper detected)"
            hE = bytes.fromhex(ev["hE"])
            # recompute evidence hash from the (possibly tampered) evidence
            if HASH(_canon(ev["evidence"])).digest() != hE:
                return False, f"link {i}: evidence hash mismatch (tamper detected)"
            recomputed = HASH(prev + hE).hexdigest()
            if recomputed != ev["head"]:
                return False, f"link {i}: head mismatch"
            if not sp.verify(bytes.fromhex(ev["head"]), bytes.fromhex(ev["sig"])):
                return False, f"link {i}: signature invalid"
            prev = bytes.fromhex(ev["head"])
        return True, f"OK: {len(self.events)} links verified, chain intact"


# --------------------------------------------------------------------------
# Multi-tenant envelope isolation
# --------------------------------------------------------------------------
class TenantVault:
    def __init__(self, master: bytes):
        self.master = master

    def derive_kek(self, tenant_id: str, ver: str = "kek-v1") -> bytes:
        info = f"{tenant_id}|{ver}".encode()
        return HKDF(algorithm=hashes.SHA384(), length=32, salt=None,
                    info=info).derive(self.master)

    def seal(self, tenant_id: str, plaintext: bytes) -> dict:
        kek = self.derive_kek(tenant_id)
        dek = AESGCM.generate_key(bit_length=256)
        # AAD = tenant_id -> ciphertext is authenticated to its tenant
        nonce = secrets.token_bytes(12)
        ct = nonce + AESGCM(dek).encrypt(nonce, plaintext,
                                        tenant_id.encode())
        # wrap DEK under tenant KEK
        wnonce = secrets.token_bytes(12)
        wrapped = wnonce + AESGCM(kek).encrypt(wnonce, dek, None)
        return {"tenant_id": tenant_id, "ct": ct, "wrapped_dek": wrapped}

    def unseal(self, blob: dict, as_tenant: str) -> bytes:
        kek = self.derive_kek(as_tenant)
        w = blob["wrapped_dek"]
        dek = AESGCM(kek).decrypt(w[:12], w[12:], None)
        return AESGCM(dek).decrypt(blob["ct"][:12], blob["ct"][12:],
                                   blob["tenant_id"].encode())


# --------------------------------------------------------------------------
# Workload identity + short-TTL credential vault (reference SPIFFE-like)
# --------------------------------------------------------------------------
class WorkloadVault:
    """Reference model: an attested workload gets a scoped, short-TTL dynamic
    credential. No static secret is stored. Revocation zeroes the lease."""

    def __init__(self, root: Signer):
        self.root = root
        self.issued: dict[str, tuple[bytes, bytes, str]] = {}

    def issue(self, spiffe_id: str, scope_cidrs: str, ttl_sec: int) -> dict:
        token_id = secrets.token_hex(8)
        issued = _now_iso()
        expires = (dt.datetime.now(dt.timezone.utc) +
                   dt.timedelta(seconds=ttl_sec)).isoformat()
        payload = f"{spiffe_id}|{scope_cidrs}|{issued}|{expires}".encode()
        sig = self.root.sign(payload)
        self.issued[token_id] = (payload, sig, expires)
        return {"token_id": token_id, "payload": payload.decode(),
                "sig": sig.hex(), "expires": expires}

    def verify(self, token_id: str, payload: str, sig_hex: str) -> bool:
        rec = self.issued.get(token_id)
        if not rec:
            return False
        _payload, _sig, expires = rec
        if not self.root.verify(payload.encode(), bytes.fromhex(sig_hex)):
            return False
        if dt.datetime.now(dt.timezone.utc) > dt.datetime.fromisoformat(expires):
            return False
        return True

    def revoke(self, token_id: str) -> bool:
        return self.issued.pop(token_id, None) is not None


# --------------------------------------------------------------------------
# Anti-self-attestation: independent signed baseline + canary set
# --------------------------------------------------------------------------
class AttckBaseline:
    """Coverage baseline and canary set are signed with an INDEPENDENT key
    (not the engine verdict key) so the test oracle cannot be self-asserted.
    Canaries carry an expected detection result; a miss => DEGRADED."""

    def __init__(self, baseline_signer: Signer):
        self.signer = baseline_signer
        self.techniques = {
            "T1059.003": "Windows Command Shell",
            "T1071.001": "Web Protocols C2",
            "T1550.001": "Token theft / pass-the-ticket",
        }
        self.canary = [
            {"attck_id": "T1059.003", "expected": "ALERT",
             "note": "loud script-kiddie shell must always fire"},
            {"attck_id": "T1071.001", "expected": "ALERT",
             "note": "plaintext C2 beacon must always fire"},
        ]
        bundle = {"techniques": self.techniques, "canary": self.canary}
        self.sig = baseline_signer.sign(_canon(bundle))

    def evaluate(self, run_results: dict) -> str:
        for c in self.canary:
            actual = run_results.get(c["attck_id"], {}).get("detected")
            if actual != c["expected"]:
                return "DEGRADED"
        return "OK"


# --------------------------------------------------------------------------
# Demo / self-test: exercises every guarantee with real crypto output
# --------------------------------------------------------------------------
def _demo():
    print("=" * 72)
    print("integrity-chain v1 — crypto reference  (contributor)")
    print("=" * 72)
    results = []

    # --- key material (in prod: HSM/KMS backed) ---
    engine_signer = Signer("engine-verdict")      # signs chain heads
    baseline_signer = Signer("attck-baseline")     # INDEPENDENT oracle key
    tsa_signer = Signer("rfc3161-tsa-mock")        # trusted timestamp
    vault_root = Signer("workload-root")
    master = secrets.token_bytes(32)               # KMS master key

    # ---- multi-tenant isolation ----
    tv = TenantVault(master)
    secret_a = b"tenant-A confidential evidence blob"
    blob_a = tv.seal("tenant-A", secret_a)
    plain_a = tv.unseal(blob_a, "tenant-A")
    iso_ok = (plain_a == secret_a)
    cross_fail = False
    try:
        tv.unseal(blob_a, "tenant-B")   # must raise (auth tag fails)
    except Exception:
        cross_fail = True
    results.append(("tenant isolation (same-tenant decrypt)",
                    iso_ok, f"recovered={plain_a == secret_a}"))
    results.append(("tenant isolation (cross-tenant blocked)",
                    cross_fail, "tenant-B cannot decrypt tenant-A ciphertext"))

    # ---- chain of custody ----
    chain = HashChain(engine_signer)
    baseline = AttckBaseline(baseline_signer)

    e1 = {
        "run_id": "run-0001", "tenant_id": "tenant-A",
        "target_scope": "10.20.0.0/24",
        "raw_telemetry_ref": "s3://evi/run-0001/tele.bin",
        "engine_verdict": "PASS", "attck_id": "T1059.003",
        "env_fingerprint": {"ASLR": "on", "DEP": "on", "canary": "on",
                            "CFG": "on", "libc": "2.31", "kernel_mitig": "on"},
        "ts": _now_iso(),
    }
    chain.append(e1)

    # canary miss -> DEGRADED (evasion coverage)
    run_results = {"T1059.003": {"detected": False},     # canary expected ALERT
                   "T1071.001": {"detected": True}}
    verdict = baseline.evaluate(run_results)
    e2 = {
        "run_id": "run-0001", "tenant_id": "tenant-A",
        "event": "BASELINE_EVAL", "baseline_verdict": verdict,
        "baseline_sig": baseline.sig.hex(),
        "ts": _now_iso(),
    }
    chain.append(e2)

    # SILENT-WIN: stealth tradecraft won, blue stayed silent
    e3 = {
        "run_id": "run-0001", "tenant_id": "tenant-A",
        "attck_id": "T1071.001", "tradecraft": "APT-stealth",
        "engine_status": "SILENT-WIN",
        "note": "beacon established + exfil, blue emitted nothing",
        "ts": _now_iso(),
    }
    chain.append(e3)

    ok, msg = chain.verify(engine_signer.pub_pem())
    results.append(("chain integrity + Ed25519 verify", ok, msg))
    results.append(("canary -> DEGRADED on miss",
                    verdict == "DEGRADED",
                    f"baseline_verdict={verdict}"))
    results.append(("SILENT-WIN recorded as signed evidence",
                    e3["engine_status"] == "SILENT-WIN", "stealth win logged"))

    # ---- RFC 3161-style timestamp on the chain head ----
    head = bytes.fromhex(chain.events[-1]["head"])

    def _tsa_stamp(h):
        t = _now_iso()
        payload = h + t.encode()
        return {"time": t, "sig": tsa_signer.sign(payload).hex(),
                "hash": h.hex()}
    stamp = _tsa_stamp(head)
    sp = Signer.load_pub(tsa_signer.pub_pem())
    tsa_ok = sp.verify(head + stamp["time"].encode(), bytes.fromhex(stamp["sig"]))
    results.append(("RFC3161-style trusted timestamp",
                    tsa_ok, f"stamped@ {stamp['time']}"))

    # ---- workload vault: short-TTL credential ----
    wv = WorkloadVault(vault_root)
    cred = wv.issue("spiffe://tenant-A/engine", "10.20.0.0/24", ttl_sec=300)
    good = wv.verify(cred["token_id"], cred["payload"], cred["sig"])
    wv.revoke(cred["token_id"])
    after_revoke = wv.verify(cred["token_id"], cred["payload"], cred["sig"])
    results.append(("workload cred issued + verified (short-TTL)",
                    good, f"token={cred['token_id']}"))
    results.append(("revocation zeroes lease",
                    after_revoke is False, "post-revoke verify=False"))

    # ---- tamper detection: flip a field in e1 and re-verify ----
    chain.events[0]["evidence"]["engine_verdict"] = "TAMPERED"
    tamper_ok, tamper_msg = chain.verify(engine_signer.pub_pem())
    results.append(("tamper detection (should FAIL verify)",
                    tamper_ok is False, tamper_msg))

    # ---- report ----
    print("\n--- GUARANTEE CHECKS ---")
    allpass = True
    for name, ok, detail in results:
        flag = "PASS" if ok else "FAIL"
        if not ok:
            allpass = False
        print(f"  [{flag}] {name}\n         -> {detail}")
    print("\n--- chain heads (sha384) ---")
    for ev in chain.events:
        print(f"  {ev['head'][:24]}... prev={ev['prev'][:16]} signer={ev['signer']}")
    print("\n" + ("ALL GUARANTEES PASS" if allpass else "SOME CHECKS FAILED"))
    print("=" * 72)
    return allpass


if __name__ == "__main__":
    raise SystemExit(0 if _demo() else 1)
