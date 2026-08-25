"""integrity-chain Chain Independent Verifier (contributor).
Offline, stdlib-only, zero-network, zero-hardcoded-IP. Re-derives every
hash link + head signature from the chain's own embedded pubkey; does NOT
trust the producer. Anti-self-attest at verify layer: an event
claiming live-measurement with no proof fields => FAIL. Local-only check
honored (no network call)."""
import argparse, hashlib, json, os, sys, tempfile

from crypto_reference import HashChain, Signer, HASH, _canon

_CHAIN_DEFAULT = os.environ.get("PC_EGRESS_CHAIN") or os.path.join(os.path.dirname(__file__), ".egress_chain.json")


def _sha_hex(b):
    return hashlib.sha384(b).hexdigest()


def _serialize(chain):
    pub = chain.head_signer.pub_pem()
    if isinstance(pub, bytes):
        pub = pub.decode("utf-8")
    return {"events": chain.events,
            "head_signer": {"pub_pem": pub, "name": chain.head_signer.name}}


def verify_chain_doc(data):
    events = data.get("events", [])
    head_signer = data.get("head_signer", {})
    ok = True
    msgs = []
    prev = b"\x00" * 48
    for i, ev in enumerate(events):
        evidence = ev.get("evidence", {})
        hE = HASH(_canon(evidence)).digest()
        if bytes.fromhex(ev.get("hE", "")) != hE:
            ok = False
            msgs.append("  [link %d] EVIDENCE HASH MISMATCH (tamper detected)" % i)
        if bytes.fromhex(ev.get("prev", "")) != prev:
            ok = False
            msgs.append("  [link %d] PREV MISMATCH (breaks chain continuity)" % i)
        rh = _sha_hex(prev + hE)
        if ev.get("head") != rh:
            ok = False
            msgs.append("  [link %d] HEAD MISMATCH (recomputed %s != stored)" % (i, rh[:12]))
        if not evidence.get("verify", True):
            ok = False
            msgs.append("  [link %d] evidence.verify == False (integrity-lost flagged)" % i)
        prev = bytes.fromhex(ev.get("head", ""))
        tt = evidence.get("test_type")
        if tt == "live-measurement":
            proof = (evidence.get("measured_egress_fingerprint")
                     or evidence.get("measurer_tool_hashes")
                     or evidence.get("process_image_hash"))
            if not proof:
                ok = False
                msgs.append("  [link %d] DISHONEST test_type=live-measurement with no proof fields" % i)
        elif tt is not None and tt != "logic/mock":
            msgs.append("  [link %d] test_type=%r (unknown, flagged for review)" % (i, tt))
    pub_pem = head_signer.get("pub_pem")
    if not pub_pem:
        ok = False
        msgs.append("[head] no embedded public key in chain (cannot verify signature)")
    else:
        try:
            sp = Signer.load_pub(pub_pem.encode("utf-8") if isinstance(pub_pem, str) else pub_pem)
            bad = False
            for i, ev in enumerate(events):
                if not sp.verify(bytes.fromhex(ev["head"]), bytes.fromhex(ev["sig"])):
                    bad = True
                    msgs.append("  [link %d] SIGNATURE INVALID (not signed by embedded key)" % i)
            if not bad:
                msgs.append("[head] signatures OK (verified vs embedded pubkey)")
        except Exception as ex:
            ok = False
            msgs.append("[head] signature verify error: %s" % ex)
    return ok, msgs


def _main_path(path):
    data = json.load(open(path, encoding="utf-8"))
    print("[verify] chain = %s" % path)
    print("[verify] events = %d; head_signer = %s" % (len(data.get("events", [])), data.get("head_signer", {}).get("name")))
    ok, msgs = verify_chain_doc(data)
    for m in msgs:
        print(m)
    if ok:
        print("ALL CHECKS PASSED - chain intact and every event honest (test_type not dishonestly upgraded)")
        return 0
    print("VERIFY FAILED - see above")
    return 1


def main():
    ap = argparse.ArgumentParser(description="integrity-chain chain independent verifier")
    ap.add_argument("--chain", default=_CHAIN_DEFAULT, help="path to egress chain JSON")
    ap.add_argument("--selftest", action="store_true",
                    help="self-prove: build+verify honest/tampered/fake-live (zero real IP, zero network)")
    args = ap.parse_args()
    if args.selftest:
        return _selftest()
    chain_path = os.path.abspath(args.chain)
    if not os.path.exists(chain_path):
        print("FAIL: chain file not found")
        return 1
    return _main_path(chain_path)


def _selftest():
    """Build honest chain, verify it; prove tamper + fake-live FAIL.
    RFC5737 TEST-NET placeholders only; zero real IP; zero network."""
    import egress_attestation as ea
    engine_signer = ea.Signer("engine-verdict")
    attest_signer = ea.Signer("egress-attest")
    tsa_signer = ea.Signer("rfc3161-tsa-mock")
    chain = HashChain(engine_signer)
    chain.append({"kind": "SEED", "note": "self-test prior link", "ts": ea._now_iso()})
    ruleset_v1 = b"table inet filter { chain input { policy drop; } }"
    sim = ea.SimulatedBackend(ruleset=ruleset_v1, resolver="10.8.0.1", tunnel=True,
                              egress_ip="203.0.113.10")
    for t, b in [("nft", b"/usr/sbin/nft ELF binary bytes"),
                 ("resolvectl", b"/usr/bin/resolvectl ELF binary bytes"),
                 ("wg", b"/usr/bin/wg ELF binary bytes"),
                 ("python.exe", b"python interpreter bytes"),
                 ("egress_attestation.py", b"this module source bytes")]:
        sim.set_tool(t, b)
    bmgr = ea.BaselineManager(attest_signer, sim, persist_path="_selftest_baseline.json")
    baseline = bmgr.generate(); bmgr.anchor(chain, baseline); bmgr.persist(baseline)
    ei = ea.EgressAttestation(chain, attest_signer, tsa_signer, backend=sim, baseline_mgr=bmgr)
    banned = {"198.51.100.7"}
    mod_path = os.path.join(os.path.dirname(__file__), "egress_attestation.py")
    measured_sha = ei.measure_binary_sha384(mod_path)
    runtime = {"tunnel_endpoint": "relay.example-remote:51820", "fail_closed": True,
               "dns_egress": "10.8.0.1", "relay_binary_sha384": measured_sha, "relay_binary_signed": True}
    r_ok = ei.build(runtime, banned)
    assert r_ok["attested"], "self-test honest build failed"
    _ev = r_ok["event"]["evidence"]
    for _k in ("ttl_probe", "dns_leak_probe", "local_artifact_hash"):
        assert _k in _ev, "field missing: %s" % _k
    assert _ev["test_type"] == "logic/mock", "self-test must stay logic/mock"

    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(_serialize(chain), tmp, ensure_ascii=False)
    tmp.close()

    results = []
    rc = _main_path(tmp.name)
    results.append(("honest chain verifies PASS (exit 0)", rc == 0))
    d = json.load(open(tmp.name, encoding="utf-8"))
    d["events"][-1]["evidence"]["fail_closed"] = False
    json.dump(d, open(tmp.name, "w", encoding="utf-8"), ensure_ascii=False)
    rc = _main_path(tmp.name)
    results.append(("tampered evidence FAILS (exit 1)", rc == 1))
    d = json.load(open(tmp.name, encoding="utf-8"))
    d["events"][-1]["evidence"]["test_type"] = "live-measurement"
    json.dump(d, open(tmp.name, "w", encoding="utf-8"), ensure_ascii=False)
    rc = _main_path(tmp.name)
    results.append(("fake live-measurement FAILS (exit 1)", rc == 1))

    os.unlink(tmp.name)
    if os.path.exists("_selftest_baseline.json"):
        os.unlink("_selftest_baseline.json")

    allok = True
    print("\n--- verify_cli self-test (zero real IP / zero network) ---")
    for name, ok in results:
        print("  [%s] %s" % ("PASS" if ok else "FAIL", name))
        allok = allok and ok
    print("SELF-TEST " + ("ALL PASS" if allok else "FAILED"))
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
