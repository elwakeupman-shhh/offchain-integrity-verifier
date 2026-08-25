"""integrity-chain CLI orchestrator with safety guardrail."""
from __future__ import annotations
import sys
import threading
import http.server
import socketserver
from config import Config
import report


def _start_demo_server(port: int):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = self.path.split("q=", 1)[1] if "q=" in self.path else ""
            body = "<html>echo:" + q + "</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "demo/1.0")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):  # silence
            pass

    with socketserver.TCPServer(("127.0.0.1", port), H) as httpd:
        httpd.serve_forever()


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cfg = Config()
    demo = "--demo" in argv
    selftest = "--selftest" in argv

    if selftest:
        assert report.build({"target": "x"}, {"check": "reflected_input",
                       "reflected": False, "severity": "info"})["engine"] == "integrity-chain"
        print("SELFTEST OK")
        return 0

    if demo:
        t = threading.Thread(target=_start_demo_server, args=(cfg.target_port,), daemon=True)
        t.start()
        import time
        time.sleep(0.3)

    # SAFETY GUARDRAIL: refuse non-loopback unless explicitly allowed.
    if not cfg.is_loopback and not cfg.allow_external:
        print("[BLOCKED] target " + cfg.target + " is not loopback. "
              "Use --allow-external only with explicit written authorization.", file=sys.stderr)
        return 2

    try:
        import recon, scanner  # lazy: live external scan path only
    except ImportError:
        print("[unsupported] live external scanning not bundled in this build", file=sys.stderr)
        return 2
    r = recon.grab(cfg.target, cfg.target_port)
    s = scanner.reflected_input_signal(cfg.target, cfg.target_port)
    rep = report.build(r, s)
    print(report.dump(rep))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
