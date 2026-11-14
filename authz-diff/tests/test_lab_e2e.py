"""Run the whole tool against the bundled lab and check every route's verdict."""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from authzdiff.analyze import Verdict
from authzdiff.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main, run
from authzdiff.config import load_config
from authzdiff.har import load_har, select
from authzdiff.replay import Client
from lab.server import make_server

ROOT = Path(__file__).resolve().parent.parent
LAB_ADDRESS = "127.0.0.1:8099"

EXPECTED = {
    "/api/health": Verdict.PUBLIC,
    "/api/me": Verdict.DIFFERS,
    "/api/plans": Verdict.SUSPECT,
    "/api/invoices": Verdict.DIFFERS,
    "/api/invoices/101": Verdict.VULNERABLE,
    "/api/invoices/101/receipt": Verdict.ENFORCED,
    "/api/users/1": Verdict.VULNERABLE,
    "/api/admin/users": Verdict.VULNERABLE,
    "/api/notes/1": Verdict.VULNERABLE,
    "/api/documents/0b9d2c0e-6f1a-4c53-9a7e-2f4d8c1b7a10": Verdict.ENFORCED,
    "/api/old-dashboard": Verdict.SKIPPED,
}


class LabEndToEnd(unittest.TestCase):
    def setUp(self):
        self.server = make_server(port=0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        address = f"127.0.0.1:{self.server.server_address[1]}"

        # The examples are written for port 8099; point copies at the test server.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.config = self.tmp / "lab.toml"
        self.har = self.tmp / "lab.har"
        self.config.write_text((ROOT / "examples/lab.toml").read_text().replace(LAB_ADDRESS, address))
        self.har.write_text((ROOT / "examples/lab.har").read_text().replace(LAB_ADDRESS, address))

    def cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["-c", str(self.config), "--har", str(self.har), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_every_route_gets_the_expected_verdict(self):
        cfg = load_config(self.config)
        chosen, dropped = select(load_har(self.har), cfg)
        results = run(cfg, chosen, Client(cfg))

        self.assertEqual({r.request.path: r.verdict for r in results}, EXPECTED)
        self.assertEqual(
            dict(dropped),
            {"method not enabled": 2, "static asset": 1, "out of scope": 1, "duplicate": 1},
        )
        leaks = {r.request.path: r.leaked_to for r in results if r.verdict is Verdict.VULNERABLE}
        self.assertEqual(leaks["/api/notes/1"], "anonymous")
        self.assertEqual(leaks["/api/invoices/101"], "other")

    def test_redirects_are_not_followed(self):
        cfg = load_config(self.config)
        chosen, _ = select(load_har(self.har), cfg)
        run(cfg, chosen, Client(cfg))
        self.assertEqual(self.server.state["redirect_target_hits"], 0)

    def test_state_changing_methods_need_the_explicit_flag(self):
        code, _, err = self.cli("--methods", "GET,PUT")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--allow-state-changing", err)

        code, out, _ = self.cli("--methods", "PUT", "--allow-state-changing")
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertRegex(out, r"VULNERABLE\s+PUT\s+/api/invoices/101")

    def test_dry_run_lists_requests_and_sends_nothing(self):
        before = dict(self.server.state["invoices"][101])
        code, out, _ = self.cli("--dry-run", "--methods", "GET,PUT", "--allow-state-changing")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("PUT http://", out)
        self.assertEqual(len(out.strip().splitlines()), len(EXPECTED) + 1)
        self.assertEqual(self.server.state["invoices"][101], before)

    def test_outputs_never_contain_credentials(self):
        report, data, bodies = self.tmp / "r.md", self.tmp / "r.json", self.tmp / "bodies"
        code, out, err = self.cli("--report", str(report), "--json", str(data), "--save-bodies", str(bodies))
        self.assertEqual(code, EXIT_FINDINGS)

        written = out + err + report.read_text() + data.read_text()
        for secret in ("lab-token-alice", "lab-token-bob", "alice-pass"):
            self.assertNotIn(secret, written)
        self.assertIn("<BOB_AUTHORIZATION>", report.read_text())
        self.assertIn("### 4. GET /api/notes/1", report.read_text())

        parsed = json.loads(data.read_text())
        self.assertEqual(len(parsed["results"]), len(EXPECTED))
        self.assertEqual(parsed["results"][0]["verdict"], "VULNERABLE")
        self.assertTrue(any(p.name.endswith(".other.200.body") for p in bodies.iterdir()))

    def test_unreachable_target_is_an_error_not_a_pass(self):
        self.server.shutdown()
        self.server.server_close()
        code, out, err = self.cli()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("nothing was tested", err)
        self.assertNotIn("VULNERABLE", out)

    def test_scope_mismatch_tests_nothing(self):
        self.config.write_text(self.config.read_text().replace('hosts = ["127.0.0.1:', 'hosts = ["127.0.0.2:'))
        code, _, err = self.cli()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("nothing to test", err)


if __name__ == "__main__":
    unittest.main()
