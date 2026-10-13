import os, sys, json, tempfile, types, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import patchpilot as pp

SRC = 'def f(c, t):\n    q = f"SELECT * FROM s WHERE token = \'{t}\'"\n    c.execute(q)\n'
GOOD = ("--- a/app.py\n+++ b/app.py\n@@ -1,3 +1,3 @@\n def f(c, t):\n"
        "-    q = f\"SELECT * FROM s WHERE token = '{t}'\"\n-    c.execute(q)\n"
        "+    q = \"SELECT * FROM s WHERE token = ?\"\n+    c.execute(q, (t,))\n")
BAD = GOOD.replace("def f(c, t):", "def other(c, t):")


def sarif(uri="app.py"):
    return {"runs": [{"results": [{"ruleId": "sqli", "message": {"text": "m"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                "region": {"startLine": 2}}}]}]}]}


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        with open(os.path.join(self.d, "app.py"), "w") as f:
            f.write(SRC)

    def write(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            f.write(text)
        return p


class TestParsing(Base):
    def test_valid(self):
        p = self.write("s.sarif", json.dumps(sarif()))
        self.assertEqual(pp.load_findings(p)[0]["path"], "app.py")

    def test_empty_file_gives_clear_error(self):
        with self.assertRaises(pp.PatchPilotError):
            pp.load_findings(self.write("e.sarif", ""))

    def test_missing_file(self):
        with self.assertRaises(pp.PatchPilotError):
            pp.load_findings(os.path.join(self.d, "nope.sarif"))

    def test_skips_findings_without_location(self):
        p = self.write("s.sarif", json.dumps({"runs": [{"results": [{"ruleId": "x"}]}]}))
        self.assertEqual(pp.load_findings(p), [])

    def test_path_traversal_blocked(self):
        with self.assertRaises(pp.PatchPilotError):
            pp.resolve_path(self.d, "../../etc/passwd")


class TestDiff(unittest.TestCase):
    def test_extract_from_fence_and_prose(self):
        self.assertIsNotNone(pp.extract_diff("Here:\n```diff\n" + GOOD + "```\nDone"))
        self.assertIsNotNone(pp.extract_diff("Sure!\n" + GOOD))

    def test_extract_rejects_prose(self):
        self.assertIsNone(pp.extract_diff("I cannot help with that."))

    def test_matching_and_mismatching(self):
        self.assertEqual(pp.diff_problems(GOOD, SRC), [])
        self.assertTrue(pp.diff_problems(BAD, SRC))


class FakeAnthropic(types.ModuleType):
    """Stands in for the SDK so the whole pipeline runs offline."""
    def __init__(self, replies):
        super().__init__("anthropic")
        self.replies = list(replies)
        for n in ("AuthenticationError", "RateLimitError", "APIConnectionError", "APIStatusError"):
            setattr(self, n, type(n, (Exception,), {}))
        outer = self

        class Client:
            def __init__(s, **k):
                s.messages = s
            def create(s, **k):
                r = outer.replies.pop(0)
                if isinstance(r, Exception):
                    raise r
                return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text=r)])
        self.Anthropic = Client


class TestEndToEnd(Base):
    def run_main(self, replies, *extra):
        fake = FakeAnthropic(replies)
        sar = self.write("s.sarif", json.dumps(sarif()))
        out = os.path.join(self.d, "out")
        with mock.patch.dict(sys.modules, {"anthropic": fake}), \
             mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}):
            code = pp.main(["--sarif", sar, "--root", self.d, "--out", out, *extra])
        return code, out

    def test_good_diff_saved(self):
        code, out = self.run_main(["```diff\n" + GOOD + "```"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(os.path.join(out, "finding1.diff")))

    def test_bad_then_good_retries(self):
        code, _ = self.run_main([BAD, GOOD])
        self.assertEqual(code, 0)

    def test_always_bad_fails_cleanly(self):
        code, out = self.run_main([BAD, BAD])
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(out))

    def test_api_error_handled(self):
        fake_err = FakeAnthropic([])
        fake_err.replies = [fake_err.RateLimitError("slow down")]
        sar = self.write("s.sarif", json.dumps(sarif()))
        with mock.patch.dict(sys.modules, {"anthropic": fake_err}), \
             mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}):
            self.assertEqual(pp.main(["--sarif", sar, "--root", self.d]), 1)

    def test_missing_key(self):
        sar = self.write("s.sarif", json.dumps(sarif()))
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with mock.patch.dict(sys.modules, {"anthropic": FakeAnthropic([])}), \
             mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(pp.main(["--sarif", sar, "--root", self.d]), 1)

    def test_dry_run_needs_no_key(self):
        sar = self.write("s.sarif", json.dumps(sarif()))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(pp.main(["--sarif", sar, "--root", self.d, "--dry-run"]), 0)


if __name__ == "__main__":
    unittest.main()
