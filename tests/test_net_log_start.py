"""Tests for _net_log_start in lib/bwrap_sandbox_lib.sh: the network log is
not optional in a private network.

    python3 -m unittest discover -s tests -p 'test_*.py'

The launcher's own function runs in bash with the fake systemd-cat from
tests/fakes/bin, which appends each record to $FAKE_NET_DIR/journal.log.
Without Python for the condenser, or when the condenser does not say it is
ready, the launch must stop (exit 3) with an abort record, before the backend
would have started.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib", "bwrap_sandbox_lib.sh")
HELPER = os.path.join(HERE, "..", "lib", "bwrap_netlog.py")
FAKES = os.path.join(HERE, "fakes", "bin")

# $1 library, $2 the test's directory, $3 fakes, $4 python ("" for none),
# $5 helper.  Prints "continued" if the launch goes on.
DRIVER = r"""
source "$1" 2>/dev/null
export FAKE_NET_DIR="$2"
PATH="$3:${PATH}"
_NET_RUNTIME_BASE="$2/rt"
_NET_BACKEND=pasta
_NET_PRIVATE=1
_PASTA_BIN=/bin/true
_NET_LOG_TOOLS=(systemd-cat)
_NET_LOG_SESSION=abc
_NET_LOG_USER=alice
_NET_LOG_FLOWS=1
_NET_LOG_PIPE=1
_NET_DNS_RELAY=1
_NET_DNS_EFFECTIVE=169.254.1.1
_NET_LOG_PY="$4"
_NET_LOG_HELPER="$5"
_NET_LOG_READY_WAIT=2
PASTA_ARGS=(--quiet)
_net_log_start
echo continued
"""


def gone(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return True


class NetLogStartTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="net-log-start.")
        os.mkdir(os.path.join(self.dir, "rt"), 0o700)
        self.journal = os.path.join(self.dir, "journal.log")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_start(self, python, helper=HELPER):
        res = subprocess.run(
            ["bash", "-c", DRIVER, "_", LIB, self.dir, FAKES, python, helper],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        return res, res.stdout.decode()

    def journal_lines(self):
        try:
            with open(self.journal) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def assert_aborted(self, res, out, reason):
        self.assertEqual(res.returncode, 3, res.stderr.decode())
        self.assertNotIn("continued", out)
        lines = self.journal_lines()
        self.assertTrue(lines and "event=start session=abc" in lines[0], lines)
        self.assertRegex(lines[-1], r"event=abort session=abc .*reason=%s$" % reason)
        self.assertEqual(os.listdir(os.path.join(self.dir, "rt")), [], "the session directory was left behind")

    def test_without_python_the_launch_stops(self):
        res, out = self.run_start("")
        self.assert_aborted(res, out, "no-python")
        self.assertIn("needs Python 3.6 or later", res.stderr.decode())
        self.assertIn("--share-net", res.stderr.decode())

    def test_without_the_helper_the_launch_stops(self):
        res, out = self.run_start("", os.path.join(self.dir, "missing.py"))
        self.assert_aborted(res, out, "helper-missing")

    def test_a_condenser_that_exits_stops_the_launch(self):
        res, out = self.run_start("/bin/false")
        self.assert_aborted(res, out, "condenser-failed")
        self.assertIn("condenser did not start", res.stderr.decode())

    def test_a_condenser_that_hangs_stops_the_launch_and_is_ended(self):
        hang = os.path.join(self.dir, "hang.py")
        pidfile = os.path.join(self.dir, "pid")
        with open(hang, "w") as f:
            f.write("import os, time\nopen(%r, 'w').write(str(os.getpid()))\ntime.sleep(60)\n" % pidfile)
        start = time.monotonic()
        res, out = self.run_start(sys.executable, hang)
        self.assert_aborted(res, out, "condenser-failed")
        self.assertLess(time.monotonic() - start, 30)
        with open(pidfile) as f:
            pid = int(f.read())
        for _ in range(50):
            if gone(pid):
                break
            time.sleep(0.1)
        self.assertTrue(gone(pid), "the condenser that did not start is still running")

    def test_a_working_condenser_lets_the_launch_go_on(self):
        res, out = self.run_start(sys.executable)
        self.assertEqual(res.returncode, 0, res.stderr.decode())
        self.assertIn("continued", out)
        # The driver has exited, so the condenser writes the end record.
        for _ in range(100):
            if any("event=end session=abc" in ln for ln in self.journal_lines()):
                break
            time.sleep(0.1)
        lines = self.journal_lines()
        self.assertTrue(any("event=end session=abc" in ln for ln in lines), lines)
        self.assertFalse(any("event=abort" in ln for ln in lines), lines)


if __name__ == "__main__":
    unittest.main()
