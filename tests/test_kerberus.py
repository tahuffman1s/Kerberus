"""Unit tests for the parts of Kerberus that don't need a KDC: klist parsing,
renewal decisions and message cleanup. tests/integration.sh covers the rest."""

import datetime as dt
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("kerberus", Path(__file__).resolve().parent.parent / "kerberus.py")
kerberus = importlib.util.module_from_spec(spec)
sys.modules["kerberus"] = kerberus
spec.loader.exec_module(kerberus)

KLIST = """\
Ticket cache: DIR::/tmp/krbdir/tkt
Default principal: alice@EXAMPLE.TEST

Valid starting     Expires            Service principal
10/19/26 23:49:00  10/20/26 09:49:00  krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
\trenew until 10/26/26 23:48:48, Flags: FRIT
10/19/26 23:50:00  10/20/26 09:49:00  host/svc.example.test@EXAMPLE.TEST
\trenew until 10/26/26 23:48:48, Flags: FRT

Ticket cache: DIR::/tmp/krbdir/tkt6z4Mm3
Default principal: bob@EXAMPLE.TEST

Valid starting     Expires            Service principal
10/19/26 23:49:06  10/20/26 09:49:06  krbtgt/EXAMPLE.TEST@EXAMPLE.TEST
\tFlags: FI
"""
NOW = dt.datetime(2026, 10, 20, 9, 0)
SETTINGS = dict(kerberus.DEFAULT_SETTINGS)


class FakeKeyring:
    def __init__(self, passwords):
        self.passwords = passwords

    def principals(self):
        return list(self.passwords)

    def lookup(self, principal):
        return self.passwords.get(principal)


class ParseTests(unittest.TestCase):
    def test_caches_and_tickets(self):
        alice, bob = kerberus.parse_klist(KLIST)
        self.assertEqual(alice.name, "DIR::/tmp/krbdir/tkt")
        self.assertEqual(alice.principal, "alice@EXAMPLE.TEST")
        self.assertEqual(alice.tgt.expires, dt.datetime(2026, 10, 20, 9, 49))
        self.assertEqual(alice.tgt.renew_until, dt.datetime(2026, 10, 26, 23, 48, 48))
        self.assertEqual(alice.tgt.flags, "FRIT")
        self.assertEqual([t.service for t in alice.services], ["host/svc.example.test@EXAMPLE.TEST"])
        self.assertIsNone(bob.tgt.renew_until)
        self.assertEqual(bob.tgt.flags, "FI")

    def test_empty_and_garbage(self):
        self.assertEqual(kerberus.parse_klist(""), [])
        self.assertEqual(kerberus.parse_klist("klist: No credentials cache found (filename: /tmp/x)\n"), [])

    def test_cache_without_tickets_is_kept(self):
        caches = kerberus.parse_klist("Ticket cache: FILE:/tmp/x\nDefault principal: a@R\n\n")
        self.assertEqual(len(caches), 1)
        self.assertIsNone(caches[0].tgt)
        self.assertEqual(caches[0].state(NOW), "expired")

    def test_tgt_prefers_own_realm(self):
        text = KLIST.replace("10/19/26 23:50:00  10/20/26 09:49:00  host/svc.example.test@EXAMPLE.TEST",
                             "10/19/26 23:50:00  10/20/26 09:49:00  krbtgt/OTHER.TEST@EXAMPLE.TEST")
        alice = kerberus.parse_klist(text)[0]
        self.assertEqual(alice.tgt.service, "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST")


class StateTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = kerberus.parse_klist(KLIST)

    def test_states(self):
        self.assertEqual(self.alice.state(NOW), "valid")
        self.assertEqual(self.alice.state(dt.datetime(2026, 10, 20, 9, 40)), "expiring")
        self.assertEqual(self.alice.state(dt.datetime(2026, 10, 20, 10, 0)), "expired")

    def test_can_renew(self):
        self.assertTrue(self.alice.can_renew(NOW))
        self.assertFalse(self.bob.can_renew(NOW))  # no renew-until, not R
        self.assertFalse(self.alice.can_renew(dt.datetime(2026, 10, 27)))  # past renew-until
        self.alice.tgt.expires = self.alice.tgt.renew_until  # renewing gains nothing
        self.assertFalse(self.alice.can_renew(NOW))

    def test_json(self):
        data = self.alice.to_json(NOW)
        self.assertEqual(data["state"], "valid")
        self.assertTrue(data["renewable"])
        self.assertEqual(data["tickets"][0]["expires"], "2026-10-20T09:49:00")


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = kerberus.parse_klist(KLIST)

    def test_not_yet(self):
        self.assertIsNone(kerberus.renewal_action(self.alice, SETTINGS, dt.datetime(2026, 10, 20, 8, 0), False))

    def test_renew_inside_window(self):
        self.assertEqual(kerberus.renewal_action(self.alice, SETTINGS, NOW, False), "renew")

    def test_renew_off(self):
        settings = dict(SETTINGS, auto_renew=False)
        self.assertIsNone(kerberus.renewal_action(self.alice, settings, NOW, False))

    def test_sign_in_when_not_renewable(self):
        self.assertIsNone(kerberus.renewal_action(self.bob, SETTINGS, NOW, False))
        self.assertEqual(kerberus.renewal_action(self.bob, SETTINGS, NOW, True), "sign-in")
        self.assertIsNone(kerberus.renewal_action(self.bob, dict(SETTINGS, reacquire=False), NOW, True))

    def test_short_tickets_renew_half_way(self):
        t = self.alice.tgt
        t.starts, t.expires = NOW, NOW + dt.timedelta(minutes=20)
        self.assertIsNone(kerberus.renewal_action(self.alice, SETTINGS, NOW + dt.timedelta(minutes=9), False))
        self.assertEqual(kerberus.renewal_action(self.alice, SETTINGS, NOW + dt.timedelta(minutes=11), False), "renew")

    def test_maintain_does_not_retry_rejected_password(self):
        calls = []
        original = kerberus.get_ticket
        kerberus.get_ticket = lambda *a, **k: calls.append(a) or kerberus.Result(False, "Password incorrect")
        try:
            failed = set()
            keyring = FakeKeyring({"bob@EXAMPLE.TEST": "wrong"})
            notices = kerberus.maintain([self.bob], SETTINGS, keyring, NOW, log=lambda m: None, failed=failed)
            self.assertEqual(failed, {"bob@EXAMPLE.TEST"})
            self.assertEqual(notices[0][2], ("rejected", "bob@EXAMPLE.TEST"))
            kerberus.maintain([self.bob], SETTINGS, keyring, NOW, log=lambda m: None, failed=failed)
            self.assertEqual(len(calls), 1)
        finally:
            kerberus.get_ticket = original

    def test_maintain_warns_before_expiry(self):
        soon = dt.datetime(2026, 10, 20, 9, 40)
        notices = kerberus.maintain([self.bob], SETTINGS, FakeKeyring({}), soon, log=lambda m: None)
        self.assertEqual(len(notices), 1)
        self.assertIn("expires in 9 min", notices[0][1])
        self.assertEqual(kerberus.maintain([self.bob], dict(SETTINGS, notify=False), None, soon, log=print), [])


class TextTests(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(kerberus.fmt_duration(30), "less than a minute")
        self.assertEqual(kerberus.fmt_duration(45 * 60), "45 min")
        self.assertEqual(kerberus.fmt_duration(3600), "1 h")
        self.assertEqual(kerberus.fmt_duration(9 * 3600 + 59 * 60), "9 h 59 min")
        self.assertEqual(kerberus.fmt_duration(7 * 86400), "7 days")

    def test_when(self):
        self.assertEqual(kerberus.fmt_when(dt.datetime(2026, 10, 20, 9, 49), NOW), "09:49")
        self.assertEqual(kerberus.fmt_when(dt.datetime(2026, 10, 21, 1, 0), NOW), "tomorrow 01:00")
        self.assertEqual(kerberus.fmt_when(dt.datetime(2026, 11, 30, 1, 0), NOW), "Nov 30, 01:00")

    def test_tool_messages(self):
        def proc(out, err, rc=1):
            return subprocess.CompletedProcess(["/usr/bin/kinit"], rc, out, err)
        self.assertEqual(kerberus.tool_message(proc(
            "Password for alice@EXAMPLE.TEST: \n",
            "kinit: Password incorrect while getting initial credentials\n")), "Password incorrect")
        self.assertEqual(kerberus.tool_message(proc(
            "Password for carol@EXAMPLE.TEST: \nEnter new password: \nEnter it again: \n"
            "Password change rejected: New password is too short.\n"
            "Please choose a password which is at least 8 characters long.\n", "", 2)),
            "Password change rejected: New password is too short. "
            "Please choose a password which is at least 8 characters long.")
        expired = kerberus.result_of(proc(
            "Password for carol@EXAMPLE.TEST: \nPassword expired.  You must change it now.\nEnter new password: \n",
            "kinit: Cannot read password while getting initial credentials\n"))
        self.assertTrue(expired.password_expired)

    def test_desktop_quote(self):
        self.assertEqual(kerberus.desktop_quote("/opt/Kerberus.AppImage"), "/opt/Kerberus.AppImage")
        self.assertEqual(kerberus.desktop_quote("/home/a b/K$.AppImage"), '"/home/a b/K\\$.AppImage"')

    def test_full_principal(self):
        original = kerberus.default_realm
        kerberus.default_realm = lambda: "EXAMPLE.TEST"
        try:
            self.assertEqual(kerberus.full_principal("alice"), "alice@EXAMPLE.TEST")
            self.assertEqual(kerberus.full_principal("bob@OTHER"), "bob@OTHER")
        finally:
            kerberus.default_realm = original


if __name__ == "__main__":
    unittest.main()
