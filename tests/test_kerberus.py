"""Unit tests for the parts of Kerberus that don't need a KDC: klist parsing,
renewal decisions and message cleanup. tests/integration.sh covers the rest."""

import base64
import datetime as dt
import importlib.util
import os
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("kerberus", Path(__file__).resolve().parent.parent / "kerberus.py")
kerberus = importlib.util.module_from_spec(spec)
sys.modules["kerberus"] = kerberus
spec.loader.exec_module(kerberus)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ntlm_client  # noqa: E402  (the verifier shared with prompt_e2e.sh)

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

    def test_program_names(self):
        self.assertEqual(kerberus.program_name("/usr/bin/kdestroy.mit"), "kdestroy")
        self.assertEqual(kerberus.program_name("/nix/store/x-firefox/bin/.firefox-wrapped"), "firefox")
        self.assertEqual(kerberus.program_name("/opt/google/chrome/chrome"), "chrome")

    def test_full_principal(self):
        original = kerberus.default_realm
        kerberus.default_realm = lambda: "EXAMPLE.TEST"
        try:
            self.assertEqual(kerberus.full_principal("alice"), "alice@EXAMPLE.TEST")
            self.assertEqual(kerberus.full_principal("bob@OTHER"), "bob@OTHER")
        finally:
            kerberus.default_realm = original


def counted(data):
    return struct.pack(">I", len(data)) + data


def principal(name):
    """A principal in the v4 ccache layout."""
    parts, _, realm = name.rpartition("@")
    comps = parts.split("/")
    return struct.pack(">II", 1, len(comps)) + counted(realm.encode()) + b"".join(counted(c.encode()) for c in comps)


def cred(client, server, end, ticket=b"ticket"):
    now = int(time.time())
    return (principal(client) + principal(server) + struct.pack(">H", 18) + counted(b"k" * 32)
            + struct.pack(">IIII", now, now, end, end + 3600) + b"\0" + struct.pack(">III", 0, 0, 0)
            + counted(ticket) + counted(b""))


def request(*parts):
    return kerberus.KcmReader(b"".join(p if isinstance(p, bytes) else p.encode() + b"\0" for p in parts))


class KcmStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.store = kerberus.KcmStore(Path(self.dir.name) / "caches.json", uid=1000)
        self.later = int(time.time()) + 3600

    def tearDown(self):
        self.dir.cleanup()

    def call(self, op, *parts):
        return self.store.handle(op, request(*parts))

    def sign_in(self, name="1000", who="alice@R", end=None):
        self.assertEqual(self.call(kerberus.KCM_OP_INITIALIZE, name, principal(who))[0], 0)
        self.assertEqual(self.call(kerberus.KCM_OP_STORE, name, cred(who, "krbtgt/R@R", end or self.later))[0], 0)

    def test_empty(self):
        self.assertEqual(self.call(kerberus.KCM_OP_GET_DEFAULT_CACHE), (0, b"1000\0"))
        self.assertEqual(self.call(kerberus.KCM_OP_GET_PRINCIPAL, "1000")[0], kerberus.KRB5_FCC_NOFILE)
        self.assertEqual(self.call(kerberus.KCM_OP_GET_CACHE_UUID_LIST)[0], kerberus.KRB5_FCC_NOFILE)
        self.assertTrue(self.store.needs_sign_in())
        self.assertTrue(self.store.needs_sign_in("1000"))

    def test_sign_in_and_list(self):
        self.sign_in()
        self.assertEqual(self.call(kerberus.KCM_OP_GET_PRINCIPAL, "1000"), (0, principal("alice@R")))
        self.assertFalse(self.store.needs_sign_in("1000"))
        self.assertFalse(self.store.needs_sign_in())
        self.call(kerberus.KCM_OP_STORE, "1000", cred("alice@R", "HTTP/web@R", self.later))
        status, reply = self.call(kerberus.KCM_OP_GET_CRED_LIST, "1000")
        r = kerberus.KcmReader(reply)
        creds = [kerberus.KcmCred.parse(r.counted()) for _ in range(r.u32())]
        self.assertEqual([c.server for c in creds], ["krbtgt/R@R", "HTTP/web@R"])
        uuids = self.call(kerberus.KCM_OP_GET_CRED_UUID_LIST, "1000")[1]
        self.assertEqual(len(uuids), 32)
        self.assertEqual(self.call(kerberus.KCM_OP_GET_CRED_BY_UUID, "1000", uuids[16:])[1], creds[1].raw)

    def test_newer_ticket_replaces_older(self):
        self.sign_in()
        self.call(kerberus.KCM_OP_STORE, "1000", cred("alice@R", "HTTP/web@R", self.later, b"old"))
        self.call(kerberus.KCM_OP_STORE, "1000", cred("alice@R", "HTTP/web@R", self.later + 60, b"new"))
        cache = self.store.caches["1000"]
        self.assertEqual(len(cache.creds), 2)
        self.assertEqual(cache.creds[-1].endtime, self.later + 60)

    def test_expired_tgt_needs_sign_in(self):
        self.sign_in(end=int(time.time()) - 10)
        self.assertTrue(self.store.needs_sign_in("1000"))
        self.assertEqual(self.store.describe(None), ("alice@R", "1000"))

    def test_collection(self):
        self.sign_in()
        name = self.call(kerberus.KCM_OP_GEN_NEW)[1].rstrip(b"\0").decode()
        self.assertTrue(name.startswith("1000:"))
        self.sign_in(name, "bob@R")
        self.call(kerberus.KCM_OP_SET_DEFAULT_CACHE, name)
        self.assertEqual(self.call(kerberus.KCM_OP_GET_DEFAULT_CACHE)[1], name.encode() + b"\0")
        uuids = self.call(kerberus.KCM_OP_GET_CACHE_UUID_LIST)[1]
        names = {self.call(kerberus.KCM_OP_GET_CACHE_BY_UUID, uuids[i:i + 16])[1] for i in (0, 16)}
        self.assertEqual(names, {b"1000\0", name.encode() + b"\0"})
        self.assertEqual(self.call(kerberus.KCM_OP_DESTROY, name)[0], 0)
        self.assertEqual(self.call(kerberus.KCM_OP_GET_PRINCIPAL, name)[0], kerberus.KRB5_FCC_NOFILE)

    def test_replace(self):
        creds = [cred("bob@R", "krbtgt/R@R", self.later), cred("bob@R", "HTTP/x@R", self.later)]
        r = request("1000", struct.pack(">i", 5), principal("bob@R"), struct.pack(">I", 2),
                    *[counted(c) for c in creds])
        self.assertEqual(self.store.handle(kerberus.KCM_OP_REPLACE, r)[0], 0)
        cache = self.store.caches["1000"]
        self.assertEqual((cache.principal_name, cache.kdc_offset, len(cache.creds)), ("bob@R", 5, 2))

    def test_saved_and_loaded(self):
        self.sign_in()
        again = kerberus.KcmStore(self.store.path, uid=1000)
        self.assertEqual(again.caches["1000"].principal_name, "alice@R")
        self.assertFalse(again.needs_sign_in("1000"))
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)

    def test_unsupported_and_malformed(self):
        self.sign_in()
        self.assertEqual(self.call(7, "1000")[0], kerberus.KRB5_CC_NOSUPP)  # RETRIEVE: the client iterates
        with self.assertRaises(ValueError):
            self.call(kerberus.KCM_OP_STORE, "1000", b"\0\0\0")

    def test_over_a_socket(self):
        path = Path(self.dir.name) / "kcm.sock"
        server = kerberus.KcmServer(self.store, path, log=lambda m: None)
        server.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(str(path))
                body = struct.pack(">BBH", 2, 0, kerberus.KCM_OP_GET_DEFAULT_CACHE)
                s.sendall(struct.pack(">I", len(body)) + body)
                length, transport, status = struct.unpack(">IIi", s.recv(12))
                self.assertEqual((transport, status), (0, 0))
                self.assertEqual(s.recv(length - 4), b"1000\0")
            with self.assertRaises(RuntimeError):  # a second server on the same socket
                kerberus.KcmServer(self.store, path).start()
        finally:
            server.stop()

    def test_socket_directory_safety(self):
        def st(uid, mode):
            return type("Stat", (), {"st_uid": uid, "st_mode": mode})()
        self.assertFalse(kerberus.others_can_replace(st(1000, 0o40700), uid=1000))  # ours
        self.assertFalse(kerberus.others_can_replace(st(0, 0o41777), uid=1000))     # /tmp: sticky
        self.assertFalse(kerberus.others_can_replace(st(0, 0o40755), uid=1000))     # nobody else writes
        self.assertTrue(kerberus.others_can_replace(st(1001, 0o40777), uid=1000))   # someone else's, open


class NtlmTests(unittest.TestCase):
    PASSWORD = "Sup3r secret pässword"

    def test_md4(self):  # RFC 1320
        for text, digest in [(b"", "31d6cfe0d16ae931b73c59d7e0c089c0"), (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
                             (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
                             (b"message digest", "d9130a8164549fe818874806e1c7014b"),
                             (b"12345678901234567890" * 4, "e33b4ddc9c38f2199c3e7b164fcc0536")]:
            self.assertEqual(kerberus.md4(text).hex(), digest)

    def test_ntlmv2_vectors(self):
        # NTOWFv2 from MS-NLMP 4.2.4; the responses as pyspnego computes them for the same inputs.
        key = kerberus.ntowf_v2("User", "Domain", "Password")
        self.assertEqual(key.hex(), "0c868a403bfd7a93a3001ef22ef02e3f")
        info = bytes.fromhex("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
        raw = (kerberus.NTLMSSP + struct.pack("<I", 2) + struct.pack("<HHI", 0, 0, 56) + struct.pack("<I", 0xE2898233)
               + bytes.fromhex("0102030405060708") + b"\0" * 8 + struct.pack("<HHI", len(info), len(info), 56)
               + kerberus.NTLM_VERSION_FIELD + info)
        challenge = kerberus.NtlmChallenge(raw)
        self.assertEqual(challenge.server_challenge.hex(), "0102030405060708")
        self.assertEqual([(i, v.decode("utf-16-le")) for i, v in challenge.pairs], [(2, "Domain"), (1, "Server")])
        self.assertIsNone(challenge.timestamp())
        client_challenge = bytes.fromhex("aa" * 8)
        temp = b"\x01\x01" + b"\0" * 14 + client_challenge + b"\0" * 4 + info + b"\0" * 4
        self.assertEqual(kerberus.hmac_md5(key, challenge.server_challenge + temp).hex(),
                         "3039a27dc6bda1b5901152cecf281414")
        self.assertEqual(kerberus.hmac_md5(key, challenge.server_challenge + client_challenge).hex(),
                         "4c645bba618a1840d1f8de1fac7dc1e4")
        # The message itself: no server timestamp, so the LMv2 response is sent.
        negotiate = kerberus.ntlm_negotiate()
        message, session_key = kerberus.ntlm_authenticate(negotiate, challenge, "User", "Domain", "Password",
                                                           "PC", client_challenge, now=-11644473600)
        self.assertEqual(ntlm_client.field(message, 12).hex(), "4c645bba618a1840d1f8de1fac7dc1e4" + "aa" * 8)
        self.assertEqual(ntlm_client.verify(negotiate, raw, message, "Password"), ("User", "Domain"))
        self.assertEqual(session_key, kerberus.hmac_md5(key, ntlm_client.field(message, 20)[:16]))

    def test_negotiate_message(self):
        message = kerberus.ntlm_negotiate()
        self.assertEqual(len(message), 40)
        self.assertEqual(message[:12], b"NTLMSSP\0\x01\0\0\0")
        flags, = struct.unpack_from("<I", message, 12)
        self.assertTrue(flags & kerberus.NTLM_UNICODE and flags & kerberus.NTLM_NTLM
                        and flags & kerberus.NTLM_EXTENDED_SESSION_SECURITY and flags & kerberus.NTLM_VERSION)

    def test_authenticate_like_a_server(self):
        negotiate = kerberus.ntlm_negotiate()
        raw = ntlm_client.make_challenge(target="ADFS1", domain="CORP")
        challenge = kerberus.NtlmChallenge(raw)
        self.assertEqual(challenge.target_name, "ADFS1")
        self.assertIsNotNone(challenge.timestamp())
        message, _ = kerberus.ntlm_authenticate(negotiate, challenge, "alice", "CORP", self.PASSWORD, "MYPC")
        self.assertEqual(ntlm_client.field(message, 12), b"\0" * 24)  # a timestamp: no LM response
        self.assertEqual(ntlm_client.field(message, 44).decode("utf-16-le"), "MYPC")
        self.assertEqual(ntlm_client.field(message, 52), b"")  # no key exchange
        self.assertEqual(ntlm_client.verify(negotiate, raw, message, self.PASSWORD), ("alice", "CORP"))
        with self.assertRaisesRegex(AssertionError, "proof"):
            ntlm_client.verify(negotiate, raw, message, "wrong")
        with self.assertRaisesRegex(AssertionError, "MIC"):
            ntlm_client.verify(negotiate, raw, message[:72] + bytes(16) + message[88:], self.PASSWORD)
        with self.assertRaises(ValueError):
            kerberus.NtlmChallenge(negotiate)

    def test_identity(self):
        self.assertEqual(kerberus.ntlm_identity("alice@CORP.EXAMPLE.COM"), ("alice", "CORP"))
        self.assertEqual(kerberus.ntlm_identity("alice@CORP.EXAMPLE.COM", "EXAMPLE"), ("alice", "EXAMPLE"))
        self.assertEqual(kerberus.ntlm_identity("bob"), ("bob", ""))
        self.assertEqual(kerberus.ntlm_identity("svc/host@R"), ("svc/host", "R"))


class NtlmHelperTests(unittest.TestCase):
    """The ntlm_auth helper Kerberus writes, talking to its server over the socket."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.runtime = Path(self.dir.name) / "run"
        self.runtime.mkdir(mode=0o700)
        self.helper = Path(self.dir.name) / "bin" / "ntlm_auth"
        kerberus.write_ntlm_helper(self.helper)
        self.asked = []
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.stop()
        self.dir.cleanup()

    def serve(self, credentials):
        self.server = kerberus.NtlmServer(credentials, self.runtime / "kerberus" / "ntlm.sock", log=lambda m: None)
        self.server.start()

    def env(self, path=""):
        return dict(os.environ, XDG_RUNTIME_DIR=str(self.runtime), PATH=path or os.environ.get("PATH", ""))

    def test_helper_is_written_once(self):
        before = self.helper.stat()
        self.assertTrue(before.st_mode & 0o111)
        kerberus.write_ntlm_helper(self.helper)
        self.assertEqual(self.helper.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.helper.read_text(), kerberus.NTLM_HELPER_SCRIPT)

    def test_firefox_exchange(self):
        def credentials(client):
            self.asked.append(client.program)
            return "alice", "CORP", NtlmTests.PASSWORD
        self.serve(credentials)
        os.environ["XDG_RUNTIME_DIR"] = str(self.runtime)  # for ntlm_client.talk's subprocess
        try:
            outcome = ntlm_client.talk(self.helper, NtlmTests.PASSWORD, timeout=10)
        finally:
            os.environ.pop("XDG_RUNTIME_DIR", None)
        self.assertEqual(outcome, "ntlm ok as CORP\\alice")
        self.assertTrue(self.asked and self.asked[0].startswith("python"), self.asked)  # the helper's parent

    def test_no_credentials_and_bad_input(self):
        self.serve(lambda client: None)
        challenge = base64.b64encode(ntlm_client.make_challenge()).decode()
        proc = subprocess.run([str(self.helper), "--helper-protocol", "ntlmssp-client-1"], env=self.env(),
                              input=f"TT {challenge}\nYR\nTT {challenge}\nTT nonsense!\nXX\nPW secret\n",
                              capture_output=True, text=True, timeout=20)
        lines = proc.stdout.splitlines()
        self.assertEqual(lines[0], "BH no NEGOTIATE yet")
        self.assertTrue(lines[1].startswith("YR "), lines)
        self.assertEqual(lines[2], "BH no credentials")
        self.assertTrue(lines[3].startswith("BH "), lines)
        self.assertEqual(lines[4:], ["BH unknown command", "OK"])

    def test_hands_over_without_kerberus(self):
        real = Path(self.dir.name) / "real" / "ntlm_auth"
        real.parent.mkdir()
        real.write_text("#!/bin/sh\necho \"REAL $*\"\n")
        real.chmod(0o755)
        path = f"{self.helper.parent}:{real.parent}:{os.environ.get('PATH', '')}"
        proc = subprocess.run(["ntlm_auth", "--helper-protocol=ntlmssp-client-1", "--username", "u"],
                              env=self.env(path), input="YR\n", capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.stdout, "REAL --helper-protocol=ntlmssp-client-1 --username u\n")
        # Another helper protocol goes to the real one even while Kerberus serves.
        self.serve(lambda client: None)
        proc = subprocess.run(["ntlm_auth", "--helper-protocol", "squid-2.5-basic"],
                              env=self.env(path), input="", capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.stdout, "REAL --helper-protocol squid-2.5-basic\n")
        # No real one: say so in the protocol.
        self.server.stop()
        self.server = None
        python = Path(self.dir.name) / "python"  # a PATH with python3 but no other ntlm_auth
        python.mkdir()
        (python / "python3").symlink_to(sys.executable)
        proc = subprocess.run([str(self.helper), "--helper-protocol", "ntlmssp-client-1"],
                              env=self.env(f"{self.helper.parent}:{python}"), input="YR\n", capture_output=True,
                              text=True, timeout=20)
        self.assertEqual((proc.returncode, proc.stdout), (1, "BH Kerberus isn't running\n"))

    def test_waits_for_credentials(self):
        """The TT request holds the connection until credentials come (the sign-in prompt)."""
        ready = threading.Event()

        def credentials(client):
            ready.wait(10)
            return "bob", "CORP", "pw"
        self.serve(credentials)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(str(self.runtime / "kerberus" / "ntlm.sock"))
            s.sendall(b"YR\n")
            f = s.makefile("rb")
            negotiate = base64.b64decode(f.readline()[3:])
            raw = ntlm_client.make_challenge()
            s.sendall(b"TT " + base64.b64encode(raw) + b"\n")
            s.settimeout(0.5)
            with self.assertRaises(TimeoutError):
                s.recv(1)
            s.settimeout(10)
            ready.set()
            line = f.readline()
            self.assertTrue(line.startswith(b"AF "), line)
            self.assertEqual(ntlm_client.verify(negotiate, raw, base64.b64decode(line[3:]), "pw"), ("bob", "CORP"))


class SessionSetupTests(unittest.TestCase):
    def test_environment_file_names_the_helper(self):
        with tempfile.TemporaryDirectory() as d:
            saved = kerberus.ENVIRONMENT_D, kerberus.KCM_KRB5_CONF, kerberus.NTLM_HELPER, kerberus.HELPER_DIR
            run, which, write_helper = subprocess.run, kerberus.shutil.which, kerberus.write_ntlm_helper
            try:
                kerberus.shutil.which = lambda name: f"/usr/bin/{name}"
                kerberus.HELPER_DIR = Path(d) / "bin"
                kerberus.NTLM_HELPER = kerberus.HELPER_DIR / "ntlm_auth"
                kerberus.ENVIRONMENT_D = Path(d) / "environment.d" / "60-kerberus.conf"
                kerberus.KCM_KRB5_CONF = Path(d) / "krb5.conf"
                kerberus.write_ntlm_helper = lambda path=None: Path(d, "bin").mkdir(exist_ok=True)
                commands, session = [], {"PATH": "/usr/local/bin:/usr/bin"}

                def run(argv, **kw):  # the systemd user manager's environment, quoted as systemctl prints it
                    commands.append(argv)
                    if argv[:3] == ["systemctl", "--user", "set-environment"]:
                        session.update(a.partition("=")[::2] for a in argv[3:])
                    shown = "\n".join(f"{k}={shlex.quote(v)}" for k, v in session.items())
                    return type("P", (), {"returncode": 0, "stdout": shown})()
                kerberus.subprocess.run = run
                kerberus.set_session_kcm(True)
                text = kerberus.ENVIRONMENT_D.read_text()
                self.assertIn("KRB5CCNAME=KCM:\n", text)
                self.assertIn(f"PATH={d}/bin${{PATH:+:$PATH}}\n", text)
                self.assertTrue(kerberus.session_setup_current())
                self.assertEqual(session["PATH"], f"{d}/bin:/usr/local/bin:/usr/bin")
                kerberus.set_session_kcm(True)  # again: the directory isn't added twice
                self.assertEqual(session["PATH"], f"{d}/bin:/usr/local/bin:/usr/bin")
                kerberus.set_session_kcm(False)
                self.assertFalse(kerberus.ENVIRONMENT_D.exists())
                self.assertFalse(kerberus.session_setup_current())
                self.assertEqual(session["PATH"], "/usr/local/bin:/usr/bin")
                self.assertIn(["systemctl", "--user", "unset-environment", "KRB5CCNAME", "KRB5_CONFIG"], commands)
                done = len(commands)
                kerberus.set_session_kcm(False)  # nothing of ours left in PATH: leave it alone
                self.assertFalse(any("PATH=" in a for c in commands[done:] for a in c), commands[done:])
            finally:
                kerberus.subprocess.run, kerberus.shutil.which, kerberus.write_ntlm_helper = run, which, write_helper
                kerberus.ENVIRONMENT_D, kerberus.KCM_KRB5_CONF, kerberus.NTLM_HELPER, kerberus.HELPER_DIR = saved


if __name__ == "__main__":
    unittest.main()
