#!/usr/bin/env python3
"""Plays an app doing NTLM through Kerberus's ntlm_auth helper, the way Firefox
does, and checks the answer against the password the server knows.

    tests/ntlm_client.py PATH/TO/ntlm_auth PASSWORD [SECONDS]

Prints "ntlm ok as DOMAIN\\user" when the AUTHENTICATE message proves the
password (and its MIC checks out), else what went wrong, with exit code 1. Also
imported by test_kerberus.py for its verifier."""

import base64
import hmac
import hashlib
import importlib.util
import os
import secrets
import struct
import subprocess
import sys
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("kerberus", Path(__file__).resolve().parent.parent / "kerberus.py")
kerberus = sys.modules.get("kerberus")
if kerberus is None:
    kerberus = importlib.util.module_from_spec(spec)
    sys.modules["kerberus"] = kerberus
    spec.loader.exec_module(kerberus)


def hmac_md5(key, data):
    return hmac.new(key, data, hashlib.md5).digest()


def make_challenge(server_challenge=None, target="SERVER", domain="CORP", timestamp=True, flags=0xE28A8205):
    """A CHALLENGE message like a Windows server's: target info with the names and, usually, a timestamp."""
    server_challenge = server_challenge or secrets.token_bytes(8)
    pairs = [(2, domain.encode("utf-16-le")), (1, target.encode("utf-16-le")),
             (4, domain.lower().encode("utf-16-le")), (3, f"{target.lower()}.{domain.lower()}".encode("utf-16-le"))]
    if timestamp:
        pairs.append((7, kerberus.filetime(time.time())))
    info = b"".join(struct.pack("<HH", i, len(v)) + v for i, v in pairs) + struct.pack("<HH", 0, 0)
    name = target.encode("utf-16-le")
    return (kerberus.NTLMSSP + struct.pack("<I", 2) + struct.pack("<HHI", len(name), len(name), 56)
            + struct.pack("<I", flags) + server_challenge + b"\0" * 8
            + struct.pack("<HHI", len(info), len(info), 56 + len(name)) + kerberus.NTLM_VERSION_FIELD + name + info)


def field(raw, offset):
    length, _, start = struct.unpack_from("<HHI", raw, offset)
    return raw[start:start + length]


def verify(negotiate, challenge, authenticate, password):
    """Check an AUTHENTICATE message the way the server would, knowing the
    password: the NTLMv2 proof, the LM response and the MIC. Returns (user, domain)."""
    assert authenticate[:12] == kerberus.NTLMSSP + struct.pack("<I", 3), "not an AUTHENTICATE message"
    lm, nt = field(authenticate, 12), field(authenticate, 20)
    domain, user = field(authenticate, 28).decode("utf-16-le"), field(authenticate, 36).decode("utf-16-le")
    flags, = struct.unpack_from("<I", authenticate, 60)
    assert flags & kerberus.NTLM_UNICODE and flags & kerberus.NTLM_NTLM, f"flags {flags:#x}"
    server_challenge = challenge[24:32]
    key = kerberus.ntowf_v2(user, domain, password)
    proof, temp = nt[:16], nt[16:]
    assert hmac_md5(key, server_challenge + temp) == proof, "the NTLMv2 proof doesn't match the password"
    assert temp[:2] == b"\x01\x01" and len(temp) > 44, "bad NTLMv2 blob"
    client_challenge = temp[16:24]
    if lm != b"\0" * 24:
        assert lm == hmac_md5(key, server_challenge + client_challenge) + client_challenge, "bad LMv2 response"
    av_flags = 0
    pos = 28
    while pos + 4 <= len(temp):
        av_id, av_len = struct.unpack_from("<HH", temp, pos)
        if av_id == 0:
            break
        if av_id == 6:
            av_flags, = struct.unpack("<I", temp[pos + 4:pos + 8])
        pos += 4 + av_len
    if av_flags & 2:
        session_key = hmac_md5(key, proof)
        mic = authenticate[72:88]
        expected = hmac_md5(session_key, negotiate + challenge + authenticate[:72] + b"\0" * 16 + authenticate[88:])
        assert hmac.compare_digest(mic, expected), "the MIC doesn't check out"
    return user, domain


def talk(helper, password, timeout=60, args=("--helper-protocol", "ntlmssp-client-1", "--use-cached-creds",
                                              "--username", os.environ.get("USER", "someone"))):
    """Run the helper like Firefox: YR, then TT with a challenge; wait for AF."""
    proc = subprocess.Popen([str(helper), *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        proc.stdin.write(b"YR\n")
        proc.stdin.flush()
        line = proc.stdout.readline().decode()
        if not line.startswith("YR "):
            return f"no NEGOTIATE message: {line.strip()!r}"
        negotiate = base64.b64decode(line[3:])
        challenge = make_challenge()
        proc.stdin.write(b"TT " + base64.b64encode(challenge) + b"\n")
        proc.stdin.flush()
        deadline = time.time() + timeout
        line = ""
        while time.time() < deadline and not line:
            line = proc.stdout.readline().decode()
            if proc.poll() is not None and not line:
                return "the helper exited"
        if not (line.startswith("AF ") or line.startswith("KK ")):
            return f"no AUTHENTICATE message: {line.strip()!r}"
        user, domain = verify(negotiate, challenge, base64.b64decode(line[3:]), password)
        return f"ntlm ok as {domain}\\{user}"
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)
        proc.stdout.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        outcome = talk(sys.argv[1], sys.argv[2], float(sys.argv[3]) if len(sys.argv) > 3 else 60)
    except AssertionError as e:
        outcome = f"bad answer: {e}"
    print(outcome, flush=True)
    sys.exit(0 if outcome.startswith("ntlm ok") else 1)
