#!/usr/bin/env python3
"""
curiosity-ctf — challenge builder
run on Kali Linux to generate challenge files from a local secret config.
"""

import os
import sys
import struct
import base64
import hashlib
import json
import zipfile
import subprocess
import tempfile
import random
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image

OUT = "challenge/files"
os.makedirs(OUT, exist_ok=True)

print("[*] building curiosity-ctf...")


# ── internal helpers ──────────────────────────────────────────
# all sensitive values are loaded from a local secret file that is excluded
# from version control.

_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _die(msg):
    print(f"[!] {msg}")
    sys.exit(1)


def _validate_flag(flag):
    if not isinstance(flag, str):
        _die("flag must be a string")
    if not re.fullmatch(r"FLAG\{[a-z0-9_]{8,64}\}", flag):
        _die("flag must match FLAG{lowercase_letters_numbers_underscores}")
    if len(flag) < 10:
        _die("flag is too short")


def _validate_parts(parts):
    if not isinstance(parts, list) or len(parts) != 6:
        _die("parts must be a list with exactly 6 values")
    for idx, part in enumerate(parts, start=1):
        if not isinstance(part, str) or not part.strip():
            _die(f"part {idx} must be a non-empty string")
        if "|" in part:
            _die(f"part {idx} may not contain '|'")


def _load_secret_config():
    path = os.environ.get("CTF_SECRET_FILE", ".secrets/challenge_secret.json")
    if not os.path.isfile(path):
        _die(
            "missing secret config: "
            f"{path}\n"
            "create it from challenge_secret.example.json and keep it private"
        )

    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    flag = cfg.get("flag")
    parts = cfg.get("parts")
    _validate_flag(flag)
    _validate_parts(parts)
    return flag, parts


def _derive_key(parts):
    raw = "|".join(parts)
    return hashlib.pbkdf2_hmac(
        "sha256",
        raw.encode("utf-8"),
        b"curiosity-ctf-v2-kdf",
        240000,
        dklen=32,
    )


def _build_alt_alphabet(parts):
    seed = hashlib.sha256(("|".join(parts) + "|alphabet").encode("utf-8")).digest()
    rng = random.Random(int.from_bytes(seed[:8], "big"))
    chars = list(_STD_B64)
    rng.shuffle(chars)
    return "".join(chars)


def _tmp_path(name):
    return os.path.join(tempfile.gettempdir(), name)


FLAG, PARTS = _load_secret_config()
P1, P2, P3, P4, P5, P6 = PARTS
ALT_B64 = _build_alt_alphabet(PARTS)


# ── step 7: encrypted flag ────────────────────────────────────
_key = _derive_key(PARTS)
_cph  = AES.new(_key, AES.MODE_CBC)
_ct   = _cph.encrypt(pad(FLAG.encode(), AES.block_size))
with open(f"{OUT}/final.enc", "wb") as f:
    f.write(b"CTF2" + _cph.iv + _ct)
print("[+] final.enc written")
del _key, _cph, _ct


# ── step 6: pcap with hidden payload ─────────────────────────
_xk6 = hashlib.sha256((P2 + "|pcap").encode("utf-8")).digest()[0]
_payload = bytes([b ^ _xk6 for b in P6.encode()])

def _pcap_global_header():
    return (struct.pack("<I", 0xa1b2c3d4) + struct.pack("<H", 2) +
            struct.pack("<H", 4) + struct.pack("<i", 0) +
            struct.pack("<I", 0) + struct.pack("<I", 65535) +
            struct.pack("<I", 1))

def _eth_ip_tcp():
    eth = bytes([0xff]*6 + [0x00]*6 + [0x08, 0x00])
    ip  = bytes([0x45,0x00,0x00,0x28,0x00,0x01,0x40,0x00,
                 0x40,0x06,0x00,0x00,0x7f,0x00,0x00,0x01,
                 0x7f,0x00,0x00,0x01])
    tcp = bytes([0x00,0x50,0x1f,0x90]+[0x00]*8+
                [0x50,0x18,0x20,0x00,0x00,0x00,0x00,0x00])
    return eth + ip + tcp

def _packet_record(ts, data):
    return (struct.pack("<I", ts) + struct.pack("<I", 0) +
            struct.pack("<I", len(data)) + struct.pack("<I", len(data)) + data)

_decoy = _eth_ip_tcp() + b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" * 3
_real  = _eth_ip_tcp() + _payload

with open(f"{OUT}/capture.pcap", "wb") as f:
    f.write(_pcap_global_header())
    for _ in range(5):
        f.write(_packet_record(1700000000, _decoy))
    f.write(_packet_record(1700000001, _real))
    for _ in range(3):
        f.write(_packet_record(1700000000, _decoy))
print("[+] capture.pcap written")


# ── step 5: LSB steganography ─────────────────────────────────
def _lsb_encode(src, secret, dst):
    img  = Image.open(src).convert("RGB")
    px   = list(img.getdata())
    bits = ''.join(format(b, '08b') for b in secret.encode()) + '00000000' * 4
    out, i = [], 0
    for r, g, b in px:
        if i < len(bits): r = (r & ~1) | int(bits[i]); i += 1
        if i < len(bits): g = (g & ~1) | int(bits[i]); i += 1
        if i < len(bits): b = (b & ~1) | int(bits[i]); i += 1
        out.append((r, g, b))
    img2 = Image.new("RGB", img.size)
    img2.putdata(out)
    img2.save(dst)

_tmp = f"{OUT}/_tmp.png"
_base = Image.new("RGB", (256, 256))
_base.putdata([((x+y)%256, (x*2)%256, (y*3)%256)
               for y in range(256) for x in range(256)])
_base.save(_tmp)
_lsb_encode(_tmp, P5, f"{OUT}/noise.png")
os.remove(_tmp)
print("[+] noise.png written")


# ── step 4: weak RSA ─────────────────────────────────────────
try:
    from sympy import nextprime
    _p  = nextprime(2**256 + random.randint(0, 1000))
    _q  = nextprime(_p + random.randint(2, 100))
    _n  = _p * _q
    _e  = 65537
    _m  = int.from_bytes(P4.encode(), 'big')
    _c  = pow(_m, _e, _n)
    with open(f"{OUT}/rsa_challenge.txt", "w") as f:
        f.write(f"n = {_n}\ne = {_e}\nc = {_c}\n")
    print("[+] rsa_challenge.txt written")
    del _p, _q, _m, _c
except ImportError:
    print("[!] sympy not found — install with: pip3 install sympy")
    sys.exit(1)


# ── step 3: custom base64 ────────────────────────────────────
_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_ALT = ALT_B64
_enc = base64.b64encode(P3.encode()).decode().translate(str.maketrans(_STD, _ALT))
with open(f"{OUT}/encoded.txt", "w") as f:
    f.write(_enc + "\n")
print("[+] encoded.txt written")


# ── step 2: ELF binary ───────────────────────────────────────
_XOR2 = hashlib.sha256((P1 + "|bin").encode("utf-8")).digest()[0]
_arr  = ", ".join(f"0x{b ^ _XOR2:02x}" for b in P2.encode())

_hi = (_XOR2 >> 4) & 0x0F
_lo = _XOR2 & 0x0F

_src = f"""#include <stdio.h>
#include <string.h>

static volatile unsigned char a[] = {{ {_arr} }};

static unsigned char get_k(void) {{
    unsigned char hi = 0x{_hi:02x};
    unsigned char lo = 0x{_lo:02x};
    return (hi << 4) | lo;
}}

int check(const char *input) {{
    unsigned char k = get_k();
    char buf[16];
    for (int i = 0; i < (int)sizeof(a); i++)
        buf[i] = a[i] ^ k;
    buf[sizeof(a)] = 0;
    return strcmp(input, buf) == 0;
}}

int main(int argc, char *argv[]) {{
    if (argc < 2) {{
        printf("usage: ./keyfrag <key>\\n");
        return 1;
    }}
    printf(check(argv[1]) ? "correct\\n" : "wrong\\n");
    return 0;
}}
"""

_tmp_c = _tmp_path("_kf.c")
with open(_tmp_c, "w") as f:
    f.write(_src)
try:
    _r = subprocess.run(
        ["gcc", "-o", f"{OUT}/keyfrag", _tmp_c, "-s", "-O1"],
        capture_output=True
    )
except FileNotFoundError:
    os.remove(_tmp_c)
    _die("gcc not found. install gcc (or build on Kali Linux) to create keyfrag")

os.remove(_tmp_c)
if _r.returncode == 0:
    print("[+] keyfrag compiled")
else:
    print(f"[!] gcc failed: {_r.stderr.decode()}")
    sys.exit(1)


# ── step 1: hidden zip in log file ───────────────────────────
_zip_path = _tmp_path("_inner.zip")
with zipfile.ZipFile(_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(
        "note.txt",
        "\n".join([
            "part1: " + P1,
            "alphabet: " + _ALT,
            "hint: alphabet remaps standard base64 before decode",
            "",
        ]),
    )

with open(f"{OUT}/system.log", "wb") as f:
    f.write(
        b"[2026-01-01 00:00:00] system started\n"
        b"[2026-01-01 00:00:01] loading modules\n"
        b"[2026-01-01 00:00:02] all systems nominal\n"
        b"[2026-01-01 00:00:03] ready\n"
    )
    with open(_zip_path, "rb") as z:
        f.write(z.read())
os.remove(_zip_path)
print("[+] system.log written")


# ── done ─────────────────────────────────────────────────────
print()
print("[+] all files written to ./challenge/files/")
print("[+] never commit .secrets/challenge_secret.json")
