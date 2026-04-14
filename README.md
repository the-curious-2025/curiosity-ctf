# curiosity-ctf

A multi-layer CTF challenge. Seven steps, one flag.

No hints. No handholding. Figure it out.

This repository now uses a private secret config so the flag and key parts are
never stored in tracked source code.

---

## Setup

**Requirements (Kali Linux)**

```
sudo apt install binwalk steghide radare2 wireshark python3-pip gcc -y
pip3 install pycryptodome pillow sympy
```

Create your local secret config (do not commit it):

```bash
mkdir -p .secrets
cp challenge_secret.example.json .secrets/challenge_secret.json
```

Edit `.secrets/challenge_secret.json` and set:

- `flag` to a new value (rotate after any suspected leak)
- `parts` to six non-empty strings

**Build the challenge**

```
python3 build_challenge.py
```

This generates all challenge files under `challenge/files/`.

---

## The Challenge

You have six files:

```
challenge/files/
├── system.log
├── keyfrag
├── encoded.txt
├── rsa_challenge.txt
├── noise.png
├── capture.pcap
└── final.enc
```

Somewhere across all of them is everything you need to decrypt `final.enc`.

The flag format is: `FLAG{...}`

`final.enc` format:

- bytes 0..3: ASCII magic `CTF2`
- bytes 4..19: AES-CBC IV
- bytes 20..N: ciphertext

---

## Steps

There are seven steps. Each one gives you a piece. You need all of them.

What tools you use is your problem.

---

## Notes

- Designed for Kali Linux. Most tools are pre-installed.
- Step 2 requires actual reverse engineering of an ELF binary.
- Step 4 requires breaking RSA — look at the parameters carefully.
- Step 6 is a pcap. Not everything in it is relevant.
- The final key is derived from all six parts combined via PBKDF2-HMAC-SHA256.
- Reading `build_challenge.py` should not reveal the flag or the six parts.

---

This project kept me up more nights than I'd like to admit — staring at the screen, debugging, rebuilding.
Worth it.
