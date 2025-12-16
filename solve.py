#!/usr/bin/env python3
import requests
import binascii

BASE = "http://crypto-keygen-ii.chals.blahaj.sg"

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

def get_trial_key():
    """Call /api/generate_key and return iv and ciphertext blocks."""
    r = requests.get(BASE + "/api/generate_key")
    data = r.json()
    hex_key = data["key"]
    raw = bytes.fromhex(hex_key)

    iv = raw[:16]
    c1 = raw[16:32]
    c2 = raw[32:48]   # we may or may not use this later

    print(f"[+] Got trial key")
    print(f"    IV  = {iv.hex()}")
    print(f"    C1  = {c1.hex()}")
    print(f"    C2  = {c2.hex()}")

    return iv, c1, c2

def sanity_ping():
    """Check that the server is reachable."""
    r = requests.get(BASE + "/api/ping")
    print("[+] Ping:", r.text)

def check_key(hex_key: str):
    """Send a key to /api/check/<key> and print the response."""
    url = BASE + "/api/check/" + hex_key
    r = requests.get(url)
    print("[+] Check response:", r.text)

def main():
    sanity_ping()

    # 1. Get a trial key (IV || C1 || C2 || ...)
    iv, c1, c2 = get_trial_key()

    # 2. Define the target admin string and split into two 16‑byte blocks
    admin = b"v@l1d_adm1n_k3y_thatimadesure_is2blocks+long_:)"
    a1 = admin[:16]
    a2 = admin[16:32]
    print(f"[+] Admin block 1: {a1}")
    print(f"[+] Admin block 2: {a2}")

    # 3. PLACEHOLDER: here is where we will do the CBC block‑twisting math.
    # Right now this just reuses the original iv and c1 so you can see
    # that the /api/check endpoint responds.

    forged_iv = iv      # TODO: compute a new IV that forces block 1 to a1
    forged_c1 = c1      # TODO: optionally modify to control block 2

    forged = forged_iv + forged_c1
    hex_forged = forged.hex()

    print(f"[+] Forged key (WIP): {hex_forged}")
    check_key(hex_forged)

if __name__ == "__main__":
    main()
