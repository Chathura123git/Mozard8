"""
cipher.py - a simple custom symmetric cipher for a classroom demo.

NOT secure for real use. It is a homemade design meant to show how
encryption and decryption work.

How it works (per byte, position i):
  1. SHIFT:  add the key byte and the position to the plaintext byte (mod 256)
             -> like Vigenere, but on bytes, and the shift changes with position
  2. CHAIN:  XOR the result with the previous ciphertext byte
             -> the same letter encrypts differently each time it appears

Decryption does the same two steps in reverse order.
"""


def _key_bytes(key: str) -> bytes:
    kb = key.encode("utf-8")
    if not kb:
        raise ValueError("Key must not be empty")
    return kb


def encrypt(plaintext: str, key: str) -> bytes:
    kb = _key_bytes(key)
    prev = sum(kb) % 256          # starting value for the chain, derived from the key
    out = bytearray()
    for i, p in enumerate(plaintext.encode("utf-8")):
        shifted = (p + kb[i % len(kb)] + i) % 256   # step 1: shift
        c = shifted ^ prev                          # step 2: chain
        out.append(c)
        prev = c
    return bytes(out)


def decrypt(ciphertext: bytes, key: str) -> str:
    kb = _key_bytes(key)
    prev = sum(kb) % 256
    out = bytearray()
    for i, c in enumerate(ciphertext):
        shifted = c ^ prev                          # undo step 2
        p = (shifted - kb[i % len(kb)] - i) % 256   # undo step 1
        out.append(p)
        prev = c
    return out.decode("utf-8", errors="replace")


if __name__ == "__main__":
    # Standalone demo: python3 cipher.py
    key = "Mozard8"
    message = "Hello, this is a secret message!"
    ct = encrypt(message, key)
    print("Key        :", key)
    print("Plaintext  :", message)
    print("Ciphertext :", ct.hex())
    print("Decrypted  :", decrypt(ct, key))
