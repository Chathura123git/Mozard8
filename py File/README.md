# Mozard8: an educational byte-level symmetric cipher

Mozard8 is a custom symmetric cipher built to **teach** how encryption, decryption and network traffic fit together. A Python/Tkinter application encrypts a message on one machine, sends it over TCP to another (a Kali Linux VM), and decrypts it there, while Wireshark shows what an eavesdropper would see on the wire.

> **Not for real use.** Mozard8 is a learning tool, not a secure cipher. See [Security evaluation](#security-evaluation). Use a vetted algorithm such as AES-GCM to protect real data.

Developed as a group project for *CC6004NM Network and Cloud Security* (BSc Cyber Security and Forensic Computing, London Metropolitan University).

## How it works

Mozard8 processes the message one byte at a time (UTF-8), with all arithmetic modulo 256. For byte `i` of the message, with key `K` of length `L`:

```
shifted = (P[i] + K[i mod L] + i) mod 256     # position-dependent shift
C[i]    = shifted XOR prev                    # ciphertext chaining
prev    = C[i]
```

The first `prev` is the sum of the key bytes mod 256. Decryption reverses the two steps: XOR with the previous ciphertext byte, then subtract the key byte and position.

**Example:** `Hello` with key `Mozard8` encrypts to `30 e5 0d dd 38`. The key bytes sum to 677, so the starting value is 165 (`0xa5`). The two `l` characters encrypt to different bytes (`0d`, `dd`), which is what the chaining step is for.

## Features

- Works on bytes, so symbols and non-English text are supported
- Tkinter GUI with sender, receiver and a colour-coded activity log showing the bytes on the wire
- Encryption on/off switch, to compare plaintext and ciphertext in Wireshark
- Command-line sender and receiver
- Input validation: empty key and invalid port are rejected with a clear error, and network failures do not crash the program
- Python standard library only; no installation needed

## Files

| File | Purpose |
|---|---|
| `cipher.py` | `encrypt()` and `decrypt()` |
| `gui.py` | Tkinter interface and TCP networking (background threads) |
| `sender.py`, `receiver.py` | Command-line alternatives |
| `test_cipher.py` | Unit tests |

## Quick start

Requires Python 3.8 or later.

```bash
# Run the cipher demo
python cipher.py

# Open the GUI (run on both machines)
python gui.py

# Unit tests
python -m unittest test_cipher -v
```

To reproduce the network demo, start the receiver first (on the Kali VM, use `python3`), then send from the other machine. Capture with Wireshark using the filter `tcp.port == 5000`.

## Security evaluation

Mozard8 was attacked as part of the project, and it breaks easily. The chaining uses ciphertext bytes an eavesdropper can already see, so XORing each byte with its predecessor and subtracting the position leaves a byte-level Vigenère cipher.

| Experiment | Result |
|---|---|
| Brute force, lowercase 3-character key | Key found after 1,372 of 17,576 candidates |
| Known-plaintext attack | `K = (V - P) mod 256`; 16 known bytes recovered all 16 key positions |

Other weaknesses: the same message and key always give the same ciphertext (no randomness), and there is no integrity check, so tampering goes undetected. Possible improvements are a key-derivation function, a random nonce, and a message authentication code.

## Screenshots

*Add: the GUI, a terminal run, and the Wireshark plaintext-versus-ciphertext comparison.*

## Team

*Add teammates' names, with their permission.*

## License

MIT (or your choice; add a `LICENSE` file).
