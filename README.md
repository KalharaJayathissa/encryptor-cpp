@ -1,115 +0,0 @@
# encryptor-cpp

A small C++ collection of file “encryptor/protector” prototypes:

- **AES mode (GUI)**: AES-256-CBC via OpenSSL (outputs `*.aes`).
- **Fast/legacy mode (CLI + GUI)**: a simple digit-passcode nibble transform (outputs `*.enc`).

> Notes
> - The **fast/legacy** mode is *not* cryptographically strong; treat it as obfuscation.
> - The **AES** mode in this repo is encryption-only (CBC) and does **not** add an authentication tag (no AEAD / no HMAC). For high-security use, prefer an authenticated mode like AES-GCM.

## What’s in this repo

- `encryptor-advanced.cpp` — Qt GUI that supports **AES-256** and **Fast/legacy** modes.
- `encryptor-gui.cpp` — Qt GUI for the **Fast/legacy** mode.
- `encryptor-v1.cpp`, `encryptor-v2.cpp`, `encryptor-v3.cpp` — CLI versions of the **Fast/legacy** mode (v3 is buffered / faster).
- Other folders (`encryptor/`, `threaded_encryptor_gui/`, etc.) contain earlier experiments and builds.

## Output naming / extensions

- **Encrypt (AES)**: `input.ext` → `input.ext.aes`
- **Encrypt (Fast/legacy)**: `input.ext` → `input.ext.enc`
- **Decrypt**: removes the expected extension and writes back to the original base name.
  - `something.enc` → `something`
  - `something.aes` → `something`

Safety guard (GUI): decrypting requires that the selected file matches the chosen mode:

- If you choose **Fast/legacy** decrypt, the file must end with `.enc`.
- If you choose **AES** decrypt, the file must end with `.aes`.

This prevents accidental overwrites (e.g., decrypting an `.aes` file using the `.enc` path).

## Build (Linux)

### Dependencies

You’ll need a C++ compiler plus Qt5 and (for AES mode) OpenSSL:

- `g++`
- `pkg-config`
- Qt: `Qt5Widgets`
- OpenSSL dev headers: `libssl` / `libcrypto`

On Debian/Ubuntu you typically install:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config qtbase5-dev libssl-dev
```

### Build the AES-capable GUI

```bash
g++ -fPIC encryptor-advanced.cpp -o file-protector-final \
  $(pkg-config --cflags --libs Qt5Widgets) -lssl -lcrypto
```

Run:

```bash
./file-protector-final
```

### Build the fast/legacy GUI

```bash
g++ -fPIC encryptor-gui.cpp -o basic-encryptor-gui \
  $(pkg-config --cflags --libs Qt5Widgets)
```

Run:

```bash
./basic-encryptor-gui
```

### Build the fast/legacy CLI (v3)

```bash
g++ -O2 encryptor-v3.cpp -o basic-encryptor
```

Run:

```bash
# Encrypt
./basic-encryptor e /path/to/file 1234

# Decrypt
./basic-encryptor d /path/to/file.enc 1234
```

## AES details (current implementation)

The AES mode in `encryptor-advanced.cpp` uses:

- Cipher: **AES-256-CBC**
- Key derivation: **PBKDF2-HMAC-SHA256**, 10,000 iterations
- Salt: 16 bytes, written at the start of the output file
- IV: derived deterministically from `SHA-256(key)` (first 16 bytes)

If you plan to harden this design, the usual next steps are: random IV stored with ciphertext, authenticated encryption (AES-GCM), and explicit error handling when `EVP_DecryptFinal_ex` fails.

## Releases

The repository has multiple release artifacts (as shown on GitHub Releases):

- **File protector-AES-256 (Latest)** — Linux GUI, **AES-256 compatible**.
- **Basic-encryptor-GUI (Pre-release)** — Linux GUI, **not AES compatible** (fast/legacy mode).
- **Basic-encryptor (Pre-release)** — Linux CLI, **not AES compatible** (fast/legacy mode).

## License

It is free of course :)
