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
g++ -O3 -fPIC encryptor-advanced.cpp -o file-protector-final \
  $(pkg-config --cflags --libs Qt5Widgets) -lssl -lcrypto
```

Run:

```bash
./file-protector-final
```

### Build the fast/legacy GUI

```bash
g++ -O3 -fPIC encryptor-gui.cpp -o basic-encryptor-gui \
  $(pkg-config --cflags --libs Qt5Widgets)
```

Alternative output name (as used in some builds):

```bash
g++ -O3 -fPIC encryptor-gui.cpp -o threaded_encryptor_gui \
  $(pkg-config --cflags --libs Qt5Widgets)
```

Run:

```bash
./basic-encryptor-gui
```

### Build the fast/legacy CLI (v1 / v2 / v3)

```bash
g++ -O3 encryptor-v1.cpp -o encryptor-v1
g++ -O3 encryptor-v2.cpp -o encryptor-v2
g++ -O3 encryptor-v3.cpp -o encryptor-v3
```

Run:

```bash
# Encrypt
./encryptor-v3 e /path/to/file 1234

# Decrypt
./encryptor-v3 d /path/to/file.enc 1234
```

## Build (Windows)

### Option A: Cross-compile from Linux (MinGW-w64)

Install the cross toolchain (Debian/Ubuntu example):

```bash
sudo apt update
sudo apt install -y mingw-w64
```

C (example template you mentioned, optimized):

```bash
x86_64-w64-mingw32-gcc -O3 your_code.c -o program_name.exe -static
```

C++ (CLI versions in this repo, optimized):

```bash
x86_64-w64-mingw32-g++ -O3 encryptor-v1.cpp -o encryptor-v1.exe -static
x86_64-w64-mingw32-g++ -O3 encryptor-v2.cpp -o encryptor-v2.exe -static
x86_64-w64-mingw32-g++ -O3 encryptor-v3.cpp -o encryptor-v3.exe -static
```

Notes:

- `-static` produces a larger `.exe` but reduces DLL dependencies.
- Cross-compiling the Qt GUIs from Linux usually requires a Windows Qt build/toolchain (e.g., MXE). If you have a Windows-target Qt `pkg-config` setup, the pattern is similar:

```bash
# Example pattern only (requires Windows Qt libs available to pkg-config)
x86_64-w64-mingw32-g++ -O3 -fPIC encryptor-gui.cpp -o threaded_encryptor_gui.exe \
  $(pkg-config --cflags --libs Qt5Widgets) -static
```

### Option B: Compile on Windows (MSYS2 / MinGW-w64)

In an MSYS2 MinGW64 shell (after installing Qt and pkg-config), you can build with:

```bash
g++ -O3 encryptor-v3.cpp -o encryptor-v3.exe
g++ -O3 encryptor-v2.cpp -o encryptor-v2.exe
g++ -O3 encryptor-v1.cpp -o encryptor-v1.exe
```

For the Qt GUI (if Qt5 is installed and `pkg-config` is available):

```bash
g++ -O3 encryptor-gui.cpp -o threaded_encryptor_gui.exe \
  $(pkg-config --cflags --libs Qt5Widgets)
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
