# Examples

This folder contains small C++ examples that use the utilities in the parent project.

## decrypt_mem

Decrypt a ciphertext file using symmetric key and IV provided as hex in memory.

Usage:

- Provide key/iv via environment variables:

  ```powershell
  $env:SYM_KEY_HEX = "00112233445566778899aabbccddeeff"
  $env:SYM_IV_HEX  = "aabbccddeeff00112233445566778899"
  .\decrypt_mem.exe Msg.enc Msg.dec
  ```

- Or pass key and iv as command-line arguments:

  ```powershell
  .\decrypt_mem.exe Msg.cipher Msg.dec 001122... aabbcc...
  ```

Assumes the input file contains **ciphertext only** (IV is provided in memory).

## decrypt_minimal (Compact example)

A single-file minimal example that demonstrates AES-128-CBC decryption using hard-coded
`myKey` and `myIV` arrays in memory. This variant mirrors the compact style used in exam
answers and quick demos.

Usage:

```powershell
./decrypt_minimal.exe
```

It expects `Msg.enc` in the current working directory and prints the decrypted
message to stdout.

## encrypt_file_key_iv

Encrypt a plaintext file using a key and IV read from files. The key/IV files may be raw binary or ASCII hex.

Usage:

```powershell
encrypt_file_key_iv.exe plaintext.bin key.bin iv.bin out.enc
```

Output format: IV concatenated with ciphertext (IV || CIPHERTEXT).

## Build

Example compile command (assuming OpenSSL and includes are available):

```powershell
# Minimal examples (single-file) - link with OpenSSL
g++ -std=c++17 decrypt_minimal.cpp -lcrypto -o decrypt_minimal.exe
g++ -std=c++17 examples/encrypt_file_key_iv.cpp -lcrypto -o encrypt_minimal.exe

# Original modular examples (if you prefer to compile the longer versions):
# g++ -std=c++17 -Iinclude ../src/*.cpp decrypt_mem.cpp -lcrypto -o decrypt_mem.exe
# g++ -std=c++17 -Iinclude ../src/*.cpp encrypt_file_key_iv.cpp -lcrypto -o encrypt_file_key_iv.exe
```

Adjust paths and linking as needed for your environment.
