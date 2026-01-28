# Variant 3: The "Signature & Verification" (Advanced)

This variant focuses on **Digital Signatures** - both verification (C++) and generation (Java).

## Exam Scenario

### Part A: C++ & OpenSSL
1. **Signature Verification**: Verify that `Signature.sig` matches `Data.bin` using public key
2. **Stream Cipher Decryption**: Decrypt using AES-CTR (counter mode, no padding)
   - Output: `verified_content.txt`

### Part B: Java & JCA
1. **Read File**: Load `verified_content.txt` from C++
2. **DSA Signature**: Sign the data using DSA algorithm (SHA256withDSA)
3. **Certificate Parsing**: Extract fields from existing .cer file

## Files
- `cpp_verify.cpp` - C++ signature verification + AES-CTR code
- `JavaSignature.java` - Java DSA signing + certificate parsing

## Compilation
```bash
# C++
g++ cpp_verify.cpp -o verify -lssl -lcrypto

# Java
javac JavaSignature.java
java JavaSignature
```

## Key Differences
| Aspect | Variant 1 | Variant 3 |
|--------|-----------|-----------|
| C++ Main | Decrypt | Verify Signature |
| Symmetric | AES-CBC | AES-CTR (stream) |
| Java | MD5 Hash | DSA Sign |
