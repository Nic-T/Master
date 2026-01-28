# Variant 2: The "Legacy & Integrity" (3DES + HMAC)

This variant uses **3DES** instead of AES and **HMAC** instead of simple hashing.

## Exam Scenario

### Part A: C++ & OpenSSL
1. **RSA Decryption**: Read `priv.pem` private key, decrypt `session.key`
2. **3DES-ECB Decryption**: Decrypt `Database.enc` using Triple DES
   - Mode: ECB (simpler than CBC, no IV needed)
   - Output: `plaintext.db`

### Part B: Java & JCA
1. **Read File**: Load `plaintext.db` from C++
2. **HMAC-SHA256**: Calculate HMAC using first 32 bytes as secret key
3. **KeyStore**: Load Java KeyStore (JKS) and extract public key

## Files
- `cpp_decrypt.cpp` - C++ 3DES decryption code
- `JavaHMAC.java` - Java HMAC + KeyStore code

## Compilation
```bash
# C++
g++ cpp_decrypt.cpp -o decrypt -lssl -lcrypto

# Java
javac JavaHMAC.java
java JavaHMAC
```

## Key Differences from Variant 1
| Aspect | Variant 1 | Variant 2 |
|--------|-----------|-----------|
| Symmetric | AES-CBC | 3DES-ECB |
| Hash | MD5 | HMAC-SHA256 |
| Cert | X.509 | KeyStore |
