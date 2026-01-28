# Variant 1: The "Proposed Standard" (Highest Probability)

This is the most likely exam scenario based on the "Proposed SAP exam subject".

## Exam Scenario

### Part A: C++ & OpenSSL
1. **RSA Key Extraction**: Read `pubISM.pem` and extract RSA public key
2. **Asymmetric Decryption**: Decrypt `key.sec` using the public key → outputs AES key
3. **AES-CBC Decryption**: Decrypt `Msg.enc` using the recovered AES key
   - First 16 bytes = IV
   - Remaining bytes = ciphertext
   - Output: `decrypted_Msg.bin`

### Part B: Java & JCA
1. **Read File**: Load `decrypted_Msg.bin` produced by C++
2. **MD5 Hash**: Calculate MD5 digest of the content
3. **Certificate**: Parse `pubISM.pem` as X.509 certificate, print attributes

## Files
- `cpp_decrypt.cpp` - C++ decryption code
- `JavaIntegrity.java` - Java hashing + certificate code

## Compilation
```bash
# C++ (Windows with OpenSSL)
g++ cpp_decrypt.cpp -o decrypt -lssl -lcrypto

# Java
javac JavaIntegrity.java
java JavaIntegrity
```

## Teacher Variations
Look for `// TEACHER MAY CHANGE:` comments in the code for likely modifications.
