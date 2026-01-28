# SAP Exam Variants - Quick Reference

All code is **minimal and exam-focused** with `// TEACHER MAY CHANGE:` comments marking likely variations.

## Variant Overview

| Variant | C++ Task | C++ Cipher | Java Task | Java Feature |
|---------|----------|------------|-----------|--------------|
| **1** | RSA pub decrypt → AES | AES-128-CBC | MD5 hash | X.509 Certificate |
| **2** | RSA priv decrypt → 3DES | 3DES-ECB | HMAC-SHA256 | KeyStore (JKS) |
| **3** | Signature verify + AES | AES-128-CTR | DSA sign | Certificate parsing |

---

## Quick Code Patterns

### C++ File Reading (all variants use this)
```cpp
std::ifstream file("input.bin", std::ios::binary | std::ios::ate);
std::streamsize size = file.tellg();
file.seekg(0, std::ios::beg);
std::vector<unsigned char> data(size);
file.read(reinterpret_cast<char*>(data.data()), size);
file.close();
```

### C++ AES Decryption (core pattern)
```cpp
EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
int len1 = 0, len2 = 0;
EVP_DecryptUpdate(ctx, plain.data(), &len1, cipher.data(), cipher.size());
EVP_DecryptFinal_ex(ctx, plain.data() + len1, &len2);
EVP_CIPHER_CTX_free(ctx);
```

### Java Hash Calculation
```java
MessageDigest md = MessageDigest.getInstance("MD5");  // or SHA-256
byte[] hash = md.digest(data);
```

### Java Certificate Loading
```java
CertificateFactory cf = CertificateFactory.getInstance("X.509");
X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
```

---

## Algorithm Quick Reference

| Task | C++ Function | Java Class |
|------|--------------|------------|
| AES-128-CBC | `EVP_aes_128_cbc()` | `Cipher.getInstance("AES/CBC/PKCS5Padding")` |
| AES-256-CBC | `EVP_aes_256_cbc()` | `Cipher.getInstance("AES/CBC/PKCS5Padding")` |
| 3DES-ECB | `EVP_des_ede3_ecb()` | `Cipher.getInstance("DESede/ECB/PKCS5Padding")` |
| AES-CTR | `EVP_aes_128_ctr()` | `Cipher.getInstance("AES/CTR/NoPadding")` |
| MD5 | - | `MessageDigest.getInstance("MD5")` |
| SHA-256 | - | `MessageDigest.getInstance("SHA-256")` |
| HMAC | - | `Mac.getInstance("HmacSHA256")` |
| RSA pub key | `PEM_read_RSA_PUBKEY()` | `KeyFactory.getInstance("RSA")` |
| RSA priv key | `PEM_read_RSAPrivateKey()` | `PKCS8EncodedKeySpec` |
| Signature | `EVP_DigestVerify*()` | `Signature.getInstance("SHA256withRSA")` |

---

## The "Pairing" Dependency

```
┌─────────────────┐      ┌─────────────────┐
│   C++ PROGRAM   │      │  JAVA PROGRAM   │
│                 │      │                 │
│ 1. Read PEM key │      │ 4. Read output  │
│ 2. Decrypt key  │──────▶│    from C++    │
│ 3. Decrypt msg  │      │ 5. Hash/Sign    │
│    → OUTPUT     │      │ 6. Cert/Store   │
└─────────────────┘      └─────────────────┘
```

**You MUST run C++ first because Java needs its output file!**
