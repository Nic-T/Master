# SAP Exam Complete Cheatsheet

## 🔑 Key Sizes & IV Sizes (MEMORIZE THIS!)

| Algorithm   | Cipher Function      | Key Size |  IV Size | Block Size |
| ----------- | -------------------- | -------: | -------: | ---------: |
| AES-128-CBC | `EVP_aes_128_cbc()`  | 16 bytes | 16 bytes |   16 bytes |
| AES-256-CBC | `EVP_aes_256_cbc()`  | 32 bytes | 16 bytes |   16 bytes |
| AES-128-CTR | `EVP_aes_128_ctr()`  | 16 bytes | 16 bytes |   (stream) |
| DES-CBC     | `EVP_des_cbc()`      |  8 bytes |  8 bytes |    8 bytes |
| 3DES-CBC    | `EVP_des_ede3_cbc()` | 24 bytes |  8 bytes |    8 bytes |
| 3DES-ECB    | `EVP_des_ede3_ecb()` | 24 bytes |     NONE |    8 bytes |

> **Rule of thumb**: AES IV = 16 bytes always. DES/3DES IV = 8 bytes.
> **ECB mode** = No IV needed (less secure, but simpler)

---

## 📁 C++ File I/O Pattern (COPY-PASTE THIS)

```cpp
// READ BINARY FILE INTO VECTOR
std::ifstream file("input.bin", std::ios::binary | std::ios::ate);
std::streamsize size = file.tellg();      // Get file size (opened at end)
file.seekg(0, std::ios::beg);             // Rewind to start
std::vector<unsigned char> data(size);    // Allocate buffer
file.read(reinterpret_cast<char*>(data.data()), size);  // Read
file.close();

// WRITE BINARY FILE FROM VECTOR
std::ofstream out("output.bin", std::ios::binary);
out.write(reinterpret_cast<char*>(data.data()), data.size());
out.close();
```

---

## 🔐 C++ Symmetric Decryption Template

```cpp
#include <openssl/evp.h>

// The pattern is ALWAYS: Init → Update → Final → Free

EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();    // 1. Create context

EVP_DecryptInit_ex(ctx,                        // 2. Initialize
    EVP_aes_128_cbc(),  // ← CHANGE: cipher algorithm
    NULL,               // Engine (always NULL for exam)
    key,                // ← CHANGE: key bytes
    iv                  // ← CHANGE: IV bytes (NULL for ECB)
);

int len1 = 0, len2 = 0;

EVP_DecryptUpdate(ctx,                         // 3. Process data
    plaintext.data(), &len1,  // output + output length
    ciphertext.data(), ciphertext.size()  // input + input length
);

EVP_DecryptFinal_ex(ctx,                       // 4. Finalize (padding)
    plaintext.data() + len1, &len2
);

int totalLen = len1 + len2;                    // Total plaintext length

EVP_CIPHER_CTX_free(ctx);                      // 5. Cleanup
```

**For ENCRYPTION: just change `Decrypt` to `Encrypt` everywhere!**

---

## 🔓 C++ RSA Key Loading

```cpp
#include <openssl/pem.h>
#include <openssl/rsa.h>

// PUBLIC KEY (from PEM file)
FILE* fp = fopen("pub.pem", "r");
RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
fclose(fp);

// PRIVATE KEY (from PEM file)
FILE* fp = fopen("priv.pem", "r");
RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);  // No password
fclose(fp);

// RSA Operations
int outLen = RSA_public_decrypt(inLen, inData, outData, rsa, RSA_PKCS1_PADDING);
int outLen = RSA_private_decrypt(inLen, inData, outData, rsa, RSA_PKCS1_PADDING);
int outLen = RSA_public_encrypt(inLen, inData, outData, rsa, RSA_PKCS1_PADDING);
int outLen = RSA_private_encrypt(inLen, inData, outData, rsa, RSA_PKCS1_PADDING);

RSA_free(rsa);  // Don't forget!
```

---

## ✅ C++ Signature Verification

```cpp
#include <openssl/evp.h>
#include <openssl/pem.h>

// Load public key for verification
FILE* fp = fopen("pub.pem", "r");
EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
fclose(fp);

EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();

EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, pkey);  // SHA-256
EVP_DigestVerifyUpdate(mdCtx, data, dataLen);                  // Add data
int result = EVP_DigestVerifyFinal(mdCtx, signature, sigLen);  // Verify

// result == 1 means VALID, otherwise INVALID

EVP_MD_CTX_free(mdCtx);
EVP_PKEY_free(pkey);
```

---

## ☕ Java Hashing (MD5, SHA-256)

```java
import java.security.MessageDigest;

// Simple hash
MessageDigest md = MessageDigest.getInstance("MD5");     // or "SHA-256"
byte[] hash = md.digest(data);

// Multi-part hash (if needed)
md.update(part1);
md.update(part2);
byte[] hash = md.digest();
```

---

## ☕ Java HMAC

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
Mac mac = Mac.getInstance("HmacSHA256");  // or "HmacSHA1", "HmacMD5"
mac.init(keySpec);
byte[] hmac = mac.doFinal(data);
```

**HMAC vs Hash**: HMAC needs a secret key, plain hash doesn't!

---

## ☕ Java X.509 Certificate

```java
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

CertificateFactory cf = CertificateFactory.getInstance("X.509");
X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);

// Common fields to extract
cert.getSubjectDN()      // Who the cert belongs to
cert.getIssuerDN()       // Who issued the cert
cert.getSerialNumber()   // Unique serial
cert.getNotBefore()      // Valid from date
cert.getNotAfter()       // Valid until date
cert.getSigAlgName()     // Signature algorithm used
cert.getPublicKey()      // Extract the public key
```

---

## ☕ Java KeyStore

```java
import java.security.KeyStore;

KeyStore ks = KeyStore.getInstance("JKS");                    // Java KeyStore
FileInputStream fis = new FileInputStream("keystore.jks");
ks.load(fis, "password".toCharArray());                       // Load with password
fis.close();

// Get certificate/key by alias
java.security.cert.Certificate cert = ks.getCertificate("myalias");
PublicKey pk = cert.getPublicKey();
```

---

## ☕ Java Digital Signature

```java
import java.security.Signature;

// SIGNING (with private key)
Signature sig = Signature.getInstance("SHA256withRSA");  // or "SHA256withDSA"
sig.initSign(privateKey);
sig.update(data);
byte[] signature = sig.sign();

// VERIFYING (with public key)
Signature sig = Signature.getInstance("SHA256withRSA");
sig.initVerify(publicKey);
sig.update(data);
boolean valid = sig.verify(signatureBytes);
```

---

## ☕ Java Symmetric Crypto

```java
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);  // or ENCRYPT_MODE
byte[] result = cipher.doFinal(inputData);
```

---

## 🔄 Java Hex Helper (ALWAYS USEFUL)

```java
public static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02x", b & 0xff));
    }
    return sb.toString();
}
```

---

## ⚠️ Common Exam Traps

| Trap | Solution |
|------|----------|
| IV from file vs hardcoded | Read exam carefully! "First 16 bytes" = extract from file |
| AES-128 vs AES-256 | Check key size: 16 bytes = 128, 32 bytes = 256 |
| ECB vs CBC mode | ECB = no IV needed, CBC = IV required |
| RSA public vs private | `RSA_public_decrypt` vs `RSA_private_decrypt` |
| HMAC vs Hash | HMAC needs a KEY, plain hash doesn't |
| .pem vs .cer | .pem = text format, .cer = usually binary DER |
| Key from env vs file | Check if key comes from `System.getenv()` |

---

## 📝 Exam Workflow Reminder

```
┌─────────────────────────────────────────────────────────────┐
│  1. READ THE EXAM CAREFULLY                                 │
│     - What files are given? (.pem, .enc, .sig, .key)        │
│     - What algorithm? (AES-128-CBC, 3DES, RSA)              │
│     - Where does IV come from? (first 16 bytes? separate?)  │
│     - What output is expected?                              │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  2. C++ PART: Decrypt/Verify                                │
│     - Load key (RSA from PEM or symmetric)                  │
│     - Decrypt encrypted key if needed                       │
│     - Decrypt message → write OUTPUT FILE                   │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  3. JAVA PART: Hash/Sign/Certificate                        │
│     - Read the OUTPUT FILE from C++                         │
│     - Calculate hash/HMAC                                   │
│     - Parse certificate OR sign data                        │
│     - Write results                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔢 Padding Rules

| Mode | Padding |
|------|---------|
| CBC | PKCS#7 padding (handled by EVP_DecryptFinal) |
| ECB | PKCS#7 padding (handled by EVP_DecryptFinal) |
| CTR | NO padding needed (stream cipher) |
| GCM | NO padding needed (stream cipher + auth tag) |

**Output buffer size**: Always allocate `ciphertext_size + block_size` for plaintext!

---

## 💡 Quick Algorithm Strings

**C++ OpenSSL Functions:**
- `EVP_aes_128_cbc()`, `EVP_aes_256_cbc()`, `EVP_aes_128_ctr()`
- `EVP_des_cbc()`, `EVP_des_ede3_cbc()`, `EVP_des_ede3_ecb()`
- `EVP_sha256()`, `EVP_sha1()`, `EVP_md5()`

**Java JCA Strings:**
- `"AES/CBC/PKCS5Padding"`, `"AES/CTR/NoPadding"`
- `"DESede/CBC/PKCS5Padding"`, `"DESede/ECB/PKCS5Padding"`
- `"MD5"`, `"SHA-256"`, `"SHA-1"`
- `"HmacSHA256"`, `"HmacSHA1"`, `"HmacMD5"`
- `"SHA256withRSA"`, `"SHA256withDSA"`, `"SHA1withRSA"`
