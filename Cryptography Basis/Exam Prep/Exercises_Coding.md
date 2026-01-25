# Cryptography Coding Exercises

Programming exercises in Python, C, and Java. You can copy these into your IDE or use an online compiler.

---

## 🐍 Python Exercises

### Exercise PY-1: XOR Cipher Implementation

**Task:** Implement a rolling XOR cipher that repeats the key if it's shorter than the message.

```python
"""
Exercise: Implement a simple XOR cipher

Tasks:
1. Write a function xor_encrypt(plaintext: bytes, key: bytes) -> bytes
2. Write a function xor_decrypt(ciphertext: bytes, key: bytes) -> bytes
3. Demonstrate key reuse vulnerability
"""

def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """XORs plaintext with key (repeating key if necessary)"""
    encrypted = bytearray()
    for i in range(len(plaintext)):
        # TODO: encrypted_byte = plaintext_byte XOR key_byte
        # Hint: Use modulo % to loop the key
        # key_byte = key[i % len(key)]
        pass
    return bytes(encrypted)

def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """XOR decryption is the SAME same operation as encryption!"""
    return xor_encrypt(ciphertext, key)

# Test your implementation
if __name__ == "__main__":
    message = b"Hello, World!"
    key = b"SECRET"
    
    print(f"Original:  {message}")
    
    # Encrypt
    encrypted = xor_encrypt(message, key)
    print(f"Encrypted: {encrypted.hex()}")
    
    # Decrypt
    decrypted = xor_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == message, "Decryption failed!"
    print("\nSUCCESS: Decryption matches original!")
```

---

### Exercise PY-2: Hash Exploration & Avalanche Effect

**Task:** Use Python's `hashlib` to demonstrate how small changes create totally different hashes.

```python
import hashlib

def demonstrate_avalanche():
    """Show how small input changes cause large hash changes"""
    messages = [
        "Hello World",
        "Hello world",  # lowercase 'w' (1 bit difference)
        "Hello World!", # added '!'
    ]
    
    print(f"{'Input String':<15} | {'SHA-256 Hash Hint':<20}")
    print("-" * 60)
    
    for msg in messages:
        # Create SHA-256 hash
        h = hashlib.sha256(msg.encode())
        digest = h.hexdigest()
        
        print(f"'{msg}'\t -> {digest[:16]}...")

def crack_md5_hash(target_hash):
    """Simple dictionary attack on MD5"""
    common_passwords = ["123456", "password", "12345678", "qwerty", "iloveyou"]
    
    print(f"\nAttempting to crack: {target_hash}")
    
    for pwd in common_passwords:
        # TODO: Hash the password and compare
        # hashed_pwd = hashlib.md5(pwd.encode()).hexdigest()
        pass

if __name__ == "__main__":
    demonstrate_avalanche()
```

---

### Exercise PY-3: AES Modes (ECB vs CBC)

**Task:** Visualize why ECB mode is insecure for patterns.

```python
"""
Requires: pip install pycryptodome
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def encrypt_ecb_vs_cbc():
    key = get_random_bytes(16) # AES-128
    
    # A repeating pattern (like specific pixel colors in an image)
    # Using 3 identical blocks of 16 bytes
    plaintext = b"AAAAAAAAAAAAAAAA" * 3 
    
    print(f"Plaintext ({len(plaintext)} bytes): {plaintext}")
    
    # 1. ECB Encryption
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    ct_ecb = cipher_ecb.encrypt(plaintext)
    
    print("\n[ECB Mode Output]")
    print(f"Block 1: {ct_ecb[0:16].hex()}")
    print(f"Block 2: {ct_ecb[16:32].hex()}")
    print(f"Block 3: {ct_ecb[32:48].hex()}")
    print("Notice: Identical input blocks -> Identical output blocks!")
    
    # 2. CBC Encryption
    iv = get_random_bytes(16)
    cipher_cbc = AES.new(key, AES.MODE_CBC, iv)
    ct_cbc = cipher_cbc.encrypt(plaintext)
    
    print("\n[CBC Mode Output]")
    print(f"Block 1: {ct_cbc[0:16].hex()}")
    print(f"Block 2: {ct_cbc[16:32].hex()}")
    print(f"Block 3: {ct_cbc[32:48].hex()}")
    print("Notice: Identical input blocks -> DIFFERENT output blocks!")

if __name__ == "__main__":
    encrypt_ecb_vs_cbc()
```

---

### Exercise PY-4: RSA Key Generation (Simplified)

**Task:** Implement the core math of RSA to understand how keys are made.

```python
"""
Simplified RSA Implementation
WARNING: For educational use only. Uses small insecure primes.
"""

def gcd(a, b):
    """Euclidean algorithm for Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def generate_keypair(p, q):
    # 1. Calculate n
    n = p * q
    
    # 2. Calculate phi (totient)
    phi = (p - 1) * (q - 1)
    
    # 3. Choose public exponent e
    e = 17 # Common small prime
    
    # Check if e is coprime to phi
    if gcd(e, phi) != 1:
        raise ValueError("e is not coprime to phi!")
    
    # 4. Calculate private exponent d
    # d * e ≡ 1 (mod phi)
    # We use a brute force search here for simplicity (use Extended Euclidean in production)
    d = 0
    k = 1
    while True:
        # We want (d * e) % phi == 1
        # Rewritten: d = (k * phi + 1) / e
        val = (k * phi + 1)
        if val % e == 0:
            d = val // e
            break
        k += 1
        
    return ((e, n), (d, n))

def encrypt(pk, plaintext_int):
    # Unpack key
    e, n = pk
    # c = m^e mod n
    cipher = pow(plaintext_int, e, n)
    return cipher

def decrypt(sk, ciphertext_int):
    # Unpack key
    d, n = sk
    # m = c^d mod n
    plain = pow(ciphertext_int, d, n)
    return plain

if __name__ == "__main__":
    # Small primes for demo
    p = 61
    q = 53
    
    public, private = generate_keypair(p, q)
    print(f"Public Key:  {public}")
    print(f"Private Key: {private}")
    
    message = 123
    print(f"\nOriginal Message: {message}")
    
    encrypted = encrypt(public, message)
    print(f"Encrypted: {encrypted}")
    
    decrypted = decrypt(private, encrypted)
    print(f"Decrypted: {decrypted}")
```

---

## 🔵 C Exercises

### Exercise C-1: Bitwise XOR Cipher

**Task:** Implement a function that encrypts data in-place using XOR.

```c
#include <stdio.h>
#include <string.h>

/*
 * XORs the buffer with the key, repeating the key as needed.
 * Works for both encryption and decryption.
 */
void xor_process(char *buffer, int buf_len, const char *key, int key_len) {
    for (int i = 0; i < buf_len; i++) {
        // TODO: Implement XOR logic
        // buffer[i] = buffer[i] ^ key[i % key_len];
    }
}

int main() {
    char data[] = "Secret Message";
    char key[] = "KEY";
    int len = strlen(data);
    
    printf("Original:  %s\n", data);
    
    // Encrypt
    xor_process(data, len, key, strlen(key));
    printf("Encrypted: ");
    for(int i=0; i<len; i++) printf("%02X ", (unsigned char)data[i]);
    printf("\n");
    
    // Decrypt (run it again)
    xor_process(data, len, key, strlen(key));
    printf("Decrypted: %s\n", data);
    
    return 0;
}
```

---

### Exercise C-2: Basic Hash (DJB2)

**Task:** Implement the famous DJB2 string hash function.

```c
#include <stdio.h>

unsigned long djb2_hash(unsigned char *str) {
    unsigned long hash = 5381;
    int c;

    while (c = *str++) {
        // hash = hash * 33 + c
        // Efficient way: ((hash << 5) + hash) + c
        hash = ((hash << 5) + hash) + c;
    }

    return hash;
}

int main() {
    unsigned char str1[] = "password123";
    unsigned char str2[] = "Password123"; // Case change
    
    printf("Hash 1: %lu\n", djb2_hash(str1));
    printf("Hash 2: %lu\n", djb2_hash(str2));
    
    return 0;
}
```

---

## ☕ Java Exercises

### Exercise J-1: Digital Signatures

**Task:** Sign a message and verify it using Java's `java.security` package.

```java
import java.security.*;
import java.util.Base64;

public class SignatureDemo {
    public static void main(String[] args) throws Exception {
        // 1. Generate Key Pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        
        // 2. Sign
        Signature signInfo = Signature.getInstance("SHA256withRSA");
        signInfo.initSign(pair.getPrivate());
        
        String msg = "I authorize $100 payment";
        signInfo.update(msg.getBytes());
        byte[] signature = signInfo.sign();
        
        System.out.println("Message: " + msg);
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));
        
        // 3. Verify
        Signature verifyInfo = Signature.getInstance("SHA256withRSA");
        verifyInfo.initVerify(pair.getPublic());
        
        // Try to verify the ORIGINAL message
        verifyInfo.update(msg.getBytes());
        boolean isCorrect = verifyInfo.verify(signature);
        System.out.println("Verification success: " + isCorrect);
        
        // 4. Verification Failure Demo
        String tampered = "I authorize $1000 payment"; // Increased amount
        verifyInfo.update(tampered.getBytes());
        boolean isTamperedCorrect = verifyInfo.verify(signature);
        System.out.println("Tampered message verified: " + isTamperedCorrect);
    }
}
```
