# Cryptography Theory Questions & Quizzes

Practice quizzes organized by topic. Write your answers directly after each question.

---

## 🔧 CrypTool Exercises

### Topic 1: Foundations & Classical Ciphers

#### CT-1.1: XOR Encryption/Decryption
1. Open CrypTool 2 → Create new workspace
2. Use the **XOR** component to encrypt the message `"HELLO"` with key `0x5A`
3. Observe the ciphertext output
4. Add another XOR component to decrypt it back
5. **Verify:** Does `M ⊕ K ⊕ K = M`?

#### CT-1.2: Caesar Cipher Analysis
1. Create a Caesar cipher encryption with shift = 3
2. Encrypt: `"THE QUICK BROWN FOX"`
3. Use CrypTool's **frequency analysis** tool on the ciphertext
4. Can you identify the shift without knowing the key?

#### CT-1.3: Entropy Measurement
1. Use CrypTool's entropy calculator on:
   - A file of random bytes (generate with Random Number Generator)
   - A text file with repeated characters like `"AAAAAAAAAA"`
   - A normal English text file
2. **Record:** What is the entropy (bits/byte) for each?

---

### Topic 2: Hash Functions

#### CT-2.1: Avalanche Effect Demonstration
1. Create a **SHA-256** hash of: `"Hello World"`
2. Create a hash of: `"Hello world"` (lowercase 'w')
3. Create a hash of: `"Hello World!"` (added exclamation)
4. **Compare:** How many characters changed in each hash?
5. **Lesson:** Tiny input changes → completely different hashes

#### CT-2.2: Hash Collision Exploration
1. Hash multiple different inputs with **MD5**
2. Research: How many hashes would you need to have a 50% collision chance?
3. Use the formula: `2^(128/2) = 2^64` attempts

#### CT-2.3: HMAC Construction
1. Build an HMAC using CrypTool's visual components:
   - Secret Key: `"MySecretKey"`
   - Message: `"Verify this message"`
2. Visualize: `HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))`
3. Change the key slightly → observe the completely different HMAC

---

### Topic 3: Symmetric Cryptography

#### CT-3.1: ECB vs CBC Pattern Leakage
1. Load an image file (like a BMP with solid colors or patterns)
2. Encrypt with **AES-ECB** mode
3. Encrypt the same image with **AES-CBC** mode
4. View both encrypted images
5. **Document:** Why are patterns visible in ECB but not CBC?

#### CT-3.2: DES Key Size Analysis
1. Encrypt a message with **DES** (56-bit key)
2. Encrypt the same message with **3DES** (168-bit key)
3. Encrypt with **AES-256** (256-bit key)
4. **Research:** How long would a brute-force attack take for each?

#### CT-3.3: Block Cipher Modes Comparison
Build encryption/decryption chains for:
1. **ECB Mode:** Simple parallel encryption
2. **CBC Mode:** Chain with IV
3. **CTR Mode:** Counter-based stream conversion

Compare: parallelization, error propagation, IV requirements

#### CT-3.4: Padding Visualization
1. Encrypt messages of different lengths with AES-CBC
2. Observe the PKCS#7 padding added:
   - 5-byte message → 3 bytes of `0x03` padding
   - 8-byte message → 8 bytes of `0x08` padding
3. What happens with a 16-byte (full block) message?

---

### Topic 4: Asymmetric Cryptography

#### CT-4.1: RSA Key Generation
1. Use CrypTool's **RSA Key Generator**
2. Generate keys with different sizes: 512, 1024, 2048, 4096 bits
3. **Measure:** Time to generate each key size
4. **Observe:** How do p, q, n, e, d change with key size?

#### CT-4.2: Digital Signature Workflow
1. Create a message: `"I authorize this transaction"`
2. **Sign it:**
   - Hash the message with SHA-256
   - Encrypt the hash with your RSA Private Key
3. **Verify it:**
   - Decrypt the signature with the Public Key
   - Compare with a fresh hash of the message
4. **Tamper test:** Change one character in the message and verify again

#### CT-4.3: Diffie-Hellman Key Exchange
1. Use CrypTool's DH simulator
2. Simulate the exchange between Alice and Bob
3. **Calculate manually:**
   - Given: p=23, g=5
   - Alice's secret: a=6, Bob's secret: b=15
   - What shared secret do they derive?

#### CT-4.4: Certificate Inspection
1. Export a certificate from your browser (any HTTPS site)
2. Open it in CrypTool's certificate viewer
3. **Identify:**
   - Subject (who is this certificate for?)
   - Issuer (which CA signed it?)
   - Public Key algorithm and key size
   - Validity period
   - Signature algorithm

---

## 📝 Quiz 1: Vocabulary and Foundations

1. **Multiple Choice:** Which cryptographic objective prevents someone from denying they sent a message?
   - A) Confidentiality
   - B) Integrity
   - C) Authentication
   - D) Non-repudiation

**Your Answer:** 

2. **True/False:** Kerckhoffs' Principle states that keeping the algorithm secret is essential for security.

**Your Answer:** 

3. **Fill in the blank:** The only cipher that provides unconditional (information-theoretic) security is the __________.

**Your Answer:** 

4. **Short Answer:** In the Dolev-Yao model, what capabilities does the attacker have over the communication channel?

**Your Answer:** 

5. **Calculation:** What is the result of `1011 ⊕ 1100`?

**Your Answer:** 

6. **Multiple Choice:** An 8-character password using only lowercase letters (a-z) has approximately how many bits of entropy?
   - A) 26 bits
   - B) 37.6 bits
   - C) 64 bits
   - D) 128 bits

**Your Answer:** 

7. **Match the terms:**
   - Steganography → ?
   - Cryptography → ?
   - Encoding → ?
   
   Options: a) Hiding message existence, b) Scrambling message content, c) Data format conversion

**Your Answer:** 

8. **True/False:** A nonce is the primary defense against eavesdropping attacks.

**Your Answer:** 

9. **Short Answer:** What is the difference between a passive and active attack?

**Your Answer:** 

10. **Multiple Choice:** In a chosen-plaintext attack, the attacker can:
    - A) Only observe encrypted traffic
    - B) Obtain plaintext-ciphertext pairs they chose
    - C) Modify messages in transit
    - D) Access the encryption key directly

**Your Answer:** 

---

## 📝 Quiz 2: Data Integrity and Hashes

1. **Multiple Choice:** What hash length does SHA-256 produce?
   - A) 128 bits
   - B) 160 bits
   - C) 256 bits
   - D) 512 bits

**Your Answer:** 

2. **True/False:** Hash functions provide confidentiality for data.

**Your Answer:** 

3. **Short Answer:** Explain the Avalanche Effect in one sentence.

**Your Answer:** 

4. **Calculation:** Using the Birthday Paradox, how many random SHA-256 hashes would you need to generate for a 50% chance of collision?

**Your Answer:** 

5. **Multiple Choice:** Which defense prevents Rainbow Table attacks?
   - A) Using SHA-3
   - B) Using a longer password
   - C) Salting
   - D) Using HMAC

**Your Answer:** 

6. **Fill in the blank:** A __________ Attack exploits the ability to append data to a hash without knowing the secret, affecting MD5, SHA-1, and SHA-2.

**Your Answer:** 

7. **True/False:** HMAC provides both data integrity AND authentication.

**Your Answer:** 

8. **Short Answer:** Why must each user have a unique salt instead of a global salt?

**Your Answer:** 

9. **Multiple Choice:** Which hash algorithm is specifically designed to resist Length-Extension Attacks?
   - A) MD5
   - B) SHA-1
   - C) SHA-256
   - D) SHA-3 (Keccak)

**Your Answer:** 

10. **Match the algorithm to its hash size:**
    - MD5 → ?
    - SHA-1 → ?
    - SHA-256 → ?
    
    Options: a) 128 bits, b) 160 bits, c) 256 bits

**Your Answer:** 

---

## 📝 Quiz 3: Symmetric Cryptography

1. **Multiple Choice:** What is the block size of AES?
   - A) 64 bits
   - B) 128 bits
   - C) 192 bits
   - D) 256 bits

**Your Answer:** 

2. **True/False:** Stream ciphers encrypt data one block at a time.

**Your Answer:** 

3. **Fill in the blank:** The security of stream ciphers depends on the quality of the __________ generator.

**Your Answer:** 

4. **Short Answer:** What is the purpose of padding in block ciphers?

**Your Answer:** 

5. **Multiple Choice:** Which AES operation provides "Confusion" by performing non-linear substitution?
   - A) ShiftRows
   - B) MixColumns
   - C) SubBytes (S-box)
   - D) AddRoundKey

**Your Answer:** 

6. **Calculation:** Using PKCS#7 padding with 8-byte blocks, how would you pad the message "HI" (2 bytes)?

**Your Answer:** 

7. **True/False:** ECB mode can be parallelized but leaks patterns.

**Your Answer:** 

8. **Multiple Choice:** The Padding Oracle Attack specifically targets:
   - A) ECB mode
   - B) CBC mode
   - C) CTR mode
   - D) OFB mode

**Your Answer:** 

9. **Short Answer:** Why is the One-Time Pad (OTP) the only theoretically unbreakable cipher?

**Your Answer:** 

10. **Match the cipher mode to its characteristic:**
    - ECB → ?
    - CBC → ?
    - CTR → ?
    
    Options: a) Pattern leakage, b) Requires IV and chaining, c) Parallelizable stream mode

**Your Answer:** 

11. **Fill in the blank:** DES uses a __________ Network architecture, while AES uses a __________ (SPN) architecture.

**Your Answer:** 

12. **True/False:** In CTR mode, reusing a Key+Nonce pair is catastrophic for security.

**Your Answer:** 

---

## 📝 Quiz 4: Asymmetric Cryptography & Protocols

1. **Multiple Choice:** RSA security is based on the difficulty of:
   - A) Discrete logarithm problem
   - B) Integer factorization problem
   - C) Elliptic curve problem
   - D) Quantum computing

**Your Answer:** 

2. **True/False:** Asymmetric encryption is faster than symmetric encryption.

**Your Answer:** 

3. **Short Answer:** What is "Hybrid Encryption" and why is it used?

**Your Answer:** 

4. **Fill in the blank:** ECC offers the same security as RSA but with __________ key sizes.

**Your Answer:** 

5. **Multiple Choice:** Diffie-Hellman is used for:
   - A) Digital signatures
   - B) Encryption
   - C) Key exchange
   - D) Hashing

**Your Answer:** 

6. **Short Answer:** What vulnerability does unauthenticated Diffie-Hellman have?

**Your Answer:** 

7. **True/False:** A digital signature provides non-repudiation.

**Your Answer:** 

8. **Multiple Choice:** In the X.509 certificate, who signs the certificate?
   - A) The certificate owner
   - B) The Registration Authority (RA)
   - C) The Certification Authority (CA)
   - D) The end user's browser

**Your Answer:** 

9. **Fill in the blank:** A CRL stands for __________ and lists certificates that have been revoked before expiration.

**Your Answer:** 

10. **Match the protocol/algorithm to its purpose:**
    - RSA → ?
    - DSA → ?
    - Diffie-Hellman → ?
    - ECDSA → ?
    
    Options: a) Encryption & Signatures, b) Signatures only, c) Key exchange, d) Elliptic Curve signatures

**Your Answer:** 

11. **Short Answer:** What is a Zero-Knowledge Proof? Give the "Magic Door" example.

**Your Answer:** 

12. **Multiple Choice:** Which quantum algorithm threatens RSA and ECC?
    - A) Grover's Algorithm
    - B) Shor's Algorithm
    - C) Dijkstra's Algorithm
    - D) RSA Algorithm

**Your Answer:** 

---

## 📊 Answer Key

### Quiz 1 Answers
1. D) Non-repudiation
2. False (the KEY should be secret, not the algorithm)
3. One-Time Pad (OTP)
4. Read, Copy, Delete, Modify, Replay messages
5. 0111
6. B) 37.6 bits (8 × log₂(26) ≈ 37.6)
7. Steganography→a, Cryptography→b, Encoding→c
8. False (nonces defend against REPLAY attacks, not eavesdropping)
9. Passive: listens without altering; Active: modifies data/operations
10. B)

### Quiz 2 Answers
1. C) 256 bits
2. False (hashes provide INTEGRITY, not confidentiality)
3. A tiny input change causes a completely different hash output
4. 2^128 ≈ 3.4 × 10^38 hashes
5. C) Salting
6. Length-Extension
7. True
8. Global salt allows pre-computed tables to work for all users
9. D) SHA-3 (Keccak)
10. MD5→a, SHA-1→b, SHA-256→c

### Quiz 3 Answers
1. B) 128 bits (key sizes are 128/192/256, but BLOCK size is always 128!)
2. False (stream ciphers encrypt bit by bit or byte by byte)
3. Keystream (or PRNG)
4. To make plaintext an exact multiple of the block size
5. C) SubBytes (S-box) - S-boxes = Confusion, P-boxes = Diffusion
6. `HI\x06\x06\x06\x06\x06\x06` (6 bytes of value 0x06)
7. True
8. B) CBC mode
9. Key is truly random, at least as long as message, never reused
10. ECB→a, CBC→b, CTR→c
11. Feistel, SPN (Substitution-Permutation Network)
12. True

### Quiz 4 Answers
1. B) Integer factorization problem
2. False (asymmetric is ~1000x SLOWER than symmetric)
3. Use RSA to encrypt a symmetric key (AES), then use AES for the actual data - combines the security of asymmetric with the speed of symmetric
4. Smaller
5. C) Key exchange
6. Man-in-the-Middle (MITM) attack
7. True
8. C) Certification Authority (CA)
9. Certificate Revocation List
10. RSA→a, DSA→b, DH→c, ECDSA→d
11. A protocol where one party proves they know a secret without revealing it. Example: Alice proves she has a key to a door inside a cave by exiting from whichever side Bob requests, without showing the key.
12. B) Shor's Algorithm
