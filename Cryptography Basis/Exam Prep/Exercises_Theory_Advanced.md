# Advanced Cryptography Theory & Concepts

**Instructions:**
- For **Multiple Key Selection** questions, mark **ALL** options that are correct. There may be one, more than one, or all options correct.
- For **Open Questions**, write a concise explanation demonstrating your understanding.
- **Do not** look up the answers; try to answer from memory and logic.
- When you are finished, prompt the AI to review your answers.

---

## 🏗️ Topic 1: Foundations & Security Models

### Question 1.1 (Select ALL correct options)
Which of the following statements about **Kerckhoffs' Principle** are accurate?
- [ ] Security should depend on the secrecy of the algorithm.
- [ ] Security must depend solely on the secrecy of the key.
- [ ] The system should remain secure even if the attacker knows every detail of the design (except the key).
- [ ] It protects against "Security by Obscurity."
- [ ] It applies only to asymmetric cryptography.

**Your Selection:** 
- [ ] Security must depend solely on the secrecy of the key.
- [ ] The system should remain secure even if the attacker knows every detail of the design (except the key).
### Question 1.2 (Open Question)
Explain the difference between **Data Origin Authentication** and **Peer Entity Authentication**. Give a practical example where you would need one but not the other.

**Your Answer:** 
Data origin auth checks where a file is downloaded from, peer entity auth checks with whom your are speaking with
### Question 1.3 (Select ALL correct options)
Under the **Dolev-Yao Model**, which capabilities does the attacker **Eve** possess?
- [ ] She can eavesdrop on all messages sent over the network.
- [ ] She can decrypt messages without the key if she has enough time.
- [ ] She can inject, modify, or delete messages in transit.
- [ ] She is a legitimate participant in the protocol.
- [ ] She controls the communication channel completely.

**Your Selection:** 
She can eavesdrop on all messages sent over the network.
 She can inject, modify, or delete messages in transit.
 She controls the communication channel completely.
---

## 🔐 Topic 2: Data Integrity & Hashes

### Question 2.1 (Select ALL correct options)
Which of the following are essential properties of a secure cryptographic **Hash Function**?
- [ ] **Pre-image resistance:** Given a hash `h`, it is hard to find any message `m` such that `Hash(m) = h`.
- [ ] **Reversibility:** It must be possible to recover the original message from the hash.
- [ ] **Avalanche Effect:** A small change in input results in a significant change in output.
- [ ] **Fixed Output Size:** The output length is constant regardless of input size.
- [ ] **Collision Resistance:** It is infeasible to find two different inputs `m1` and `m2` such that `Hash(m1) = Hash(m2)`.

**Your Selection:** 
Given a hash `h`, it is hard to find any message `m` such that `Hash(m) = h`.
A small change in input results in a significant change in output.
The output length is constant regardless of input size.
It is infeasible to find two different inputs `m1` and `m2` such that `Hash(m1) = Hash(m2)`.

### Question 2.2 (Open Question)
Why is **HMAC** (Hash-based Message Authentication Code) considered stronger than simply appending a secret key to a message and hashing it (e.g., `Hash(Key || Message)`)? Mention the specific attack that HMAC prevents.

**Your Answer:** 

I don't remember this

### Question 2.3 (Select ALL correct options)
Regarding **Salting** in password storage:
- [ ] Depending on the implementation, the salt must be kept secret from the attacker.
- [ ] A unique salt prevents the use of pre-computed Rainbow Tables.
- [ ] Salting forces the attacker to brute-force each user's password individually.
- [ ] The salt increases the entropy of the user's password itself.
- [ ] The salt is stored in the database alongside the hashed password.

**Your Selection:** 
A unique salt prevents the use of pre-computed Rainbow Tables.
Salting forces the attacker to brute-force each user's password individually.
The salt increases the entropy of the user's password itself.
---

## 🔑 Topic 3: Symmetric Cryptography

### Question 3.1 (Select ALL correct options)
Select the statements that correctly describe **Block Cipher Modes of Operation**:
- [ ] **ECB** is the fastest mode because it requires no synchronization, but it is deterministic and leaks patterns.
- [ ] **CBC** requires an Initialization Vector (IV) that must be kept secret.
- [ ] **CTR** mode converts a block cipher into a stream cipher and allows random access (parallel decryption).
- [ ] In **CBC** mode, a bit error in one ciphertext block affects the decryption of only that specific block.
- [ ] **GCM** (Galois/Counter Mode) provides both confidentiality (Encryption) and authenticity (Integrity).

**Your Selection:** 
**CBC** requires an Initialization Vector (IV) that must be kept secret.
In **CBC** mode, a bit error in one ciphertext block affects the decryption of only that specific block.
 **GCM** (Galois/Counter Mode) provides both confidentiality (Encryption) and authenticity (Integrity).
### Question 3.2 (Open Question)
Explain the concepts of **Confusion** and **Diffusion** in the context of AES. Which specific component of the AES algorithm is responsible for Confusion, and which components are responsible for Diffusion?

**Your Answer:** 

I don't remember

### Question 3.3 (Select ALL correct options)
Which of the following are true regarding **AES** (Advanced Encryption Standard)?
- [ ] It is based on a Feistel Network structure.
- [ ] It operates on a fixed block size of 128 bits, regardless of the key size.
- [ ] It supports key sizes of 128, 192, and 256 bits.
- [ ] It is mathematically based on finite field arithmetic in $GF(2^8)$.
- [ ] Because it uses S-boxes, it is vulnerable to linear cryptanalysis if the S-boxes are not carefully chosen.

**Your Selection:** 
It supports key sizes of 128, 192, and 256 bits.
Because it uses S-boxes, it is vulnerable to linear cryptanalysis if the S-boxes are not carefully chosen.
It is mathematically based on finite field arithmetic in $GF(2^8)$.
### Question 3.4 (Open Question)
Why is reusing a **Nonce** in **CTR mode** (or any stream cipher) considered a catastrophic failure? What exactly can an attacker recover if they capture two messages encrypted with the same Key and Nonce?

**Your Answer:** 

I don't remember, idk what a nonce is

---

## 🌍 Topic 4: Asymmetric Cryptography & Protocols

### Question 4.1 (Select ALL correct options)
Which of the following statements about **Public Key Infrastructure (PKI)** and **Certificates** are correct?
- [ ] A **Digital Certificate** binds a Public Key to an Identity (Subject).
- [ ] If a **Root CA**'s private key is compromised, all certificates issued by it (and its intermediate CAs) are effectively compromised.
- [ ] A **CRL** (Certificate Revocation List) is used to check if a certificate has expired.
- [ ] The **CA** signs the certificate using the Subject's Public Key.
- [ ] The **CA** signs the certificate using its own (the CA's) Private Key.

**Your Selection:** 
 A **Digital Certificate** binds a Public Key to an Identity (Subject).
 If a **Root CA**'s private key is compromised, all certificates issued by it (and its intermediate CAs) are effectively compromised.
 A **CRL** (Certificate Revocation List) is used to check if a certificate has expired.
 The **CA** signs the certificate using its own (the CA's) Private Key.
### Question 4.2 (Open Question)
Describe the **Man-in-the-Middle (MITM)** attack on the unauthenticated **Diffie-Hellman** key exchange. How does using Digital Signatures (or PKI) prevent this attack?

**Your Answer:** 

The attacker can intercept the message between the parties, and can change the message and send it to the other party, like it would come from the first party.

### Question 4.3 (Select ALL correct options)
Regarding **RSA** and **ECC**:
- [ ] RSA's security relies on the Integer Factorization problem.
- [ ] ECC's security relies on the Discrete Logarithm problem over elliptic curves.
- [ ] A 256-bit ECC key provides roughly the same security level as a 3072-bit RSA key.
- [ ] RSA is generally faster at key generation than ECC.
- [ ] Both RSA and ECC are currently vulnerable to Shor's Algorithm (Quantum Computing).

**Your Selection:** 
RSA's security relies on the Integer Factorization problem.

### Question 4.4 (Open Question)
In a **Digital Signature** scheme (like RSA signatures), why do we sign the *Hash* of the message rather than the message itself? Give at least two reasons.

**Your Answer:** 
Because the purpose of digital signatures is to ensure the euthenticity and integrity of the message, not the confidentiality of the message.
Also signing only the has and not the entire message, makes it faster, because the hash has a maximum size of 256 bits, while the message can be longer, or can be a file

---

## 📉 Explanations for Common Mistakes & Missed Concepts

### 1. Data Integrity & Hashes
- **HMAC vs. Simple Hash (Q2.2):**
  - **The Problem:** Simply hashing `Hash(Key || Message)` is vulnerable to the **Length Extension Attack**. Attackers can append data to your message and calculate a valid new hash without knowing the key.
  - **The Fix:** HMAC uses a nested structure `H(Key ⊕ opad || H(Key ⊕ ipad || Message))` that "closes" the hash, preventing extension.

### 2. Symmetric Cryptography
- **Block Cipher Modes (Q3.1):**
  - **CBC IV:** The Initialization Vector (IV) does **not** need to be secret; it just needs to be random/unpredictable.
  - **CBC Error Propagation:** A bit error in ciphertext block 1 garbles plaintext block 1 entirely AND flips specific bits in plaintext block 2. It does not just affect one block.
- **Confusion vs. Diffusion (Q3.2):**
  - **Confusion:** Hides the relationship between key and ciphertext. Achieved by **SubBytes (S-Box)**.
  - **Diffusion:** Spreads the influence of a single input bit across the entire output. Achieved by **ShiftRows** and **MixColumns**.
- **AES Block Size (Q3.3):**
  - AES **always** uses a 128-bit block size, even if you use a 192-bit or 256-bit key. Rijndael (the precursor) supported other sizes, but the AES standard fixed it at 128.
- **Nonce Reuse in CTR (Q3.4):**
  - **Catastrophic Failure:** If you reuse a Nonce + Key pair, you generate the **same keystream**.
  - **Consequence:** `C1 ⊕ C2 = P1 ⊕ P2`. The attacker can XOR the two ciphertexts to remove the encryption entirely and recover the XOR of the plaintexts!

### 3. Public Key Infrastructure (PKI)
- **CRL vs. Expiration (Q4.1):**
  - A **CRL** (Certificate Revocation List) checks if a certificate was **revoked** (e.g., key stolen) before its time was up. Simple expiration is checked just by comparing the dates in the certificate.
- **ECC vs. RSA (Q4.3):**
  - **Key Size:** ECC is much more efficient. A 256-bit ECC key offers similar security to a 3072-bit RSA key.
  - **Quantum Threat:** Shor's Algorithm breaks **both** RSA (factoring) and ECC (discrete log).
