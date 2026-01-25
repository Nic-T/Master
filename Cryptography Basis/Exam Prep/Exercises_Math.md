# Cryptography Math Exercises

Practical math exercises for cryptography. Write your calculations and answers below each problem.

---

## 🔢 Quick Reference: Conversion Methods

### Hex ↔ Binary Formula (The 8-4-2-1 Rule)
Instead of memorizing the whole table, use the **8-4-2-1** rule for **each hex digit**.

1. **Split** the hex string into individual digits.
2. **Convert** each digit using the values 8, 4, 2, 1.
   - does it fit 8? yes=1, no=0. Remainder?
   - does remainder fit 4? ... and so on.

**Example: 0xB7**
1. **Digit B (11)**:
   - 8? Yes (11-8=3) → **1**
   - 4? No (3<4)     → **0**
   - 2? Yes (3-2=1)  → **1**
   - 1? Yes (1-1=0)  → **1**
   - Result: **1011**

2. **Digit 7**:
   - 8? No (7<8)     → **0**
   - 4? Yes (7-4=3)  → **1**
   - 2? Yes (3-2=1)  → **1**
   - 1? Yes (1-1=0)  → **1**
   - Result: **0111**

**Combine:** 1011 0111

### Calculating Logarithms (ln and log₂)
You need `log₂` for entropy, but calculators often only have `ln` (Natural Log, base *e* approx 2.718).

**Formula:**
`log₂(x) = ln(x) / ln(2)`
`log₂(x) ≈ ln(x) / 0.693`

**Without a calculator (Estimation):**
`log₂(x)` is basically "how many times do I multiply 2 to get x?" OR "how many bits to write the number x?"

- `log₂(16)` → `2 × 2 × 2 × 2 = 16` (4 times) → **4**
- `log₂(1000)` → `2^10 = 1024` (close to 1000) → **approx 10**
- `log₂(1,000,000)` → `2^20` (approx 1 million) → **approx 20**

**Common Powers of 2:**
- `2^10` ≈ 1 Thousand (10 bits)
- `2^20` ≈ 1 Million (20 bits)
- `2^30` ≈ 1 Billion (30 bits)

---

## Math 1: XOR Operations

### Exercise M1.1: Calculate XOR
```
a) 10110101 ⊕ 11001100 = ?
```
**Your Answer:** 
10110101
11001100
01111001
```
b) 0xAB ⊕ 0x5F = ?
   Hint: Convert to binary first
   0xAB = A = 10 B=11
   10-8=2 1
   2<4 => 0
   2-2=0 => 1
   0<1 => 0
   A = 1010
   11-8 = 3 1
   3<4 =>0
   3-2=1 1
   1-1=0 1
   1011

   0xAB = 1010 1011
   0x5F = ________
   5 
   5<8 0
   5-4 =1 1
   1 <2 0
   1-1=0 1

   0101
   F = 1111

   so 0x5F = 0101 1111



   XOR  = ________
```
**Your Answer:** 

1010 1011
0101 1111
1111 0100


```
c) Verify: (A ⊕ B) ⊕ B = A, with A = 10101010, B = 11110000
   Step 1: A ⊕ B = ?
   Step 2: Result ⊕ B = ?
   Does it equal A?
```
**Your Answer:** 

1010 1010
1111 0000
0101 1010

0101 1010
1111 0000
1010 1010

it equals A

---

### Exercise M1.2: Swap Two Variables Using XOR
```
A = 25 (binary: 00011001)
B = 42 (binary: 00101010)

Step 1: A = A ⊕ B = 00011001 ⊕ 00101010 = ?
Step 2: B = A ⊕ B = (result) ⊕ 00101010 = ?
Step 3: A = A ⊕ B = (result from step 1) ⊕ (result from step 2) = ?

Final: A = ? (should be 42), B = ? (should be 25)
```
**Your Work:**

0001 1001
0010 1010
0011 0011

A = 0011 0011

0011 0011
0010 1010
0001 1001

0011 0011
0001 1001
0010 1010

**Explanation: How to convert back to decimal:**
Just add up the values of the positions where there is a **1**.

**For 25 (0001 1001):**
| 128 | 64 | 32 | **16** | **8** | 4 | 2 | **1** |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | 0 | **1** | **1** | 0 | 0 | **1** |
Calculation: `16 + 8 + 1` = **25**

**For 42 (0010 1010):**
| 128 | 64 | **32** | 16 | **8** | 4 | **2** | 1 |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 0 | 0 | **1** | 0 | **1** | 0 | **1** | 0 |
Calculation: `32 + 8 + 2` = **42**

**Your Answer:** 

---

## Math 2: Entropy Calculations

### Exercise M2.1: Calculate Entropy in Bits
```
a) A single die roll (6 possible outcomes)
   H = log₂(6) = log(6) / log(2) = ?
```
**Your Answer:** 

log2(2*3) = log2(2) + log2(3) = 1+ log2(3) = 1+1.585= 2.585
3 bits

```
b) A 4-digit PIN (0-9 for each digit)
   Total possibilities = 10^4 = 10,000
   H = log₂(10,000) = 4 × log₂(10) = 4 × 3.32 = ?
```
**Your Answer:** 

2^10 = 1024

2^11 = 2048

2^12 = 4096

2^13 = 8192

2^14 = 16384

so 14 bits 

```
c) An 8-character password using:
   
   Lowercase only (26 chars):
   H = 8 × log₂(26) = 8 × 4.7 = ?
   
   Lowercase + uppercase (52 chars):
   H = 8 × log₂(52) = 8 × 5.7 = ?
   
   Alphanumeric + symbols (94 chars):
   H = 8 × log₂(94) = 8 × 6.55 = ?
```
**Your Answers:** 

for the first one it is 8*4.7 = 38

for the second one it is 8*5.7 = 46

for the third one it is 8*6.55 = 53

---

### Exercise M2.2: Real-World Security Analysis
```
A key is 256 bits long. If derived from a 6-character lowercase password, 
what is the ACTUAL entropy?

Calculation: 6 × log₂(26) = 6 × 4.7 = ?

it goes up to 28 bits

Is this secure for a 256-bit algorithm? Why or why not?
```
It is not secure because the number of bits are not enough and the others will be simply added with 0x00

**Your Answer:** 

---

## Math 3: Modular Arithmetic

### Exercise M3.1: Basic Modulo Operations
```
a) 17 mod 5 = ?
   17 = 5 × 3 + 2, so answer is 2

b) 100 mod 7 = ?
   100 = 7 × ? + ?
2
c) (15 + 28) mod 12 = ?
   = 43 mod 12 = ?
7
d) (7 × 8) mod 10 = ?
   = 56 mod 10 = ?
```
6
**Your Answers:**
a) 
b) 
c) 
d) 

---

### Exercise M3.2: Clock Arithmetic
```
If it's 10:00 now, what time will it be in 27 hours?

Calculation: (10 + 27) mod 24 = 37 mod 24 = ?
```
**Your Answer:** 
13
---

### Exercise M3.3: Modular Exponentiation (Important for RSA!)
```
Calculate 3^5 mod 7 step by step:

3^1 mod 7 = 3
3^2 mod 7 = 9 mod 7 = ?
3^3 mod 7 = 3 × (3^2) mod 7 = 3 × ? = ? mod 7 = ?
3^4 mod 7 = 3 × (3^3) mod 7 = 3 × ? = ? mod 7 = ?
3^5 mod 7 = 3 × (3^4) mod 7 = 3 × ? = ? mod 7 = ?
```
**Your Work:**

3^1 mod 7 = 3
3^2 mod 7 = 9 mod 7 = 2
3^3 mod 7 = 3 × (3^2) mod 7 = 3 × 2 = 6 mod 7 = 6
3^4 mod 7 = 3 × (3^3) mod 7 = 3 × 6 = 18 mod 7 = 4
3^5 mod 7 = 3 × (3^4) mod 7 = 3 × 4 = 12 mod 7 = 5


**Final Answer:** 3^5 mod 7 = 

---

### Exercise M3.4: More Modular Exponentiation
```
Calculate 2^10 mod 13 using square-and-multiply:

2^1 = 2
2^2 = 4
2^4 = 4^2 = 16 mod 13 = ?
2^8 = ?^2 mod 13 = ?
**Your Work:**

2^4 mod 13 = 16 mod 13 = 3
2^8 mod 13 = (2^4)^2 mod 13 = 3^2 = 9
2^10 mod 13 = 2^8 * 2^2 mod 13 = 9 * 4 mod 13 = 36 mod 13 = 10

**🎓 Detailed Explanation of the Error:**
You calculated `2^8` as `8^2`. This is why it was wrong:
*   The notation `2^8` means "2 to the power of 8".
*   In the previous step, you found `2^4 = 3` (in modulo 13).
*   To get from `2^4` to `2^8`, you **SQUARE** both sides: 
    *   $(2^4)^2 = 2^8$
*   Therefore, you must square the **RESULT** of `2^4`:
    *   $3^2 = 9$

**Rule of Thumb:**
In Square-and-Multiply, you never use the exponent (like 4, 8, 16) as a number in your calculation. You only use the **RESULTS** from the previous lines and square them.


**Final Answer:** 

---

## Math 4: Birthday Paradox

### Exercise M4.1: Collision Probability Thresholds
```
For a hash function with n-bit output, you need approximately 2^(n/2) attempts 
for a 50% collision chance.

Calculate for each algorithm:
- MD5 (128-bit): 2^(128/2) = 2^64 ✓ (given)
- SHA-1 (160-bit): 2^(160/2) = 2^? = ?
- SHA-256 (256-bit): 2^(256/2) = 2^? = ?
- SHA-512 (512-bit): 2^(512/2) = 2^? = ?
```
**Your Answers:**
SHA-1: 2^80
SHA-256: 2^128
SHA-512: 2^256

---

### Exercise M4.2: Birthday Problem Calculation
```
In a room of 23 people, probability of shared birthday ≈ 50%

This comes from: √365 ≈ ?

For 30 people, is the probability higher or lower than 50%?
Why?
```
**Your Answer:** 
it is higher
---

You're designing a system that uses 64-bit random session IDs.
After how many sessions should you expect a 50% chance of collision?

Answer: 2^(64/2) = 2^32 = ? sessions

Is this enough for a busy website?
```
**Your Answer:** 
2^32 = 4,294,967,296

no, 128 minimum would be better
---

## Math 5: RSA Calculations

### Exercise M5.1: Key Generation (Small Numbers)
```
Given: p = 3, q = 11

Step 1: Calculate n = p × q = ?
Step 2: Calculate φ(n) = (p-1) × (q-1) = ?
Step 3: Choose e = 3 (must be coprime to φ(n), i.e., gcd(e, φ(n)) = 1)
Step 4: Calculate d such that e × d ≡ 1 (mod φ(n))
        3 × d ≡ 1 (mod 20)
        Try d = 7: 3 × 7 = 21, 21 mod 20 = ?
        
Public Key: (e, n) = (?, ?)
Private Key: (d, n) = (?, ?)

---

## Math 5: RSA Calculations

### Exercise M5.1: Key Generation (Small Numbers)
```
Given: p = 3, q = 11

Step 1: Calculate n = p × q = ?
Step 2: Calculate φ(n) = (p-1) × (q-1) = ?
Step 3: Choose e = 3 (must be coprime to φ(n), i.e., gcd(e, φ(n)) = 1)
Step 4: Calculate d such that e × d ≡ 1 (mod φ(n))
        3 × d ≡ 1 (mod 20)
        Try d = 7: 3 × 7 = 21, 21 mod 20 = ?
        
Public Key: (e, n) = (?, ?)
Private Key: (d, n) = (?, ?)
```
**Your Work:**




**Your Answers:**
n = 
φ(n) = 
d = 
Public Key = 
Private Key = 

---

### Exercise M5.2: RSA Encryption/Decryption
```
Using: n = 33, e = 3, d = 7

ENCRYPTION:
Message M = 5
Ciphertext C = M^e mod n = 5^3 mod 33 = 125 mod 33 = ?

DECRYPTION:
Ciphertext C = (your answer above)
Decrypted M = C^d mod n = ?^7 mod 33 = ?

Hint for ?^7 mod 33:
?^2 mod 33 = ?
?^4 = (?^2)^2 mod 33 = ?
?^6 = ?^4 × ?^2 mod 33 = ?
?^7 = ?^6 × ? mod 33 = ?

Verify: Does decrypted M = 5?
```
**Your Work:**




**Your Answer:** 

---

### Exercise M5.3: Why RSA Works (Larger Example)
```
Given: p = 61, q = 53

1. Calculate n = p × q = ?
2. Calculate φ(n) = (p-1) × (q-1) = ?
3. e = 17 (commonly used)
4. Find d where 17 × d ≡ 1 (mod φ(n))
   Hint: d = 2753 (verify: 17 × 2753 mod ? = 1)
```
**Your Work:**




**Your Answer:** 

---

## Math 6: Diffie-Hellman Key Exchange

### Exercise M6.1: Complete DH Exchange Step-by-Step
```
Public Parameters: p = 23, g = 5

ALICE (secret a = 6):
Step 1: Calculate A = g^a mod p = 5^6 mod 23
        5^2 mod 23 = 25 mod 23 = ?
        5^4 mod 23 = (5^2)^2 mod 23 = ?^2 mod 23 = ?
        5^6 mod 23 = 5^4 × 5^2 mod 23 = ? × ? mod 23 = ?
        Alice sends A = ? to Bob

BOB (secret b = 15):
Step 2: Calculate B = g^b mod p = 5^15 mod 23
        5^1 = 5
        5^2 = 2 (calculated above)
        5^4 = 4 (calculated above)
        5^8 = 4^2 mod 23 = 16
        5^15 = 5^8 × 5^4 × 5^2 × 5^1 mod 23 = 16 × 4 × 2 × 5 mod 23 = ?
        Bob sends B = ? to Alice

SHARED SECRET CALCULATION:
Step 3 (Alice): s = B^a mod p = ?^6 mod 23 = ?
Step 4 (Bob): s = A^b mod p = ?^15 mod 23 = ?

Both should get the SAME shared secret!
```
**Your Work:**




**Your Answers:**
A (Alice's public value) = 
B (Bob's public value) = 
Shared Secret = 

---

### Exercise M6.2: Simpler DH Example
```
Public: p = 11, g = 2
Alice's secret: a = 3
Bob's secret: b = 5

A = 2^3 mod 11 = ?
B = 2^5 mod 11 = ?

Alice's shared secret = B^3 mod 11 = ?
Bob's shared secret = A^5 mod 11 = ?

Do they match?
```
**Your Work:**




**Your Answer:** 

---

## Math 7: Finite Field Arithmetic (GF(2^8) for AES)

### Exercise M7.1: Polynomial Representation
```
In AES, bytes are treated as polynomials in GF(2^8).
Each bit represents a coefficient of x^n.

Convert bytes to polynomials:
a) 0x53 = 01010011 = x^6 + x^4 + x + 1 ✓ (given)
   (positions 6, 4, 1, 0 have 1s)

b) 0x83 = 10000011 = ?
   Binary: 1000 0011
   Which bit positions have 1s? 7, 1, 0
   Polynomial = ?

c) 0xCA = 11001010 = ?
   Which bit positions have 1s?
   Polynomial = ?
```
**Your Answers:**
b) 
c) 

---

### Exercise M7.2: XOR as Polynomial Addition
```
In GF(2), addition is XOR. So x + x = 0.

0x53 ⊕ 0xCA = ?

In binary:
0x53 = 01010011
0xCA = 11001010
XOR  = ?????????

In polynomial form:
(x^6 + x^4 + x + 1) + (x^7 + x^6 + x^3 + x) = ?

Note: x^6 + x^6 = 0 and x + x = 0

Simplified polynomial = ?
```
**Your Work:**




**Your Answer:** 

---

## 📊 Answer Key

### Math 1 Answers
- M1.1a: 01111001
- M1.1b: 0xAB = 10101011, 0x5F = 01011111, XOR = 11110100 = 0xF4
- M1.1c: 10101010 ⊕ 11110000 = 01011010, then 01011010 ⊕ 11110000 = 10101010 ✓
- M1.2: After 3 XOR operations, A = 42 (00101010), B = 25 (00011001)

### Math 2 Answers
- M2.1a: log₂(6) = 2.58 bits
- M2.1b: 4 × log₂(10) = 13.3 bits
- M2.1c: Lowercase = 37.6 bits, Mixed case = 45.6 bits, All chars = 52.4 bits
- M2.2: 6 × 4.7 = 28.2 bits - NOT SECURE! Only 28 bits of actual entropy for a 256-bit algorithm

### Math 3 Answers
- M3.1: a) 2, b) 2, c) 7, d) 6
- M3.2: 13 (1:00 PM)
- M3.3: 3² = 2, 3³ = 6, 3⁴ = 4, 3⁵ = 5
- M3.4: 2^4 = 3, 2^8 = 9, 2^10 = 36 mod 13 = 10

### Math 4 Answers
- M4.1: SHA-1 = 2^80, SHA-256 = 2^128, SHA-512 = 2^256
- M4.2: √365 ≈ 19.1. For 30 people, probability is HIGHER (about 70%)
- M4.3: 2^32 ≈ 4.3 billion sessions - probably fine for most websites

### Math 5 Answers
- M5.1: n = 33, φ(n) = 20, d = 7. Public = (3, 33), Private = (7, 33)
- M5.2: C = 125 mod 33 = 26. Decryption: 26^7 mod 33 = 5 ✓
- M5.3: n = 3233, φ(n) = 3120, verify 17 × 2753 = 46801, 46801 mod 3120 = 1 ✓

### Math 6 Answers
- M6.1: 5² = 2, 5⁴ = 4, 5⁶ = 8. A = 8. B = 19. Shared secret = 2
- M6.2: A = 8, B = 10. Alice: 10^3 mod 11 = 10. Bob: 8^5 mod 11 = 10. Match! ✓

### Math 7 Answers
- M7.1b: x^7 + x + 1
- M7.1c: x^7 + x^6 + x^3 + x
- M7.2: Binary XOR = 10011001 = 0x99. Polynomial = x^7 + x^4 + x^3 + 1
