/*
 * main.cpp
 * Demonstration program that:
 *  1) Uses an RSA public key to recover a symmetric key (exam-style example)
 *  2) Uses the recovered key to decrypt an AES/DES-encrypted message
 *
 * Expected files:
 *  - pubISM.pem : PEM encoded RSA public key
 *  - key.sec    : RSA-encrypted symmetric key (binary)
 *  - Msg.enc    : IV || ciphertext (IV size depends on algorithm)
 *
 * Error behavior: exits with non-zero code on failure.
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "FileIO.h"

#include "RSAUtils.h"

#include "Symmetric.h"

// =============================================================
// MAIN: PUTTING IT ALL TOGETHER
// =============================================================
int main() {
    // ---------------------------------------------------------
    // SCENARIO 1: GET THE SYMMETRIC KEY VIA RSA
    // ---------------------------------------------------------
    std::cout << "Step 1: RSA Decrypting key.sec...\n";
    std::vector<unsigned char> recoveredKey = rsaDecryptFile("pubISM.pem", "key.sec");
    
    if (recoveredKey.empty()) {
        // Detailed errors are printed inside rsaDecryptFile
        return 1;
    }
    std::cout << "Key Retrieved! Size: " << recoveredKey.size() << " bytes." << std::endl;

    // ---------------------------------------------------------
    // SCENARIO 2: PREPARE IV AND DATA
    // ---------------------------------------------------------
    // Read the encrypted message file. Format used here: IV concatenated with ciphertext.
    // For AES-CBC the IV length is 16 bytes. For DES/3DES the IV length is 8 bytes.
    std::vector<unsigned char> fileContent = readFile("Msg.enc");
    if (fileContent.empty()) {
        std::cerr << "Failed to read Msg.enc or file empty." << std::endl;
        return 1;
    }
    if (fileContent.size() < 8) { // minimal IV size check
        std::cerr << "Msg.enc too small to contain an IV and ciphertext." << std::endl;
        return 1;
    }

    // Choose IV length according to algorithm you plan to use below.
    int ivLen = 16; // 16 for AES, change to 8 for DES/3DES
    if (fileContent.size() < ivLen) {
        std::cerr << "Msg.enc too small for selected IV length (" << ivLen << ")." << std::endl;
        return 1;
    }

    // Split IV and Ciphertext
    std::vector<unsigned char> iv(fileContent.begin(), fileContent.begin() + ivLen);
    std::vector<unsigned char> ciphertext(fileContent.begin() + ivLen, fileContent.end());

    // ---------------------------------------------------------
    // SCENARIO 3: DECRYPT (Change Algorithm Here!)
    // ---------------------------------------------------------
    std::cout << "Step 2: Decrypting Message...\n";

    // OPTIONS (Uncomment the one you need for the exam):
    
    // OPTION A: AES-128
    auto decrypted = symmetricOperation(ciphertext, recoveredKey, iv, EVP_aes_128_cbc(), 0);

    // OPTION B: DES (Key must be 8 bytes)
    // auto decrypted = symmetricOperation(ciphertext, recoveredKey, iv, EVP_des_cbc(), 0);

    // OPTION C: 3DES (Key must be 24 bytes)
    // auto decrypted = symmetricOperation(ciphertext, recoveredKey, iv, EVP_des_ede3_cbc(), 0);

    if (decrypted.empty()) return 1;

    // ---------------------------------------------------------
    // SCENARIO 4: WRITE TO DISK
    // ---------------------------------------------------------
    decrypted.push_back('\0'); // Add null term just for printing to console safely
    std::cout << "Message: " << decrypted.data() << std::endl;
    
    // Remove null terminator before writing to file (to keep file binary pure)
    decrypted.pop_back(); 
    writeFile("Msg.dec", decrypted);

    return 0;
}