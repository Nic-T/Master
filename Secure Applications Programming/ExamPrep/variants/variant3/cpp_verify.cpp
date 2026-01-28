/*
 * VARIANT 3: Signature Verification + AES-CTR Decryption
 * 
 * This variant verifies a digital signature, then decrypts with stream cipher.
 * 
 * STEPS:
 *   1. Load public key from pub.pem
 *   2. Verify Signature.sig against Data.bin
 *   3. Decrypt Encrypted.bin using AES-CTR (stream cipher mode)
 *   4. Write verified_content.txt
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main() {
    // ============================================
    // STEP 1: LOAD RSA PUBLIC KEY
    // ============================================
    // TEACHER MAY CHANGE: filename "pub.pem"
    FILE* fp = fopen("pub.pem", "r");
    
    EVP_PKEY* pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    // ============================================
    // STEP 2: READ DATA AND SIGNATURE FILES
    // ============================================
    // TEACHER MAY CHANGE: filenames
    
    // Read the original data
    std::ifstream dataFile("Data.bin", std::ios::binary | std::ios::ate);
    std::streamsize dataSize = dataFile.tellg();
    dataFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> data(dataSize);
    dataFile.read(reinterpret_cast<char*>(data.data()), dataSize);
    dataFile.close();

    // Read the signature
    std::ifstream sigFile("Signature.sig", std::ios::binary | std::ios::ate);
    std::streamsize sigSize = sigFile.tellg();
    sigFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> signature(sigSize);
    sigFile.read(reinterpret_cast<char*>(signature.data()), sigSize);
    sigFile.close();

    // ============================================
    // STEP 3: VERIFY SIGNATURE
    // ============================================
    // TEACHER MAY CHANGE: digest algorithm (EVP_sha1, EVP_sha512, etc.)
    
    EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();

    // Initialize verification with SHA-256
    EVP_DigestVerifyInit(mdCtx, NULL, EVP_sha256(), NULL, pkey);

    // Add the data to verify
    EVP_DigestVerifyUpdate(mdCtx, data.data(), data.size());

    // Verify the signature
    int verifyResult = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());

    EVP_MD_CTX_free(mdCtx);
    EVP_PKEY_free(pkey);

    if (verifyResult == 1) {
        std::cout << "Signature VALID!" << std::endl;
    } else {
        std::cout << "Signature INVALID!" << std::endl;
        return 1;  // Stop if signature fails
    }

    // ============================================
    // STEP 4: AES-CTR DECRYPTION (Stream Cipher)
    // ============================================
    // CTR mode = no padding needed, acts like stream cipher
    // TEACHER MAY CHANGE: to EVP_aes_128_cbc() or other modes
    
    // Read encrypted file (first 16 bytes = IV/nonce, rest = ciphertext)
    std::ifstream encFile("Encrypted.bin", std::ios::binary | std::ios::ate);
    std::streamsize encSize = encFile.tellg();
    encFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encData(encSize);
    encFile.read(reinterpret_cast<char*>(encData.data()), encSize);
    encFile.close();

    // Extract IV (first 16 bytes) and ciphertext
    unsigned char iv[16];
    std::copy(encData.begin(), encData.begin() + 16, iv);
    std::vector<unsigned char> ciphertext(encData.begin() + 16, encData.end());

    // Hardcoded key for exam (TEACHER MAY PROVIDE different key)
    unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    std::vector<unsigned char> plaintext(ciphertext.size() + 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // AES-128-CTR: stream cipher mode, no padding issues
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    int len1 = 0, len2 = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len1,
                      ciphertext.data(), ciphertext.size());

    EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2);

    int totalLen = len1 + len2;
    plaintext.resize(totalLen);

    EVP_CIPHER_CTX_free(ctx);

    // ============================================
    // STEP 5: WRITE OUTPUT
    // ============================================
    std::ofstream outFile("verified_content.txt", std::ios::binary);
    outFile.write(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    outFile.close();

    std::cout << "Done! Wrote verified_content.txt (" << totalLen << " bytes)" << std::endl;
    return 0;
}
