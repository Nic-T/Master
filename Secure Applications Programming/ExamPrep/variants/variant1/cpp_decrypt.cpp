/*
 * VARIANT 1: RSA Key Extraction + AES-CBC Decryption
 * 
 * This is the most likely exam scenario. Simple and compact.
 * 
 * STEPS:
 *   1. Load RSA public key from pubISM.pem
 *   2. Decrypt key.sec to get AES key (using RSA public decrypt)
 *   3. Decrypt Msg.enc (first 16 bytes = IV, rest = ciphertext)
 *   4. Write decrypted_Msg.bin
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main() {
    // ============================================
    // STEP 1: LOAD RSA PUBLIC KEY FROM PEM FILE
    // ============================================
    // TEACHER MAY CHANGE: filename "pubISM.pem" to something else
    FILE* fp = fopen("pubISM.pem", "r");
    
    // Read the public key (PEM format)
    RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    // ============================================
    // STEP 2: DECRYPT key.sec TO GET AES KEY
    // ============================================
    // TEACHER MAY CHANGE: filename "key.sec" to something else
    std::ifstream keyFile("key.sec", std::ios::binary | std::ios::ate);
    
    // Read entire file into vector
    std::streamsize keySize = keyFile.tellg();
    keyFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encKey(keySize);
    keyFile.read(reinterpret_cast<char*>(encKey.data()), keySize);
    keyFile.close();

    // Prepare buffer for decrypted AES key
    std::vector<unsigned char> aesKey(RSA_size(rsa));

    // RSA_public_decrypt: recovers data encrypted with private key
    // TEACHER MAY CHANGE: padding type (RSA_PKCS1_PADDING, RSA_NO_PADDING, etc.)
    int aesKeyLen = RSA_public_decrypt(
        encKey.size(),          // input length
        encKey.data(),          // input data
        aesKey.data(),          // output buffer
        rsa,                    // RSA key
        RSA_PKCS1_PADDING       // padding mode
    );
    aesKey.resize(aesKeyLen);   // Trim to actual size (16 or 32 bytes usually)

    RSA_free(rsa);              // Done with RSA

    // ============================================
    // STEP 3: READ Msg.enc (IV + CIPHERTEXT)
    // ============================================
    // TEACHER MAY CHANGE: filename "Msg.enc"
    std::ifstream msgFile("Msg.enc", std::ios::binary | std::ios::ate);
    
    std::streamsize msgSize = msgFile.tellg();
    msgFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encData(msgSize);
    msgFile.read(reinterpret_cast<char*>(encData.data()), msgSize);
    msgFile.close();

    // First 16 bytes = IV (Initialization Vector)
    // TEACHER MAY CHANGE: IV could be separate file, or IV could be all zeros
    unsigned char iv[16];
    std::copy(encData.begin(), encData.begin() + 16, iv);

    // Rest = actual ciphertext
    std::vector<unsigned char> ciphertext(encData.begin() + 16, encData.end());

    // ============================================
    // STEP 4: AES-CBC DECRYPTION
    // ============================================
    // TEACHER MAY CHANGE: algorithm (EVP_aes_256_cbc, EVP_des_ede3_cbc, etc.)
    const EVP_CIPHER* cipher = (aesKey.size() == 32) 
        ? EVP_aes_256_cbc() 
        : EVP_aes_128_cbc();

    // Allocate output buffer (ciphertext + 1 block for padding)
    std::vector<unsigned char> plaintext(ciphertext.size() + 16);

    // Create context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Initialize decryption
    EVP_DecryptInit_ex(ctx, cipher, NULL, aesKey.data(), iv);

    int len1 = 0, len2 = 0;

    // Decrypt main body
    EVP_DecryptUpdate(ctx, plaintext.data(), &len1, 
                      ciphertext.data(), ciphertext.size());

    // Finalize (removes padding)
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2);

    int totalLen = len1 + len2;
    plaintext.resize(totalLen);

    EVP_CIPHER_CTX_free(ctx);

    // ============================================
    // STEP 5: WRITE OUTPUT FILE
    // ============================================
    // TEACHER MAY CHANGE: output filename
    std::ofstream outFile("decrypted_Msg.bin", std::ios::binary);
    outFile.write(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    outFile.close();

    std::cout << "Done! Wrote decrypted_Msg.bin (" << totalLen << " bytes)" << std::endl;
    return 0;
}
