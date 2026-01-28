/*
 * VARIANT 2: RSA Private Key Decryption + 3DES-ECB Decryption
 * 
 * Uses Triple DES (DESede) instead of AES.
 * ECB mode = no IV needed (simpler but less secure).
 * 
 * STEPS:
 *   1. Load RSA private key from priv.pem
 *   2. Decrypt session.key to get 3DES key (24 bytes)
 *   3. Decrypt Database.enc using 3DES-ECB
 *   4. Write plaintext.db
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>

int main() {
    // ============================================
    // STEP 1: LOAD RSA PRIVATE KEY FROM PEM
    // ============================================
    // TEACHER MAY CHANGE: filename "priv.pem"
    // DIFFERENCE FROM V1: using PRIVATE key, not public
    FILE* fp = fopen("priv.pem", "r");
    
    // Read private key (may have password - NULL means no password)
    // TEACHER MAY CHANGE: password callback for encrypted private key
    RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    // ============================================
    // STEP 2: DECRYPT session.key TO GET 3DES KEY
    // ============================================
    // TEACHER MAY CHANGE: filename "session.key"
    std::ifstream keyFile("session.key", std::ios::binary | std::ios::ate);
    
    std::streamsize keySize = keyFile.tellg();
    keyFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encKey(keySize);
    keyFile.read(reinterpret_cast<char*>(encKey.data()), keySize);
    keyFile.close();

    // Buffer for decrypted 3DES key (24 bytes for 3DES)
    std::vector<unsigned char> desKey(RSA_size(rsa));

    // RSA_private_decrypt: decrypt data encrypted with public key
    // TEACHER MAY CHANGE: padding type
    int desKeyLen = RSA_private_decrypt(
        encKey.size(),          // input length
        encKey.data(),          // input data
        desKey.data(),          // output buffer
        rsa,                    // RSA key
        RSA_PKCS1_PADDING       // padding mode
    );
    desKey.resize(desKeyLen);   // Should be 24 bytes for 3DES

    RSA_free(rsa);

    // ============================================
    // STEP 3: READ ENCRYPTED DATABASE FILE
    // ============================================
    // TEACHER MAY CHANGE: filename "Database.enc"
    std::ifstream dataFile("Database.enc", std::ios::binary | std::ios::ate);
    
    std::streamsize dataSize = dataFile.tellg();
    dataFile.seekg(0, std::ios::beg);
    std::vector<unsigned char> encData(dataSize);
    dataFile.read(reinterpret_cast<char*>(encData.data()), dataSize);
    dataFile.close();

    // ============================================
    // STEP 4: 3DES-ECB DECRYPTION
    // ============================================
    // ECB mode = no IV needed! (simpler)
    // TEACHER MAY CHANGE: EVP_des_ede3_cbc() if CBC mode requested
    
    std::vector<unsigned char> plaintext(encData.size() + 8);  // +8 for DES block

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // 3DES-ECB: key is 24 bytes, NO IV (NULL)
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_ecb(), NULL, desKey.data(), NULL);

    int len1 = 0, len2 = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &len1, 
                      encData.data(), encData.size());

    EVP_DecryptFinal_ex(ctx, plaintext.data() + len1, &len2);

    int totalLen = len1 + len2;
    plaintext.resize(totalLen);

    EVP_CIPHER_CTX_free(ctx);

    // ============================================
    // STEP 5: WRITE OUTPUT
    // ============================================
    // TEACHER MAY CHANGE: output filename
    std::ofstream outFile("plaintext.db", std::ios::binary);
    outFile.write(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
    outFile.close();

    std::cout << "Done! Wrote plaintext.db (" << totalLen << " bytes)" << std::endl;
    return 0;
}
