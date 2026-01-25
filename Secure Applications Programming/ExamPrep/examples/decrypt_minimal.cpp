#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Exam Data (Key and IV)
unsigned char myKey[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
unsigned char myIV[]  = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 
                          0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

int main() {
    // ============================================
    // STEP 1: READ FILE (The C++ Way)
    // ============================================
    std::ifstream file("Msg.enc", std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open Msg.enc" << std::endl;
        return 1;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> encData(static_cast<size_t>(fileSize));
    if (!file.read(reinterpret_cast<char*>(encData.data()), fileSize)) {
        std::cerr << "Error reading Msg.enc" << std::endl;
        return 1;
    }
    file.close();

    // ============================================
    // STEP 2: OPENSSL DECRYPTION
    // ============================================
    std::vector<unsigned char> decData(static_cast<size_t>(fileSize) + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to allocate EVP_CIPHER_CTX" << std::endl;
        return 1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV) != 1) {
        std::cerr << "EVP_DecryptInit_ex failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int len1 = 0;
    int len2 = 0;

    if (EVP_DecryptUpdate(ctx, decData.data(), &len1, encData.data(), static_cast<int>(fileSize)) != 1) {
        std::cerr << "EVP_DecryptUpdate failed" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (EVP_DecryptFinal_ex(ctx, decData.data() + len1, &len2) != 1) {
        std::cerr << "Error: Decryption Failed (Wrong Key or Corrupted File?)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }

    int totalLen = len1 + len2;
    if (totalLen < static_cast<int>(decData.size())) {
        decData[totalLen] = '\0';
    } else {
        decData.push_back('\0');
    }

    std::cout << "Decrypted Message: " << reinterpret_cast<char*>(decData.data()) << std::endl;

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
