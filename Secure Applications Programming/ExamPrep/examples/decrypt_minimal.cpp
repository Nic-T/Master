/*
 Minimal AES-128-CBC decryption example (exam-friendly)
 - Purpose: show the simple mechanism of reading a ciphertext, decrypting with
   OpenSSL EVP (AES-128-CBC) and printing the plaintext.
 - This implementation is intentionally minimal and focuses on the crypto
   mechanism rather than production-grade error handling.

 Notes:
 - Assumes ciphertext was produced with the same key/IV and fits in memory.
 - We allocate ciphertext_length + AES_block_size (16) for the plaintext to
   allow for PKCS#7 padding removed by EVP_DecryptFinal_ex.
 - `len1` and `len2` are output lengths (bytes written) from Update and Final.
*/

#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Exam Data (Key and IV)
unsigned char key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
unsigned char iv[]  = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 
                          0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

int main() {
    // ============================================
    // STEP 1: READ FILE (The C++ Way)
    // ============================================
    std::ifstream file("Msg.enc", std::ios::binary | std::ios::ate);

    // Opened with ios::ate so tellg() returns file size; rewind to start for reading
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> encData(fileSize);
    file.read(reinterpret_cast<char*>(encData.data()), fileSize);
    
    file.close();

    // Allocate output buffer: ciphertext size + one AES block (16) to allow for padding
    size_t outSize = static_cast<size_t>(fileSize) + 16; // AES block size
    std::vector<unsigned char> decData(outSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    // len1 = bytes written by EVP_DecryptUpdate, len2 = bytes from EVP_DecryptFinal_ex
    int len1 = 0;
    int len2 = 0;

    // Decrypt main body (sets len1)
    EVP_DecryptUpdate(ctx, decData.data(), &len1, encData.data(), static_cast<int>(fileSize));

    // Finalize decryption, remove padding and write remaining bytes at decData+len1 (sets len2)
    EVP_DecryptFinal_ex(ctx, decData.data() + len1, &len2);

    int totalLen = len1 + len2;

    // Null-terminate plaintext for safe printing as a C-string (we allocated +16 bytes)
    decData[totalLen] = '\0';
    std::cout << "Decrypted Data: " << reinterpret_cast<char*>(decData.data()) << std::endl;


    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
