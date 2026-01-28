#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

/*
 * Minimal AES-128-CBC decrypt (exam-style compact example)
 * - Key and IV are hard-coded as byte arrays for clarity in exams.
 * - Reads `Msg.enc` (ciphertext-only) from the current directory and
 *   prints the recovered plaintext to stdout.
 */

unsigned char myKey[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                          0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char myIV[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
                          0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };

int main() {
    // --- Read ciphertext file into a vector ---
    std::ifstream f("Msg.enc", std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        std::cerr << "Could not open Msg.enc" << std::endl; // quick error for exams
        return 1;
    }
    std::streamsize size = f.tellg();
    f.seekg(0, std::ios::beg);

    std::vector<unsigned char> enc(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(enc.data()), size)) {
        std::cerr << "Read error" << std::endl;
        return 1;
    }
    f.close();

    // --- Prepare output buffer with room for padding ---
    std::vector<unsigned char> out(enc.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));

    // --- Decrypt using OpenSSL EVP ---
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // Initialize for AES-128-CBC with our key/IV
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV);

    int len1 = 0, len2 = 0;
    // Process ciphertext
    EVP_DecryptUpdate(ctx, out.data(), &len1, enc.data(), static_cast<int>(enc.size()));

    // Finalize (checks padding). Return code != 1 indicates failure.
    if (EVP_DecryptFinal_ex(ctx, out.data() + len1, &len2) != 1) {
        std::cerr << "Decryption failed (bad key/IV or corrupted ciphertext)" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 2;
    }
    EVP_CIPHER_CTX_free(ctx);

    // Resize to actual plaintext length and print
    out.resize(len1 + len2);
    // Add a null terminator for safe printing as a C-string (plaintext may be text in examples)
    out.push_back('\0');
    std::cout << reinterpret_cast<char*>(out.data()) << std::endl;

    return 0;
}