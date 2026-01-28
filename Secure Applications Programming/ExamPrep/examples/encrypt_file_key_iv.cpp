#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

/*
 * Minimal encrypt example (exam-style):
 * - Uses a fixed AES-128 key/IV (shown inline for clarity)
 * - Encrypts `examples/demo_plain.txt` if present, otherwise uses a small
 *   built-in demo plaintext and writes ciphertext-only to `examples/Msg.enc`.
 */
unsigned char key[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char iv[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };

int main() {
    // Read plaintext from a local demo file if present
    std::ifstream f("examples/demo_plain.txt", std::ios::binary | std::ios::ate);
    std::vector<unsigned char> plain;

    std::streamsize s = f.tellg(); 
    f.seekg(0, std::ios::beg);
    plain.resize(static_cast<size_t>(s));
    f.read(reinterpret_cast<char*>(plain.data()), s);
    f.close();
    

    // Encrypt with AES-128-CBC using OpenSSL EVP interface
    std::vector<unsigned char> out(plain.size() + 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len1 = 0, len2 = 0;

    EVP_EncryptUpdate(ctx, out.data(), &len1, plain.data(), static_cast<int>(plain.size()));

    EVP_EncryptFinal_ex(ctx, out.data() + len1, &len2);

    EVP_CIPHER_CTX_free(ctx);

    out.resize(len1 + len2);

    // Write ciphertext-only (no IV) to the examples folder so decrypt_minimal
    // can read it directly for a compact demonstration.
    std::ofstream o("examples/EncMsg.enc", std::ios::binary);

    o.write(reinterpret_cast<char*>(out.data()), out.size());
    o.close();

    std::cout << "Encrypted to examples/Msg.enc (ciphertext only)." << std::endl;
    return 0;
}
