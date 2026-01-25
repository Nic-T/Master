#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Minimal encrypt: AES-128-CBC encrypt using hard-coded key/IV
unsigned char myKey[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char myIV[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };

int main() {
    // Read plaintext (demo_plain.txt)
    std::ifstream f("examples/demo_plain.txt", std::ios::binary | std::ios::ate);
    std::vector<unsigned char> plain;
    if (f.is_open()) {
        std::streamsize s = f.tellg(); f.seekg(0, std::ios::beg);
        plain.resize(static_cast<size_t>(s));
        f.read(reinterpret_cast<char*>(plain.data()), s);
        f.close();
    } else {
        std::string demo = "Demo plaintext for encrypt_minimal example\n";
        plain.assign(demo.begin(), demo.end());
    }

    // Encrypt
    std::vector<unsigned char> out(plain.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
    int l1=0, l2=0;
    EVP_EncryptUpdate(ctx, out.data(), &l1, plain.data(), static_cast<int>(plain.size()));
    EVP_EncryptFinal_ex(ctx, out.data()+l1, &l2);
    EVP_CIPHER_CTX_free(ctx);

    out.resize(l1+l2);
    // Write ciphertext-only (no IV prefix) to examples/Msg.enc
    std::ofstream o("examples/Msg.enc", std::ios::binary);
    o.write(reinterpret_cast<char*>(out.data()), out.size());
    o.close();

    std::cout << "Encrypted to examples/Msg.enc (ciphertext only)." << std::endl;
    return 0;
}
