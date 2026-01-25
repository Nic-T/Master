#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Minimal main: AES-128-CBC decrypt using a hard-coded key and IV (exam-style)
unsigned char myKey[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char myIV[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };

int main() {
    // Read file
    std::ifstream f("Msg.enc", std::ios::binary | std::ios::ate);
    if (!f.is_open()) { std::cerr << "Could not open Msg.enc" << std::endl; return 1; }
    std::streamsize s = f.tellg(); f.seekg(0, std::ios::beg);
    std::vector<unsigned char> enc(static_cast<size_t>(s));
    if (!f.read(reinterpret_cast<char*>(enc.data()), s)) { std::cerr << "Read error" << std::endl; return 1; }
    f.close();

    // Decrypt
    std::vector<unsigned char> out(enc.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
    int l1=0, l2=0;
    EVP_DecryptUpdate(ctx, out.data(), &l1, enc.data(), static_cast<int>(enc.size()));
    if (EVP_DecryptFinal_ex(ctx, out.data()+l1, &l2) != 1) { std::cerr << "Decryption failed" << std::endl; EVP_CIPHER_CTX_free(ctx); return 2; }
    EVP_CIPHER_CTX_free(ctx);

    out.resize(l1+l2);
    out.push_back('\0');
    std::cout << reinterpret_cast<char*>(out.data()) << std::endl;
    return 0;
}