#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Minimal decrypt example: reads examples/Msg.enc and writes examples/Msg.dec
unsigned char myKey[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char myIV[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };


/**
 * Example 1: Simple demo that decrypts a ciphertext file using a symmetric key
 * and IV that are provided directly in memory as vectors. This example is
 * intentionally minimal and self-contained for teaching purposes.
 *
 * Behavior:
 *  - Uses hard-coded demo key and IV (in vector form) defined below.
 *  - If the ciphertext file does not exist, the example will create a demo
 *    ciphertext by encrypting a small demo plaintext with those values.
 */
int main() {
    // Standalone minimal read/write helpers
    auto readFileSimple = [](const char* path)->std::vector<unsigned char>{
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f.is_open()) return {};
        std::streamsize s = f.tellg(); f.seekg(0, std::ios::beg);
        std::vector<unsigned char> buf(static_cast<size_t>(s));
        if (!f.read(reinterpret_cast<char*>(buf.data()), s)) return {};
        return buf;
    };

    auto writeFileSimple = [](const char* path, const std::vector<unsigned char>& data)->bool{
        std::ofstream o(path, std::ios::binary);
        if (!o.is_open()) return false;
        o.write(reinterpret_cast<const char*>(data.data()), data.size());
        return true;
    };

    const char* inPath = "examples/Msg.enc";
    const char* outPath = "examples/Msg.dec";

    std::vector<unsigned char> ciphertext = readFileSimple(inPath);
    if (ciphertext.empty()) {
        // Create demo plaintext and encrypt it to produce a ciphertext file
        std::string demo = "Demo plaintext for decrypt_mem example\n";
        std::vector<unsigned char> plain(demo.begin(), demo.end());

        std::vector<unsigned char> tmp(plain.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
        int l1=0,l2=0;
        EVP_EncryptUpdate(ctx, tmp.data(), &l1, plain.data(), static_cast<int>(plain.size()));
        EVP_EncryptFinal_ex(ctx, tmp.data()+l1, &l2);
        EVP_CIPHER_CTX_free(ctx);
        tmp.resize(l1+l2);
        writeFileSimple(inPath, tmp);
        ciphertext = std::move(tmp);
    }

    // Decrypt
    std::vector<unsigned char> out(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
    int dl1=0, dl2=0;
    EVP_DecryptUpdate(dctx, out.data(), &dl1, ciphertext.data(), static_cast<int>(ciphertext.size()));
    if (EVP_DecryptFinal_ex(dctx, out.data()+dl1, &dl2) != 1) { std::cerr << "Decryption failed" << std::endl; EVP_CIPHER_CTX_free(dctx); return 2; }
    EVP_CIPHER_CTX_free(dctx);

    out.resize(dl1+dl2);
    writeFileSimple(outPath, out);
    std::cout << "Decrypted written to: " << outPath << std::endl;
    return 0;
}
