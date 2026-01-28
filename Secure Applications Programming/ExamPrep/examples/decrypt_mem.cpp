#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>

// Minimal decrypt example: reads examples/Msg.enc and writes examples/Msg.dec
// Hard-coded key/IV are used to keep this an exam-style compact example.
unsigned char myKey[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
unsigned char myIV[]  = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };

int main() {
    // Simple helpers to keep this example self-contained; use your project's
    // IO helpers in real code.
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

    const char* inPath = "examples/Msg.enc";   // expected ciphertext-only file
    const char* outPath = "examples/Msg.dec"; // decrypted plaintext output

    // If the ciphertext file is missing for the demo, create a small demo
    // ciphertext by encrypting a short plaintext with the same key/IV.
    std::vector<unsigned char> ciphertext = readFileSimple(inPath);
    if (ciphertext.empty()) {
        std::string demo = "Demo plaintext for decrypt_mem example\n";
        std::vector<unsigned char> plain(demo.begin(), demo.end());

        std::vector<unsigned char> tmp(plain.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        // Encrypt demo plaintext using AES-128-CBC
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
        int l1=0,l2=0;
        EVP_EncryptUpdate(ctx, tmp.data(), &l1, plain.data(), static_cast<int>(plain.size()));
        EVP_EncryptFinal_ex(ctx, tmp.data()+l1, &l2);
        EVP_CIPHER_CTX_free(ctx);

        tmp.resize(l1+l2);
        writeFileSimple(inPath, tmp); // save demo ciphertext for future runs
        ciphertext = std::move(tmp);
    }

    // Decrypt the ciphertext and write the plaintext to disk
    std::vector<unsigned char> out(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(dctx, EVP_aes_128_cbc(), NULL, myKey, myIV);
    int dl1=0, dl2=0;
    EVP_DecryptUpdate(dctx, out.data(), &dl1, ciphertext.data(), static_cast<int>(ciphertext.size()));
    if (EVP_DecryptFinal_ex(dctx, out.data()+dl1, &dl2) != 1) {
        std::cerr << "Decryption failed (bad key/IV or corrupted ciphertext)" << std::endl;
        EVP_CIPHER_CTX_free(dctx);
        return 2;
    }
    EVP_CIPHER_CTX_free(dctx);

    out.resize(dl1+dl2);
    writeFileSimple(outPath, out); // write plaintext to examples/Msg.dec
    std::cout << "Decrypted written to: " << outPath << std::endl;

    return 0;
}
