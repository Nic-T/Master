#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstring> // strcmp

// forward declaration of encrypt() implemented in EncryptFile.cpp
int encrypt();

int decrypt() {

    unsigned char key[] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    unsigned char iv[] = { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7, 0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf };
    std::ifstream file("Msg.enc", std::ios::binary | std::ios::ate);

    if (!file) {
        std::cerr << "Failed to open Msg.enc for reading." << std::endl;
        return 1;
    }

    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> encData((size_t)fileSize);
    file.read(reinterpret_cast<char*>(encData.data()), fileSize);
    
    file.close();

    size_t outSize = fileSize + 16; // AES block size
    std::vector<unsigned char> decData(outSize);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    int len1 = 0;
    int len2 = 0;

    EVP_DecryptUpdate(ctx, decData.data(), &len1, encData.data(), static_cast<int>(fileSize));

    if (!EVP_DecryptFinal_ex(ctx, decData.data()+len1,&len2 )) {
        std::cerr << "Decryption failed (bad padding or wrong key/IV)." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    int totalLen = len1 + len2;



    std::string outStr(reinterpret_cast<char*>(decData.data()), static_cast<size_t>(totalLen));
    std::cout << "Decrypted Data:" << outStr << std::endl;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " encrypt|decrypt" << std::endl;
        return 1;
    }

    if (std::strcmp(argv[1], "encrypt") == 0) {
        return encrypt();
    }
    if (std::strcmp(argv[1], "decrypt") == 0) {
        return decrypt();
    }

    std::cout << "Unknown command. Usage: " << argv[0] << " encrypt|decrypt" << std::endl;
    return 1;
}