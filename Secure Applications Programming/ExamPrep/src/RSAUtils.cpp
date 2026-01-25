#include "RSAUtils.h"
#include "FileIO.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <iostream>
#include <cstdio>

/**
 * rsaDecryptFile:
 * - pemPath: path to a PEM encoded public key file
 * - encryptedPath: path to the RSA-encrypted blob (binary)
 *
 * Returns recovered plaintext bytes on success, or an empty vector on error.
 * The function prints error information to stderr to aid debugging.
 */
std::vector<unsigned char> rsaDecryptFile(const char* pemPath, const char* encryptedPath) {
    // 1. Open the PEM file
    FILE* pemFile = fopen(pemPath, "rb");
    if (!pemFile) {
        std::cerr << "Unable to open PEM file: " << pemPath << std::endl;
        return {};
    }

    // 2. Parse the public key (PEM_read_RSA_PUBKEY expects a SubjectPublicKeyInfo format)
    RSA* rsa = PEM_read_RSA_PUBKEY(pemFile, NULL, NULL, NULL);
    fclose(pemFile);
    if (!rsa) {
        std::cerr << "Failed to parse PEM Public Key." << std::endl;
        return {};
    }

    // 3. Load the encrypted data blob
    std::vector<unsigned char> encData = readFile(encryptedPath);
    if (encData.empty()) {
        std::cerr << "Encrypted input empty or couldn't be read: " << encryptedPath << std::endl;
        RSA_free(rsa);
        return {};
    }

    // 4. Decrypt using the public key (expects the counterpart was encrypted with the private key)
    std::vector<unsigned char> decData(RSA_size(rsa));

    int resultLen = RSA_public_decrypt(static_cast<int>(encData.size()), encData.data(), decData.data(), rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa); // Free RSA structure

    if (resultLen == -1) {
        std::cerr << "RSA Decryption Failed." << std::endl;
        ERR_print_errors_fp(stderr);
        return {};
    }

    // Shrink to actual size and return
    decData.resize(resultLen);
    return decData;
} 
