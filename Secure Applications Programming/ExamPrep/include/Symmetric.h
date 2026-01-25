#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <vector>
#include <openssl/evp.h>

/**
 * @file Symmetric.h
 * @brief Wrapper around OpenSSL EVP API for basic encrypt/decrypt operations.
 *
 * Parameters:
 *  - input: data to encrypt or decrypt
 *  - key: symmetric key bytes (length must match `algorithm` requirements)
 *  - iv: initialization vector bytes (length must match `algorithm` requirements)
 *  - algorithm: pointer to an EVP_CIPHER (e.g., `EVP_aes_128_cbc()`)
 *  - mode: 0 = decrypt, 1 = encrypt
 *
 * Returns the processed bytes or an empty vector on failure.
 */
std::vector<unsigned char> symmetricOperation(
    const std::vector<unsigned char>& input, 
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const EVP_CIPHER* algorithm,
    int mode
);

#endif // SYMMETRIC_H 
