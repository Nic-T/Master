#include "Symmetric.h"

#include <openssl/evp.h>
#include <iostream>

/**
 * symmetricOperation - wrapper for OpenSSL EVP encrypt/decrypt
 * - Creates an EVP_CIPHER_CTX, initializes for encrypt/decrypt, performs Update/Final,
 *   and returns the resulting bytes. Returns empty vector on any failure.
 *
 * Important:
 * - Caller must supply correct `key` and `iv` lengths for `algorithm`.
 * - mode == 1 -> encrypt, mode == 0 -> decrypt.
 */
std::vector<unsigned char> symmetricOperation(
    const std::vector<unsigned char>& input, 
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const EVP_CIPHER* algorithm,
    int mode
) {
    // Allocate context (must be freed with EVP_CIPHER_CTX_free)
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to allocate EVP_CIPHER_CTX." << std::endl;
        return {};
    }
    
    // 1. Initialize context for encrypt or decrypt
    int init_ok = 0;
    if (mode == 1) {
        init_ok = EVP_EncryptInit_ex(ctx, algorithm, NULL, key.data(), iv.data());
    } else {
        init_ok = EVP_DecryptInit_ex(ctx, algorithm, NULL, key.data(), iv.data());
    }
    if (init_ok != 1) {
        std::cerr << "EVP Init failed (invalid key/iv or algorithm)." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // Prepare output buffer: input length + block size for padding
    std::vector<unsigned char> output(input.size() + EVP_CIPHER_block_size(algorithm));
    int len1 = 0, len2 = 0;

    // 2. Process data in one shot (suitable for small messages)
    int update_ok = 0;
    if (mode == 1) {
        update_ok = EVP_EncryptUpdate(ctx, output.data(), &len1, input.data(), static_cast<int>(input.size()));
    } else {
        update_ok = EVP_DecryptUpdate(ctx, output.data(), &len1, input.data(), static_cast<int>(input.size()));
    }
    if (update_ok != 1) {
        std::cerr << "EVP Update failed." << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    // 3. Finalize (process padding)
    int final_ok = 0;
    if (mode == 1) {
        final_ok = EVP_EncryptFinal_ex(ctx, output.data() + len1, &len2);
    } else {
        final_ok = EVP_DecryptFinal_ex(ctx, output.data() + len1, &len2);
    }

    EVP_CIPHER_CTX_free(ctx); // Always free context

    if (final_ok != 1) {
        std::cerr << "Symmetric Operation Failed (Wrong Key/IV or corrupted ciphertext?)." << std::endl;
        return {};
    }

    // Resize to final output length and return
    output.resize(len1 + len2);
    return output;
} 
