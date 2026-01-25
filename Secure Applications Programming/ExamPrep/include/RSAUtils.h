#ifndef RSAUTILS_H
#define RSAUTILS_H

#include <vector>

/**
 * @file RSAUtils.h
 * @brief Utilities for RSA-related exam examples (PEM parsing + decryption).
 *
 * NOTE: The example uses `PEM_read_RSA_PUBKEY` and `RSA_public_decrypt` to
 * recover a symmetric key encrypted using the matching private key. This
 * mirrors common exam-style scenarios and intentionally keeps error handling
 * minimal so the steps are clear.
 */

/**
 * Decrypt a small RSA-encrypted blob using a PEM public key file.
 * Returns the recovered plaintext bytes or an empty vector on error.
 */
std::vector<unsigned char> rsaDecryptFile(const char* pemPath, const char* encryptedPath);

#endif // RSAUTILS_H 
