/*
 Minimal RSA encryption/decryption example (exam-friendly)
 - Generates a local RSA keypair, encrypts a small plaintext with the public key
   using OAEP padding, then decrypts with the private key and prints the result.
 - This is intentionally minimal and focuses on the mechanism rather than
   production practices (no key persistence or advanced error handling).
*/

#include <iostream>
#include <vector>
#include <cstring>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int main() {
    // ---------- GENERATE RSA KEYPAIR ----------
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4); // 65537
    if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        std::cerr << "RSA_generate_key_ex failed" << std::endl;
        ERR_print_errors_fp(stderr);
        BN_free(e);
        RSA_free(rsa);
        return 1;
    }
    BN_free(e);

    // ---------- PLAINTEXT ----------
    const unsigned char msg[] = "Hello RSA (OAEP)!";
    const int msg_len = static_cast<int>(std::strlen(reinterpret_cast<const char*>(msg)));

    // RSA_size gives size of modulus in bytes and is the size of an RSA ciphertext
    int rsa_size = RSA_size(rsa);
    std::vector<unsigned char> enc(static_cast<size_t>(rsa_size));

    // ---------- ENCRYPT (with PUBLIC key) ----------
    // Use RSA_public_encrypt with OAEP padding (safe for small messages)
    int enc_len = RSA_public_encrypt(msg_len, msg, enc.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (enc_len == -1) {
        std::cerr << "RSA_public_encrypt failed" << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return 1;
    }

    // ---------- DECRYPT (with PRIVATE key) ----------
    std::vector<unsigned char> dec(static_cast<size_t>(rsa_size));
    int dec_len = RSA_private_decrypt(enc_len, enc.data(), dec.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (dec_len == -1) {
        std::cerr << "RSA_private_decrypt failed" << std::endl;
        ERR_print_errors_fp(stderr);
        RSA_free(rsa);
        return 1;
    }

    // Null-terminate and print
    dec[dec_len] = '\0';
    std::cout << "Decrypted message: " << reinterpret_cast<char*>(dec.data()) << std::endl;

    // Clean up
    RSA_free(rsa);
    return 0;
}
