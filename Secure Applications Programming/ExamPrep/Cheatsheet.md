| Algorithm   | Cipher Function      | Key Size |  IV Size |
| ----------- | -------------------- | -------: | -------: |
| AES-128-CBC | `EVP_aes_128_cbc()`  | 16 bytes | 16 bytes |
| AES-256-CBC | `EVP_aes_256_cbc()`  | 32 bytes | 16 bytes |
| DES-CBC     | `EVP_des_cbc()`      |  8 bytes |  8 bytes |
| 3DES-CBC    | `EVP_des_ede3_cbc()` | 24 bytes |  8 bytes |
