import exam.FileIO;
import exam.SecureMem;
import exam.SymmetricCrypto;
import exam.HashUtils;
import exam.CertUtils;

import java.util.Arrays;
import java.util.Base64;

/**
 * Main exam workflow demonstrating certificate handling, hashing and symmetric crypto.
 * The program was reorganized into small focused classes under package `exam`.
 */
public class ExamMaster {
    public static void main(String[] args) {
        try {
            // Cert demo (optional)
            try {
                var cert = CertUtils.loadCertificate("mycert.cer");
                System.out.println("Cert Loaded: " + cert.getSubjectDN());
            } catch (Exception e) {
                System.out.println("No cert file found, skipping...");
            }

            // Read decrypted file (example produced by C++ program)
            byte[] rawContent = FileIO.readFile("Msg.dec");
            if (rawContent.length < 16) {
                System.out.println("File too small!");
                return;
            }

            // Support loading key/IV from environment hex variables (optional)
            String keyHex = System.getenv("SYM_KEY_HEX");
            String ivHex = System.getenv("SYM_IV_HEX");

            byte[] iv = Arrays.copyOfRange(rawContent, 0, 16);
            byte[] message = Arrays.copyOfRange(rawContent, 16, rawContent.length);

            System.out.println("IV Extracted: " + Base64.getEncoder().encodeToString(iv));

            // Hashing (MD5)
            byte[] digest = HashUtils.calculateHash("MD5", message);
            System.out.print("MD5 Hash: ");
            for (byte b : digest) System.out.printf("%02x", b);
            System.out.println();

            // Prepare key (either env or example key)
            byte[] key;
            if (keyHex != null) {
                byte[] parsed = SecureMem.hexToBytes(keyHex);
                if (parsed == null) {
                    System.err.println("Invalid SYM_KEY_HEX");
                    return;
                }
                key = parsed;
                System.out.println("Key loaded from SYM_KEY_HEX");
            } else {
                // Example dummy key, copy and trim/pad to 16 bytes
                key = Arrays.copyOf("SecretKey1234567".getBytes(), 16);
            }

            // Re-encrypt as a demonstration (AES/CBC/PKCS5Padding)
            byte[] cipherText = SymmetricCrypto.symmetricOp("AES/CBC/PKCS5Padding", "AES", javax.crypto.Cipher.ENCRYPT_MODE, key, iv, message);
            System.out.println("Re-Encrypted size: " + cipherText.length);
            FileIO.writeFile("JavaOutput.enc", cipherText);

            // HMAC demo
            byte[] hmac = HashUtils.calculateHMAC("HmacSHA256", key, message);
            System.out.println("HMAC Generated.");

            // Securely clear sensitive buffers
            SecureMem.secureClear(key);
            SecureMem.secureClear(iv);
            SecureMem.secureClear(message);
            SecureMem.secureClear(rawContent);
            SecureMem.secureClear(cipherText);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}