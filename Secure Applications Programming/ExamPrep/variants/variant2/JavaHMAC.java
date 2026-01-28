/*
 * VARIANT 2: HMAC Verification + KeyStore Management
 * 
 * Uses HMAC instead of simple hashing, and KeyStore instead of certificate.
 * 
 * STEPS:
 *   1. Read plaintext.db (from C++ output)
 *   2. Calculate HMAC-SHA256 (using first 32 bytes as key)
 *   3. Load Java KeyStore and extract public key
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class JavaHMAC {

    // Helper: convert bytes to hex string
    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {

        // ============================================
        // STEP 1: READ THE DECRYPTED FILE
        // ============================================
        // TEACHER MAY CHANGE: filename "plaintext.db"
        byte[] data = Files.readAllBytes(Paths.get("plaintext.db"));

        System.out.println("Read " + data.length + " bytes");

        // ============================================
        // STEP 2: CALCULATE HMAC-SHA256
        // ============================================
        // HMAC needs a SECRET KEY (unlike MD5 which needs no key)
        // TEACHER MAY CHANGE: key source, algorithm ("HmacSHA1", "HmacMD5")

        // Use first 32 bytes of file as HMAC key
        byte[] hmacKey = new byte[32];
        System.arraycopy(data, 0, hmacKey, 0, Math.min(32, data.length));

        // Create HMAC key specification
        SecretKeySpec keySpec = new SecretKeySpec(hmacKey, "HmacSHA256");

        // Get HMAC instance
        // TEACHER MAY CHANGE: "HmacSHA256" to "HmacSHA1" or "HmacMD5"
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);

        // Calculate HMAC of entire content
        byte[] hmacResult = mac.doFinal(data);

        System.out.println("HMAC-SHA256: " + toHex(hmacResult));

        // ============================================
        // STEP 3: LOAD JAVA KEYSTORE (JKS)
        // ============================================
        // TEACHER MAY CHANGE: keystore filename, password, alias

        String keystoreFile = "mykeystore.jks";
        String keystorePassword = "changeit"; // Default Java password
        String alias = "mykey"; // Key alias in keystore

        // Load keystore
        KeyStore ks = KeyStore.getInstance("JKS");

        // TEACHER MAY PROVIDE: different keystore file or password
        FileInputStream fis = new FileInputStream(keystoreFile);
        ks.load(fis, keystorePassword.toCharArray());
        fis.close();

        // ============================================
        // STEP 4: EXTRACT PUBLIC KEY FROM KEYSTORE
        // ============================================
        // Get certificate for the alias
        java.security.cert.Certificate cert = ks.getCertificate(alias);

        // Get public key from certificate
        PublicKey publicKey = cert.getPublicKey();

        System.out.println("\n=== KeyStore Info ===");
        System.out.println("Alias: " + alias);
        System.out.println("Key Algorithm: " + publicKey.getAlgorithm());
        System.out.println("Key Format: " + publicKey.getFormat());

        // ============================================
        // OPTIONAL: WRITE RESULTS TO FILE
        // ============================================
        String output = "HMAC-SHA256: " + toHex(hmacResult) + "\n" +
                "KeyStore Alias: " + alias + "\n" +
                "Key Algorithm: " + publicKey.getAlgorithm() + "\n";

        Files.write(Paths.get("hmac_result.txt"), output.getBytes());
        System.out.println("\nWrote hmac_result.txt");
    }
}
