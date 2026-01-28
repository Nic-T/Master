/*
 * VARIANT 3: DSA Signature Generation + Certificate Parsing
 * 
 * This variant SIGNS data (opposite of C++ which verifies).
 * 
 * STEPS:
 *   1. Read verified_content.txt (from C++ output)
 *   2. Sign using DSA (or RSA) algorithm
 *   3. Parse existing certificate and print fields
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;

public class JavaSignature {

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
        // STEP 1: READ THE VERIFIED FILE
        // ============================================
        // TEACHER MAY CHANGE: filename
        byte[] data = Files.readAllBytes(Paths.get("verified_content.txt"));

        System.out.println("Read " + data.length + " bytes");

        // ============================================
        // STEP 2: LOAD PRIVATE KEY FOR SIGNING
        // ============================================
        // TEACHER MAY CHANGE: key file, algorithm (RSA vs DSA)

        // Read PKCS#8 encoded private key
        byte[] keyBytes = Files.readAllBytes(Paths.get("private.key"));

        // Create key specification
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // TEACHER MAY CHANGE: "DSA" to "RSA"
        KeyFactory kf = KeyFactory.getInstance("DSA");
        PrivateKey privateKey = kf.generatePrivate(keySpec);

        // ============================================
        // STEP 3: CREATE DIGITAL SIGNATURE
        // ============================================
        // TEACHER MAY CHANGE: "SHA256withDSA" to "SHA256withRSA", "SHA1withDSA", etc.

        Signature sig = Signature.getInstance("SHA256withDSA");

        // Initialize for signing
        sig.initSign(privateKey);

        // Add data to sign
        sig.update(data);

        // Generate signature
        byte[] signatureBytes = sig.sign();

        System.out.println("Signature: " + toHex(signatureBytes));
        System.out.println("Signature length: " + signatureBytes.length + " bytes");

        // Write signature to file
        Files.write(Paths.get("output.sig"), signatureBytes);
        System.out.println("Wrote output.sig");

        // ============================================
        // STEP 4: PARSE EXISTING CERTIFICATE
        // ============================================
        // TEACHER MAY CHANGE: certificate filename
        Path certPath = Paths.get("mycert.cer");

        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        InputStream certStream = Files.newInputStream(certPath);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        certStream.close();

        // ============================================
        // STEP 5: PRINT CERTIFICATE FIELDS
        // ============================================
        // TEACHER MAY ASK: specific fields
        System.out.println("\n=== Certificate Info ===");
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Issuer:  " + cert.getIssuerDN());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid To:   " + cert.getNotAfter());
        System.out.println("Serial:  " + cert.getSerialNumber());
        System.out.println("Algorithm: " + cert.getSigAlgName());

        // ============================================
        // OPTIONAL: WRITE SUMMARY TO FILE
        // ============================================
        String output = "Signature: " + toHex(signatureBytes) + "\n" +
                "Subject: " + cert.getSubjectDN() + "\n" +
                "Issuer: " + cert.getIssuerDN() + "\n" +
                "Valid: " + cert.getNotBefore() + " to " + cert.getNotAfter() + "\n";

        Files.write(Paths.get("signature_info.txt"), output.getBytes());
        System.out.println("\nWrote signature_info.txt");
    }
}
