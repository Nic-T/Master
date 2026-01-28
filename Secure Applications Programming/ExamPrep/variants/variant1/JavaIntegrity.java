/*
 * VARIANT 1: MD5 Hashing + Certificate Parsing
 * 
 * This is the Java part of the exam. Uses output from C++ program.
 * 
 * STEPS:
 *   1. Read decrypted_Msg.bin (from C++ output)
 *   2. Calculate MD5 hash
 *   3. Load and parse X.509 certificate
 *   4. Print results
 */

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;

public class JavaIntegrity {

    // Helper: convert bytes to hex string for printing
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
        // TEACHER MAY CHANGE: filename "decrypted_Msg.bin"
        byte[] data = Files.readAllBytes(Paths.get("decrypted_Msg.bin"));
        
        System.out.println("Read " + data.length + " bytes");

        // ============================================
        // STEP 2: CALCULATE MD5 HASH
        // ============================================
        // TEACHER MAY CHANGE: algorithm ("SHA-1", "SHA-256", etc.)
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        // Simple hash of entire content
        byte[] hash = md.digest(data);
        
        System.out.println("MD5 Hash: " + toHex(hash));

        // ============================================
        // ALTERNATIVE: Using first 16 bytes as salt
        // ============================================
        // TEACHER MAY ASK: "Use first 16 bytes as IV/salt for hashing"
        // Uncomment below if needed:
        /*
        byte[] first16 = new byte[16];
        System.arraycopy(data, 0, first16, 0, 16);
        
        md.reset();
        md.update(first16);           // Add salt first
        md.update(data);              // Then add content
        byte[] saltedHash = md.digest();
        
        System.out.println("Salted MD5: " + toHex(saltedHash));
        */

        // ============================================
        // STEP 3: LOAD X.509 CERTIFICATE
        // ============================================
        // TEACHER MAY CHANGE: filename "pubISM.pem" or "mycert.cer"
        Path certPath = Paths.get("pubISM.pem");
        
        // Create certificate factory
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        // Load certificate from file
        InputStream certStream = Files.newInputStream(certPath);
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certStream);
        certStream.close();

        // ============================================
        // STEP 4: PRINT CERTIFICATE ATTRIBUTES
        // ============================================
        // TEACHER MAY ASK: different fields
        System.out.println("\n=== Certificate Info ===");
        System.out.println("Subject: " + cert.getSubjectDN());
        System.out.println("Issuer:  " + cert.getIssuerDN());
        System.out.println("Serial:  " + cert.getSerialNumber());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid To:   " + cert.getNotAfter());

        // ============================================
        // OPTIONAL: SAVE RESULTS TO FILE
        // ============================================
        // TEACHER MAY ASK: "Write output to certificate_info.txt"
        String output = "MD5 Hash: " + toHex(hash) + "\n" +
                        "Subject: " + cert.getSubjectDN() + "\n" +
                        "Issuer: " + cert.getIssuerDN() + "\n";
        
        Files.write(Paths.get("certificate_info.txt"), output.getBytes());
        System.out.println("\nWrote certificate_info.txt");
    }
}
