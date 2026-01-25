import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;
import java.util.Base64; // Use java.util.Base64 for JDK 8+

public class ExamMaster {

    // =============================================================
    // HELPER 1: FILE I/O (Standard byte reading)
    // =============================================================
    public static byte[] readFile(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    public static void writeFile(String path, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(data);
        }
    }

    // =============================================================
    // HELPER 2: SYMMETRIC CRYPTO (AES / DES / 3DES)
    // =============================================================
    public static byte[] symmetricOp(String algoFull, String keyAlgo, int mode, byte[] keyBytes, byte[] ivBytes, byte[] data) throws Exception {
        // 1. Setup Key and IV
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, keyAlgo); // e.g., "AES" or "DES"
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

        // 2. Initialize Cipher
        Cipher cipher = Cipher.getInstance(algoFull); // e.g., "AES/CBC/PKCS5Padding"
        cipher.init(mode, keySpec, ivSpec);

        // 3. Execute
        return cipher.doFinal(data);
    }

    // =============================================================
    // HELPER 3: HASHING & HMAC
    // =============================================================
    public static byte[] calculateHash(String algo, byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo); // "MD5" or "SHA-256"
        md.update(data);
        return md.digest();
    }

    public static byte[] calculateHMAC(String algo, byte[] keyBytes, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(algo); // e.g., "HmacSHA256"
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algo);
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    // =============================================================
    // HELPER 4: CERTIFICATES & KEYS
    // =============================================================
    public static PublicKey loadPublicKeyFromPem(String filename) throws Exception {
        // Simple parser to strip Headers (-----BEGIN...) and Newlines
        String keyStr = new String(readFile(filename));
        keyStr = keyStr
            .replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "")
            .replaceAll("\\s", ""); // Remove newlines

        byte[] decoded = Base64.getDecoder().decode(keyStr);
        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static X509Certificate loadCertificate(String filename) throws Exception {
        FileInputStream fis = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
        fis.close();
        return cert;
    }

    // =============================================================
    // MAIN: EXAM WORKFLOW
    // =============================================================
    public static void main(String[] args) {
        try {
            // -----------------------------------------------------
            // TASK 1: CERTIFICATE MANAGEMENT
            // -----------------------------------------------------
            // "Instantiate an X.509 certificate..."
            // Note: If you don't have a .cer file, skip this in testing.
            try {
                X509Certificate cert = loadCertificate("mycert.cer");
                System.out.println("Cert Loaded: " + cert.getSubjectDN());
            } catch (Exception e) {
                System.out.println("No cert file found, skipping...");
            }

            // -----------------------------------------------------
            // TASK 2: HANDLING THE DECRYPTED FILE
            // -----------------------------------------------------
            // Scenario: C++ output 'Msg.dec'. But prompt says "First 16 bytes are IV"
            byte[] rawContent = readFile("Msg.dec");

            if (rawContent.length < 16) {
                System.out.println("File too small!");
                return;
            }

            // A. SPLITTING ARRAYS (Crucial Exam Skill)
            // Use Arrays.copyOfRange(source, from, to)
            byte[] iv = Arrays.copyOfRange(rawContent, 0, 16);
            byte[] message = Arrays.copyOfRange(rawContent, 16, rawContent.length);

            System.out.println("IV Extracted: " + Base64.getEncoder().encodeToString(iv));

            // -----------------------------------------------------
            // TASK 3: HASHING (MD5)
            // -----------------------------------------------------
            byte[] digest = calculateHash("MD5", message);

            // Print HEX (Required)
            System.out.print("MD5 Hash: ");
            for (byte b : digest) {
                System.out.printf("%02x", b);
            }
            System.out.println();

            // -----------------------------------------------------
            // VARIATION: SYMMETRIC ENCRYPTION (If asked in Java)
            // -----------------------------------------------------
            // Example: Encrypting the message back using AES-CBC
            // We need a 16-byte key (Example dummy key)
            byte[] key = Arrays.copyOf("SecretKey1234567".getBytes(), 16); 
            
            // To Swap to DES: use key len 8, "DES", "DES/CBC/PKCS5Padding"
            byte[] cipherText = symmetricOp(
                "AES/CBC/PKCS5Padding", // Algorithm String
                "AES",                  // Key Algorithm
                Cipher.ENCRYPT_MODE,    // Mode
                key,                    // Key
                iv,                     // IV
                message                 // Data
            );
            
            System.out.println("Re-Encrypted size: " + cipherText.length);
            writeFile("JavaOutput.enc", cipherText);

            // -----------------------------------------------------
            // VARIATION: HMAC
            // -----------------------------------------------------
            byte[] hmac = calculateHMAC("HmacSHA256", key, message);
            System.out.println("HMAC Generated.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}