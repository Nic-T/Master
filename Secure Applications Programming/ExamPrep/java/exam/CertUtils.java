package exam;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Certificate and key utilities for reading PEM and certificates.
 */
public final class CertUtils {
    private CertUtils() {}

    public static PublicKey loadPublicKeyFromPem(String filename) throws Exception {
        String keyStr = new String(Files.readAllBytes(Paths.get(filename)));
        keyStr = keyStr.replaceAll("(-+BEGIN PUBLIC KEY-+\\r?\\n|-+END PUBLIC KEY-+\\r?\\n?)", "").replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(keyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static X509Certificate loadCertificate(String filename) throws Exception {
        try (FileInputStream fis = new FileInputStream(filename)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(fis);
        }
    }
}