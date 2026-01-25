package exam;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public final class HashUtils {
    private HashUtils() {}

    public static byte[] calculateHash(String algo, byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo);
        md.update(data);
        return md.digest();
    }

    public static byte[] calculateHMAC(String algo, byte[] keyBytes, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(algo);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algo);
        mac.init(keySpec);
        return mac.doFinal(data);
    }
}