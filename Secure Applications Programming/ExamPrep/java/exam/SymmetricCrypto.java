package exam;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Small wrapper for symmetric crypto operations using the JCE.
 */
public final class SymmetricCrypto {
    private SymmetricCrypto() {}

    /**
     * Perform a symmetric operation.
     * @param transformation Full JCE transformation, e.g. "AES/CBC/PKCS5Padding".
     * @param keyAlgo Key algorithm for SecretKeySpec, e.g. "AES" or "DES".
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     */
    public static byte[] symmetricOp(String transformation, String keyAlgo, int mode, byte[] keyBytes, byte[] ivBytes, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, keyAlgo);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(mode, keySpec, ivSpec);
        return cipher.doFinal(data);
    }
}