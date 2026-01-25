package exam;

/**
 * Utilities for handling sensitive data in memory.
 * Note: Java cannot guarantee memory won't be copied by the JVM, but zeroing
 * arrays reduces exposure time in application memory.
 */
public final class SecureMem {
    private SecureMem() {}

    /**
     * Overwrite the provided byte array with zeros and help the GC by nulling
     * the reference (caller should null its references if needed).
     */
    public static void secureClear(byte[] arr) {
        if (arr == null) return;
        for (int i = 0; i < arr.length; i++) arr[i] = 0;
    }

    /**
     * Convert hex string (optionally with 0x prefix or whitespace) to bytes.
     * Returns null on parse error.
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) return null;
        String s = hex.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        s = s.replaceAll("\\s+", "");
        if ((s.length() % 2) != 0) return null;
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi == -1 || lo == -1) return null;
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}