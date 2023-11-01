import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class TOTP {

    private static final String ALGORITHM = "HmacSHA256";
    private static final int CODE_DIGITS = 6;
    private static final int[] DIGITS_POWER = {1, 10, 100, 1000, 10000, 100000, 1000000};

    private TOTP() {

    }

    public static String generateTOTP(byte[] key) {
        return generateTOTP(key, System.currentTimeMillis());
    }

    public static String generateTOTP(byte[] key, long time) {
        StringBuilder sb = new StringBuilder(Long.toHexString(time).toUpperCase());

        while (sb.length() < 16) sb.insert(0, "0");

        byte[] hash = calculateHmacSha256(key, convertHexStringToBytes(sb.toString()));

        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[CODE_DIGITS];

        sb = new StringBuilder(Integer.toString(otp));

        while (sb.length() < CODE_DIGITS) {
            sb.insert(0, "0");
        }

        return sb.toString();
    }

    private static byte[] convertHexStringToBytes(String hexString) {
        byte[] bytes = new BigInteger("10" + hexString, 16).toByteArray();

        return Arrays.copyOfRange(bytes, 1, bytes.length);
    }

    private static byte[] calculateHmacSha256(byte[] key, byte[] message) {
        Key secretKey = new SecretKeySpec(key, ALGORITHM);

        Mac mac;

        try {
            mac = Mac.getInstance(ALGORITHM);

            mac.init(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        return mac.doFinal(message);
    }
}
