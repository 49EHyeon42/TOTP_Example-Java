import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Main {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String[] args) {
        byte[] key = getRandomKey();

        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

        scheduler.scheduleWithFixedDelay(() -> {
            Instant instant = Instant.ofEpochMilli(System.currentTimeMillis());

            System.out.println(instant.atZone(ZoneId.systemDefault()).format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) +
                    " OTP = " + TOTP.generateTOTP(key, System.currentTimeMillis() / 30000));
        }, 0, 1, TimeUnit.SECONDS);
    }

    // 32 bytes
    private static byte[] getRandomKey() {
        byte[] key = new byte[32];

        SECURE_RANDOM.nextBytes(key);

        return key;
    }
}
