import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;

public final class AesKeyGenerator {

    private static final String CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Generates a 32-character AES key using [a-zA-Z0-9]
     */
    public static String generate32CharKey() {

        StringBuilder key = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {

            int index = SECURE_RANDOM.nextInt(CHARSET.length());
            key.append(CHARSET.charAt(index));
        }
        return key.toString();
    }

    public static String generateAes256KeyBase64() throws Exception {

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, SECURE_RANDOM); // AES-256
        SecretKey secretKey = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}
