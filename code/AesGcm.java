import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class AesGcm {

    public byte[] encrypt(String json, String key32) throws Exception {

        byte[] keyBytes = key32.getBytes(StandardCharsets.UTF_8);
        byte[] iv = Arrays.copyOfRange(keyBytes, 0, 12);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(128, iv)
        );

        return c.doFinal(json.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(byte[] cipher, String key32) throws Exception {

        byte[] keyBytes = key32.getBytes(StandardCharsets.UTF_8);
        byte[] iv = Arrays.copyOfRange(keyBytes, 0, 12);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(keyBytes, "AES"),
                new GCMParameterSpec(128, iv)
        );

        return new String(c.doFinal(cipher), StandardCharsets.UTF_8);
    }
}
