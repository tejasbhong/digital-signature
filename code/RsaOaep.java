import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

public final class RsaOaep {

    public String encrypt(String data, PublicKey key) throws Exception {

        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(c.doFinal(data.getBytes()));
    }

    public String decrypt(String b64, PrivateKey key) throws Exception {

        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        return new String(c.doFinal(Base64.getDecoder().decode(b64)));
    }
}
