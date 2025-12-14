import java.security.*;
import java.util.Base64;

public final class RsaSign {

    public String sign(byte[] data, PrivateKey key) throws Exception {

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(key);
        s.update(data);
        return Base64.getEncoder().encodeToString(s.sign());
    }

    public boolean verify(byte[] data, String signature, PublicKey key) throws Exception {

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(key);
        s.update(data);
        return s.verify(Base64.getDecoder().decode(signature));
    }
}
