import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

public class ConsumerClient {

    private final String supplierPublicKeyPath = "path/to/supplier-public-key";

    private final String consumerPrivateKeyPath = "path/to/consumer-private-key";

    private String lastAesKey;

    private final RsaSign rsaSign;
    private final RsaOaep rsaOaep;
    private final AesGcm aesGcm;

    public ConsumerClient() {
        this.rsaSign = new RsaSign();
        this.rsaOaep = new RsaOaep();
        this.aesGcm = new AesGcm();
    }

    public Map<String, String> buildRequest(String json) throws Exception {

        lastAesKey = AesKeyGenerator.generate32CharKey();

        byte[] encryptedPayload = aesGcm.encrypt(json, lastAesKey);

        PublicKey supplierPub = PemUtils.loadPublicKey(supplierPublicKeyPath);
        String encryptedKey = rsaOaep.encrypt(lastAesKey, supplierPub);

        PrivateKey consumerPrivateKey = PemUtils.loadPrivateKey(consumerPrivateKeyPath);
        String signature = rsaSign.sign(encryptedPayload, consumerPrivateKey);

        return Map.of(
                "encryptedKey", encryptedKey,
                "payload", Base64.getEncoder().encodeToString(encryptedPayload),
                "signature", signature
        );
    }

    public String processResponse(
            String payloadB64,
            String signatureB64,
            String aesKey) throws Exception {

        byte[] encryptedPayload = Base64.getDecoder().decode(payloadB64);

        PublicKey supplierPublicKey = PemUtils.loadPublicKey(supplierPublicKeyPath);

        if (!rsaSign.verify(encryptedPayload, signatureB64, supplierPublicKey)) {
            throw new SecurityException("Invalid response signature");
        }

        return aesGcm.decrypt(encryptedPayload, aesKey);
    }

    public String getLastAesKey() {
        return lastAesKey;
    }
}
