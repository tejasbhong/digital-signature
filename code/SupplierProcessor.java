import java.security.*;
import java.util.*;

public class SupplierProcessor {

    private final String consumerPublicKeyPath = "path/to/consumer-public-key";

    private final String supplierPrivateKeyPath = "path/to/supplier-private-key";

    private final RsaSign rsaSign;
    private final RsaOaep rsaOaep;
    private final AesGcm aesGcm;

    public SupplierProcessor() {
        this.rsaSign = new RsaSign();
        this.rsaOaep = new RsaOaep();
        this.aesGcm = new AesGcm();
    }

    public Map<String, String> process(
            String encryptedKey,
            String payloadB64,
            String signatureB64
    ) throws Exception {

        PrivateKey supplierPrivateKey = PemUtils.loadPrivateKey(supplierPrivateKeyPath);

        String aesKey = rsaOaep.decrypt(encryptedKey, supplierPrivateKey);

        byte[] payload = Base64.getDecoder().decode(payloadB64);

        PublicKey consumerPublicKey = PemUtils.loadPublicKey(consumerPublicKeyPath);

        if (!rsaSign.verify(payload, signatureB64, consumerPublicKey)) {
            throw new SecurityException("Invalid request signature");
        }

        String requestJson = aesGcm.decrypt(payload, aesKey);

        // ---- Business logic ----
        String responseJson = "{\"status\":\"SUCCESS\"}";
        // ------------------------

        byte[] encryptedResponse = aesGcm.encrypt(responseJson, aesKey);

        String responseSignature = rsaSign.sign(encryptedResponse, supplierPrivateKey);

        return Map.of(
                "payload", Base64.getEncoder().encodeToString(encryptedResponse),
                "signature", responseSignature
        );
    }
}
