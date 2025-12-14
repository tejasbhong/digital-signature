import java.util.Map;

/**
 * End-to-end integration test using ONLY:
 * - ConsumerClient
 * - SupplierProcessor
 * - ConsumerResponseProcessor
 * <p>
 * Assumptions:
 * - application.properties paths are correct
 * - Spring @Value fields are resolved (or replaced with setters)
 */
public class EndToEndFlowTest {

    public static void main(String[] args) throws Exception {

        System.out.println("==== END-TO-END SECURE FLOW TEST ====");

        // --------------------------------------------------
        // Instantiate components
        // --------------------------------------------------

        ConsumerClient consumerClient = new ConsumerClient();
        SupplierProcessor supplierProcessor = new SupplierProcessor();

        // --------------------------------------------------
        // 1. Consumer builds request
        // --------------------------------------------------

        String requestJson = """
                {
                  "orderId": 101,
                  "amount": 500,
                  "currency": "INR"
                }
                """;

        Map<String, String> request = consumerClient.buildRequest(requestJson);

        System.out.println("\n[Consumer] Request generated");
        System.out.println(request);

        // --------------------------------------------------
        // 2. Supplier processes request and generates response
        // --------------------------------------------------

        Map<String, String> response = supplierProcessor.process(
                request.get("encryptedKey"),
                request.get("payload"),
                request.get("signature")
        );

        System.out.println("\n[Supplier] Response generated");
        System.out.println(response);

        // --------------------------------------------------
        // 3. Consumer processes response
        // --------------------------------------------------

        String finalResponse = consumerClient.processResponse(
                response.get("payload"),
                response.get("signature"),
                consumerClient.getLastAesKey()
        );

        System.out.println("\n[Consumer] Final decrypted response:");
        System.out.println(finalResponse);

        System.out.println("\n==== TEST COMPLETED SUCCESSFULLY ====");
    }
}
