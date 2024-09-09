import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class TestApplication {

    private static final String CURVE = "secp256r1"; // P-256 curve

    public static void main(String[] args) {
        try {
            // Add BouncyCastle Provider
            Security.addProvider(new BouncyCastleProvider());

            // Generate EC key pair
            ECGenParameterSpec parameterSpec = new ECGenParameterSpec(CURVE);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
            keyPairGenerator.initialize(parameterSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Extract and print private key
            PrivateKey privateKey = keyPair.getPrivate();
            String privateKeyPem = convertToPem(privateKey);
            System.out.println("Private Key in PEM format:\n" + privateKeyPem);

            // Save the private key in binary format to a file (optional)
            String privateKeyFilePath = "private_key.bin";
            saveKeyToBinaryFile(privateKey, privateKeyFilePath);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Convert private key to PEM format
    private static String convertToPem(PrivateKey privateKey) {
        String base64Key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" +
                base64Key +
                "\n-----END PRIVATE KEY-----";
    }

    // Save the private key in binary format
    private static void saveKeyToBinaryFile(PrivateKey privateKey, String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(privateKey.getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
