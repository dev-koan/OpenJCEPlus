package ibm.jceplus.junit.base;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

public class BaseTestPBMAC1 extends BaseTestJunit5 {
    private List<String> algorithms = Arrays.asList("PBEWithHmacSHA1", "PBEWithHmacSHA224", "PBEWithHmacSHA256", "PBEWithHmacSHA384", 
            "HmacSHA512", "HmacSHA512/224", "HmacSHA512/256");

    private final String message = "This is a message for PBMAC1 testing";
    private final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecureRandom secureRandom = new SecureRandom();
    private SecretKey key;
    private byte[] salt = new byte[20];
    private int iterationCount = 300000;
    

    @ParameterizedTest
    @FieldSource("algorithms")
    void testPBMACFunctionality(String alg) throws Exception {
        SecretKey key = createKey(alg);
        Mac mac = Mac.getInstance(alg, getProviderName());
        mac.init(key);

        byte[] macText = mac.doFinal(message.getBytes());
        assertNotEquals(null, macText, "Mac generated NULL");
        assertEquals(mac.getMacLength(), macText.length);
    }

    private SecretKey createKey(String alg) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec("mypassword".toCharArray());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(alg, getProviderName());
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);
        return pbeKey;
    }
    
}
