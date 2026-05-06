package ibm.jceplus.junit.base;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import sun.security.util.KnownOIDs;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

public class BaseTestPBMAC1 extends BaseTestJunit5 {
    final char[] PASSWORD = "passwordtryagain".toCharArray();
    private SecretKey key;
    private List<String> algorithms = Arrays.asList("HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", 
            "HmacSHA512", "HmacSHA512/224", "HmacSHA512/256");

    @BeforeAll
    public void setup() {
        PBEKeySpec spec = new PBEKeySpec(PASSWORD, null, getKeySize(), getKeySize())
    }

    @ParameterizedTest
    @FieldSource("algorithms")
    


    
}
