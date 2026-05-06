package ibm.jceplus.junit.openjceplus;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

import ibm.jceplus.junit.base.BaseTestPBMAC1;

@TestInstance(Lifecycle.PER_CLASS)
public class TestPBMAC1 extends BaseTestPBMAC1 {
    
    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }
}
