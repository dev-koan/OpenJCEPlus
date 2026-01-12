/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestRC2Cipher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestRC2Cipher extends BaseTestRC2Cipher {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    /**
     * This method is to check whether a mode is valid for the cipher
     * but not supported by a given provider.
     */
    @Override
    public boolean isModeValidButUnsupported(String mode) {
        if (mode.equalsIgnoreCase("CFB") || mode.equalsIgnoreCase("CFB64")
                || mode.equalsIgnoreCase("OFB")) {
            return true;
        }

        return super.isModeValidButUnsupported(mode);
    }
}

