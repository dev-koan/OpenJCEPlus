package com.ibm.crypto.plus.provider.ock;

public final class PKCS12Key {
    public static byte[] derive(OCKContext ockContext, byte[] password,
    byte[] salt, int iterations, int n, int type) throws Exception {
        byte[] key = new byte[n];
        NativeInterface.PKCS12Key_derive(ockContext.getId(), password, salt, iterations, type, n, key);
        return key;
    }
}
