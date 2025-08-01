package com.zxl.cypto.provider;

import java.security.Provider;

public final class OpenSSLProvider1 extends Provider {
    public OpenSSLProvider1() {
        super("OpenSSL1", 1.0, "OpenSSL-backed crypto provider");
        put("KeyPairGenerator.RSA", "com.zxl.cypto.provider.OpenSSLRSAGenerator");
    }
}
