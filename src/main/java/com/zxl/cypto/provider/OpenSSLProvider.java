package com.zxl.cypto.provider;

import java.security.Provider;

public final class OpenSSLProvider extends Provider {
    public OpenSSLProvider() {
        super("OpenSSL", 1.0, "OpenSSL-backed crypto provider");
        put("KeyPairGenerator.RSA", "com.zxl.cypto.provider.OpenSSLRSAGenerator");
    }
}
