package com.zxl.cypto.provider;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
public final class OpenSSLProvider2 extends Provider {
    private static final long serialVersionUID = 1L;
    public static final String PROVIDER_NAME = "OpenSSL2";
    // 先初始化 LOOKUP
    private static final MethodHandles.Lookup LOOKUP = MethodHandles.lookup();
    private static final String PACKAGE_PREFIX = "com.zxl.cypto.provider.";

    // 再初始化 INSTANCE
    public static final OpenSSLProvider2 INSTANCE = new OpenSSLProvider2();

    // 改为非 static 内部类
    private final class OpenSSLService extends Service {
        private final MethodHandle ctor;
        private final MethodHandle algorithmSetter;

        OpenSSLService(String type, String algorithm, String className) {
            super(OpenSSLProvider2.this, type, algorithm, PACKAGE_PREFIX + className, null, null);
            try {
                Class<?> clazz = Class.forName(PACKAGE_PREFIX + className);

                MethodHandle tmpCtor = LOOKUP.findConstructor(clazz, MethodType.methodType(void.class))
                  .asType(MethodType.methodType(Object.class));
                ctor = tmpCtor;

                MethodHandle tmpSetter = null;
                try {
                    tmpSetter = LOOKUP.findVirtual(clazz, "setAlgorithmName",
                      MethodType.methodType(void.class, String.class));
                } catch (NoSuchMethodException ignored) {}
                algorithmSetter = tmpSetter;

            } catch (Throwable t) {
                throw new RuntimeException("Failed to initialize OpenSSL service", t);
            }
        }

        @Override
        public Object newInstance(Object param) throws NoSuchAlgorithmException {
            if (param != null) {
                throw new NoSuchAlgorithmException("Constructor parameter not supported");
            }
            try {
                Object instance = ctor.invokeExact();
                if (algorithmSetter != null) {
                    algorithmSetter.invoke(instance, getAlgorithm());
                }
                return instance;
            } catch (Throwable t) {
                throw new NoSuchAlgorithmException("Service instantiation failed", t);
            }
        }
    }

    private OpenSSLProvider2() {
        super(PROVIDER_NAME, 1.0, "OpenSSL-backed crypto provider");
        // 使用非 static 内部类，传 this
        putService(new OpenSSLService("KeyPairGenerator", "RSA", "OpenSSLRSAGenerator"));
    }

    public static void install() {
        Security.insertProviderAt(INSTANCE, 1);
    }
}
