package org.example;

import java.security.AccessController;
import java.security.PrivilegedAction;

public class OpenSSLUtil {
  private static final boolean IS_OPENSSL_LOADED;

  static {
    IS_OPENSSL_LOADED = loadOpenSSLCryptoLib();
  }

  // Load lib opensslcrypto

  @SuppressWarnings("removal")
  private static boolean loadOpenSSLCryptoLib() {
    // The absolute path to OpenSSL libcrypto file
    String opensslCryptoLibPath =
        GetPropertyAction.privilegedGetProperty("jdk.openssl.cryptoLibPath");
    boolean loaded = true;
    try {
      AccessController.doPrivileged(
          (PrivilegedAction<Void>)
              () -> {
                if (opensslCryptoLibPath == null) {
                  System.loadLibrary("opensslcrypto");
                } else {
                  System.load(opensslCryptoLibPath);
                }
                return null;
              });
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Failed to load OpenSSL libcrypto: " + e);
      loaded = false;
    }
    return loaded;
  }

  public static boolean isOpenSSLLoaded() {
    return IS_OPENSSL_LOADED;
  }
}
