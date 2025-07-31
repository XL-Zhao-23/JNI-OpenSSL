package org.example;

import java.security.AccessController;
import java.security.PrivilegedAction;
import sun.security.action.GetBooleanAction;

/** The native implementation with OpenSSL for SunRsaSign algorithms. */
final class NativeSunRsaSign {
  private static final boolean IS_NATIVE_CRYPTO_ENABLED;
  static {
    boolean enableNativeCrypto =
        GetBooleanAction.privilegedGetProperty("jdk.sunrsasign.enableNativeCrypto");

    IS_NATIVE_CRYPTO_ENABLED =
        enableNativeCrypto

            // OpenSSL crypto lib must be loaded at first

            && OpenSSLUtil.isOpenSSLLoaded()
            && loadSunRSASignCryptoLib();
  }

  // Load lib sunrsasigncrypto

  @SuppressWarnings("removal")
  private static boolean loadSunRSASignCryptoLib() {

    boolean loaded = true;

    try {
      AccessController.doPrivileged(
          (PrivilegedAction<Void>)
              () -> {
                System.loadLibrary("sunrsasigncrypto");
                return null;
              });
    } catch (UnsatisfiedLinkError e) {

      System.err.println("Failed to load sunrsasigncrypto: " + e);

      loaded = false;
    }

    return loaded;
  }

  static boolean isNativeCryptoEnabled() {
    return IS_NATIVE_CRYPTO_ENABLED;
  }

  static native void rsaModPow(byte[] base, byte[] exponent, byte[] modulus, byte[] out);
}
