package org.example;

public class NativeCrypto {
  static {
    System.loadLibrary("nativecrypto"); // 加载 libnativecrypto.so
  }

  public static native byte[] generateECKeyPair(String curveName);
}
