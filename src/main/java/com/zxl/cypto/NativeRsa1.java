package com.zxl.cypto;

public class NativeRsa1 {
  static {
    System.loadLibrary("opensslrsa"); // libopensslrsa.so / .dll / .dylib
  }

  public static native byte[] generateRSAKeyPairNative();

}
