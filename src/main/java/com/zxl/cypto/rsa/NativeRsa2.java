package com.zxl.cypto.rsa;

import java.security.*;
import java.security.spec.*;

public class NativeRsa2 {
  static {
    System.loadLibrary("rsa2");
  }

  // native 方法返回 [0]=PKCS8私钥， [1]=X509公钥
  public static native byte[][] generateRSAKeyPairNative(int bits);

  public static KeyPair generateKeyPair(int bits) {
    byte[][] keys = generateRSAKeyPairNative(bits);
    if (keys == null || keys.length != 2) {
      throw new RuntimeException("Failed to generate key pair from native code");
    }

    try {
      KeyFactory factory = KeyFactory.getInstance("RSA");
      PrivateKey priv = factory.generatePrivate(new PKCS8EncodedKeySpec(keys[0]));
      PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(keys[1]));
      return new KeyPair(pub, priv);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Error decoding native key bytes", e);
    }
  }
}
