package com.zxl.cypto;

public class NativeRsa {

  static {
    System.loadLibrary("opensslrsa");
  }

  public static native byte[][] generateRSAKeyPairNative(int bits); // 0: priv, 1: pub

  public static KeyPair generateKeyPair(int bits) throws GeneralSecurityException {
    byte[][] keys = generateRSAKeyPairNative(bits);

    // 构造 PrivateKey 和 PublicKey
    KeyFactory factory = KeyFactory.getInstance("RSA");
    
    PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(keys[0]);
    PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(keys[1]));
    PrivateKey priv = factory.generatePrivate(privSpec);

    return new KeyPair(pub, priv);
  }
}
