package org.example;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
// cl /LD nativecrypto.c /I "E:\java\JDK17\include" /I "E:\java\JDK17\include\win32" /I
// "G:\software\OpenSSL-Win64\include" /link "G:\software\OpenSSL-Win64\lib\libcrypto.lib"
// /OUT:nativecrypto.dll

public class OpenSSLECKeyGen {

  public static KeyPair generate(String curve) throws Exception {
    String curveName = "prime256v1";
    System.out.println("curveName = " + curveName);
    byte[] array = NativeCrypto.generateECKeyPair(curveName);
    if (array == null) {
      System.err.println("Native method returned null!");
      return null;
    }
    ByteBuffer buffer = ByteBuffer.wrap(array).order(java.nio.ByteOrder.LITTLE_ENDIAN);
    int privLen = buffer.getInt();
    if (privLen < 0 || privLen > array.length - 4) {
      throw new IllegalArgumentException("Invalid private key length: " + privLen);
    }
    byte[] priv = new byte[privLen];
    byte[] pub = new byte[array.length - 4 - privLen];
    buffer.get(priv);
    buffer.get(pub);

    KeyFactory kf = KeyFactory.getInstance("EC");
    PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(priv));
    PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(pub));
    return new KeyPair(publicKey, privateKey);
  }

  public static void main(String[] args) throws Exception {
    KeyPair kp = generate("secp256r1");
    System.out.println("EC KeyPair Generated:");
    System.out.println("Public: " + kp.getPublic().getFormat());
    System.out.println("Private: " + kp.getPrivate().getFormat());
  }
}
