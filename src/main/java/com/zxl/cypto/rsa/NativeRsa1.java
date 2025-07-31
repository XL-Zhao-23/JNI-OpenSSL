package com.zxl.cypto.rsa;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.StringReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class NativeRsa1 {
  static {
    System.loadLibrary("rsa1");
  }

  public static native byte[] generateRSAKeyPairNative();
  public static KeyPair generate() throws Exception {

    byte[] array = NativeRsa1.generateRSAKeyPairNative();

    // 1. 提取私钥长度（前4字节，小端）
    int len =
      (array[0] & 0xFF)
        | ((array[1] & 0xFF) << 8)
        | ((array[2] & 0xFF) << 16)
        | ((array[3] & 0xFF) << 24);

    // 2. 拆分 PEM 内容
    String privPem = new String(array, 4, len);
    String pubPem = new String(array, 4 + len, array.length - 4 - len);

    // 3. 解析私钥（PKCS#1 PEM） → PrivateKey
    PEMParser pemParser = new PEMParser(new StringReader(privPem));
    Object obj = pemParser.readObject();
    pemParser.close();

    // Debug: Print the PEM content and object type
//    System.out.println("Private key PEM content:");
//    System.out.println(privPem);
//    System.out.println("Parsed object type: " + (obj != null ? obj.getClass().getName() : "null"));

    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

    PrivateKey privateKey;
    if (obj instanceof RSAPrivateKey) {
      // PKCS#1 format - convert to PKCS#8
      RSAPrivateKey rsaPriv = (RSAPrivateKey) obj;
      PrivateKeyInfo privateKeyInfo =
        new PrivateKeyInfo(
          new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
            org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
            org.bouncycastle.asn1.DERNull.INSTANCE),
          rsaPriv);
      privateKey = converter.getPrivateKey(privateKeyInfo);
    } else if (obj instanceof org.bouncycastle.openssl.PEMKeyPair) {
      // PEMKeyPair format
      org.bouncycastle.openssl.PEMKeyPair keyPair = (org.bouncycastle.openssl.PEMKeyPair) obj;
      privateKey = converter.getPrivateKey(keyPair.getPrivateKeyInfo());
    } else if (obj instanceof PrivateKeyInfo) {
      // PKCS#8 format
      privateKey = converter.getPrivateKey((PrivateKeyInfo) obj);
    } else {
      throw new IllegalArgumentException("Invalid private key format: " + obj.getClass().getName());
    }

    // 4. 解析公钥（PKCS#1 PEM） → PublicKey
    PEMParser pubParser = new PEMParser(new StringReader(pubPem));
    Object pubObj = pubParser.readObject();
    pubParser.close();

    PublicKey publicKey = converter.getPublicKey((SubjectPublicKeyInfo) pubObj);

    return new KeyPair(publicKey, privateKey);
  }
}
