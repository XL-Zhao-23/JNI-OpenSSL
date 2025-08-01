package com.zxl.cypto;

import com.zxl.cypto.provider.OpenSSLProvider1;
import com.zxl.cypto.provider.OpenSSLProvider2;

import java.security.*;

public class Main {
  public static void main(String[] args) {

//    try {
//      // 注册 BouncyCastle Provider（只需注册一次）
//      Security.addProvider(new BouncyCastleProvider());
//      System.out.println("Testing RSA key generation...");
//      KeyPair keyPair = RsaKeyUtil.generate();
//      System.out.println("Successfully generated RSA key pair!");
//      System.out.println("Private key algorithm: " + keyPair.getPrivate().getAlgorithm());
//      System.out.println("Public key algorithm: " + keyPair.getPublic().getAlgorithm());
//    } catch (Exception e) {
//      System.err.println("Error generating RSA key pair:");
//      e.printStackTrace();
//    }


    Security.addProvider(new OpenSSLProvider1());
    Security.addProvider(OpenSSLProvider2.INSTANCE);
    try {
      KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSL2");
      gen.initialize(2048);
      KeyPair kp = gen.generateKeyPair();

      System.out.println("Public Key: " + kp.getPublic());
      System.out.println("Private Key: " + kp.getPrivate());
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }
}
