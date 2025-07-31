package com.zxl.cypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;

public class Main {
  public static void main(String[] args) {
    try {
      // 注册 BouncyCastle Provider（只需注册一次）
      Security.addProvider(new BouncyCastleProvider());
      System.out.println("Testing RSA key generation...");
      KeyPair keyPair = RsaKeyUtil.generate();
      System.out.println("Successfully generated RSA key pair!");
      System.out.println("Private key algorithm: " + keyPair.getPrivate().getAlgorithm());
      System.out.println("Public key algorithm: " + keyPair.getPublic().getAlgorithm());
    } catch (Exception e) {
      System.err.println("Error generating RSA key pair:");
      e.printStackTrace();
    }
  }
}
