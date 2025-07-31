package com.zxl.cypto.rsa;

import java.security.*;
import java.security.spec.*;

public class NativeRsa3 {
  static {
    System.loadLibrary("rsa3");
  }

  // 新增：初始化 native 线程上下文，返回一个 long 句柄（指针）
  private static native long initNativeContext(int bits);

  // 新增：释放 native 线程上下文
  private static native void freeNativeContext(long ctxPtr);

  // 新增：用已有上下文批量生成 RSA 密钥对，返回二维数组
  // 返回格式：keyPairs[count][0]=私钥bytes，keyPairs[count][1]=公钥bytes
  private static native byte[][][] generateRSAKeyPairsNative(long ctxPtr, int count);

  // Java层 ThreadLocal 管理 native 上下文句柄
  private static final ThreadLocal<Long> nativeContext = ThreadLocal.withInitial(() -> initNativeContext(2048));

  public static void freeContext() {
    Long ctxPtr = nativeContext.get();
    if (ctxPtr != null) {
      freeNativeContext(ctxPtr);
      nativeContext.remove();
    }
  }

  // 单个生成，调用批量接口简化
  public static KeyPair generateKeyPair() {
    byte[][][] keysBatch = generateKeyPairs(1);
    byte[][] keys = keysBatch[0];
    return decodeKeyPair(keys);
  }

  // 批量生成密钥对
  public static byte[][][] generateKeyPairs(int count) {
    long ctxPtr = nativeContext.get();
    if (ctxPtr == 0) {
      ctxPtr = initNativeContext(2048);
      nativeContext.set(ctxPtr);
    }
    return generateRSAKeyPairsNative(ctxPtr, count);
  }

  private static KeyPair decodeKeyPair(byte[][] keys) {
    if (keys == null || keys.length != 2) {
      throw new RuntimeException("Invalid key pair bytes");
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
