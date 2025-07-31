package com.zxl.cypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;

@BenchmarkMode({Mode.All})
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 3)      // 预热3次，每次3秒
@Measurement(iterations = 5, time = 5)  // 正式测量5次，每次5秒
@Fork(1)                                                           // 启动1个JVM进程运行测试
public class RsaBenchmark {

  private KeyPairGenerator jdkGenerator;

  @Setup(Level.Iteration)
  public void setup() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    jdkGenerator = KeyPairGenerator.getInstance("RSA");
    jdkGenerator.initialize(2048); // 指定密钥长度
  }

  @Benchmark
  public KeyPair testOpenSSLRSAGen() throws Exception {
    return RsaKeyUtil.generate(); // 使用 OpenSSL 的 Native 方法
  }

  @Benchmark
  public KeyPair testJDKRSAGen() throws Exception {
    return jdkGenerator.generateKeyPair(); // 使用 JDK 原生方法
  }
}
