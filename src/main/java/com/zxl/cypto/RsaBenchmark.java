package com.zxl.cypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.concurrent.TimeUnit;

import com.zxl.cypto.rsa.NativeRsa2;
import com.zxl.cypto.rsa.NativeRsa3;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 3)      // 预热3轮，每轮3秒
@Measurement(iterations = 5, time = 5)  // 测量5轮，每轮5秒
@Fork(1)                               // 启动1个JVM实例
public class RsaBenchmark {

  private KeyPairGenerator jdkGenerator;

  @Setup(Level.Iteration)
  public void setup() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    jdkGenerator = KeyPairGenerator.getInstance("RSA");
    jdkGenerator.initialize(2048);
  }
//  @Benchmark
//  public KeyPair testJDKRSAGen() throws Exception {
//    return jdkGenerator.generateKeyPair();
//  }
//  @Benchmark
//  public KeyPair testJDKRSAGen1() throws Exception {
//    return jdkGenerator.generateKeyPair();
//  }
//
//  @Benchmark
//  public KeyPair testNativeRsa2() {
//    return NativeRsa2.generateKeyPair(2048);
//  }

  @Benchmark
  public KeyPair testNativeRsa3() {
    return NativeRsa3.generateKeyPair();
  }

  // 运行结束时释放 NativeRsa3 的本地资源，防止内存泄漏
  @TearDown(Level.Trial)
  public void tearDown() {
    NativeRsa3.freeContext();
  }
}
