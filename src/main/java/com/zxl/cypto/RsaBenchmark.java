package com.zxl.cypto;

import java.security.*;
import java.util.concurrent.TimeUnit;

import com.zxl.cypto.provider.OpenSSLProvider1;
import com.zxl.cypto.provider.OpenSSLProvider2;
import com.zxl.cypto.rsa.NativeRsa2;
import com.zxl.cypto.rsa.NativeRsa3;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
//java -Djava.library.path=G:\IdeaProject\issue2\src\main\java -jar target/issue2-1.0-SNAPSHOT.jar
//Benchmark                     Mode  Cnt   Score   Error  Units
//RsaBenchmark.testJDKRSAGen   thrpt    5   7.981 ± 1.398  ops/s
//RsaBenchmark.testNativeRsa1  thrpt    5  11.529 ± 4.868  ops/s
//RsaBenchmark.testNativeRsa2  thrpt    5  12.658 ± 4.177  ops/s
//RsaBenchmark.testNativeRsa3  thrpt    5  13.606 ± 4.787  ops/s

//Benchmark                Mode  Cnt        Score        Error  Units
//RsaBenchmark.provider1  thrpt    5  2204796.742 ± 417543.544  ops/s
//RsaBenchmark.provider2  thrpt    5  6936790.673 ± 915992.159  ops/s

// batchsize = 100
//Benchmark                          Mode  Cnt  Score   Error  Units
//RsaBenchmark.batchGenerationRsa2  thrpt    5  0.108 ± 0.044  ops/s
//RsaBenchmark.batchGenerationRsa3  thrpt    5  0.114 ± 0.040  ops/s

// batchsize = 1000
//Benchmark                          Mode  Cnt  Score   Error  Units
//RsaBenchmark.batchGenerationRsa2  thrpt    5  0.010 ± 0.001  ops/s
//RsaBenchmark.batchGenerationRsa3  thrpt    5  0.011 ± 0.003  ops/s


@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 3)      // 预热3轮，每轮3秒
@Measurement(iterations = 5, time = 5)  // 测量5轮，每轮5秒
@Fork(1)                               // 启动1个JVM实例
public class RsaBenchmark {

  private KeyPairGenerator jdkGenerator;
  private int batchSize;

  @Setup(Level.Iteration)
  public void setup() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    jdkGenerator = KeyPairGenerator.getInstance("RSA");
    jdkGenerator.initialize(2048);
    batchSize = 1000;
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

//  @Benchmark
//  public KeyPair testNativeRsa3() {
//    return NativeRsa3.generateKeyPair();
//  }
//
//  // 运行结束时释放 NativeRsa3 的本地资源，防止内存泄漏
//  @TearDown(Level.Trial)
//  public void tearDown() {
//    NativeRsa3.freeContext();
//  }

//  @Benchmark
//  public void provider2(){
//    Security.addProvider(OpenSSLProvider2.INSTANCE);
//    try {
//      // handle方式发现服务
//      KeyPairGenerator.getInstance("RSA", "OpenSSL2");
//    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
//      throw new RuntimeException(e);
//    }
//  }
//
//  @Benchmark
//  public void provider1(){
//    Security.addProvider(new OpenSSLProvider1());
//    try {
//      // 反射方式发现服务
//      KeyPairGenerator.getInstance("RSA", "OpenSSL1");
//    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
//      throw new RuntimeException(e);
//    }
//  }

  @Benchmark
  public void batchGenerationRsa2(){
    for(int i = 0; i < batchSize; i++){
      NativeRsa2.generateKeyPair(2048);
    }
  }

  @Benchmark
  public void batchGenerationRsa3(){
    NativeRsa3.generateKeyPairs(batchSize);
  }

}
