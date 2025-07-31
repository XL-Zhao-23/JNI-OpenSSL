package org.example;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.TimeUnit;
// PS G:\IdeaProject\issue2\src\main\native> cd ../java
// PS G:\IdeaProject\issue2\src\main\java> javac org/example/OpenSSLECKeyGen.java
// PS G:\IdeaProject\issue2\src\main\java> java org.example.OpenSSLECKeyGen
import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Thread)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(1)
public class OpenSSLECKeyGenBenchmark {

  @Param({"secp256r1"})
  public String curveName;

  private KeyPairGenerator jdkGenerator;

  @Setup(Level.Iteration)
  public void setup() throws Exception {
    jdkGenerator = KeyPairGenerator.getInstance("EC");
    jdkGenerator.initialize(new ECGenParameterSpec(curveName));
  }

  /** 使用 JNI + OpenSSL 实现的 EC 密钥生成 */
  @Benchmark
  public KeyPair testOpenSSLECKeyGen() throws Exception {
    return OpenSSLECKeyGen.generate(curveName);
  }

  /** Java 标准库原生实现的 EC 密钥生成 */
  @Benchmark
  public KeyPair testJDKECKeyGen() {
    return jdkGenerator.generateKeyPair();
  }
}
