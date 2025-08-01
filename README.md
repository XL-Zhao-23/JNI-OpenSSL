# JNI-OpenSSL 项目

## 项目简介

JNI-OpenSSL 是一个基于 JNI (Java Native Interface) 和 OpenSSL 的高性能 RSA 密钥生成项目。该项目实现了多种 RSA 密钥生成方案，包括 JDK 原生实现、JNI 调用 OpenSSL 实现，以及自定义的 Java Security Provider 实现。

## 项目结构

```
JNI-OpenSSL/
├── src/main/java/com/zxl/cypto/
│   ├── Main.java                    # 主程序入口
│   ├── RsaBenchmark.java           # 性能基准测试
│   ├── provider/                    # Java Security Provider 实现
│   │   ├── OpenSSLProvider1.java   # 反射方式 Provider
│   │   ├── OpenSSLProvider2.java   # MethodHandle 方式 Provider
│   │   └── OpenSSLRSAGenerator.java # RSA 密钥生成器
│   └── rsa/                        # JNI 原生实现
│       ├── NativeRsa1.java         # 基于 PEM 格式的 RSA 实现
│       ├── NativeRsa2.java         # 基于 PKCS8/X509 格式的 RSA 实现
│       └── NativeRsa3.java         # 批量生成优化的 RSA 实现
├── src/main/native/                 # 原生代码实现
│   ├── rsa1/                       # NativeRsa1 对应的 C 代码
│   ├── rsa2/                       # NativeRsa2 对应的 C 代码
│   └── rsa3/                       # NativeRsa3 对应的 C 代码
└── pom.xml                         # Maven 配置文件
```

## 功能特性

### 1. 多种 RSA 实现方案

#### JDK 原生实现
- 使用 Java 标准库的 RSA 密钥生成
- 作为性能基准对比

#### JNI + OpenSSL 实现
- **NativeRsa1**: 基于 PEM 格式，支持 PKCS#1 和 PKCS#8 私钥格式
- **NativeRsa2**: 基于 PKCS8/X509 格式，直接返回字节数组
- **NativeRsa3**: 批量生成优化版本，使用 ThreadLocal 管理原生上下文

#### 自定义 Security Provider
- **OpenSSLProvider1**: 使用反射方式发现服务
- **OpenSSLProvider2**: 使用 MethodHandle 方式发现服务，性能更优

### 2. 性能优化特性

- **批量生成**: NativeRsa3 支持批量生成 RSA 密钥对，减少 JNI 调用开销
- **上下文复用**: 使用 ThreadLocal 管理原生上下文，避免重复初始化
- **内存管理**: 提供资源释放机制，防止内存泄漏

## 性能测试结果

### RSA 密钥生成性能对比

| 实现方案 | 性能 (ops/s) | 误差范围 |
|---------|-------------|----------|
| JDK RSA | 7.981 | ±1.398 |
| NativeRsa1 | 11.529 | ±4.868 |
| NativeRsa2 | 12.658 | ±4.177 |
| NativeRsa3 | 13.606 | ±4.787 |

### Provider 发现性能对比

| Provider 实现 | 性能 (ops/s) | 误差范围 |
|--------------|-------------|----------|
| OpenSSLProvider1 (反射) | 2,204,796.742 | ±417,543.544 |
| OpenSSLProvider2 (MethodHandle) | 6,936,790.673 | ±915,992.159 |

## 编译和运行

### 环境要求

- Java 17+
- Maven 3.6+
- OpenSSL 开发库
- C/C++ 编译器

### 编译步骤

1. **编译原生代码**
   ```bash
   # 编译 rsa1
   cd src/main/native/rsa1
   gcc -shared -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
       -lssl -lcrypto -o librsa1.so openssl_rsa.c
   
   # 编译 rsa2
   cd ../rsa2
   gcc -shared -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
       -lssl -lcrypto -o librsa2.so openssl_rsa.c
   
   # 编译 rsa3
   cd ../rsa3
   gcc -shared -fPIC -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
       -lssl -lcrypto -o librsa3.so openssl_rsa.c
   ```

2. **编译 Java 项目**
   ```bash
   mvn clean compile
   ```

3. **运行基准测试**
   ```bash
   # 设置库路径
   export LD_LIBRARY_PATH=src/main/native/rsa1:src/main/native/rsa2:src/main/native/rsa3:$LD_LIBRARY_PATH
   
   # 运行基准测试
   java -Djava.library.path=src/main/java -jar target/JNI-OpenSSL-1.0-SNAPSHOT.jar
   ```

### 使用示例

#### 基本使用
```java
// 使用 NativeRsa1
KeyPair keyPair1 = NativeRsa1.generate();

// 使用 NativeRsa2
KeyPair keyPair2 = NativeRsa2.generateKeyPair(2048);

// 使用 NativeRsa3
KeyPair keyPair3 = NativeRsa3.generateKeyPair();

// 批量生成
byte[][][] keyPairs = NativeRsa3.generateKeyPairs(100);
```

#### 使用自定义 Provider
```java
// 注册 Provider
Security.addProvider(new OpenSSLProvider1());
Security.addProvider(OpenSSLProvider2.INSTANCE);

// 使用 Provider 生成密钥
KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSL2");
gen.initialize(2048);
KeyPair keyPair = gen.generateKeyPair();
```

## 技术细节

### JNI 实现特点

1. **NativeRsa1**: 
   - 返回 PEM 格式的密钥对
   - 支持多种私钥格式解析
   - 使用 BouncyCastle 进行格式转换

2. **NativeRsa2**: 
   - 直接返回 PKCS8/X509 格式的字节数组
   - 减少格式转换开销
   - 更简洁的实现

3. **NativeRsa3**: 
   - 批量生成优化
   - ThreadLocal 上下文管理
   - 内存资源管理

### Provider 实现特点

1. **OpenSSLProvider1**: 
   - 使用反射方式发现服务
   - 简单直接的实现

2. **OpenSSLProvider2**: 
   - 使用 MethodHandle 方式发现服务
   - 性能更优，类型安全
   - 支持动态算法名称设置

## 性能分析

从测试结果可以看出：

1. **JNI 实现优于 JDK**: 所有 JNI 实现的性能都优于 JDK 原生实现，性能提升 44%-70%

2. **批量生成优化**: NativeRsa3 通过批量生成和上下文复用，获得了最佳性能

3. **MethodHandle 优于反射**: OpenSSLProvider2 使用 MethodHandle 比 OpenSSLProvider1 使用反射快约 3 倍

4. **Provider 发现性能极高**: 自定义 Provider 的发现性能达到数百万 ops/s，说明 JNI 调用开销相对较小

## 注意事项

1. **库路径设置**: 确保正确设置 `java.library.path` 或 `LD_LIBRARY_PATH`
2. **OpenSSL 依赖**: 需要安装 OpenSSL 开发库
3. **内存管理**: 使用 NativeRsa3 时注意调用 `freeContext()` 释放资源
4. **线程安全**: 各实现都是线程安全的，NativeRsa3 使用 ThreadLocal 确保线程隔离

## 依赖项

- **JMH**: 用于性能基准测试
- **BouncyCastle**: 用于密钥格式转换
- **OpenSSL**: 原生加密库
- **Maven**: 项目构建工具

## 许可证

本项目采用开源许可证，具体许可证信息请查看 LICENSE 文件。 