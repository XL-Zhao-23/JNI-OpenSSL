#include <jni.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

// 结构体用来缓存线程上下文
typedef struct {
    EVP_PKEY_CTX *pctx;
    int bits;
} NativeRsaContext;

#ifdef _WIN32
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif

// RSA 密钥生成上下文是有状态的
// 声明线程局部变量，每个线程都会拥有一个独立的 NativeRsaContext 指针
// 创建 RSA 密钥生成上下文（EVP_PKEY_CTX）算法类型（这里是 RSA）、相关参数（比如密钥长度、指数等，稍后会设置）、
// 生成密钥时需要的内部状态和资源。
static THREAD_LOCAL NativeRsaContext *tls_ctx = NULL;

// 创建并初始化 RSA Key 生成上下文
JNIEXPORT jlong JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_initNativeContext
  (JNIEnv *env, jclass clazz, jint bits) {
    if (tls_ctx != NULL) {
        // 如果之前已经初始化过线程上下文，先释放它，避免内存泄漏
        if (tls_ctx->pctx) EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
    }
    // 分配内存用于 NativeRsaContext 结构体
    tls_ctx = (NativeRsaContext *)malloc(sizeof(NativeRsaContext));
    if (!tls_ctx) return 0;

    // 设置密钥长度
    tls_ctx->bits = bits;


    tls_ctx->pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!tls_ctx->pctx) {
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }
    // 初始化密钥生成操作
    if (EVP_PKEY_keygen_init(tls_ctx->pctx) <= 0) {
        EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }
    // 设置 RSA 位数参数
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(tls_ctx->pctx, bits) <= 0) {
        EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }

    // 将 native 指针转为 jlong 返回 Java 层（用于缓存或后续释放）
    // 指针对应的java jni类型是 jlong
    return (jlong)(uintptr_t)tls_ctx;
}


JNIEXPORT void JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_freeNativeContext
  (JNIEnv *env, jclass clazz, jlong ctxPtr) {
    // 将 Java long 类型还原为 native 指针
    NativeRsaContext *ctx = (NativeRsaContext *)(uintptr_t)ctxPtr;
    if (ctx != NULL) {
        // 释放 EVP 上下文
        if (ctx->pctx) EVP_PKEY_CTX_free(ctx->pctx);
        // 释放结构体本身
        free(ctx);
    }
    // 清空线程局部缓存
    tls_ctx = NULL;
}

// 批量生成密钥对，减少 JNI 进入次数
JNIEXPORT jobjectArray JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_generateRSAKeyPairsNative
  (JNIEnv *env, jclass clazz, jlong ctxPtr, jint count) {
    // 将 long 转换为上下文指针
    NativeRsaContext *ctx = (NativeRsaContext *)(uintptr_t)ctxPtr;
    // 校验上下文和请求数量
    if (!ctx || !ctx->pctx || count <= 0) {
        jclass excCls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (excCls) (*env)->ThrowNew(env, excCls, "Invalid context or count");
        return NULL;
    }
    // 准备 Java 类型：byte[]、byte[][]
    jclass byteArrayCls = (*env)->FindClass(env, "[B");
    if (byteArrayCls == NULL) return NULL;

    // 外层是 count 个 keyPair (byte[][])，每个 keyPair 是长度为2的 byte[] 数组
    jclass byte2DArrayCls = (*env)->FindClass(env, "[[B");
    if (byte2DArrayCls == NULL) return NULL;
    // 创建最终结果数组（每个元素是 byte[][]）
    jobjectArray result = (*env)->NewObjectArray(env, count, byte2DArrayCls, NULL);
    if (result == NULL) return NULL;

    for (int i = 0; i < count; i++) {
        // 创建一个新的 EVP_PKEY_CTX（不复用 pctx 避免并发问题）
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!pctx) goto error;
        if (EVP_PKEY_keygen_init(pctx) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            goto error;
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, ctx->bits) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            goto error;
        }
        // 执行生成操作
        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            goto error;
        }
        EVP_PKEY_CTX_free(pctx);

        // 私钥编码为 DER 格式（PKCS#8）
        PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(pkey);
        if (!p8inf) {
            EVP_PKEY_free(pkey);
            goto error;
        }
        unsigned char *priv_der = NULL;
        int priv_len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv_der);
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        if (priv_len <= 0) {
            EVP_PKEY_free(pkey);
            goto error;
        }

        // 公钥编码为 DER 格式（X.509 SubjectPublicKeyInfo）
        unsigned char *pub_der = NULL;
        int pub_len = i2d_PUBKEY(pkey, &pub_der);
        EVP_PKEY_free(pkey);
        if (pub_len <= 0) {
            OPENSSL_free(priv_der);
            goto error;
        }

        // 创建私钥byte[]
        jbyteArray jpriv = (*env)->NewByteArray(env, priv_len);
        if (!jpriv) {
            OPENSSL_free(priv_der);
            OPENSSL_free(pub_der);
            goto error;
        }
        (*env)->SetByteArrayRegion(env, jpriv, 0, priv_len, (jbyte *)priv_der);

        // 创建公钥byte[]
        jbyteArray jpub = (*env)->NewByteArray(env, pub_len);
        if (!jpub) {
            OPENSSL_free(priv_der);
            OPENSSL_free(pub_der);
            goto error;
        }
        (*env)->SetByteArrayRegion(env, jpub, 0, pub_len, (jbyte *)pub_der);

        OPENSSL_free(priv_der);
        OPENSSL_free(pub_der);

         // 将私钥和公钥组成 Java 的 byte[][] 数组
        jobjectArray keyPair = (*env)->NewObjectArray(env, 2, byteArrayCls, NULL);
        if (!keyPair) goto error;

        (*env)->SetObjectArrayElement(env, keyPair, 0, jpriv);
        (*env)->SetObjectArrayElement(env, keyPair, 1, jpub);

        // 把这个 keyPair 放进结果数组
        (*env)->SetObjectArrayElement(env, result, i, keyPair);
    }

    return result;

error:
    {
        // 抛出 Java RuntimeException，并附带 OpenSSL 错误信息
        jclass excCls = (*env)->FindClass(env, "java/lang/RuntimeException");
        if (excCls) {
            char errbuf[256];
            unsigned long err = ERR_get_error(); // 获取 OpenSSL 最后一条错误码
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            (*env)->ThrowNew(env, excCls, errbuf);
        }
        return NULL;
    }
}
