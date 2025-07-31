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

// 线程局部缓存上下文指针
static THREAD_LOCAL NativeRsaContext *tls_ctx = NULL;

// 创建并初始化 RSA Key 生成上下文
JNIEXPORT jlong JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_initNativeContext
  (JNIEnv *env, jclass clazz, jint bits) {
    if (tls_ctx != NULL) {
        // 可能调用了两次，先释放
        if (tls_ctx->pctx) EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
    }

    tls_ctx = (NativeRsaContext *)malloc(sizeof(NativeRsaContext));
    if (!tls_ctx) return 0;

    tls_ctx->bits = bits;
    tls_ctx->pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!tls_ctx->pctx) {
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }
    if (EVP_PKEY_keygen_init(tls_ctx->pctx) <= 0) {
        EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(tls_ctx->pctx, bits) <= 0) {
        EVP_PKEY_CTX_free(tls_ctx->pctx);
        free(tls_ctx);
        tls_ctx = NULL;
        return 0;
    }

    // 返回指针作为 long 给 Java 层保存（也可以不用返回，直接用 tls_ctx）
    return (jlong)(uintptr_t)tls_ctx;
}

// 释放上下文
JNIEXPORT void JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_freeNativeContext
  (JNIEnv *env, jclass clazz, jlong ctxPtr) {
    NativeRsaContext *ctx = (NativeRsaContext *)(uintptr_t)ctxPtr;
    if (ctx != NULL) {
        if (ctx->pctx) EVP_PKEY_CTX_free(ctx->pctx);
        free(ctx);
    }
    tls_ctx = NULL;
}

// 批量生成密钥对，减少 JNI 进入次数
JNIEXPORT jobjectArray JNICALL Java_com_zxl_cypto_rsa_NativeRsa3_generateRSAKeyPairsNative
  (JNIEnv *env, jclass clazz, jlong ctxPtr, jint count) {
    NativeRsaContext *ctx = (NativeRsaContext *)(uintptr_t)ctxPtr;
    if (!ctx || !ctx->pctx || count <= 0) {
        jclass excCls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (excCls) (*env)->ThrowNew(env, excCls, "Invalid context or count");
        return NULL;
    }

    jclass byteArrayCls = (*env)->FindClass(env, "[B");
    if (byteArrayCls == NULL) return NULL;

    // 外层是 count 个 keyPair (byte[][])，每个 keyPair 是长度为2的 byte[] 数组
    jclass byte2DArrayCls = (*env)->FindClass(env, "[[B");
    if (byte2DArrayCls == NULL) return NULL;

    jobjectArray result = (*env)->NewObjectArray(env, count, byte2DArrayCls, NULL);
    if (result == NULL) return NULL;

    for (int i = 0; i < count; i++) {
        // 重新初始化 EVP_PKEY_CTX，避免复用带来的状态问题
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

        EVP_PKEY *pkey = NULL;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            goto error;
        }
        EVP_PKEY_CTX_free(pctx);

        // 私钥转 PKCS#8
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

        // 公钥转 X509
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

        // 创建 keyPair byte[][] 数组
        jobjectArray keyPair = (*env)->NewObjectArray(env, 2, byteArrayCls, NULL);
        if (!keyPair) goto error;

        (*env)->SetObjectArrayElement(env, keyPair, 0, jpriv);
        (*env)->SetObjectArrayElement(env, keyPair, 1, jpub);

        // 将 keyPair 放入结果数组
        (*env)->SetObjectArrayElement(env, result, i, keyPair);
    }

    return result;

error:
    {
        jclass excCls = (*env)->FindClass(env, "java/lang/RuntimeException");
        if (excCls) {
            char errbuf[256];
            unsigned long err = ERR_get_error();
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            (*env)->ThrowNew(env, excCls, errbuf);
        }
        return NULL;
    }
}
