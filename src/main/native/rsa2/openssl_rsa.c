#include <jni.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

JNIEXPORT jobjectArray JNICALL Java_com_zxl_cypto_rsa_NativeRsa2_generateRSAKeyPairNative
  (JNIEnv *env, jclass clazz, jint bits) {

    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned char *priv_der = NULL;
    unsigned char *pub_der = NULL;
    int priv_len = 0, pub_len = 0;
    jobjectArray result = NULL;

    // 1. 生成 RSA 密钥
    bne = BN_new();
    if (!bne || !BN_set_word(bne, RSA_F4)) goto cleanup;

    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, bits, bne, NULL)) goto cleanup;

    pkey = EVP_PKEY_new();
    if (!pkey || !EVP_PKEY_assign_RSA(pkey, rsa)) goto cleanup;
    rsa = NULL;  // pkey 现在拥有 rsa，防止重复释放

    // 2. 转换为 PKCS#8 私钥格式
    PKCS8_PRIV_KEY_INFO *p8inf = EVP_PKEY2PKCS8(pkey);
    if (!p8inf) goto cleanup;
    priv_len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv_der);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (priv_len <= 0) goto cleanup;


    // 3. 转换为 X.509 公钥格式
    pub_len = i2d_PUBKEY(pkey, &pub_der);
    if (pub_len <= 0) goto cleanup;

    // 4. 构造 Java byte[][] 结果
    jclass byteArrayCls = (*env)->FindClass(env, "[B");
    if (byteArrayCls == NULL) goto cleanup;

    result = (*env)->NewObjectArray(env, 2, byteArrayCls, NULL);
    if (result == NULL) goto cleanup;

    jbyteArray jpriv = (*env)->NewByteArray(env, priv_len);
    jbyteArray jpub  = (*env)->NewByteArray(env, pub_len);
    if (!jpriv || !jpub) goto cleanup;

    (*env)->SetByteArrayRegion(env, jpriv, 0, priv_len, (jbyte *)priv_der);
    (*env)->SetByteArrayRegion(env, jpub, 0, pub_len, (jbyte *)pub_der);

    (*env)->SetObjectArrayElement(env, result, 0, jpriv);
    (*env)->SetObjectArrayElement(env, result, 1, jpub);

cleanup:
    if (bne) BN_free(bne);
    if (rsa) RSA_free(rsa);  // 只有没被转交给 EVP_PKEY 才 free
    if (pkey) EVP_PKEY_free(pkey);
    if (priv_der) OPENSSL_free(priv_der);  // 一定不能用 free()
    if (pub_der)  OPENSSL_free(pub_der);

    if (!result) {
        jclass excCls = (*env)->FindClass(env, "java/lang/RuntimeException");
        if (excCls) {
            char errbuf[256];
            unsigned long err = ERR_get_error();
            ERR_error_string_n(err, errbuf, sizeof(errbuf));
            (*env)->ThrowNew(env, excCls, errbuf);
        }
    }

    return result;
}
