#include <jni.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

JNIEXPORT jbyteArray JNICALL Java_com_zxl_cypto_NativeRsa_generateRSAKeyPairNative
  (JNIEnv *env, jclass clazz) {

    int keylen = 2048;
    unsigned long e = RSA_F4; // 65537

    RSA *rsa = NULL;
    BIGNUM *bne = BN_new();
    if (bne == NULL) return NULL;
    if (!BN_set_word(bne, e)) goto err;

    rsa = RSA_new();
    if (rsa == NULL) goto err;

    if (!RSA_generate_key_ex(rsa, keylen, bne, NULL)) goto err;

    // 写私钥到内存BIO，PEM格式PKCS#1私钥
    BIO *pri = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL)) goto err;

    // 写公钥到内存BIO，PEM格式PKCS#1公钥
    BIO *pub = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(pub, rsa)) goto err;

    BUF_MEM *pri_buf;
    BIO_get_mem_ptr(pri, &pri_buf);

    BUF_MEM *pub_buf;
    BIO_get_mem_ptr(pub, &pub_buf);

    int total_len = 4 + (int)pri_buf->length + (int)pub_buf->length;

    // 创建Java byte数组
    jbyteArray result = (*env)->NewByteArray(env, total_len);
    if (result == NULL) goto err;

    jbyte *buf = (jbyte *)malloc(total_len);
    if (buf == NULL) goto err;

    // 按小端序写入私钥长度
    buf[0] = (pri_buf->length) & 0xff;
    buf[1] = (pri_buf->length >> 8) & 0xff;
    buf[2] = (pri_buf->length >> 16) & 0xff;
    buf[3] = (pri_buf->length >> 24) & 0xff;

    memcpy(buf + 4, pri_buf->data, pri_buf->length);
    memcpy(buf + 4 + pri_buf->length, pub_buf->data, pub_buf->length);

    // 设置Java数组内容
    (*env)->SetByteArrayRegion(env, result, 0, total_len, buf);

    free(buf);
    BIO_free(pri);
    BIO_free(pub);
    RSA_free(rsa);
    BN_free(bne);

    return result;

err:
    if (rsa) RSA_free(rsa);
    if (bne) BN_free(bne);
    return NULL;
}
