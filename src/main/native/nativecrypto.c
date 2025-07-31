#include <jni.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "nativecrypto.h"

JNIEXPORT jbyteArray JNICALL Java_org_example_NativeCrypto_generateECKeyPair(JNIEnv *env, jclass clazz, jstring curveName) {
    if (curveName == NULL) {
        printf("[nativecrypto] curveName is NULL!\n");
        return NULL;
    }
    const char *curve = (*env)->GetStringUTFChars(env, curveName, 0);
    if (curve == NULL) {
        printf("[nativecrypto] GetStringUTFChars failed!\n");
        return NULL;
    }
    printf("[nativecrypto] curveName = %s\n", curve);
    int nid = OBJ_sn2nid(curve);
    if (nid == 0) {
        printf("[nativecrypto] OBJ_sn2nid failed for curve: %s\n", curve);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(nid);
    if (!ec_key) {
        printf("[nativecrypto] EC_KEY_new_by_curve_name failed!\n");
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    if (!EC_KEY_generate_key(ec_key)) {
        printf("[nativecrypto] EC_KEY_generate_key failed!\n");
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }

    // Private key (PKCS8)
    BIO *privBio = BIO_new(BIO_s_mem());
    if (!privBio) {
        printf("[nativecrypto] BIO_new for privBio failed!\n");
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    EVP_PKEY *privPkey = EVP_PKEY_new();
    if (!privPkey) {
        printf("[nativecrypto] EVP_PKEY_new for privPkey failed!\n");
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    EVP_PKEY_set1_EC_KEY(privPkey, ec_key);
    if (!i2d_PKCS8PrivateKey_bio(privBio, privPkey, NULL, NULL, 0, NULL, NULL)) {
        printf("[nativecrypto] i2d_PKCS8PrivateKey_bio failed!\n");
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    BUF_MEM *privBuf;
    BIO_get_mem_ptr(privBio, &privBuf);
    if (!privBuf || !privBuf->data || privBuf->length <= 0) {
        printf("[nativecrypto] privBuf is invalid!\n");
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }

    // Public key (SPKI)
    EVP_PKEY *pubPkey = EVP_PKEY_new();
    if (!pubPkey) {
        printf("[nativecrypto] EVP_PKEY_new for pubPkey failed!\n");
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    EVP_PKEY_set1_EC_KEY(pubPkey, ec_key);
    BIO *pubBio = BIO_new(BIO_s_mem());
    if (!pubBio) {
        printf("[nativecrypto] BIO_new for pubBio failed!\n");
        EVP_PKEY_free(pubPkey);
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    if (!i2d_PUBKEY_bio(pubBio, pubPkey)) {
        printf("[nativecrypto] i2d_PUBKEY_bio failed!\n");
        BIO_free(pubBio);
        EVP_PKEY_free(pubPkey);
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    BUF_MEM *pubBuf;
    BIO_get_mem_ptr(pubBio, &pubBuf);
    if (!pubBuf || !pubBuf->data || pubBuf->length <= 0) {
        printf("[nativecrypto] pubBuf is invalid!\n");
        BIO_free(pubBio);
        EVP_PKEY_free(pubPkey);
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }

    // Combine into one byte array: [4-byte len][priv][pub]
    int totalLen = 4 + privBuf->length + pubBuf->length;
    jbyteArray result = (*env)->NewByteArray(env, totalLen);
    if (!result) {
        printf("[nativecrypto] NewByteArray failed!\n");
        BIO_free(pubBio);
        EVP_PKEY_free(pubPkey);
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }
    jbyte *out = malloc(totalLen);
    if (!out) {
        printf("[nativecrypto] malloc failed!\n");
        BIO_free(pubBio);
        EVP_PKEY_free(pubPkey);
        EVP_PKEY_free(privPkey);
        BIO_free(privBio);
        EC_KEY_free(ec_key);
        (*env)->ReleaseStringUTFChars(env, curveName, curve);
        return NULL;
    }

    int privLen = (int)privBuf->length;
    memcpy(out, &privLen, 4);
    memcpy(out + 4, privBuf->data, privBuf->length);
    memcpy(out + 4 + privBuf->length, pubBuf->data, pubBuf->length);

    (*env)->SetByteArrayRegion(env, result, 0, totalLen, out);

    free(out);
    BIO_free(pubBio);
    EVP_PKEY_free(pubPkey);
    EVP_PKEY_free(privPkey);
    BIO_free(privBio);
    EC_KEY_free(ec_key);
    (*env)->ReleaseStringUTFChars(env, curveName, curve);
    return result;
}
