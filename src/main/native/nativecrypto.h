#include <jni.h>

#ifndef _Included_com_tencent_kona_crypto_NativeCrypto
#define _Included_com_tencent_kona_crypto_NativeCrypto
#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jbyteArray JNICALL Java_org_example_NativeCrypto_generateECKeyPair(JNIEnv *, jclass, jstring);
#ifdef __cplusplus
}
#endif
#endif
