/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>
#include <string.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include "openssl/evp.h"
#include "openssl/pkcs12.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    PKCS12Key_derive
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_PKCS12Key_1derive(
    JNIEnv *env, jclass thisObj, jlong contextId, jbyteArray password,
    jbyteArray salt, jint iterations, jint type, jint n, jbyteArray key) {
    static const char* functionName   = "NativeInterface.PKCS12Key_derive";
    unsigned char*     passwordNative = NULL;
    unsigned char*     saltNative     = NULL;
    int                passwordLength = 0;
    int                saltLength     = 0;
    unsigned char*     keyNative      = NULL;
    jboolean           isCopy         = 0;
    
    saltNative = (*env)->GetPrimitiveArrayCritical(env, salt, &isCopy);
    saltLength = (*env)->GetArrayLength(env, salt);

    passwordNative = (*env)->GetPrimitiveArrayCritical(env, password, &isCopy);
    passwordLength = (*env)->GetArrayLength(env, password);

    keyNative = (*env)->GetPrimitiveArrayCritical(env, key, &isCopy);

    PKCS12_key_gen_uni(passwordNative, passwordLength, saltNative, saltLength, type, iterations, n, keyNative, EVP_sha1());
}
