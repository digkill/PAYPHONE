#include <jni.h>
#include "payphone_mobile.h"

#define JNI_NAME(name) Java_com_payphone_android_transport_NativeQuic_##name

JNIEXPORT jlong JNICALL JNI_NAME(open)(JNIEnv *env, jobject self, jbyteArray key, jbyteArray pin) {
    (void)self;
    if ((*env)->GetArrayLength(env, key) != 32) return 0;
    jbyte *k = (*env)->GetByteArrayElements(env, key, NULL);
    if (!k) return 0;
    jsize len = pin ? (*env)->GetArrayLength(env, pin) : 0;
    jbyte *p = pin ? (*env)->GetByteArrayElements(env, pin, NULL) : NULL;
    if (pin && !p) { (*env)->ReleaseByteArrayElements(env, key, k, JNI_ABORT); return 0; }
    uint64_t handle = pp_open((const uint8_t *)k, (const uint8_t *)p, len);
    if (p) (*env)->ReleaseByteArrayElements(env, pin, p, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, k, JNI_ABORT);
    return (jlong)handle;
}

JNIEXPORT jint JNICALL JNI_NAME(socketFd)(JNIEnv *env, jobject self, jlong handle) {
    (void)env; (void)self; return pp_socket_fd(handle);
}

JNIEXPORT jint JNICALL JNI_NAME(connect)(JNIEnv *env, jobject self, jlong handle, jbyteArray address, jbyteArray sni) {
    (void)self;
    jbyte *a = (*env)->GetByteArrayElements(env, address, NULL);
    if (!a) return -1;
    jbyte *s = (*env)->GetByteArrayElements(env, sni, NULL);
    if (!s) { (*env)->ReleaseByteArrayElements(env, address, a, JNI_ABORT); return -1; }
    int result = pp_connect(handle, (const uint8_t *)a, (*env)->GetArrayLength(env, address),
                           (const uint8_t *)s, (*env)->GetArrayLength(env, sni));
    (*env)->ReleaseByteArrayElements(env, address, a, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, sni, s, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL JNI_NAME(send)(JNIEnv *env, jobject self, jlong handle, jbyteArray data) {
    (void)self;
    jbyte *d = (*env)->GetByteArrayElements(env, data, NULL);
    if (!d) return -1;
    int result = pp_send(handle, (const uint8_t *)d, (*env)->GetArrayLength(env, data));
    (*env)->ReleaseByteArrayElements(env, data, d, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL JNI_NAME(receive)(JNIEnv *env, jobject self, jlong handle, jbyteArray out) {
    (void)self;
    uint8_t buffer[65535];
    if ((*env)->GetArrayLength(env, out) < (jsize)sizeof(buffer)) return -1;
    int result = pp_receive(handle, buffer, sizeof(buffer));
    if (result > 0) (*env)->SetByteArrayRegion(env, out, 0, result, (const jbyte *)buffer);
    return result;
}

JNIEXPORT void JNICALL JNI_NAME(close)(JNIEnv *env, jobject self, jlong handle) {
    (void)env; (void)self; pp_close(handle);
}
