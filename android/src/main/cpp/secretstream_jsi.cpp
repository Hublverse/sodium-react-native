#include "secretstream_push.h"

#include <jni.h>

extern "C" JNIEXPORT jboolean JNICALL
Java_com_sodiumreactnative_SodiumReactNativeModule_nativeInstallSecretstreamPush(
    JNIEnv *,
    jobject,
    jlong runtimePointer) {
  if (runtimePointer == 0) {
    return JNI_FALSE;
  }

  try {
    sodiumInstallSecretstreamPush(
        *reinterpret_cast<facebook::jsi::Runtime *>(runtimePointer));
    return JNI_TRUE;
  } catch (...) {
    return JNI_FALSE;
  }
}
