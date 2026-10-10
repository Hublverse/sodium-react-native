#include "secretstream_push.h"

#include "sodium.h"

namespace {

constexpr int kBadInput = 1;
constexpr int kBadOutput = 2;
const char *kPushName = "__sodiumSecretstreamPushBytes";

struct Bytes {
  uint8_t *data;
  size_t length;
};

bool readTypedArray(
    facebook::jsi::Runtime &runtime,
    const facebook::jsi::Value &value,
    Bytes &out) {
  if (!value.isObject()) {
    return false;
  }

  facebook::jsi::Object object = value.asObject(runtime);
  facebook::jsi::Value bufferValue = object.getProperty(runtime, "buffer");
  if (!bufferValue.isObject()) {
    return false;
  }

  facebook::jsi::Object bufferObject = bufferValue.asObject(runtime);
  if (!bufferObject.isArrayBuffer(runtime)) {
    return false;
  }

  facebook::jsi::ArrayBuffer buffer = bufferObject.getArrayBuffer(runtime);
  facebook::jsi::Value offsetValue = object.getProperty(runtime, "byteOffset");
  facebook::jsi::Value lengthValue = object.getProperty(runtime, "byteLength");
  if (!offsetValue.isNumber() || !lengthValue.isNumber()) {
    return false;
  }

  const double offsetNumber = offsetValue.asNumber();
  const double lengthNumber = lengthValue.asNumber();
  if (offsetNumber < 0 || lengthNumber < 0) {
    return false;
  }

  const size_t offset = static_cast<size_t>(offsetNumber);
  const size_t length = static_cast<size_t>(lengthNumber);
  const size_t bufferSize = buffer.size(runtime);
  if (offset > bufferSize || length > bufferSize - offset) {
    return false;
  }

  uint8_t *data = buffer.data(runtime);
  if (data == nullptr && length != 0) {
    return false;
  }

  out.data = length == 0 ? nullptr : data + offset;
  out.length = length;
  return true;
}

facebook::jsi::Value pushBytes(
    facebook::jsi::Runtime &runtime,
    const facebook::jsi::Value *args,
    size_t count) {
  if (count < 5 || !args[4].isNumber()) {
    return facebook::jsi::Value(kBadInput);
  }

  const double tagNumber = args[4].asNumber();
  if (tagNumber < 0 || tagNumber > 255) {
    return facebook::jsi::Value(kBadInput);
  }

  Bytes state{nullptr, 0};
  Bytes ciphertext{nullptr, 0};
  Bytes message{nullptr, 0};
  Bytes additionalData{nullptr, 0};
  if (!readTypedArray(runtime, args[0], state) ||
      !readTypedArray(runtime, args[1], ciphertext) ||
      !readTypedArray(runtime, args[2], message)) {
    return facebook::jsi::Value(kBadInput);
  }
  if (!args[3].isNull() && !args[3].isUndefined() &&
      !readTypedArray(runtime, args[3], additionalData)) {
    return facebook::jsi::Value(kBadInput);
  }

  const size_t stateBytes = crypto_secretstream_xchacha20poly1305_statebytes();
  const size_t authenticatedBytes =
      crypto_secretstream_xchacha20poly1305_abytes();
  if (state.length != stateBytes ||
      ciphertext.length != message.length + authenticatedBytes) {
    return facebook::jsi::Value(kBadInput);
  }

  if (sodium_init() < 0) {
    return facebook::jsi::Value(kBadInput);
  }

  unsigned long long ciphertextLength = 0;
  const int result = crypto_secretstream_xchacha20poly1305_push(
      reinterpret_cast<crypto_secretstream_xchacha20poly1305_state *>(state.data),
      ciphertext.data,
      &ciphertextLength,
      message.data,
      message.length,
      additionalData.data,
      additionalData.length,
      static_cast<unsigned char>(tagNumber));
  if (result != 0) {
    return facebook::jsi::Value(static_cast<double>(result));
  }
  if (ciphertextLength != ciphertext.length) {
    return facebook::jsi::Value(kBadOutput);
  }
  return facebook::jsi::Value(0);
}

} // namespace

void sodiumInstallSecretstreamPush(facebook::jsi::Runtime &runtime) {
  if (runtime.global().hasProperty(runtime, kPushName)) {
    return;
  }

  facebook::jsi::Function push = facebook::jsi::Function::createFromHostFunction(
      runtime,
      facebook::jsi::PropNameID::forAscii(runtime, kPushName),
      5,
      [](facebook::jsi::Runtime &rt,
         const facebook::jsi::Value &,
         const facebook::jsi::Value *args,
         size_t count) -> facebook::jsi::Value {
        try {
          return pushBytes(rt, args, count);
        } catch (...) {
          return facebook::jsi::Value(kBadInput);
        }
      });
  runtime.global().setProperty(runtime, kPushName, std::move(push));
}
