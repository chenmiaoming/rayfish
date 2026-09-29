#!/usr/bin/env bash
set -euo pipefail

: "${ANDROID_KEYSTORE_BASE64:?Set ANDROID_KEYSTORE_BASE64}"
: "${ANDROID_KEYSTORE_PASSWORD:?Set ANDROID_KEYSTORE_PASSWORD}"
: "${ANDROID_KEY_ALIAS:?Set ANDROID_KEY_ALIAS}"
: "${ANDROID_KEY_PASSWORD:?Set ANDROID_KEY_PASSWORD}"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:?Set ANDROID_HOME or ANDROID_SDK_ROOT}}"
apksigner="$sdk/build-tools/35.0.0/apksigner"
[[ -x "$apksigner" ]] || { echo 'Install Android build-tools 35.0.0.' >&2; exit 1; }

cd "$(dirname "$0")/../android"
if [[ -e keystore.properties ]]; then
    echo 'Refusing to overwrite existing keystore.properties.' >&2
    exit 1
fi

umask 077
signing_dir=$(mktemp -d)
cleanup() {
    rm -f -- keystore.properties "$signing_dir/release.p12"
    rmdir -- "$signing_dir"
}
trap cleanup EXIT

python3 - "$signing_dir/release.p12" <<'PY'
import base64
import os
from pathlib import Path
import sys

keystore = Path(sys.argv[1])
keystore.write_bytes(base64.b64decode(os.environ['ANDROID_KEYSTORE_BASE64'], validate=True))
properties = {
    'storeFile': str(keystore),
    'storePassword': os.environ['ANDROID_KEYSTORE_PASSWORD'],
    'keyAlias': os.environ['ANDROID_KEY_ALIAS'],
    'keyPassword': os.environ['ANDROID_KEY_PASSWORD'],
}

def escape(value):
    escapes = {'\\': '\\\\', '\n': '\\n', '\r': '\\r', '\t': '\\t', ' ': '\\ '}
    units = value.encode('utf-16-be')
    return ''.join(
        escapes.get(chr(unit), chr(unit) if 33 <= unit <= 126 else f'\\u{unit:04x}')
        for unit in (int.from_bytes(units[i:i + 2], 'big') for i in range(0, len(units), 2))
    )

with open('keystore.properties', 'x', encoding='ascii') as output:
    for name, value in properties.items():
        output.write(f'{name}={escape(value)}\n')
PY

expected=$(keytool -exportcert -keystore "$signing_dir/release.p12" \
    -storepass:env ANDROID_KEYSTORE_PASSWORD -alias "$ANDROID_KEY_ALIAS" | sha256sum)
expected=${expected%% *}

./gradlew --no-daemon :app:assembleRelease "$@"
apk=app/build/outputs/apk/release/app-release.apk
certificate=$("$apksigner" verify --print-certs "$apk")
actual=$(sed -n 's/^Signer #1 certificate SHA-256 digest: //p' <<< "$certificate")
if [[ "$actual" != "$expected" ]]; then
    echo 'APK signing certificate does not match the configured release key.' >&2
    exit 1
fi
echo 'Release APK signature verified.'
