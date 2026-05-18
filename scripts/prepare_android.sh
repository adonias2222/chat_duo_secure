#!/usr/bin/env bash
set -e

flutter create . --platforms=android --project-name chat_duo_secure --org br.com.chatduo

MANIFEST="android/app/src/main/AndroidManifest.xml"
if [ -f "$MANIFEST" ] && ! grep -q "android.permission.CAMERA" "$MANIFEST"; then
  python3 - <<'PYMANIFEST'
from pathlib import Path
p = Path('android/app/src/main/AndroidManifest.xml')
s = p.read_text()
perms = '''
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
    <uses-permission android:name="android.permission.BLUETOOTH" />
    <uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_MEDIA_IMAGES" />
    <uses-permission android:name="android.permission.READ_MEDIA_VIDEO" />
    <uses-permission android:name="android.permission.READ_MEDIA_AUDIO" />
'''
s = s.replace('<manifest xmlns:android="http://schemas.android.com/apk/res/android">', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n' + perms)
p.write_text(s)
PYMANIFEST
fi

if [ -f "android/app/build.gradle.kts" ]; then
  sed -i 's/minSdk = flutter.minSdkVersion/minSdk = 23/g' android/app/build.gradle.kts || true
fi
if [ -f "android/app/build.gradle" ]; then
  sed -i 's/minSdkVersion flutter.minSdkVersion/minSdkVersion 23/g' android/app/build.gradle || true
fi

echo "Android preparado para WebRTC, câmera, microfone e internet."
