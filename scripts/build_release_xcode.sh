#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

VER="9.21-06"
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
COMMON=(-isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -fblocks -Werror=return-type -Werror=implicit-function-declaration)
DYLIB_FW=(-framework Foundation -framework UIKit -framework CoreGraphics -framework CoreTelephony -framework Security)
APP_FW=(-framework Foundation -framework UIKit -framework CoreGraphics)
mkdir -p build dist

# 双架构编译
for ARCH in arm64 arm64e; do
    xcrun --sdk iphoneos clang -arch "$ARCH" "${COMMON[@]}" "${DYLIB_FW[@]}" \
        -dynamiclib -install_name @rpath/NDSpoofer_${VER}.dylib \
        NDSpoofer.m -o "build/NDSpoofer_${ARCH}.dylib"
    xcrun --sdk iphoneos clang -arch "$ARCH" "${COMMON[@]}" "${APP_FW[@]}" \
        CraneManager/NDCraneManager.m -o "build/NDCraneManager_${ARCH}"
done

# 合并 dylib 并 ad-hoc 签名
lipo -create build/NDSpoofer_arm64.dylib build/NDSpoofer_arm64e.dylib -output "dist/NDSpoofer_${VER}.dylib"
codesign --force --sign - --timestamp=none "dist/NDSpoofer_${VER}.dylib"

# 打包 RootHide deb
APP=build/package/Applications/NDCraneManager.app
mkdir -p "$APP" build/package/Library/libSandy build/package/DEBIAN build/deb
lipo -create build/NDCraneManager_arm64 build/NDCraneManager_arm64e -output "$APP/NDCraneManager"
cp CraneManager/Info.plist ndspoofer_config.plist CraneManager/AppIcon60x60@2x.png CraneManager/AppIcon60x60@3x.png "$APP/"
cp CraneManager/NDCraneManager.libSandy.plist build/package/Library/libSandy/NDCraneManager.plist
cp CraneManager/control CraneManager/postinst CraneManager/prerm build/package/DEBIAN/
chmod 0755 "$APP/NDCraneManager" build/package/DEBIAN/postinst build/package/DEBIAN/prerm
codesign --force --sign - --timestamp=none --entitlements CraneManager/NDCraneManager.entitlements "$APP"

printf '2.0\n' > build/deb/debian-binary
COPYFILE_DISABLE=1 tar -C build/package/DEBIAN -czf build/deb/control.tar.gz .
COPYFILE_DISABLE=1 tar -C build/package --exclude='./DEBIAN' -czf build/deb/data.tar.gz .
(cd build/deb && ar -rc "../../dist/NDSpooferCraneManager_${VER}_RootHide.deb" debian-binary control.tar.gz data.tar.gz)

# 校验
codesign --verify --strict "dist/NDSpoofer_${VER}.dylib"
codesign --verify --strict "$APP"
lipo -info "dist/NDSpoofer_${VER}.dylib"
lipo -info "$APP/NDCraneManager"
otool -hv "dist/NDSpoofer_${VER}.dylib"
otool -l "dist/NDSpoofer_${VER}.dylib" | grep -A2 '__interpose' || true
ar -t "dist/NDSpooferCraneManager_${VER}_RootHide.deb"
tar -tzf build/deb/data.tar.gz

cp ndspoofer_config.plist dist/
(cd dist && shasum -a 256 "NDSpoofer_${VER}.dylib" "NDSpooferCraneManager_${VER}_RootHide.deb" > SHA256SUMS.txt)
cat dist/SHA256SUMS.txt
