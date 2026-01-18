#!/usr/bin/env bash
set -e

appName="x-tunnel"
builtAt="$(date +'%F %T %z')"
gitCommit=$(git log --pretty=format:"%h" -1)
version=$(git describe --abbrev=0 --tags 2>/dev/null || echo "v1.0.0")

ldflags="-w -s \
-X 'main.builtAt=$builtAt' \
-X 'main.gitCommit=$gitCommit' \
-X 'main.version=$version'"

mkdir -p build

# ========================================
# 直接粘贴 OpenList 原始验证过千次的函数（零修改）
# ========================================

# 1. BuildWinArm64（windows-arm64）
BuildWinArm64() {
  echo "building for windows-arm64"
  curl -fsSL -o zcc-arm64 https://github.com/OpenListTeam/OpenList/raw/main/wrapper/zcc-arm64
  curl -fsSL -o zcxx-arm64 https://github.com/OpenListTeam/OpenList/raw/main/wrapper/zcxx-arm64
  chmod +x zcc-arm64 zcxx-arm64
  CC="$PWD/zcc-arm64" CXX="$PWD/zcxx-arm64" \
    GOOS=windows GOARCH=arm64 CGO_ENABLED=1 \
    go build -o "build/${appName}-windows-arm64.exe" -ldflags="$ldflags" .
}

# 2. BuildReleaseLinuxMusl（所有 musl 冷门）
BuildReleaseLinuxMusl() {
  mkdir -p "build"
  local muslflags="--extldflags '-static -fpic' $ldflags"
  local BASE="https://github.com/OpenListTeam/musl-compilers/releases/latest/download/"
  local FILES=(x86_64-linux-musl-cross aarch64-linux-musl-cross mips-linux-musl-cross mips64-linux-musl-cross mips64el-linux-musl-cross mipsel-linux-musl-cross powerpc64le-linux-musl-cross s390x-linux-musl-cross loongarch64-linux-musl-cross)
  for i in "${FILES[@]}"; do
    curl -fsSL -o "${i}.tgz" "${BASE}${i}.tgz"
    sudo tar xf "${i}.tgz" --strip-components 1 -C /usr/local
    rm -f "${i}.tgz"
  done
  local OS_ARCHES=(linux-musl-amd64 linux-musl-arm64 linux-musl-mips linux-musl-mips64 linux-musl-mips64le linux-musl-mipsle linux-musl-ppc64le linux-musl-s390x linux-musl-loong64)
  local CGO_ARGS=(x86_64-linux-musl-gcc aarch64-linux-musl-gcc mips-linux-musl-gcc mips64-linux-musl-gcc mips64el-linux-musl-gcc mipsel-linux-musl-gcc powerpc64le-linux-musl-gcc s390x-linux-musl-gcc loongarch64-linux-musl-gcc)
  for i in "${!OS_ARCHES[@]}"; do
    os_arch=${OS_ARCHES[$i]}
    cgo_cc=${CGO_ARGS[$i]}
    export GOOS=${os_arch%%-*} GOARCH=${os_arch##*-} CC=$cgo_cc CGO_ENABLED=1
    echo "building for ${os_arch}"
    go build -o "./build/$appName-$os_arch" -ldflags="$muslflags" .
  done
}

# 3. BuildReleaseLinuxMuslArm（11 个极端 arm 变种）
BuildReleaseLinuxMuslArm() {
  mkdir -p "build"
  local muslflags="--extldflags '-static -fpic' $ldflags"
  local BASE="https://github.com/OpenListTeam/musl-compilers/releases/latest/download/"
  local FILES=(arm-linux-musleabi-cross arm-linux-musleabihf-cross armel-linux-musleabi-cross armel-linux-musleabihf-cross armv5l-linux-musleabi-cross armv5l-linux-musleabihf-cross armv6-linux-musleabi-cross armv6-linux-musleabihf-cross armv7l-linux-musleabihf-cross armv7m-linux-musleabi-cross armv7r-linux-musleabihf-cross)
  for i in "${FILES[@]}"; do
    curl -fsSL -o "${i}.tgz" "${BASE}${i}.tgz"
    sudo tar xf "${i}.tgz" --strip-components 1 -C /usr/local
    rm -f "${i}.tgz"
  done
  local OS_ARCHES=(linux-musleabi-arm linux-musleabihf-arm linux-musleabi-armel linux-musleabihf-armel linux-musleabi-armv5l linux-musleabihf-armv5l linux-musleabi-armv6 linux-musleabihf-armv6 linux-musleabihf-armv7l linux-musleabi-armv7m linux-musleabihf-armv7r)
  local CGO_ARGS=(arm-linux-musleabi-gcc arm-linux-musleabihf-gcc armel-linux-musleabi-gcc armel-linux-musleabihf-gcc armv5l-linux-musleabi-gcc armv5l-linux-musleabihf-gcc armv6-linux-musleabi-gcc armv6-linux-musleabihf-gcc armv7l-linux-musleabihf-gcc armv7m-linux-musleabi-gcc armv7r-linux-musleabihf-gcc)
  local GOARMS=('' '' '' '' '5' '5' '6' '6' '7' '7' '7')
  for i in "${!OS_ARCHES[@]}"; do
    os_arch=${OS_ARCHES[$i]}
    cgo_cc=${CGO_ARGS[$i]}
    arm=${GOARMS[$i]}
    echo "building for ${os_arch}"
    export GOOS=linux GOARCH=arm CC=$cgo_cc CGO_ENABLED=1 GOARM=$arm
    go build -o "./build/$appName-$os_arch" -ldflags="$muslflags" .
  done
}

# 4. BuildReleaseAndroid（Android 四件套）
BuildReleaseAndroid() {
  mkdir -p "build"
  wget https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
  unzip android-ndk-r26b-linux.zip
  rm android-ndk-r26b-linux.zip
  local OS_ARCHES=(amd64 arm64 386 arm)
  local CGO_ARGS=(x86_64-linux-android24-clang aarch64-linux-android24-clang i686-linux-android24-clang armv7a-linux-androideabi24-clang)
  for i in "${!OS_ARCHES[@]}"; do
    os_arch=${OS_ARCHES[$i]}
    cgo_cc=$(realpath android-ndk-r26b/toolchains/llvm/prebuilt/linux-x86_64/bin/${CGO_ARGS[$i]})
    echo "building for android-${os_arch}"
    export GOOS=android GOARCH=${os_arch##*-} CC=$cgo_cc CGO_ENABLED=1
    [[ $os_arch == "arm" ]] && export GOARCH=arm
    go build -o "./build/$appName-android-$os_arch" -ldflags="$ldflags" .
  done
}

# 5. BuildLoongGLIBC（OpenList 原版，一字未改）
BuildLoongGLIBC() {
  local target_abi="$2"
  local output_file="$1"
  local oldWorldGoVersion="1.25.0"
 
  if [ "$target_abi" = "abi1.0" ]; then
    echo building for linux-loong64-abi1.0
  else
    echo building for linux-loong64-abi2.0
    target_abi="abi2.0"
  fi
 
  if [ "$target_abi" = "abi1.0" ]; then
    # === abi1.0 老世界（OpenList 原版代码）===
    if ! curl -fsSL --retry 3 -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://github.com/loong64/loong64-abi1.0-toolchains/releases/download/20250821/go${oldWorldGoVersion}.linux-amd64.tar.gz" \
      -o go-loong64-abi1.0.tar.gz; then return 1; fi
    rm -rf go-loong64-abi1.0 && mkdir go-loong64-abi1.0
    tar -xzf go-loong64-abi1.0.tar.gz -C go-loong64-abi1.0 --strip-components=1
    rm go-loong64-abi1.0.tar.gz
 
    if ! curl -fsSL --retry 3 -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://github.com/loong64/loong64-abi1.0-toolchains/releases/download/20250722/loongson-gnu-toolchain-8.3.novec-x86_64-loongarch64-linux-gnu-rc1.1.tar.xz" \
      -o gcc8-loong64-abi1.0.tar.xz; then return 1; fi
    rm -rf gcc8-loong64-abi1.0 && mkdir gcc8-loong64-abi1.0
    tar -Jxf gcc8-loong64-abi1.0.tar.xz -C gcc8-loong64-abi1.0 --strip-components=1
    rm gcc8-loong64-abi1.0.tar.xz
 
    local cache_dir="$(pwd)/go-loong64-abi1.0-cache"
    mkdir -p "$cache_dir"

    env GOOS=linux GOARCH=loong64 \
        CC="$(pwd)/gcc8-loong64-abi1.0/bin/loongarch64-linux-gnu-gcc" \
        CXX="$(pwd)/gcc8-loong64-abi1.0/bin/loongarch64-linux-gnu-g++" \
        CGO_ENABLED=1 GOCACHE="$cache_dir" \
        $(pwd)/go-loong64-abi1.0/bin/go build -a -o "$output_file" -ldflags="$ldflags" .
  else
    # === abi2.0 新世界（OpenList 原版代码）===
    if ! curl -fsSL --retry 3 -H "Authorization: Bearer $GITHUB_TOKEN" \
      "https://github.com/loong64/cross-tools/releases/download/20250507/x86_64-cross-tools-loongarch64-unknown-linux-gnu-legacy.tar.xz" \
      -o gcc12-loong64-abi2.0.tar.xz; then return 1; fi
    rm -rf gcc12-loong64-abi2.0 && mkdir gcc12-loong64-abi2.0
    tar -Jxf gcc12-loong64-abi2.0.tar.xz -C gcc12-loong64-abi2.0 --strip-components=1
    rm gcc12-loong64-abi2.0.tar.xz

    CC=$(pwd)/gcc12-loong64-abi2.0/bin/loongarch64-unknown-linux-gnu-gcc \
    CXX=$(pwd)/gcc12-loong64-abi2.0/bin/loongarch64-unknown-linux-gnu-g++ \
    GOOS=linux GOARCH=loong64 CGO_ENABLED=1 \
      go build -a -o "$output_file" -ldflags="$ldflags" .
  fi
}

# 6. MakeRelease（打包，OpenList 原版）
MakeRelease() {
  cd build
  if [ -d compress ]; then
    rm -rv compress
  fi
  mkdir compress
  
  # Add -lite suffix if useLite is true
  liteSuffix=""
  if [ "$useLite" = true ]; then
    liteSuffix="-lite"
  fi
  
  for i in $(find . -type f -name "$appName-linux-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-android-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-darwin-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-freebsd-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-dragonfly-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-netbsd-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-openbsd-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-plan9-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f -name "$appName-solaris-*"); do
    tar -czvf compress/"$i".tar.gz "$i"
  done
  for i in $(find . -type f \( -name "$appName-windows-*" -o -name "$appName-windows7-*" \)); do
    zip compress/$(echo $i | sed 's/\.[^.]*$//').zip "$i"
  done
  
  cd compress
  sha256sum * > SHA256SUMS.txt
  echo "x-tunnel 全平台构建完成！共 $(ls -1 | grep -E '\.(tar\.gz|zip)$' | wc -l) 个文件"
  
  cd ../..
}

BuildWin7() {
  local prefix="$1"
  go_version=$(go version | grep -o 'go[0-9]\+\.[0-9]\+\.[0-9]\+' | sed 's/go//')
  echo "building windows7 (detected go$go_version)"
  curl -fsSL --retry 3 -o go-win7.zip -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://github.com/XTLS/go-win7/releases/download/patched-${go_version}/go-for-win7-linux-amd64.zip"
  rm -rf go-win7 && unzip -q go-win7.zip -d go-win7 && rm go-win7.zip
  chmod +x ./wrapper/zcc-win7* ./wrapper/zcxx-win7* 2>/dev/null || true

  for arch in 386 amd64; do
    if [ "$arch" = "386" ]; then
      CC="$PWD/wrapper/zcc-win7-386" CXX="$PWD/wrapper/zcxx-win7-386"
    else
      CC="$PWD/wrapper/zcc-win7" CXX="$PWD/wrapper/zcxx-win7"
    fi
    GOOS=windows GOARCH=$arch CC="$CC" CXX="$CXX" CGO_ENABLED=1 \
      "$PWD/go-win7/bin/go" build -o "${prefix}-${arch}.exe" -ldflags="$ldflags" .
  done
}

BuildReleaseFreeBSD() {
  sudo apt-get install -y clang lld
  mkdir -p "build/freebsd"
  
  # Get latest FreeBSD 14.x release version from GitHub 
  freebsd_version=$(eval "curl -fsSL --max-time 2 $GITHUB_TOKEN \"https://api.github.com/repos/freebsd/freebsd-src/tags\"" | \
    jq -r '.[].name' | \
    grep '^release/14\.' | \
    grep -v -- '-p[0-9]*$' | \
    sort -V | \
    tail -1 | \
    sed 's/release\///' | \
    sed 's/\.0$//')
  
  if [ -z "$freebsd_version" ]; then
    echo "Failed to get FreeBSD version, falling back to 14.3"
    freebsd_version="14.3"
  fi

  echo "Using FreeBSD version: $freebsd_version"
  
  OS_ARCHES=(amd64 arm64 i386)
  GO_ARCHES=(amd64 arm64 386)
  CGO_ARGS=(x86_64-unknown-freebsd${freebsd_version} aarch64-unknown-freebsd${freebsd_version} i386-unknown-freebsd${freebsd_version})
  for i in "${!OS_ARCHES[@]}"; do
    os_arch=${OS_ARCHES[$i]}
    cgo_cc="clang --target=${CGO_ARGS[$i]} --sysroot=/opt/freebsd/${os_arch}"
    echo building for freebsd-${os_arch}
    sudo mkdir -p "/opt/freebsd/${os_arch}"
    wget -q https://download.freebsd.org/releases/${os_arch}/${freebsd_version}-RELEASE/base.txz
    sudo tar -xf ./base.txz -C /opt/freebsd/${os_arch}
    rm base.txz
    export GOOS=freebsd
    export GOARCH=${GO_ARCHES[$i]}
    export CC=${cgo_cc}
    export CGO_ENABLED=1
    export CGO_LDFLAGS="-fuse-ld=lld"
    go build -o ./build/$appName-freebsd-$os_arch -ldflags="$ldflags" .
  done
}

# 编译单个平台
build_single() {
    local platform=$1
    local goos=$(echo "$platform" | cut -d'/' -f1)
    local goarch_full=$(echo "$platform" | cut -d'/' -f2)
    
    # 解析架构和变体
    local goarch="$goarch_full"
    local goarm=""
    local gomips=""
    local arch_suffix="$goarch_full"
    
    # 处理ARM变体
    if [[ "$goarch_full" =~ ^armv([5-8])$ ]]; then
        goarch="arm"
        goarm="${BASH_REMATCH[1]}"
        arch_suffix="armv${goarm}"
    # 处理MIPS变体
    elif [[ "$goarch_full" =~ ^mips(le)?-(hard|soft)$ ]]; then
        if [[ "$goarch_full" == *"le"* ]]; then
            goarch="mipsle"
        else
            goarch="mips"
        fi
        # 转换MIPS变体名称为Go编译器认可的格式
        if [[ "${BASH_REMATCH[2]}" == "hard" ]]; then
            gomips="hardfloat"
        else
            gomips="softfloat"
        fi
        arch_suffix="$goarch_full"
    fi
    
    echo -e "正在编译 ${platform}..."
    
    # 设置输出文件名
    local output_name="${appName}-${goos}-${arch_suffix}"
    if [[ "$goos" == "windows" ]]; then
        output_name="${appName}-${goos}-${arch_suffix}.exe"
    fi
    
    # 创建输出目录
    local output_dir="build"
    mkdir -p "$output_dir"
    
    # 准备编译命令
    local env_vars="GOOS=$goos GOARCH=$goarch"
    if [[ -n "$goarm" ]]; then
        env_vars="$env_vars GOARM=$goarm"
    fi
    if [[ -n "$gomips" ]]; then
        env_vars="$env_vars GOMIPS=$gomips"
    fi
    
    #if [[ -n "$SOURCE_FILE" ]]; then
    #    local build_cmd="$env_vars go build -trimpath -ldflags='-s -w' -o '${output_dir}/${output_name}' $SOURCE_FILE"
    #else
    #    local build_cmd="$env_vars go build -trimpath -ldflags='-s -w' -o '${output_dir}/${output_name}'"
    #fi

    local build_cmd="$env_vars go build -trimpath -ldflags='-s -w' -o '${output_dir}/${output_name}'"

    # 执行编译
    if eval "$build_cmd" 2>/dev/null; then
        local file_size=$(du -h "${output_dir}/${output_name}" | cut -f1)
        echo -e "✓ ${platform} 编译成功 (${file_size})"
        echo -e "  输出文件: ${output_dir}/${output_name}"
    else
        echo -e "✗ ${platform} 编译失败"
    fi
}

# ========================================
# 主入口：直接调用 OpenList 的 release 逻辑（只多打几个）
# ========================================
BuildRelease() {
  rm -rf build
  mkdir -p build

  #build_single "android/386"
  #build_single "android/amd64"
  #build_single "android/arm"
  #build_single "android/arm64"
  #build_single "darwin/386"
  #build_single "darwin/amd64"
  #build_single "darwin/arm"
  #build_single "darwin/arm64"
  #build_single "dragonfly/amd64"
  #build_single "freebsd/386"
  #build_single "freebsd/amd64"
  #build_single "freebsd/arm"
  #build_single "freebsd/arm64"
  #build_single "linux/386"
  #build_single "linux/amd64" 
  #build_single "linux/armv5"
  #build_single "linux/armv6"
  #build_single "linux/armv7"
  #build_single "linux/arm64"
  #build_single "linux/mips-hard"
  #build_single "linux/mips-soft"
  #build_single "linux/mips64" 
  #build_single "linux/mipsle-hard"
  #build_single "linux/mipsle-soft"
  #build_single "linux/mips64le" 
  #build_single "linux/ppc64"
  #build_single "linux/ppc64le"
  #build_single "linux/riscv64"
  #build_single "linux/s390x"
  #build_single "netbsd/386"
  #build_single "netbsd/amd64"
  #build_single "netbsd/arm"
  #build_single "netbsd/arm64"
  #build_single "openbsd/386"
  #build_single "openbsd/amd64"
  #build_single "openbsd/arm"
  #build_single "openbsd/arm64"
  #build_single "plan9/386"
  #build_single "plan9/amd64"
  #build_single "solaris/amd64"
  #build_single "windows/386"
  #build_single "windows/amd64"
  #build_single "windows/arm"
  #build_single "windows/arm64"

  build_single "darwin/386"
  build_single "darwin/arm"
  build_single "dragonfly/amd64"
  build_single "freebsd/arm"
  build_single "linux/mips-hard"
  build_single "linux/mips-soft"
  build_single "linux/mipsle-hard"
  build_single "linux/mipsle-soft"
  build_single "linux/ppc64"
  build_single "netbsd/386"
  build_single "netbsd/amd64"
  build_single "netbsd/arm"
  build_single "netbsd/arm64"
  build_single "openbsd/386"
  build_single "openbsd/amd64"
  build_single "openbsd/arm"
  build_single "openbsd/arm64"
  build_single "plan9/386"
  build_single "plan9/amd64"
  build_single "solaris/amd64"
  build_single "windows/arm"

  # 1. xgo 打主流 + FreeBSD + armv5 + s390x
  docker pull crazymax/xgo:latest
  go install github.com/crazy-max/xgo@latest
  xgo -out "$appName" -ldflags="$ldflags" \
    -targets=windows/amd64,windows/386,darwin/amd64,darwin/arm64,linux/amd64,linux/386,linux/arm64,linux/arm-7,linux/arm-6,linux/arm-5,linux/ppc64le,linux/riscv64,linux/s390x,linux/mips,linux/mipsle,linux/mips64,linux/mips64le,freebsd/amd64,freebsd/arm64,freebsd/386 .

  mv "$appName"-* build/
  BuildWinArm64                 # windows-arm64
  BuildWin7 build/"$appName"-windows7
  BuildReleaseLinuxMusl         # 9 个 musl 冷门
  BuildReleaseLinuxMuslArm      # 11 个极端 arm
  BuildReleaseAndroid           # Android 四件套
  #BuildLoongGLIBC "build/$appName-linux-loong64-abi1.0" abi1.0
  #BuildLoongGLIBC "build/$appName-linux-loong64" abi2.0
  BuildReleaseFreeBSD


}

case "$1" in
  release)
    BuildRelease
    MakeRelease
    ;;
  *)
    echo "用法: $0 release"
    ;;
esac
