#!/usr/bin/env bash
# Optical 跨平台构建脚本。Linux / macOS / Windows(Git Bash) 通用。
#
# 目标矩阵（按平台分组）：
#   Windows  x86_64-pc-windows-gnu     需要 mingw-w64（Linux/macOS 交叉）；Windows 本机建议直接用 MSVC
#   Linux    x86_64-unknown-linux-musl  静态链接，任何发行版都能跑
#   Linux    aarch64-unknown-linux-musl 静态 arm64
#   macOS    aarch64-apple-darwin       Apple Silicon（M 系列）
#   macOS    x86_64-apple-darwin        Intel
#
# ⚠️ 苹果两系芯片只能在 macOS 本机或 macOS CI runner 上编译：
#    TLS 后端 ring 要为目标平台编 C/asm，必须有 macOS SDK + clang，
#    Windows / Linux 上都交叉不出来。这是所有带 ring 的 Rust 项目的共同限制，
#    不是本项目的问题。脚本在非 macOS 上跑 macos-* 会直接报错提示，不假装能编。
#
# 用法：
#   ./scripts/build.sh                 # 本机目标
#   ./scripts/build.sh windows         # Windows x64 (gnu)
#   ./scripts/build.sh linux-musl      # Linux x64 静态
#   ./scripts/build.sh linux-arm64     # Linux arm64 静态
#   ./scripts/build.sh macos-arm64     # Apple Silicon（仅 macOS）
#   ./scripts/build.sh macos-x64       # Intel（仅 macOS）
#   ./scripts/build.sh all             # 本机能编的都编，编不动的跳过并提示

set -euo pipefail

TARGET="${1:-native}"
OS="$(uname -s)"

build_with_target() {
  local t="$1"
  rustup target add "$t"
  cargo build --release --target "$t"
}

require_macos() {
  if [[ "$OS" != "Darwin" ]]; then
    echo "❌ $1 只能在 macOS 上编译：ring 需要 macOS SDK + clang，当前系统是 $OS" >&2
    exit 1
  fi
}

case "$TARGET" in
  native)
    cargo build --release
    ;;
  windows|x86_64-pc-windows-gnu)
    build_with_target x86_64-pc-windows-gnu
    ;;
  linux-musl|x86_64-unknown-linux-musl)
    build_with_target x86_64-unknown-linux-musl
    ;;
  linux-arm64|aarch64-unknown-linux-musl)
    build_with_target aarch64-unknown-linux-musl
    ;;
  macos-arm64|aarch64-apple-darwin)
    require_macos aarch64-apple-darwin
    build_with_target aarch64-apple-darwin
    ;;
  macos-x64|x86_64-apple-darwin)
    require_macos x86_64-apple-darwin
    build_with_target x86_64-apple-darwin
    ;;
  all)
    cargo build --release
    for t in x86_64-pc-windows-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
      rustup target add "$t" 2>/dev/null || { echo "⚠️ 跳过 $t（rustup 加不上 target）"; continue; }
      cargo build --release --target "$t" || echo "⚠️ 跳过 $t（缺少交叉工具链）"
    done
    if [[ "$OS" == "Darwin" ]]; then
      # 苹果两系芯片：本机既是 macOS 就都能编
      build_with_target aarch64-apple-darwin
      build_with_target x86_64-apple-darwin
    else
      echo "ℹ️ 苹果两系芯片（aarch64/x86_64-apple-darwin）请到 macOS 本机或 macOS CI 编译"
    fi
    ;;
  *)
    echo "未知目标：$TARGET" >&2
    echo "可用：native windows linux-musl linux-arm64 macos-arm64 macos-x64 all" >&2
    exit 1
    ;;
esac

echo "✅ 完成。产物在 target/<triple>/release/optical"
