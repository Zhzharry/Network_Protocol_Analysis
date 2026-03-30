#!/usr/bin/env bash
# 第二部分：拉取 Ubuntu 24 并以特权方式启动容器（挂载整个「协议分析实验一」目录）
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="${UBUNTU_IMAGE:-ubuntu:24.04}"

echo "==> 拉取镜像: $IMAGE"
docker pull "$IMAGE"

echo "==> 启动容器（挂载 $ROOT -> /workspace）"
echo "    进入容器后安装依赖: bash /workspace/实验资料/scripts/01-install-deps.sh"
echo ""

exec docker run --rm -it \
  --privileged \
  --net=host \
  -v "$ROOT:/workspace" \
  -w /workspace \
  "$IMAGE" \
  bash -c '
    chmod +x /workspace/实验资料/scripts/*.sh 2>/dev/null || true
    if [[ "${RUN_INSTALL:-0}" == "1" ]]; then
      /workspace/实验资料/scripts/01-install-deps.sh
    fi
    exec bash -l
  '
