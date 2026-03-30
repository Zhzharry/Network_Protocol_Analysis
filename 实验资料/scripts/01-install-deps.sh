#!/usr/bin/env bash
# 第一部分：在 Ubuntu 24（宿主机或容器内）一键安装实验依赖
# 依赖路径：协议分析实验一/源代码/my_nslookup/requirements.txt
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 实验资料/scripts -> 上两级为「协议分析实验一」根目录
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REQ="$ROOT/源代码/my_nslookup/requirements.txt"

export DEBIAN_FRONTEND=noninteractive

if [[ ! -f "$REQ" ]]; then
  echo "错误: 未找到 $REQ"
  exit 1
fi

echo "==> [1/3] apt-get update"
apt-get update

echo "==> [2/3] 安装系统包: python3, pip, libpcap-dev, tcpdump, 网络工具"
apt-get install -y \
  python3 \
  python3-pip \
  python3-venv \
  libpcap-dev \
  tcpdump \
  iproute2 \
  net-tools \
  ca-certificates

echo "==> [3/3] pip 安装 Python 依赖 (scapy, rich)"
python3 -m pip install --break-system-packages -r "$REQ"

echo ""
echo "依赖安装完成。在项目根目录「协议分析实验一」下可执行:"
echo "  sudo python3 源代码/my_nslookup/main.py <DNS_IP> <域名>"
