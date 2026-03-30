# DNS 解析器实验 — 操作与使用指南

本文档说明「网络协议分析实践」中 **my_nslookup** 实验的目录结构、环境搭建、程序用法、分层显示、Docker 与常见问题。原理与协议细节见课程 PDF《02-DNS实践》及 **`实验资料/实验思路.md`**。

---

## 一、项目目录结构

代码与资料已分开放置：**资料与脚本**在 `实验资料/`，**全部程序代码**在 `源代码/my_nslookup/`。

```
协议分析实验一/
├── 目录说明.md                     # 根目录说明（若存在）
├── 实验资料/
│   ├── Dockerfile.multifile        # 多文件模式镜像（源代码/my_nslookup/）
│   ├── Dockerfile.singlefile       # 单文件模式镜像（my_nslookup/my_nslookup.py）
│   ├── scripts/
│   │   ├── 01-install-deps.sh    # 安装 apt 与 pip 依赖
│   │   └── 02-start-lab-container.sh
│   ├── DNS实验操作与使用指南.md   # 本文件
│   ├── 实验思路.md
│   └── 02-DNS实践(2).pdf
└── 源代码/
    └── my_nslookup/                # 全部 Python 源码与 requirements.txt
        ├── main.py
        ├── display.py
        ├── packet_builder.py
        ├── packet_sender.py
        ├── dns_parser.py
        ├── pcap_writer.py
        ├── utils.py
        └── requirements.txt
```

---

## 二、环境要求

| 项目 | 说明 |
|------|------|
| 系统 | 推荐 **Ubuntu 24.04**（实体机、虚拟机或 Docker 容器） |
| Python | **Python 3**（镜像内一般为 3.12） |
| 权限 | 原始套接字与 libpcap 需要 **root** 或等价能力；Docker 需 **`--privileged`**（或 `NET_ADMIN` + `NET_RAW`） |
| 网络 | 能访问 DNS（如 `8.8.8.8`）；需能解析 **默认网关 MAC**（跨网段访问 DNS 时） |

**说明（Docker Desktop / Windows）：** 在 Windows 上使用 Docker 时，通常 **没有** 与 Linux 完全一致的 `--net=host`；使用默认 **bridge** 即可（容器内一般为 `eth0`，地址形如 `172.17.x.x`）。在 **原生 Linux** 或需要抓真实网卡流量时，可按课程要求使用 `--net=host` 并指定物理网卡名。

---

## 三、环境搭建方式

### 3.1 方式 A：使用 Dockerfile（两种模式，可复现）

在 **`协议分析实验一`（根目录）** 下执行（**`-f` 指定 Dockerfile，`.` 为构建上下文**）。

**多文件模式**（完整工程 `源代码/my_nslookup/`）：

```bash
docker build -f 实验资料/Dockerfile.multifile -t dns-lab:24 .
```

**单文件模式**（仅 `my_nslookup/my_nslookup.py`，依赖仍来自 `源代码/my_nslookup/requirements.txt`）：

```bash
docker build -f 实验资料/Dockerfile.singlefile -t dns-lab-single:24 .
```

**运行容器（示例）：**

```bash
docker run --rm -it --privileged dns-lab:24
```

- **`--privileged`**：满足 Scapy 发链路层帧、抓包的需要。
- 若需把 **工程目录** 同步到容器，挂载根目录（路径按本机修改）：

```bash
docker run --rm -it --privileged -v "/path/to/协议分析实验一:/workspace" -w /workspace dns-lab:24
```

进入容器后：

```bash
cd /workspace
# 多文件镜像内工程在 /workspace/my_nslookup/
python3 my_nslookup/main.py 8.8.8.8 example.com --iface eth0 --output /workspace/capture.pcap
# 单文件镜像内入口为
# python3 my_nslookup/my_nslookup.py 8.8.8.8 example.com --output /workspace/capture.pcap
```

**注意：** 未挂载时，生成的文件只在容器内；退出容器后若未挂载，数据会随容器删除。

### 3.2 方式 B：分步脚本（Linux / WSL / 容器内）

1. **安装依赖（第一部分）**  
   在已进入的 Ubuntu 环境（含容器）中执行：

   ```bash
   chmod +x 实验资料/scripts/01-install-deps.sh
   ./实验资料/scripts/01-install-deps.sh
   ```

   脚本会安装：`python3`、`pip`、`libpcap-dev`、`tcpdump`、`iproute2`、`net-tools` 等，并按 **`源代码/my_nslookup/requirements.txt`** 安装 **scapy、rich**。

2. **启动实验容器（第二部分，可选）**  
   执行 **`实验资料/scripts/02-start-lab-container.sh`** 会拉取 Ubuntu 24 并以特权方式挂载整个 **`协议分析实验一`** 到 `/workspace`；进入容器后安装依赖：

   `bash /workspace/实验资料/scripts/01-install-deps.sh`

### 3.3 Ubuntu 24 与 pip（PEP 668）

Ubuntu 24 对系统 Python 启用了 **PEP 668**，全局 `pip install` 需加 **`--break-system-packages`**（本实验 Dockerfile 与脚本已按此方式安装）。

**请勿在 Dockerfile 或脚本中执行 `pip install -U pip`：**  
通过 `apt` 安装的 `pip` 无法用 PyPI 的 `pip` 正常覆盖卸载，可能报错 `Cannot uninstall pip … RECORD file not found`。

---

## 四、程序入口与基本用法

程序路径：**`源代码/my_nslookup/main.py`**（工作目录为 **`协议分析实验一` 根目录** 时）。

**必选参数（非交互时）：**

- 第一个参数：**DNS 服务器 IPv4**（如 `8.8.8.8`）
- 第二个参数：**域名**（也支持带协议的网址，见下文）

**常用示例：**

```bash
sudo python3 源代码/my_nslookup/main.py 8.8.8.8 www.baidu.com
sudo python3 源代码/my_nslookup/main.py 8.8.8.8 www.google.com --type AAAA
sudo python3 源代码/my_nslookup/main.py 114.114.114.114 qq.com --type MX
```

容器内若已是 **root**，可省略 `sudo`。

---

## 五、命令行参数说明（汇总）

| 参数 | 含义 |
|------|------|
| `dns_server` | DNS 服务器 IP（位置参数，交互模式可省略后由提示输入） |
| `domain` | 域名或网址（位置参数） |
| `-i` / `--interactive` | 交互式输入 DNS、域名、记录类型、网卡、`--show`、`--output`、`--order` 等 |
| `-S` / `--show` | 控制终端显示哪些协议层（逗号分隔，见第六节） |
| `--order` | `osi`（默认）或 `reverse`，控制各层打印顺序（见第七节） |
| `--type` | `A` / `AAAA` / `CNAME` / `NS` / `MX` / `TXT` |
| `--iface` | 网卡名，默认 `eth0`；以 `ip -br link` 或 `ip link` 为准 |
| `--src-ip` / `--src-mac` / `--gw-mac` | 可选；不写则自动获取本机 IP/MAC，网关 MAC 默认 ARP |
| `--src-port` | UDP 源端口；不写则随机 |
| `--output` | 输出 pcap 路径，默认 `capture.pcap` |
| `--no-color` | 禁用终端颜色（重定向到文件时更清晰） |
| `--show-help` | 打印 `--show` 与 `--order` 的说明后退出 |

程序内另提供 **`python3 main.py --show-help`** 查看分层关键字与 `osi/reverse` 含义。

---

## 六、`--show` 分层显示（`-S`）

用于只查看某几层，便于写报告或对照 Wireshark。

**常用关键字：**

| 关键字 | 含义 |
|--------|------|
| `all` | 全部（默认） |
| `summary` | 会话摘要表（域名、DNS、网卡、网关等） |
| `eth` | 请求侧以太网 |
| `ip` | 请求侧 IPv4 |
| `udp` | 请求侧 UDP |
| `dns` | 请求侧 DNS 查询 |
| `resp` / `response` | 展开为 `resp_eth`、`resp_ip`、`resp_udp`、`resp_dns` |
| `req` / `request` | 展开为请求侧 `eth`、`ip`、`udp`、`dns` |
| `resp_eth` / `resp_ip` / `resp_udp` / `resp_dns` | 应答帧链路层 / 网络层 / 传输层 / DNS 解析 |

**中文别名（部分）：** 链路→`eth`，网络→`ip`，传输→`udp`，应答/响应→与 `resp` 相同。

**示例：**

```bash
python3 源代码/my_nslookup/main.py 8.8.8.8 example.com -S eth,ip,dns
python3 源代码/my_nslookup/main.py 8.8.8.8 example.com -S resp_dns
```

---

## 七、`--order` 打印顺序

| 取值 | 含义 |
|------|------|
| `osi`（默认） | **请求**：链路 → 网络 → 传输 → 应用。**应答**：以太网 → IP → UDP → DNS（与线路上帧头顺序一致）。 |
| `reverse` | **请求**：应用 → 传输 → 网络 → 链路。**应答**：先 DNS 再 UDP → IP → 以太网（偏「协议栈自顶向下」视角）。 |

界面中用 **① / ②** 规则线区分「发送请求帧」与「接收应答帧」两段（在对应层被选中时显示）。

---

## 八、交互模式（`-i`）

```bash
python3 源代码/my_nslookup/main.py -i
```

按提示输入：**DNS IP**、**域名或网址**、**记录类型**、**网卡**、**显示层**、**pcap 路径**、**各层顺序（osi/reverse）**。  
若在命令行已写出部分位置参数，交互里会作为默认值带出。

---

## 九、域名与「网址」输入

程序会将输入 **规范化**为查询用主机名，例如：

- `https://www.qq.com/path` → `www.qq.com`
- 带端口 `host:443` 会尝试去掉端口再查询（按实现规则）

仍建议在报告中说明：DNS 查询的是 **主机名**，不是完整 URL。

---

## 十、pcap 与 Wireshark

- 程序将 **请求帧与应答帧**（若收到）写入 `--output` 指定的 **pcap**。
- 使用 **Wireshark** 打开 pcap，可验证：以太网地址、IP/UDP 校验和、DNS 事务 ID 是否一致等。
- 过滤器示例：`dns`、`udp.port == 53`、`ip.addr == 8.8.8.8`。

---

## 十一、权限、网关与常见问题

### 11.1 权限

若提示无法发包或无法抓包，请用 **root** 运行，或 Docker **`--privileged`**。

### 11.2 网关 MAC 无法解析

程序需要 **下一跳 MAC**（通常为本机默认网关）以封装以太网帧。若 ARP 失败，可手动指定：

```bash
python3 源代码/my_nslookup/main.py 8.8.8.8 example.com --gw-mac xx:xx:xx:xx:xx:xx
```

### 11.3 超时未收到应答

可能原因：防火墙、DNS 不可达、接口名错误、过滤器过严、未授权抓包等。请检查接口名、DNS IP、以及是否在正确网络环境中运行。

### 11.4 ICMP Port Unreachable（原理说明）

使用原始包发送 UDP 时，若本机未在该端口上让内核“认领”流量，可能产生 ICMP。本实现通过 **绑定 UDP 源端口** 等方式减轻该问题；课程中也可配合 **iptables** 丢弃特定 ICMP（见 `实验思路.md`）。

---

## 十二、与课程要求、评分要点的对应（摘要）

| 课程要求（实践 1 摘要） | 程序中的体现 |
|-------------------------|----------------|
| 程序名 my_nslookup | `源代码/my_nslookup/main.py` |
| 必选：DNS IP、域名 | 位置参数；支持网址规范化 |
| 可选：本机 MAC、网关 MAC、本机 IP、UDP 源端口 | `--src-mac`、`--gw-mac`、`--src-ip`、`--src-port` |
| 自行构造 DNS/UDP/IP/以太网并打印各层 | `packet_builder.py` + `display.py` 分层输出 |
| 发送并捕获响应 | `packet_sender.py`（`sendp` + `sniff`） |
| 打印响应各层 | `resp_*` 与 DNS 解析表 |
| 保存 pcap 并用 Wireshark 验证 | `pcap_writer.py` + `--output` |
| 友好格式、用户友好度 | Rich 表格/面板、`-i`、`-S`、`--order` |

详细评分表以课程通知与邮箱要求为准。

---

## 十三、提交与命名（以课程说明为准）

请以任课教师最新通知为准；历史命名示例：

- 邮件：**40638183@qq.com**（若课程未变更）
- 命名示例：`2026春网络协议分析实践实验一-第x组-源代码/PPT/实验报告`

---

## 十四、快速命令备忘

```bash
# 构建镜像（在「协议分析实验一」根目录）— 多文件示例
docker build -f 实验资料/Dockerfile.multifile -t dns-lab:24 .
# 单文件：docker build -f 实验资料/Dockerfile.singlefile -t dns-lab-single:24 .

# 进入容器（并挂载工程）
docker run --rm -it --privileged -v "$PWD:/workspace" -w /workspace dns-lab:24

# 运行（示例）
python3 源代码/my_nslookup/main.py 8.8.8.8 example.com --iface eth0 -S all --order osi

# 查看分层与顺序帮助
python3 源代码/my_nslookup/main.py --show-help
```

---

*文档版本与仓库内代码同步维护；若参数与脚本有变更，以 `main.py --help` 与实际脚本为准。*
