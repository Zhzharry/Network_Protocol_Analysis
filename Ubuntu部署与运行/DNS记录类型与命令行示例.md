# `--type` 记录类型说明与命令行示例

以下均在**项目根目录** `协议分析实验一/` 下执行；**必须**使用真实网卡名替换 `eth0`（`ip -br link` 查看）。以下命令均需 **`sudo`**（链路层发包与抓包）。

程序入口二选一（等价）：

- 模块化：`python3 源代码/my_nslookup/main.py …`
- 单文件：`python3 my_nslookup/my_nslookup.py …`

---

## 交互模式（`-i` / `--interactive`）

不提供命令行里的 **DNS 服务器** 与 **域名** 时，使用 **`-i`**（或 **`--interactive`**）进入交互模式，程序会**逐项询问**（Rich 提示），无需事先写好位置参数。

### 如何进入

在项目根目录执行（同样需要 **`sudo`**，并建议终端环境支持交互输入）：

```bash
sudo python3 my_nslookup/my_nslookup.py -i
```

模块化入口：

```bash
sudo python3 源代码/my_nslookup/main.py -i
```

### 交互中会问什么

按顺序大致为（可直接回车使用默认值）：

| 提示项 | 含义 | 默认示例 |
|--------|------|----------|
| DNS 服务器 IP | 上游解析服务器 | `8.8.8.8` |
| 域名或网址 | 可含 `http(s)://`，会自动取主机名 | `example.com` |
| 记录类型 | 与下文 **`--type`** 一致，多选一 | `A` |
| 网卡接口名 | 与 `--iface` 相同 | `eth0` |
| 显示哪些层 | 逗号分隔或 `all`，同 `--show` | `all` |
| pcap 输出路径 | 同 `--output` | `capture.pcap` |
| 各层打印顺序 | `osi` 或 `reverse`，同 `--order` | `osi` |

记录类型在交互里为 **A / AAAA / CNAME / NS / MX / TXT**，与命令行 **`--type`** 含义相同。

### 与其它参数组合

命令行上仍可附加**未在交互里询问的选项**，会与交互结果一起生效，例如：

```bash
sudo python3 my_nslookup/my_nslookup.py -i --preflight
```

```bash
sudo python3 my_nslookup/my_nslookup.py -i --hex --export-txt dns_lab.txt --timeout 8
```

（`--preflight`、`--hex`、`--export-txt`、`--timeout` 等说明见 `python3 … --help`。）

交互过程中在**记录类型、网卡**之后，会额外询问（均可**回车**使用自动探测/随机）：

- 本机 MAC、网关 MAC、本机 IPv4、UDP 源端口。  
若在启动命令里已写 `--src-mac` / `--gw-mac` / `--src-ip` / `--src-port`，会作为**默认值**显示在提示中，可改可清空。

---

## 可选：本机 MAC / 网关 MAC / 本机 IP / UDP 源端口（命令行）

以下参数**均可省略**；省略时行为与原先一致（ioctl、ARP、网卡 IP、随机高位端口）。

| 参数 | 含义 |
|------|------|
| `--src-mac MAC` | 以太网源地址（本机），如 `aa:bb:cc:dd:ee:ff` |
| `--gw-mac MAC` | 帧中「下一跳」目的 MAC，一般为网关（ARP 失败时可手填） |
| `--src-ip IPv4` | IP 首部源地址 |
| `--src-port PORT` | UDP 源端口，整数 1–65535 |

示例（与模块化 `main.py` 同理，路径换成 `源代码/my_nslookup/main.py` 即可）：

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 example.com \
  --iface eth0 --src-ip 192.168.1.100 --src-port 54321 \
  --gw-mac 52:54:00:12:34:56
```

---

## 1. `--type` 与 DNS 类型码对照（参数矩阵）

命令行里 **`--type`** 只填**类型名**（不填数字）。程序内部会按 RFC1035 映射为 QTYPE 数值。

| 类型名 `--type` | DNS 类型码 (QTYPE) | 查询内容说明 | 示例域名（实验常用） |
|-----------------|-------------------|--------------|----------------------|
| **A** | 1 | IPv4 地址 | `www.baidu.com` |
| **AAAA** | 28 | IPv6 地址 | `www.google.com` |
| **CNAME** | 5 | 别名指向的权威名称（链上可能多跳） | `www.baidu.com` |
| **NS** | 2 | 该域由哪些权威域名服务器解析 | `baidu.com`、`example.com` |
| **MX** | 15 | 邮件交换记录（优先级 + 主机名） | `qq.com` |
| **TXT** | 16 | 文本记录（验证、SPF 等） | `google.com` |

默认：省略 `--type` 时等价于 **`--type A`**。

---

## 2. 运行后会输出什么（按 `--show all`）

实际输出与 `--show` 有关；下面以 **`--show all`**（默认即全部）为例：

1. **标题与会话参数表**：查询域名、DNS 服务器、记录类型、网卡、本机 IP/MAC、网关与下一跳 MAC、UDP 源端口等。  
2. **① 发送请求帧**：各层解析（以太网 → IPv4 → UDP → DNS 查询），含 `=== Sending DNS Query ===` 提示。  
3. **请求帧长度**、**发包成功**一行。  
4. **② 接收应答帧**（若超时则只有超时提示）：各层解析 + `=== Received DNS Response ===`。  
5. **DNS 应答头部**：Transaction ID、Flags、各段计数等。  
6. **DNS 资源记录（RR）**：逐条竖向打印（`Record 1:` … `Name` / `Type` / `Class` / `TTL` / `RDLength` / **`RDATA` 全文**）。  
7. **pcap 面板**：已写入 `capture.pcap`（或 `--output` 指定路径）。  
8. **查询结果摘要**：状态、RTT、Transaction ID、RR 条数、IPv4/CNAME 要点等（可用 `--no-summary` 关闭）。  
9. 若加了 **`--hex`**：附录完整请求/应答以太网帧十六进制；若加了 **`--export-txt`**：另存 UTF-8 文本报告。

---

## 3. 命令行示例（单文件版 `my_nslookup.py`）

将 `eth0` 换成你的网卡名。

### 3.1 A 记录（默认，可省略 `--type A`）

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 www.baidu.com --iface eth0 --type A --show all
```

### 3.2 AAAA（IPv6）

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 www.google.com --iface eth0 --type AAAA --show all
```

### 3.3 CNAME

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 www.baidu.com --iface eth0 --type CNAME --show all
```

### 3.4 NS（权威 NS，域名填**区域名**如 `baidu.com`）

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 baidu.com --iface eth0 --type NS --show all
```

同一类型还可换 DNS 与区域，例如：

```bash
sudo python3 my_nslookup/my_nslookup.py 114.114.114.114 example.com --iface eth0 --type NS --show all
```

### 3.5 MX（邮件）

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 qq.com --iface eth0 --type MX --show all
```

### 3.6 TXT

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 google.com --iface eth0 --type TXT --show all
```

### 3.7 附加：环境预检 + 十六进制 + 文本报告（答辩常用）

```bash
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 www.baidu.com \
  --iface eth0 --type A --preflight --hex --export-txt dns_lab.txt --show all
```

---

## 4. 模块化入口（把路径换成 `源代码/my_nslookup/main.py`）

与上一节一一对应，例如 NS：

```bash
sudo python3 源代码/my_nslookup/main.py 8.8.8.8 baidu.com --iface eth0 --type NS --show all
```

Docker 容器内（镜像已拷贝到 `/workspace`）：

```bash
python3 /workspace/my_nslookup/my_nslookup.py 8.8.8.8 baidu.com --iface eth0 --type NS --show all
```

---

## 5. 帮助与更多参数

```bash
python3 my_nslookup/my_nslookup.py --help
python3 my_nslookup/my_nslookup.py --show-help
```

完整分层关键字、顺序 `--order`、超时 `--timeout`、报告导出等见 **`--help`** 与 **[Ubuntu构建与运行指南.md](./Ubuntu构建与运行指南.md)**。
