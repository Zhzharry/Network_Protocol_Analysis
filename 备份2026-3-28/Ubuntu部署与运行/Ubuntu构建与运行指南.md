# Ubuntu 上构建与运行 my_nslookup

适用于 **Ubuntu 22.04 / 24.04**（实体机、虚拟机或 WSL2 若支持原始套接字与网卡注入）。程序需 **链路层发包与抓包**，一般需要 **root（sudo）** 与 **libpcap**。

---

## 一、准备工作

1. 将整个 **`协议分析实验一`** 文件夹放到 Ubuntu 上（`git clone`、`scp`、共享文件夹均可）。
2. 在项目根目录打开终端：

   ```bash
   cd /path/to/协议分析实验一
   ```

3. 查看本机网卡名（后面 `--iface` 要用）：

   ```bash
   ip -br link
   # 或
   ip addr
   ```

   常见名称：`eth0`、`ens33`、`enp0s3` 等；**容器内**若用 host 网络，名称与宿主机一致。

---

## 二、方式 A：宿主机直接运行（推荐先通）

### 1. 一键安装依赖

```bash
chmod +x 实验资料/scripts/01-install-deps.sh
sudo 实验资料/scripts/01-install-deps.sh
```

脚本会安装：`python3`、`pip`、`libpcap-dev`、`tcpdump`、`iproute2` 等，并按 `源代码/my_nslookup/requirements.txt` 安装 **scapy、rich**。

### 2. 运行（必须 sudo）

```bash
cd /path/to/协议分析实验一

# 模块化入口
sudo python3 源代码/my_nslookup/main.py 8.8.8.8 www.baidu.com --iface eth0 --show all

# 或单文件入口（等价）
sudo python3 my_nslookup/my_nslookup.py 8.8.8.8 www.baidu.com --iface eth0 --show all
```

把 **`eth0` 换成你机器上真实的网卡名**。若省略 `--iface`，代码里默认是 `eth0`，在不少 VM 上会报错，需显式指定。

### 3. 与老师演示一致的测试建议

老师文档中常用 **公共 DNS `8.8.8.8`**，域名示例 **`www.baidu.com`**（可看到 **CNAME 链 + 多条 A 记录**）。你也可以用：

| 项目 | 示例 |
|------|------|
| DNS 服务器 | `8.8.8.8`、`114.114.114.114` |
| 域名 | `www.baidu.com`、`example.com` |
| 记录类型 | 默认 `--type A`；其它类型见 `python3 ... --help` |

输出中应能看到 **发送各层字段、接收各层字段、DNS 应答 RR 表**，并生成 **`capture.pcap`**（可用 Wireshark 打开）。

---

## 三、方式 B：Docker 镜像（环境隔离）

**构建上下文必须是项目根目录** `协议分析实验一/`（与 `COPY 源代码/...` 路径一致）。

### 1. 多文件工程镜像

```bash
cd /path/to/协议分析实验一

docker build -f 源代码/my_nslookup/Dockerfile.multifile -t dns-lab:24 .

docker run --rm -it --privileged --net=host dns-lab:24
```

进入容器后（`--net=host` 便于直接用宿主机网卡名发包）：

```bash
python3 /workspace/my_nslookup/main.py 8.8.8.8 www.baidu.com --iface eth0 --show all
```

若未挂载源码，工作目录在镜像内为 `/workspace`，镜像构建时已 `COPY` 进 `my_nslookup/` 模块。

### 2. 单文件镜像

```bash
docker build -f my_nslookup/Dockerfile.singlefile -t dns-lab-single:24 .

docker run --rm -it --privileged --net=host dns-lab-single:24

python3 /workspace/my_nslookup/my_nslookup.py 8.8.8.8 www.baidu.com --iface eth0 --show all
```

### 3. 挂载整个仓库开发调试（可选）

不重建镜像，直接挂载当前目录，便于改代码即测：

```bash
docker run --rm -it --privileged --net=host \
  -v "$(pwd):/workspace" -w /workspace \
  ubuntu:24.04 bash
```

容器内执行一次 `实验资料/scripts/01-install-deps.sh`（需 `sudo` 或 root），再运行 `sudo python3 源代码/my_nslookup/main.py ...`。

项目也提供 **`实验资料/scripts/02-start-lab-container.sh`**：拉取 `ubuntu:24.04` 并挂载仓库到 `/workspace`，进入后同样运行 `01-install-deps.sh` 即可。

---

## 四、常见问题

| 现象 | 处理 |
|------|------|
| 找不到网卡 / ioctl 失败 | 用 `ip link` 确认名称，传 `--iface <正确名称>` |
| 权限不足 | 使用 `sudo`；Docker 使用 `--privileged` |
| 无法解析网关 MAC | 检查能否访问网关；必要时 `--gw-mac` 手动指定 |
| 一直超时 | 确认 DNS IP 可达、防火墙未拦 UDP/53、接口选对 |
| WSL2 | 原始套接字/网卡行为因版本而异，若失败优先用 **VMware/VirtualBox 里完整 Ubuntu** 或 **Docker --net=host** 在 Linux 宿主机上跑 |

---

## 五、与仓库其它文档的关系

- 更细的交互参数、分层显示说明：根目录 **`实验资料/DNS实验操作与使用指南.md`**
- 老师截图字段对照：**`实验结果老师版的描述/Untitled.md`**、**`实验结果老师版的描述/PDF与演示对照检查清单.md`**

完成上述步骤后，你在 Ubuntu 上即具备与实验要求一致的 **构建结构** 与 **运行方式**；测试域名与 DNS 与 **老师演示（`8.8.8.8` + `www.baidu.com` 等）** 对齐即可。
