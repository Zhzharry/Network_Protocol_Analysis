# PDF + 老师演示对照 — 功能检查清单与代码结论

依据：`实验资料/02-DNS实践(2).pdf`（实践 1 要求 + 评分要点）及 `Untitled.md`（老师运行结果逐字段说明）。

---

## 第一步：检查清单（Todo）

### A. PDF《实践 1》硬性要求

| # | 要求 | 状态 |
|---|------|------|
| A1 | 程序名 `my_nslookup` | ✅ |
| A2 | 必选：DNS 服务器 IP、域名 | ✅ |
| A3 | 可选：本机 MAC、网关 MAC、本机 IP、UDP 源端口 | ✅ |
| A4 | 自行构造并打印：**应用层 DNS、UDP、IP、以太网**（发送包各层主要字段） | ✅ / 见 B |
| A5 | 使用发包 API 发送并**捕获响应** | ✅（Scapy sendp + sniff） |
| A6 | **响应包各层主要字段**打印 | ✅ / 见 B |
| A7 | **请求 + 响应**写入 pcap，可用 Wireshark 验证 | ✅ |

### B. PDF 评分要点（现场演示）

| # | 要求 | 状态 |
|---|------|------|
| B1 | **友好格式**打印链路层、网络层、传输层信息 | ✅ / 见 C |
| B2 | 针对 UDP：**DNS 请求与应答全部信息**（示例：请求域名、NS、CNAME、A、AAAA 等） | ✅ / 见 C |

### C. 老师演示（Untitled.md）逐图字段对齐

| # | 内容 | 状态 |
|---|------|------|
| C1 | **以太网**：目的/源 MAC、Type 0x0800 | ✅ |
| C2 | **IP（请求）**：Version、Header Length、**TOS**、Total Length、**Identification**、**Flags/Fragment**、TTL、Protocol、Header Checksum、Src/Dst IP | ⚠️ → **已补全** |
| C3 | **UDP（请求）**：源/目的端口、Length、Checksum、**Data Length（载荷长度）** | ⚠️ → **已补全** |
| C4 | **DNS（请求）**：Transaction ID、**Flags 及 QR/Opcode/AA/TC/RD/RA/Z/RCODE**、Questions、**各计数（Answer/Authority/Additional）**、**完整 Query Name**、QTYPE、Class | ⚠️ → **已补全**（完整域名本就使用用户输入；非仅首 label） |
| C5 | **响应** 以太网：MAC 与发包**对调**（方向正确） | ✅（由抓包如实打印） |
| C6 | **响应 IP/UDP**：含 TOS、ID、Flags、**UDP Data Length** 等 | ⚠️ → **已补全** |
| C7 | **Answer 记录**：每条含 Name、Type、**Class**、TTL、**RDLength**、RDATA；支持**多条 CNAME 链**与**多条 A** | ⚠️ → **已补全解析循环**；表格增加 Class、RDLength |
| C8 | Transaction ID **随机**（老师固定 0x3039；我们随机 —— 符合加分说明） | ✅ |

---

## 第二步：代码结论（对照清单）

| 项 | 说明 |
|----|------|
| **构造与发送** | `packet_builder` + `packet_sender` 完成四层构造、L2 注入与按事务 ID 收包。 |
| **多记录** | `parse_dns_response` 对 Answer/Authority/Additional 逐条 `_parse_one_rr`，**不会只取第一条**；CNAME 链由多条 RR 依次呈现。 |
| **缺口与处理** | 原实现 IP 缺 TOS/ID/Flags、UDP 缺 Data Length、DNS 请求缺位级 Flags 与 0 计数行、RR 缺 Class/RDLength；已在 `display.py` / `dns_parser.py` / `main.py` 中补全（见提交）。 |
| **单文件版** | `my_nslookup/my_nslookup.py` 已与 `源代码/my_nslookup` 同步上述输出字段。 |

---

*本文档随代码迭代维护。*
