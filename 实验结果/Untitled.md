这是老师演示的完整运行结果，我来逐图详细描述：

---

**图1 — 发送 DNS 查询包（以太帧 + IP + UDP 层）**

```
=== Sending DNS Query ===
[Ethernet]
  Destination MAC: ee:ff:ff:ff:ff:ff（网关MAC，已截断）
  Source MAC     : 00:16:3e:55:d6:f（本机MAC，已截断）
  Type           : 0x0800 (IPv4)

[IP]
  Version        : 4
  Header Length  : 20 bytes
  TOS            : 0x00
  Total Length   : 59
  Identification : 0x1234
  Flags/Fragment : 0x0000
  TTL            : 64
  Protocol       : 17 (UDP)
  Header Checksum: 0x82c3
  Source IP      : 172.30.41.141
  Destination IP : 8.8.8.8

[UDP]
  Source Port    : 54321
  Destination Port: 53
  Length         : 39
  Checksum       : 0x5944
  Data Length    : 31
```

---

**图2 — 发送 DNS 查询包（DNS 应用层）**

```
[DNS]
  Transaction ID : 0x3039 (12345)
  Flags          : 0x0100
    QR           : 0 (Query)      ← 这是查询包
    Opcode       : 0
    AA           : 0
    TC           : 0
    RD           : 1              ← 请求递归查询
    RA           : 0
    Z            : 0
    RCODE        : 0
  Questions      : 1
  Answer RRs     : 0
  Authority RRs  : 0
  Additional RRs : 0

  Query Name: www
  Query Type: A (1), Class: IN (1)
```

---

**图3 — 收到 DNS 响应包（以太帧 + IP + UDP 层）**

```
=== Received DNS Response ===
[Ethernet]
  Destination MAC: 00:16:3e:55:d6:f0  ← 本机MAC（和发包Source MAC一致）
  Source MAC     : ee:ff:ff:ff:ff:ff  ← 网关MAC（和发包Dest MAC一致，方向反了）
  Type           : 0x0800 (IPv4)

[IP]
  Version        : 4
  Header Length  : 20 bytes
  TOS            : 0x14
  Total Length   : 144              ← 比请求包大得多（有应答内容）
  Identification : 0xc88e
  Flags/Fragment : 0x0000
  TTL            : 113              ← 从8.8.8.8出发经过若干跳后剩余
  Protocol       : 17 (UDP)
  Header Checksum: 0x9aff
  Source IP      : 8.8.8.8          ← DNS服务器返回
  Destination IP : 172.30.41.141

[UDP]
  Source Port    : 53               ← DNS服务器端口
  Destination Port: 54321           ← 和发包Source Port一致
  Length         : 124
  Checksum       : 0xa7b8
  Data Length    : 116
```

---

**图4/5 — DNS 应答记录（Answer Records，两张图内容相同）**

```
[Answer Records]

Record 1:
  Name    : www.baidu.com
  Type    : 5 (CNAME)           ← 别名记录
  Class   : 1
  TTL     : 457
  RDLength: 15
  RDATA   : www.a.shifen.com    ← baidu.com 的权威名称指向这里

Record 2:
  Name    : www.a.shifen.com
  Type    : 5 (CNAME)           ← 再一次 CNAME 跳转
  Class   : 1
  TTL     : 16
  RDLength: 14
  RDATA   : www.wshifen.com

Record 3:
  Name    : www.wshifen.com
  Type    : 1 (A)               ← 最终 IPv4 地址
  Class   : 1
  TTL     : 185
  RDLength: 4
  RDATA   : 103.235.46.102

Record 4:
  Name    : www.wshifen.com
  Type    : 1 (A)               ← 第二个 IPv4 地址（负载均衡）
  Class   : 1
  TTL     : 185
  RDLength: 4
  RDATA   : 103.235.46.115
```

---

## 需要特别注意的点

**关于这份演示结果本身：**

1. **Query Name 只显示了 `www`，不是 `www.baidu.com`**，说明老师的演示代码在打印 Question 段域名时可能只取了第一个 label，你实现时要注意把完整域名拼出来打印。

2. **Transaction ID 是固定值 `0x3039 (12345)`**，老师演示时硬编码了，你最好改成随机生成，更符合真实场景，也是一个小的加分点。

3. **CNAME 链有两跳**：`www.baidu.com` → `www.a.shifen.com` → `www.wshifen.com` → 最终 IP。这意味着你的 DNS 解析器必须能正确处理**多条连续 CNAME 记录**，不能只处理一条就停止。

4. **同一个域名返回了两个 A 记录**（103.235.46.102 和 103.235.46.115），这是 DNS 负载均衡的体现，你的解析器要能循环解析所有 Answer 记录，不能只取第一条。

5. **收包的 Source/Destination MAC 和发包完全对调了**，这是正常的，验证你的以太帧方向理解是否正确。

6. **响应包 TTL 是 113**，说明 8.8.8.8 出发时 TTL 是 128（Windows 默认）或 64，经过若干路由器递减后到达。这个字段你只需要如实打印，不用处理。