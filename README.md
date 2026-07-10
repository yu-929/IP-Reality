# IP-Reality 节点发现工具

基于 CT 日志 + TLS 历史账本，反向提取全球 IP:PORT，通过双重 TLS 握手精准筛选存在配置特性的 REALITY 节点。

## 快速开始

```bash
# Linux / macOS 一键安装
curl -fsSL https://raw.githubusercontent.com/yu-929/IP-Reality/main/install.sh | bash

# 菜单模式
xiao

# 命令行模式
xiao --sni images.apple.com --cf-domain my-cdn.example.com

# Windows: 下载项目 -> 双击 build.bat -> dist\xiao.exe
```

## 这是什么

REALITY 协议虽然加密了 SNI，但 Xray-core 的 `serverNames` 配置为空数组 `[]` 时，服务端不限制允许的 SNI。任何 TLS 握手只要证书对得上，它都接受。

这意味着你用苹果证书做 REALITY，别人用自己控制的 Cloudflare 域名去握手，REALITY 服务端一样会透传给目标服务器。目标服务器配了 CF CDN，回 `cf-ray` 头 — 等于这个节点能被当 CF 反代用。

xiao 自动化发现这些节点。

## 核心原理

```
正常 REALITY:
  客户端 -> [SNI=apple.com] -> REALITY服务端 -> 苹果服务器

配置特性 REALITY:
  客户端 -> [SNI=你的CF域名] -> REALITY服务端 -> Cloudflare -> 返回 cf-ray
                                                    ^
                                          serverNames 没限制
```

## 为什么不用传统盲扫

传统用几十万 CIDR masscan 扫 443，99.9% 的 IP 没有 TLS。xiao 只扫描已知有 TLS 服务的 IP：

1. **CT 日志** (crt.sh) — 查出哪些 IP 部署了指定大厂的证书
2. **TLS 历史账本** (Rapid7 Project Sonar) — 捞出所有见过该 SNI 的 IP

## 参数说明

| 参数 | 说明 |
|------|------|
| `--sni` | 目标大厂 SNI。例如 `images.apple.com` |
| `--sni-list` | 多个 SNI 的列表文件，一行一个 |
| `--cf-domain` | **必填**。你的 CF 域名，必须开启 CDN 小黄云 |
| `--ledger` | TLS 账本目录。工具自动识别 `port-*-tls.json.gz` |
| `--ports` | 伴随嗅探的端口。默认 443,8443,2053,2083,2096,2443 |
| `--concurrency` | 验证并发数。默认 500 |
| `--timeout` | 单次握手超时秒数。默认 3.0 |
| `--output` | 输出文件。默认 `xiao_result.json` |
| `--no-redundancy` | 关闭冗余验证 |
| `--no-ledger` | 跳过 TLS 账本，仅用 CT 日志 |
| `--verbose` | 详细日志 (写入 xiao-debug.log) |
| `--quiet` | 安静模式 |

## 运行示例

```bash
# 最简用法
xiao --sni images.apple.com --cf-domain my-cdn.example.com

# 多 SNI 批量
xiao --sni-list ./snis.txt --cf-domain my-cdn.example.com

# 高并发 VPS
xiao --sni images.apple.com --cf-domain my-cdn.example.com \
    --concurrency 2000 --timeout 2.5

# 配合 TLS 账本
xiao --sni swdist.apple.com --cf-domain my-cdn.example.com \
    --ledger /data/sonar-scans/

# 指定输出
xiao --sni images.apple.com --cf-domain my-cdn.example.com \
    --output nodes.json
```

## 输出格式

```
终端:
  [+] 45.67.89.123:8443  images.apple.com  [US]
  [+] 142.248.139.188:443 images.apple.com  [JP] SoftBank

JSON:
[
  {
    "ip": "45.67.89.123",
    "port": 8443,
    "target_sni": "images.apple.com",
    "common_name": "images.apple.com",
    "status": "AVAILABLE",
    "geo": {"country": "US", "city": "New York", "asn": ""},
    "timestamp": "2026-07-10T12:00:00+00:00"
  }
]
```

## 系统要求

- Python 3.10+
- Linux 自动 `ulimit -n 65535`
- 不依赖 masscan、nmap
- 不需要 API Key

## 安装

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/yu-929/IP-Reality/main/install.sh | bash
```

安装后全局可用 `xiao` 命令。

### Windows

1. 下载项目 ZIP 或 `git clone`
2. 双击 `build.bat`
3. 输出 `dist\xiao.exe`
4. 命令行运行

```cmd
dist\xiao.exe --sni images.apple.com --cf-domain your.domain.com
```

### 开发模式

```bash
git clone https://github.com/e13815332/ip-reality.git
cd ip-reality
pip install -e .
xiao --sni images.apple.com --cf-domain my-cdn.example.com
```

## 推荐 SNI

大厂 CDN 域名，证书覆盖广：

```
images.apple.com
swdist.apple.com
swcdn.apple.com
updates.cdn-apple.com
download.microsoft.com
```

## 常见问题

**Q: 为什么 Step 1 和 Step 2 不能复用同一个 TLS 连接？**
A: TLS 握手时 SNI 已确定，同一个连接不能换 SNI 再握一次。必须新建 TCP 连接。

**Q: 为什么证书解析必须用 binary_form？**
A: Python 的 `getpeercert()` 返回 dict，但 `verify_mode=CERT_NONE` 时 dict 可能为空。`binary_form=True` 直接拿 DER 二进制，用 `cryptography` 库解析最可靠。

**Q: 没装 GeoIP 数据库怎么办？**
A: 不影响运行，Geo 字段返回空。去 MaxMind 官网免费注册下载 GeoLite2-City.mmdb，放 `/usr/share/GeoIP/` 即可。

**Q: TLS 账本去哪下载？**
A: https://opendata.rapid7.com/sonar.ssl/ — 免费公开，每两周更新。工具 `--auto-ledger` 默认自动下载。
