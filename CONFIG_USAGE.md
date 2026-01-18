# x-tunnel 客户端配置文件使用指南

## 概述
x-tunnel 客户端现在支持通过 YAML 配置文件来配置所有参数，同时保持对命令行参数的完整支持。

## 使用方法

### 基础使用

1. **复制示例配置文件**
   ```bash
   cp config.example.yaml config.yaml
   ```

2. **编辑配置文件** - 根据您的需要修改 `config.yaml` 中的参数

3. **运行客户端**
   ```bash
   ./x-tunnel-client -config config.yaml
   ```

## 参数优先级

参数优先级（从高到低）：
1. **命令行参数** - 最高优先级
2. **配置文件参数** - 中等优先级  
3. **程序默认值** - 最低优先级

当同时使用配置文件和命令行参数时，**命令行参数会覆盖配置文件中的对应值**。

#### 工作原理

程序的参数加载流程：
1. 初始化所有参数为默认值
2. 解析命令行参数
3. 如果指定了配置文件，加载配置文件
4. 对于配置文件中的参数，仅当**该参数未在命令行中设置过**时才应用

#### 使用示例

```bash
# 配置文件中设置了:
# listen: "socks5://0.0.0.0:1080"
# forward: "wss://example.com:443/path"
# connection_num: 3

# 命令行参数会覆盖配置文件的值
./x-tunnel-client -config config.yaml -l "socks5://127.0.0.1:8888"
# 结果: listen 使用命令行值，其他参数使用配置文件值

# 哪些参数被设置了？
# -l: 命令行设置 -> 使用 127.0.0.1:8888
# forward: 未在命令行设置 -> 使用配置文件的 example.com
# connection_num: 未在命令行设置 -> 使用配置文件的 3
```

#### 只用配置文件

```bash
# 配置文件设置所有参数，无需命令行参数
./x-tunnel-client -config config.yaml
```

#### 只用命令行参数

```bash
# 不指定配置文件，完全使用命令行参数（保留原有方式）
./x-tunnel-client \
  -l "socks5://0.0.0.0:1080" \
  -f "wss://example.com:443/path" \
  -n 3
```

## 配置文件参数说明

| 参数 | 类型 | 必需 | 说明 | 示例 |
|------|------|------|------|------|
| `listen` | string | 是 | SOCKS5 监听地址 | `"socks5://0.0.0.0:1080"` |
| `forward` | string | 是 | 服务器地址 | `"wss://example.com:443/path"` |
| `ip` | string | 否 | 指定连接的IP地址（逗号分隔） | `"1.2.3.4,5.6.7.8"` |
| `udp_block_ports` | string | 否 | 拦截的UDP端口列表 | `"443,53"` |
| `token` | string | 否 | 身份验证令牌 | `"your-token-here"` |
| `connection_num` | int | 否 | 每个IP的WebSocket连接数 | `3` |
| `insecure` | bool | 否 | 忽略证书校验 | `false` |
| `ips` | string | 否 | IP解析偏好 | `"4,6"` (优先IPv4) |
| `dns_server` | string | 否 | ECH查询DNS服务器 | `"https://doh.pub/dns-query"` |
| `ech_domain` | string | 否 | ECH公钥查询域名 | `"cloudflare-ech.com"` |
| `fallback` | bool | 否 | 禁用ECH回落到TLS 1.3 | `false` |
| `dial_timeout` | string | 否 | 拨号超时 | `"3s"` |
| `ws_handshake_timeout` | string | 否 | WebSocket握手超时 | `"5s"` |
| `ws_write_timeout` | string | 否 | WebSocket写入超时 | `"5s"` |
| `ws_read_timeout` | string | 否 | WebSocket读取超时 | `"10s"` |
| `ping_interval` | string | 否 | Ping间隔 | `"3s"` |
| `reconnect_delay` | string | 否 | 重连延迟 | `"1s"` |

## 配置示例

### 最简配置
```yaml
listen: "socks5://0.0.0.0:1080"
forward: "wss://example.com:443/tunnel"
```

### 完整配置
```yaml
listen: "socks5://user:password@0.0.0.0:1080"
forward: "wss://example.com:443/tunnel"
ip: "1.2.3.4,5.6.7.8"
udp_block_ports: "443,53"
token: "your-auth-token"
connection_num: 5
insecure: false
ips: "4,6"
dns_server: "https://doh.pub/dns-query"
ech_domain: "cloudflare-ech.com"
fallback: false
dial_timeout: "3s"
ws_handshake_timeout: "5s"
ws_write_timeout: "5s"
ws_read_timeout: "10s"
ping_interval: "3s"
reconnect_delay: "1s"
```

## 命令行参数

所有原有的命令行参数仍然可用：

```bash
./x-tunnel-client \
  -config config.yaml \           # 配置文件路径
  -l "socks5://0.0.0.0:1080" \   # SOCKS5监听地址
  -f "wss://example.com:443" \   # 服务器地址
  -ip "1.2.3.4" \                # 指定IP
  -block "443,53" \              # 拦截端口
  -token "token" \               # 认证令牌
  -n 3 \                         # 连接数
  -insecure \                    # 忽略证书
  -dns "https://doh.pub" \       # DNS服务器
  -ech "cloudflare-ech.com" \    # ECH域名
  -fallback \                    # ECH回落
  -ips "4,6"                     # IP偏好
```

## 时间格式

超时和间隔参数使用 Go 的时间格式：
- `"100ms"` - 100毫秒
- `"1s"` - 1秒
- `"1m"` - 1分钟
- `"1h"` - 1小时

## 故障排除

1. **配置文件不存在**
   - 确保 `-config` 参数指向正确的文件路径
   - 使用绝对路径以避免歧义

2. **YAML 语法错误**
   - 使用在线 YAML 验证工具检查配置文件
   - 确保正确使用了缩进（使用空格，不是Tab）

3. **参数不被应用**
   - 检查命令行是否覆盖了配置文件设置
   - 查看日志输出确认配置文件已成功加载

## 示例工作流

```bash
# 1. 复制示例配置
cp config.example.yaml config.yaml

# 2. 编辑配置文件
nano config.yaml

# 3. 运行客户端（日志会显示配置文件加载成功）
./x-tunnel-client -config config.yaml

# 4. 通过命令行参数临时覆盖配置（如果需要）
./x-tunnel-client -config config.yaml -l "socks5://127.0.0.1:8080"
```
