# x-tunnel 配置文件支持 - 实现总结

## 修改概览

已成功为 x-tunnel 客户端添加了 YAML 配置文件支持。

## 修改内容

### 1. 代码修改（x-tunnel-client.go）

#### 添加导入
- 新增 `os` 包用于文件操作
- 新增 `gopkg.in/yaml.v3` 包用于 YAML 解析

#### 添加结构体
- **FileConfig**: 新增结构体用于映射配置文件的参数
  - 包含所有可配置的参数
  - 使用 YAML 标签进行字段映射

#### 添加全局变量
- `configFile`: 配置文件路径的命令行参数

#### 更新 init() 函数
- 新增 `-config` 参数用于指定配置文件路径

#### 添加 loadConfigFromFile() 函数
- 读取并解析 YAML 配置文件
- 应用配置到全局变量
- 实现命令行参数优先级机制（命令行 > 配置文件 > 默认值）
- 提供详细的日志输出

#### 修改 main() 函数
- 在 flag.Parse() 之后立即加载配置文件
- 配置文件优先级低于命令行参数

### 2. 文件创建

#### config.example.yaml
- 包含所有可配置参数的示例配置
- 详细注释说明每个参数的用途和格式
- 用户可直接复制此文件进行自定义配置

#### CONFIG_USAGE.md
- 详细的使用指南和文档
- 参数说明表
- 配置示例
- 故障排除指南
- 时间格式说明

## 功能特性

✅ **完整的配置文件支持** - 所有参数都可在 YAML 文件中配置
✅ **参数优先级** - 命令行参数 > 配置文件 > 默认值
✅ **向后兼容** - 保持原有命令行参数功能不变
✅ **灵活配置** - 可同时使用配置文件和命令行参数
✅ **详细文档** - 提供示例和使用指南
✅ **错误处理** - 配置文件错误会给出清晰的错误信息
✅ **日志输出** - 配置加载成功时提供日志提示

## 使用示例

### 基础使用
```bash
# 使用配置文件运行
./x-tunnel-client -config config.yaml
```

### 混合使用
```bash
# 配置文件 + 命令行参数
# 命令行参数会覆盖配置文件中的对应值
./x-tunnel-client -config config.yaml -l "socks5://127.0.0.1:8888"
```

### 纯命令行（保留原有方式）
```bash
# 不使用配置文件，保持原有命令行方式
./x-tunnel-client -l "socks5://0.0.0.0:1080" -f "wss://example.com:443"
```

## 配置文件示例结构

```yaml
# 必需参数
listen: "socks5://0.0.0.0:1080"
forward: "wss://example.com:443/path"

# 可选参数
ip: ""
udp_block_ports: "443"
token: ""
connection_num: 3
insecure: false
ips: ""
dns_server: "https://doh.pub/dns-query"
ech_domain: "cloudflare-ech.com"
fallback: false

# 高级配置（超时设置）
dial_timeout: ""
ws_handshake_timeout: ""
ws_write_timeout: ""
ws_read_timeout: ""
ping_interval: ""
reconnect_delay: ""
```

## 依赖项

代码使用了以下库：
- `gopkg.in/yaml.v3` - YAML 解析库

如果项目中还未安装，可运行：
```bash
go get gopkg.in/yaml.v3
```

## 向后兼容性

✅ 完全向后兼容 - 现有的命令行脚本和使用方式无需任何改动
✅ 配置文件完全可选 - 不提供 `-config` 参数时，程序仍然可以正常工作

## 文件列表

修改的文件：
- `x-tunnel-client.go` - 主程序，添加了配置文件支持

新增文件：
- `config.example.yaml` - 配置文件示例
- `CONFIG_USAGE.md` - 使用说明文档

## 验证

代码已通过 Go 编译器检查，无编译错误或警告。
