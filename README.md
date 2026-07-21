# subscription-converter

将 Clash/Mihomo 或 Base64 URI 订阅转换为 sing-box 配置，并通过本地 HTTP
接口提供给 SFM 等客户端。

支持：

- Clash/Mihomo YAML
- Base64 包装的 Shadowsocks、VMess、VLESS URI
- AnyTLS、Hysteria2 端口跳跃、VLESS Reality
- Proxy Provider、Rule Provider、RULE-SET、GEOIP、GEOSITE
- select、url-test、relay，以及 fallback/load-balance 兼容转换
- Clash DNS policy、FakeIP、fallback 和 proxy/direct resolver
- sing-box JSON 输出
- 本地文件、标准输入和 HTTP(S) 订阅源

## 快速启动

```bash
cp config.example.yaml config.yaml
# 编辑 config.yaml
make run
```

`config.yaml` 示例：

```yaml
server:
  listen: 127.0.0.1:9099

subscriptions:
  - name: primary
    source: https://example.com/subscription
    # 可选；省略时自动识别，也可以指定 base64 或 clash。
    format: base64
    headers:
      Authorization: Bearer replace-me
    timeout: 30s
    cache: 10m
```

访问转换后的配置：

```text
http://127.0.0.1:9099/subscriptions/primary?format=sing-box
```

检查服务：

```bash
open http://127.0.0.1:9099/
curl http://127.0.0.1:9099/healthz
curl http://127.0.0.1:9099/subscriptions
```

## macOS launchd

安装为当前用户的 LaunchAgent：

```bash
make launchd-install
```

安装位置：

- 程序、配置和规则：`~/Library/Application Support/subscription-converter`
- LaunchAgent：`~/Library/LaunchAgents/cn.fatalc.subscription-converter.plist`

常用命令：

```bash
make launchd-status
make launchd-restart

# 修改项目目录中的 config.yaml 后同步并重启。
make launchd-sync-config

make launchd-uninstall
```

卸载不会删除已安装的配置。服务默认只监听 `127.0.0.1:9099`。

## 单次转换

```bash
make build

bin/subscription-converter convert \
  -input config.yaml \
  -from clash \
  -to sing-box \
  -output config.json

sing-box check -c config.json
```

输入格式可以设为 `auto`、`base64` 或 `clash`。转换警告写入标准错误。

## Patch rules

顶层 `patches` 应用于所有订阅，订阅中的 `patches` 只应用于当前订阅：

```yaml
patches:
  - source: https://example.com/proxy-rules.yaml
    headers:
      Authorization: Bearer replace-me
    timeout: 30s
    cache: 1h

subscriptions:
  - name: justmysocks
    source: https://example.com/base64-subscription
    format: base64
    patches:
      - source: ./rules/justmysocks.yaml
```

默认 Patch format 是 `clash-rules`，规则文件格式为：

```yaml
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - DOMAIN,blocked.example,REJECT
  - MATCH,proxy
```

也可以显式设置 `format: patch`，使用强类型 `DocumentPatch`。

`format: sing-box` 将文件解码为完整的强类型 `SingBoxConfig`；作为 Patch 使用时，
当前合并其中的 `route.rule_set`、`route.rules` 和 `route.final`：

```yaml
route:
  rule_set:
    - type: remote
      tag: geoip-cn
      format: binary
      url: https://example.com/geoip-cn.srs
      download_detour: proxy
  rules:
    - rule_set: [geoip-cn]
      outbound: direct
  final: direct
```

Rule-set 按 `tag` 合并，订阅 Patch 覆盖顶层 Patch，顶层 Patch 覆盖订阅原定义；
引用不存在的 rule-set 会导致转换失败。规则优先级为：

```text
subscription patches → top-level patches → source rules → final
```

Patch 文件读取失败、规则无效、重复 `MATCH` 或引用未知策略时，本次转换直接失败。

订阅、Patch、Proxy Provider 和 Rule Provider 共用同一个 Source Loader。本地文件、HTTP、
HTTPS 使用相同的大小限制；远程 Source 支持自定义 Header、超时、内存缓存、ETag 和
Last-Modified 条件请求。缓存默认关闭。

## 开发

```bash
make test
make vet
```

项目根目录是公共核心包 `subscriptionconverter`，`base64`、`clash`、`singbox` 是独立
Codec package，`builtin.New()` 负责组装内置格式。自定义场景也可以通过
`subscriptionconverter.New(codecs...)` 只注册需要的 Codec。中间 `Document` 使用强类型
节点、DNS、路由、策略组、TLS 和传输结构。

GEOIP 和 GEOSITE 在输出 sing-box 时转换为远程 rule-set。Clash YAML/text Rule Provider
会先由转换器读取，再输出为 sing-box inline rule-set；Mihomo MRS 二进制 Provider 当前会
明确报错。

`relay` 转换为 sing-box detour 链。sing-box 没有与 Clash ordered fallback 和
round-robin/consistent-hashing load-balance 等价的 outbound，因此 fallback 使用 urltest、
load-balance 使用 selector，并输出明确警告。

FakeIP 使用 sing-box 1.12+ 的强类型 FakeIP DNS server。FakeIP 与 fallback 同时启用时
无法保持 Mihomo 在 FakeIP 后方选择上游 DNS 的并发解析语义，fallback 选择会明确告警并省略。
Mihomo VLESS `encryption: none` 按标准 sing-box VLESS 输出；其他 encryption 扩展不受
sing-box 支持，相关节点会明确告警并跳过。
