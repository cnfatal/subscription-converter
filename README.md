# subscription-converter

将 Clash/Mihomo 或 Base64 URI 订阅转换为 sing-box 配置，并通过本地 HTTP
接口提供给 SFM 等客户端。

支持：

- Clash/Mihomo YAML
- Base64 包装的 Shadowsocks、VMess、VLESS URI
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

- 程序和配置：`~/Library/Application Support/subscription-converter`
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
  - source: ~/.config/proxy-rules.yaml

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

## 开发

```bash
make test
make vet
```

项目根目录是公共 Go 包 `subscriptionconverter`。新增格式只需实现 `Codec` 并注册到
`Converter`。中间 `Document` 使用强类型节点、DNS、路由、策略组、TLS 和传输结构。

GEOIP 规则在输出 sing-box 时转换为远程 `geoip-<code>` rule-set。目前无法等价转换的
GEOSITE、rule-provider、DNS fallback/fake-IP 和
load-balance 语义会产生警告，不会静默改变行为。
