# subscription-converter

[![CI](https://github.com/cnfatal/subscription-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/cnfatal/subscription-converter/actions/workflows/ci.yml)

`subscription-converter` converts Clash/Mihomo and Base64 URI subscriptions into
sing-box JSON configurations. It can run as a CLI or expose named subscriptions
through a small HTTP service for clients such as SFM.

## Features

- Clash/Mihomo YAML and Base64-wrapped Shadowsocks, VMess, and VLESS URIs
- AnyTLS, Hysteria2 port hopping, VLESS Reality, Trojan, TUIC, SOCKS5, and HTTP
- Proxy Providers, Rule Providers, `RULE-SET`, `GEOIP`, and `GEOSITE`
- `select`, `url-test`, and `relay` groups
- Compatibility conversion for `fallback` and `load-balance` groups
- Clash DNS policies, FakeIP, fallback DNS, and proxy/direct resolvers
- Global and per-subscription patches
- Local files, standard input, and HTTP(S) sources
- HTTP headers, timeouts, in-memory caching, ETag, and Last-Modified revalidation

## Quick start

Requirements: Go 1.24 or later.

```bash
cp config.example.yaml config.yaml
$EDITOR config.yaml
make run
```

Open the index page at <http://127.0.0.1:9099/> or request a named subscription:

```bash
curl 'http://127.0.0.1:9099/subscriptions/primary?format=sing-box'
```

Additional service endpoints:

```text
GET /healthz
GET /version
GET /subscriptions
GET /subscriptions/{name}?format=sing-box
```

## Configuration

```yaml
server:
  listen: 127.0.0.1:9099

patches:
  - source: ./rules/proxy-rules.yaml
    format: clash
  - source: ./rules/inbounds.yaml
    format: sing-box

subscriptions:
  - name: primary
    source: https://example.com/subscription
    # Optional. Omit to recognize the input automatically.
    format: clash
    headers:
      Authorization: Bearer replace-me
    timeout: 30s
    cache: 10m
    patches:
      - source: ./rules/primary.yaml
```

Every source supports local paths and HTTP(S). Remote sources may specify
`headers`, `timeout`, and `cache`. Relative paths are resolved from the parent
configuration file. `~` is resolved through the current operating-system user,
including launchd environments without `HOME`.

The repository tracks `rules/proxy-rules.yaml` and `rules/inbounds.yaml` as its
default policy and client-listener configuration. Subscription credentials stay
in the ignored `config.yaml`.

## CLI

Convert one subscription:

```bash
make build

bin/subscription-converter convert \
  -input subscription.yaml \
  -from clash \
  -to sing-box \
  -output config.json

sing-box check -c config.json
```

`-from` accepts `auto`, `base64`, or `clash`. Conversion warnings are written to
standard error.

List registered formats:

```bash
bin/subscription-converter formats
```

Print build and Git version information:

```bash
bin/subscription-converter version
```

## Patches

Top-level patches apply to every subscription. Patches nested under a
subscription apply only to that subscription. Their priority is:

```text
subscription patches -> top-level patches -> source rules -> final
```

The default patch format is `clash`. It accepts a complete Clash configuration,
not only a `rules` fragment:

```yaml
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - DOMAIN,blocked.example,REJECT
  - MATCH,proxy
```

Clash proxies and proxy-provider nodes are merged by name, proxy groups are
merged by name, enabled DNS configuration replaces the current DNS section,
and rules are prepended with `MATCH`/`FINAL` overriding the final policy. Local
proxy and rule provider paths are resolved relative to the Clash patch file.
Conversion warnings are retained and logged by the server.

The `patch` format accepts a strongly typed `DocumentPatch`. The `sing-box`
format accepts a sing-box configuration and applies `inbounds` while merging
`route.rule_set`, `route.rules`, and `route.final`.

When omitted, `inbounds` retains the default auto-routed TUN. When supplied,
the complete list replaces the current inbounds; use `inbounds: []` to emit a
configuration without any inbound. For example, a local HTTP and SOCKS mixed
proxy can be supplied by a `sing-box` patch:

```yaml
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890
    set_system_proxy: true
```

To expose the proxy to a trusted LAN, listen on `0.0.0.0` and configure users:

```yaml
inbounds:
  - type: mixed
    tag: lan-in
    listen: 0.0.0.0
    listen_port: 7890
    users:
      - username: proxy
        password: replace-me
```

Supported inbound types are `tun`, `mixed`, `socks`, and `http`. Inbound tags
must be unique. A subscription-level inbound patch replaces a top-level inbound
patch because subscription patches have higher priority. `server.listen` is
only the converter's HTTP listen address and does not configure the generated
sing-box proxy listener.

Rule sets are merged by tag. Invalid rules, duplicate final rules, missing rule
sets, and unknown policies fail the conversion instead of being silently
ignored.

## macOS service

Install or update the current user's launchd service:

```bash
make launchd-install
```

This installs the binary and configuration under:

```text
~/Library/Application Support/subscription-converter
```

The LaunchAgent is written to:

```text
~/Library/LaunchAgents/cn.fatalc.subscription-converter.plist
```

Remove the LaunchAgent while retaining the installed configuration:

```bash
make launchd-uninstall
```

## Container image

The published multi-architecture image supports `linux/amd64` and
`linux/arm64`:

```bash
docker run --rm \
  -p 9099:9099 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  ghcr.io/cnfatal/subscription-converter:latest
```

For container use, set `server.listen` to `0.0.0.0:9099` and mount any local
patch files referenced by the configuration.

## Compatibility notes

- Mihomo MRS Rule Provider files are rejected; YAML and text providers are
  supported.
- Ordered fallback is approximated with sing-box `urltest`.
- Load-balancing groups are downgraded to selectors because sing-box has no
  equivalent outbound balancer.
- FakeIP combined with Clash fallback DNS cannot preserve Mihomo's upstream
  selection semantics; the fallback selection is omitted with a warning.
- Non-`DIRECT` Provider download proxies are rejected because the converter
  cannot execute downloads through a Clash policy group.
