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
  - source: ./rules/global.yaml

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

The default patch format is `clash-rules`:

```yaml
rules:
  - DOMAIN-SUFFIX,example.com,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT
  - DOMAIN,blocked.example,REJECT
  - MATCH,proxy
```

The `patch` format accepts a strongly typed `DocumentPatch`. The `sing-box`
format accepts a sing-box configuration and merges `route.rule_set`,
`route.rules`, and `route.final`.

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
