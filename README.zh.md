<div align="center">

# honk

**用 Rust 编写的实验性 Linux 透明代理引擎。**

**[文档](doc/README.md)** / **[网页界面示范](https://demo.daeuniverse.org/)** / **[下载](https://github.com/6106757-lab/honk/releases)**

[English](README.md) / 简体中文

[功能概览](#功能概览) / [定制内容](#本-fork-的定制内容) / [安装](#安装) / [网页界面](#网页界面) / [报告问题](#报告问题)

</div>

> **早期 alpha，不建议用于生产。** 可能发生破坏性变更，部分功能尚未完成，真实环境验证仍然有限。

honk 的 eBPF 数据面和配置语法参考 dae 的设计，出站组与 Clash API 参考 sing-box 的设计。它是独立实现，并非任一项目的移植。

## 功能概览

- 透明 TCP/UDP：通过 TC eBPF、`dae0`/`daens` 和编译路由处理 LAN 转发及本机发起的流量。
- 出站：SOCKS5、Shadowsocks/2022、Trojan、AnyTLS、Hysteria2、TUIC、Juicity、VMess、VLESS、`direct` 和 `block`。Trojan/VMess/VLESS 支持 H2 XHTTP（`packet-up`、`stream-up`、`stream-one`）；VMess 仅支持 TCP。详见[协议限制](doc/zh/reference/nodes.md)。
- 组策略：Selector（默认）、URLTest、LoadBalance、Fallback 和 Score。Score 使用业务观测与有界验证，详见[组策略参考](doc/zh/reference/groups.md#score-策略)。
- DNS：支持 UDP、TCP、DoT、DoH、DoQ、DoH3 上游，可经节点或组出站，并提供路由和缓存。
- 配置与控制：dae 语法、订阅、重载、Clash 兼容 REST/WebSocket API，以及 `honk-tool` CLI 工具箱。

不提供 FakeIP 引擎、完整 mihomo 兼容性或 Windows/macOS 数据面。

## 本 fork 的定制内容

本仓库基于 [daeuniverse/honk](https://github.com/daeuniverse/honk)，额外提供以下功能，配置方法见[链式代理与 MASQUE 配置指南](doc/zh/guide/chained-proxy-and-masque.md)：

- **MASQUE（connect-ip）出站**：可从订阅导入 `type: masque` 节点（含 Cloudflare WARP），以 HTTP/2 或 HTTP/3 承载，支持 TUN 设备与内置界面延迟测试。
- **链式代理（detour）**：节点可写 `dialer-proxy`（Clash 订阅 / 分享链接）或 `detour`（sing-box JSON）；组可写 `detour:`，前置可为节点、组或 `direct`。
- **引用组继承**：`filter: group(X)` 的组自动继承上游组的 detour，显式 `detour:`（含 `direct`）可覆盖；TCP、UDP 拨号与 Clash / 原生 API 延迟测试共用同一解析。
- **前置热切换**：切换前置节点或前置组成员后热重载即生效，无需重启；MASQUE 隧道按承载路径分别建立，空闲隧道在重载时回收。
- **内置定制版 doona 界面**：`full` 构建内置 [6106757-lab/doona](https://github.com/6106757-lab/doona) `v0.1.0-rc.4` 编译的界面，支持 MASQUE 延迟测试。
- **现成二进制**：[Releases](https://github.com/6106757-lab/honk/releases) 提供已编译的 x86_64 musl `full` 构建，下载即可部署，不需要本地 Rust 编译环境。

上游 `main` 目前不含上述功能；本仓库独立维护，问题请提交到[本仓库 Issues](https://github.com/6106757-lab/honk/issues)。

## 安装

从 [本仓库 Releases](https://github.com/6106757-lab/honk/releases) 下载已编译好的归档。当前发布物为 x86_64 Linux 静态 musl 的 `full` 构建（原生 API + Clash API + 内置 doona / doona lite），下载后可直接部署，不需要本地 Rust 编译环境。下表描述上游的构建矩阵，本仓库 Release 目前只发布 `full`。

| 构建 | 原生 API | Clash API | 内嵌 doona 与 doona lite |
| --- | --- | --- | --- |
| `full` | 是 | 是 | 是 |
| `native-api` | 是 | 否 | 否 |
| `clash-api` | 否 | 是 | 否 |

各构建均提供静态链接的 musl 版本，`full` 另提供链接 glibc 的 `gnu` 版本。名称含 `stock` 的归档使用系统分配器而非 jemalloc。每个版本的 Downloads 一节列出校验和及构建来源证明。

OpenWrt 用户可使用 [daeuniverse 软件源](https://openwrt.daeuniverse.org/zh-cn/)。

自行编译请按[从源码构建](doc/zh/how-to-start.md#从源码构建)准备。发布二进制内嵌 eBPF；仅执行 `cargo build --release` 不会启用真实数据面。

按[启动指南](doc/zh/how-to-start.md)检查内核、安装程序并验证连通性。首次部署会修改网络 hook、命名空间和 sysctl，须保留带外管理通道。

## 网页界面

honk 可配合以下两类网页界面使用：

- [doona](https://github.com/Zakkaus/doona)：基于原生 API，提供运行观测、诊断与配置编辑功能。doona lite 为其轻量预览版。在线演示见[标准版](https://demo.daeuniverse.org/)与 [lite 版](https://demo.daeuniverse.org/lite/)。本仓库 `full` 构建内置的是 [6106757-lab/doona](https://github.com/6106757-lab/doona) `v0.1.0-rc.4` 编译的界面，支持对 MASQUE 节点做延迟测试。
- Clash 面板：基于 Clash 兼容 API，例如 [zashboard](https://github.com/Zephyruso/zashboard)。

![doona 活动页的流量图表与状态卡片](https://doona.daeuniverse.org/screenshots/zh-CN/activity-light.webp)

![doona lite 节点页](https://doona.daeuniverse.org/images/lite-nodes-light.webp)

使用 `full` 构建时，在 `experimental.native_api` 中将 `ui` 设为 `'embedded'` 即可启用 doona，设为 `'embedded-lite'` 则启用 doona lite。`native-api` 构建可将 `ui` 设为另行[安装的 doona](https://doona.daeuniverse.org/zh-CN/install.html) 所在目录。配置步骤见 [doona 快速入门](https://doona.daeuniverse.org/zh-CN/quick-start.html)。启用 Clash 面板需配置 `experimental.clash_api`，honk 首次启动时自动下载 zashboard。各设置项的说明见 [experimental 设置](doc/zh/reference/experimental.md)。

## 文档

[文档索引](doc/README.md)汇总中英文配置指南、原生与 Clash API 参考、子系统设计及运维指南。

## 版本与兼容性

- 自 `v0.1.0` 起，发布遵循 [SemVer](https://semver.org/lang/zh-CN/)；带 `-alpha.N`、`-beta.N` 或 `-rc.N` 后缀的标签为预发布。`1.0` 之前，次版本可能改变配置或行为，升级前应阅读发布说明。
- 透明代理需要 root 权限、Linux 6.12+、所需内核选项和 bpffs。详见上方链接的启动指南。
- 配置使用 [dae 语法](doc/zh/configuration.md)。修改已有部署前，请查阅 [NFQUEUE 运行说明](doc/zh/design/nfqueue.md)和 [VLESS 迁移指南](doc/zh/reference/nodes.md#从-vless_mode-迁移)。
- 原生 API 使用 `/api/v1`，其契约在 `1.0` 之前可能随次版本变化。`GET /api/v1/version` 返回契约标识。

## 开发

工作区包含配置、共享 eBPF 类型、NFQUEUE、出站、核心和工具 crate；`crates/honk-ebpf` 单独构建。详见 [Justfile](Justfile) 与[贡献政策](CONTRIBUTING.md)。

无 root 的用户态开发可使用 [mock 模式](doc/zh/how-to-start.md#无-root-开发)。`--mock-ebpf` 不会拦截流量，不能代替数据面测试。

本仓库的二进制由 GitHub Actions 构建，产物直接发布到 [Releases](https://github.com/6106757-lab/honk/releases)，无需本地编译环境；构建工作流见 [build.yml](.github/workflows/build.yml)，发布校验和随每个 Release 提供。

## 报告问题

代理、路由和 DNS 问题请提交至 [本仓库 Issues](https://github.com/6106757-lab/honk/issues)；内置界面问题请提交至 [doona fork Issues](https://github.com/6106757-lab/doona/issues)。上游专属功能的问题仍应提到 daeuniverse/honk。

安全漏洞请按 [SECURITY.md](.github/SECURITY.md) 报告。

## 致谢

- [dae](https://github.com/daeuniverse/dae) / daed-rs：eBPF 透明代理谱系
- [sing-box](https://github.com/SagerNet/sing-box)：出站组与 Clash API 模式
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound)：协议参考
- [juicity-rs](https://github.com/juicity/juicity-rs)（Markson Pigeonzilla Plus）：Juicity 协议参考、wire 格式对齐及真实互通测试
- [aya-rs](https://github.com/aya-rs/aya)：Rust eBPF

## 许可证

[GPL-3.0-only](LICENSE)。

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```

仅用于开发的 [dae 解析器 oracle](tools/dae-parse/README.md)链接了 dae（AGPL-3.0-only）。它不随发布物分发，也不链接进 `honk-core`。

## TODO

- [ ] 评估 AF_XDP 与 XDP 路径以进一步提升性能
- [ ] 在 Clash 兼容 API 之外添加 honk 专用 REST API
- [ ] 添加入站支持
- [ ] 探索 macOS 与 Windows 支持；数据面基于 Linux eBPF，这两个平台需要另一种接管流量的方式
