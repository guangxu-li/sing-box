---
icon: material/alert-decagram
---

# 路由

!!! quote "sing-box 1.15.0 中的更改"

    :material-plus: [pin_endpoints](#pin_endpoints)  
    :material-plus: [pinned_routes](#pinned_routes)

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [default_http_client](#default_http_client)  
    :material-plus: [find_neighbor](#find_neighbor)  
    :material-plus: [dhcp_lease_files](#dhcp_lease_files)

!!! quote "sing-box 1.12.0 中的更改"

    :material-plus: [default_domain_resolver](#default_domain_resolver)  
    :material-note-remove: [geoip](#geoip)  
    :material-note-remove: [geosite](#geosite)

!!! quote "sing-box 1.11.0 中的更改"

    :material-plus: [default_network_strategy](#default_network_strategy)  
    :material-plus: [default_network_type](#default_network_type)  
    :material-plus: [default_fallback_network_type](#default_fallback_network_type)  
    :material-plus: [default_fallback_delay](#default_fallback_delay)

!!! quote "sing-box 1.8.0 中的更改"

    :material-plus: [rule_set](#rule_set)  
    :material-delete-clock: [geoip](#geoip)  
    :material-delete-clock: [geosite](#geosite)

### 结构

```json
{
  "route": {
    "geoip": {},
    "geosite": {},
    "rules": [],
    "rule_set": [],
    "final": "",
    "auto_detect_interface": false,
    "pin_endpoints": false,
    "pinned_routes": [],
    "override_android_vpn": false,
    "default_interface": "",
    "default_mark": 0,
    "find_process": false,
    "find_neighbor": false,
    "dhcp_lease_files": [],
    "default_http_client": "",
    "default_network_strategy": "",
    "default_fallback_delay": ""
  }
}
```

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

### 字段

| 键         | 格式                    |
|-----------|-----------------------|
| `geoip`   | [GeoIP](./geoip/)     |
| `geosite` | [Geosite](./geosite/) |

#### rule

一组 [路由规则](./rule/)    。

#### rule_set

!!! question "自 sing-box 1.8.0 起"

一组 [规则集](/zh/configuration/rule-set/)。

#### final

默认出站标签。如果为空，将使用第一个可用于对应协议的出站。

#### auto_detect_interface

!!! quote ""

    仅支持 Linux、Windows 和 macOS。

默认将出站连接绑定到默认网卡，以防止在 tun 下出现路由环路。

如果设置了 `outbound.bind_interface` 设置，则不生效。

#### pin_endpoints

!!! question "自 sing-box 1.15.0 起"

!!! quote ""

    仅支持 macOS。

通过物理默认网关为每个端点的远程地址保持一条主机路由，并在路由表变化时重新确认。

此项防止端点自身的传输被另一个隧道的默认路由捕获。运行在另一个 WireGuard 隧道内的
WireGuard 端点仍能完成握手，因为握手包很小，而每个完整大小的数据包都会被外层隧道的 MTU
静默丢弃，于是端点报告已连接却不承载任何流量。

目前由 `wireguard` 端点支持，适用于配置为字面地址的对端。配置为域名的对端在每次拨号时解析，
不会被固定。

网关按地址族分别解析，因为主机路由只能经由同一地址族的网关安装。当某一地址族没有经由物理接口的默认路由时，
不为该地址族固定任何地址，以免将固定路由安装到隧道中。

当某个地址已存在 sing-box 无法原样还原的路由时，将完全不固定该地址：例如经由接口而非网关的路由，
带有 `-reject`、`-blackhole` 的路由。替换此类路由会将其销毁，因为内核按目标地址删除主机路由，
且无法将其原样还原。由于该地址随之失去保护，而这正是此选项要防止的情况，sing-box 将拒绝启动，
而不是在缺少保护的情况下继续运行。

`-mtu` 等每路由度量值在替换过程中不会被保留，且无法事先识别：内核会在路径 MTU 发现过程中自行写入这些值，
因此显式设置的值与探测得出的值无法区分。

已指向正确网关的路由将保持不变，且不会在关闭时被移除，因为它们可能属于其他程序。由 sing-box 安装的固定路由将在其正常停止时移除。
因崩溃而残留的固定路由会在下次运行时被视为属于其他程序：若其仍然正确则保持不变；若该次运行需要替换它，则会在该次运行停止时被还原。

#### pinned_routes

!!! question "自 sing-box 1.15.0 起"

!!! quote ""

    仅支持 macOS。

需要额外固定的地址，作用与 `pin_endpoints` 对端点的作用相同。

主机路由与进程无关，因此此项可覆盖 sing-box 并不知晓的程序所使用的地址，例如运行在同一台机器上、
其传输可能被隧道捕获的另一个 VPN 客户端。`pin_endpoints` 无法推导出这些地址，因为它们不出现在任何
sing-box 配置中。

设置此项或 `pin_endpoints` 中的任意一个即可启用固定；两个列表将合并使用。

#### override_android_vpn

!!! quote ""

    仅支持 Android。

启用 `auto_detect_interface` 时接受 Android VPN 作为上游网卡。

#### default_interface

!!! quote ""

    仅支持 Linux、Windows 和 macOS。

默认将出站连接绑定到指定网卡，以防止在 tun 下出现路由环路。

如果设置了 `auto_detect_interface` 设置，则不生效。

#### default_mark

!!! quote ""

    仅支持 Linux。

默认为出站连接设置路由标记。

如果设置了 `outbound.routing_mark` 设置，则不生效。

#### find_process

!!! quote ""

    仅支持 Linux、Windows 和 macOS。

在没有 `process_name`、`process_path`、`package_name`、`user` 或 `user_id` 规则时启用进程搜索以输出日志。

#### find_neighbor

!!! question "自 sing-box 1.14.0 起"

!!! quote ""

    仅支持 Linux 和 macOS。

在没有 `source_mac_address` 或 `source_hostname` 规则时启用邻居解析以输出日志。

参阅 [邻居解析](/configuration/shared/neighbor/) 了解设置方法。

#### dhcp_lease_files

!!! question "自 sing-box 1.14.0 起"

!!! quote ""

    仅支持 Linux 和 macOS。

用于主机名和 MAC 地址解析的自定义 DHCP 租约文件路径。

为空时自动从常见 DHCP 服务器（dnsmasq、odhcpd、ISC dhcpd、Kea）检测。

#### default_http_client

!!! question "自 sing-box 1.14.0 起"

远程规则集使用的默认 [HTTP 客户端](/zh/configuration/shared/http-client/) 的标签。

如果为空且 `http_clients` 已定义，将使用第一个 HTTP 客户端。

#### default_domain_resolver

!!! question "自 sing-box 1.12.0 起"

详情参阅 [拨号字段](/zh/configuration/shared/dial/#domain_resolver)。

可以被 `outbound.domain_resolver` 覆盖。

#### network_strategy

!!! question "自 sing-box 1.11.0 起"

详情参阅 [拨号字段](/zh/configuration/shared/dial/#network_strategy)。

当 `outbound.bind_interface`, `outbound.inet4_bind_address` 或 `outbound.inet6_bind_address` 已设置时不生效。

可以被 `outbound.network_strategy` 覆盖。

与 `default_interface` 冲突。

#### default_network_type

!!! question "自 sing-box 1.11.0 起"

详情参阅 [拨号字段](/zh/configuration/shared/dial/#default_network_type)。

#### default_fallback_network_type

!!! question "自 sing-box 1.11.0 起"

详情参阅 [拨号字段](/zh/configuration/shared/dial/#default_fallback_network_type)。

#### default_fallback_delay

!!! question "自 sing-box 1.11.0 起"

详情参阅 [拨号字段](/zh/configuration/shared/dial/#fallback_delay)。
