---
icon: material/alert-decagram
---

# Route

!!! quote "Changes in sing-box 1.15.0"

    :material-plus: [pin_endpoints](#pin_endpoints)  
    :material-plus: [pinned_routes](#pinned_routes)

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [default_http_client](#default_http_client)  
    :material-plus: [find_neighbor](#find_neighbor)  
    :material-plus: [dhcp_lease_files](#dhcp_lease_files)

!!! quote "Changes in sing-box 1.12.0"

    :material-plus: [default_domain_resolver](#default_domain_resolver)  
    :material-note-remove: [geoip](#geoip)  
    :material-note-remove: [geosite](#geosite)

!!! quote "Changes in sing-box 1.11.0"

    :material-plus: [default_network_strategy](#default_network_strategy)  
    :material-plus: [default_network_type](#default_network_type)  
    :material-plus: [default_fallback_network_type](#default_fallback_network_type)  
    :material-plus: [default_fallback_delay](#default_fallback_delay)

!!! quote "Changes in sing-box 1.8.0"

    :material-plus: [rule_set](#rule_set)  
    :material-delete-clock: [geoip](#geoip)  
    :material-delete-clock: [geosite](#geosite)

### Structure

```json
{
  "route": {
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
    "default_domain_resolver": "", // or {}
    "default_network_strategy": "",
    "default_network_type": [],
    "default_fallback_network_type": [],
    "default_fallback_delay": "",
    
    // Removed

    "geoip": {},
    "geosite": {}
  }
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### rules

List of [Route Rule](./rule/)

#### rule_set

!!! question "Since sing-box 1.8.0"

List of [rule-set](/configuration/rule-set/)

#### final

Default outbound tag. the first outbound will be used if empty.

#### auto_detect_interface

!!! quote ""

    Only supported on Linux, Windows and macOS.

Bind outbound connections to the default NIC by default to prevent routing loops under tun.

Takes no effect if `outbound.bind_interface` is set.

#### pin_endpoints

!!! question "Since sing-box 1.15.0"

!!! quote ""

    Only supported on macOS.

Keep a host route towards every endpoint's remote address through the physical default
gateway, re-asserted whenever the routing table changes.

This prevents an endpoint's own transport from being captured by another tunnel's default
route. A WireGuard endpoint running inside another WireGuard tunnel still completes its
handshakes, since those are small, while every full sized data packet is silently dropped
by the outer tunnel's MTU, so the endpoint reports itself connected while carrying nothing.

Currently honoured by `wireguard` endpoints, for peers configured with a literal address.
Peers configured with a domain are resolved per dial and are not pinned.

A gateway is resolved per address family, since a host route can only be installed through
a gateway of the same family. Nothing is pinned for a family with no default route leaving
through a physical interface, so that a pin is never installed into a tunnel.

An address is not pinned at all when a route to it already exists which sing-box could not
put back as it was: one through an interface rather than a gateway, or one carrying
`-reject` or `-blackhole`. Replacing such a route would destroy it, since the kernel deletes
a host route by destination, and it could not be put back as it was. Since the address is
then unprotected, which is what this option exists to prevent, sing-box refuses to start
rather than running on without it.

Per-route metrics such as `-mtu` are not preserved across a replacement, and cannot be
detected beforehand: the kernel writes them itself during path MTU discovery, so a set
value is indistinguishable from a discovered one.

Routes already pointing at the right gateway are left alone and are not removed on
shutdown, since they may belong to something else. Pins installed by sing-box are removed
when it stops normally. One left behind by a crash is treated on the next run as belonging
to something else: it is left alone if it is still correct, and put back when that run stops
if that run had to replace it.

#### pinned_routes

!!! question "Since sing-box 1.15.0"

!!! quote ""

    Only supported on macOS.

Additional addresses to pin, as `pin_endpoints` does for endpoints.

A host route is process agnostic, so this covers addresses belonging to programs sing-box
knows nothing about, such as another VPN client running on the same machine whose transport
would otherwise be captured by a tunnel. `pin_endpoints` cannot derive those, since they
appear in no sing-box configuration.

Pinning is enabled by setting either this or `pin_endpoints`; the two lists are combined.

#### override_android_vpn

!!! quote ""

    Only supported on Android.

Accept Android VPN as upstream NIC when `auto_detect_interface` enabled.

#### default_interface

!!! quote ""

    Only supported on Linux, Windows and macOS.

Bind outbound connections to the specified NIC by default to prevent routing loops under tun.

Takes no effect if `auto_detect_interface` is set.

#### default_mark

!!! quote ""

    Only supported on Linux.

Set routing mark by default.

Takes no effect if `outbound.routing_mark` is set.

#### find_process

!!! quote ""

    Only supported on Linux, Windows, and macOS.

Enable process search for logging when no `process_name`, `process_path`, `package_name`, `user` or `user_id` rules exist.

#### find_neighbor

!!! question "Since sing-box 1.14.0"

!!! quote ""

    Only supported on Linux and macOS.

Enable neighbor resolution for logging when no `source_mac_address` or `source_hostname` rules exist.

See [Neighbor Resolution](/configuration/shared/neighbor/) for setup.

#### dhcp_lease_files

!!! question "Since sing-box 1.14.0"

!!! quote ""

    Only supported on Linux and macOS.

Custom DHCP lease file paths for hostname and MAC address resolution.

Automatically detected from common DHCP servers (dnsmasq, odhcpd, ISC dhcpd, Kea) if empty.

#### default_http_client

!!! question "Since sing-box 1.14.0"

Tag of the default [HTTP Client](/configuration/shared/http-client/) used by remote rule-sets.

If empty and `http_clients` is defined, the first HTTP client is used.

#### default_domain_resolver

!!! question "Since sing-box 1.12.0"

See [Dial Fields](/configuration/shared/dial/#domain_resolver) for details.

Can be overridden by `outbound.domain_resolver`.

#### default_network_strategy

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#network_strategy) for details.

Takes no effect if `outbound.bind_interface`, `outbound.inet4_bind_address` or `outbound.inet6_bind_address` is set.

Can be overridden by `outbound.network_strategy`.

Conflicts with `default_interface`.

#### default_network_type

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#network_type) for details.

#### default_fallback_network_type

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#fallback_network_type) for details.

#### default_fallback_delay

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#fallback_delay) for details.
