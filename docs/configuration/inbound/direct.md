`direct` inbound is a tunnel server.

### Structure

```json
{
  "type": "direct",
  "tag": "direct-in",
  
  ... // Listen Fields

  "network": "udp",
  "override_address": "1.0.0.1",
  "override_port": 53,
  "dns_hijack_loopback": false,
  "dns_hijack_exclude_source": ""
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

#### override_address

Override the connection destination address.

#### override_port

Override the connection destination port.

#### dns_hijack_loopback

!!! question "Since sing-box 1.15.0"

!!! quote ""

    Only supported on macOS.

Redirect the system's loopback DNS port into this listener, by loading a pf `rdr` rule.

This takes `:53` back from a VPN client which owns `127.0.0.1` and has registered itself as
the system resolver. A tunnel cannot capture loopback by routing, so pf is the only
mechanism which reaches it.

Rules are loaded into an anchor under `com.apple/`, which the stock `/etc/pf.conf` already
evaluates through its wildcard anchor lines, so no system configuration needs editing. The
option refuses to start where that file is absent, since the anchor would then never be
traversed and the redirect would silently do nothing.

Only the protocols this listener actually opened are redirected, each to the port it
actually bound. `listen` must be a loopback address, and not an unspecified one, since there
would be no way to tell which loopback the listener answers on.

Rules are loaded once this listener is accepting, and removed on a normal shutdown, so a
new connection is not redirected to a port nothing answers on. A flow already established
through the redirect can outlive the rules, since pf keeps state for a translation rule
until it expires.

The rules live in the kernel rather than in the process, so a crash leaves them behind and
DNS keeps being redirected to a port which is no longer listening. A restart on the same
port reloads the same anchor and takes the redirect over again. The anchor is named after
the port actually bound, so with `listen_port` left to the system a restart may be given a
different port, and the stale anchor then has to be removed by hand with
`pfctl -a <anchor> -F nat`.

#### dns_hijack_exclude_source

!!! question "Since sing-box 1.15.0"

Do not redirect queries originating from this source address.

Required when sing-box resolves upstream through the same loopback port it is capturing,
which would otherwise route its own query back into itself. Give the address the upstream
DNS server's dialer is bound to.

pf takes one source per rule, so this applies only to the matching address family.
