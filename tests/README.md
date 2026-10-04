# Isolated integration tests

Build the production image first, then run from the repository:

```sh
podman build --http-proxy=false -t localhost/vpncsocks .
python3 tests/integration.py
```

The runner needs Linux rootless Podman, pasta, `/dev/net/tun`, at least 65,536 subordinate UIDs/GIDs, and host `curl` and `ssh`. It builds `localhost/vpncsocks-integration`, which adds Python and OpenSSH to the production image. Disposable containers use the production capabilities and network settings, including `NET_ADMIN` and loose reverse-path filtering. They do not require `SYS_ADMIN` or a privileged container.

The fake vpnc creates a veth called `tun0` and moves its peer into an isolated child user/network namespace. The peer serves DNS, HTTP, TLS, SSH on port 2222 and a binary service that responds only after stdin EOF. Only the runtime's network configuration hook is called; no real VPN gateway or credentials are used. Test credentials, keys and certificates are synthetic. Containers and temporary credentials are removed after each run; the test image remains available for reruns.

The production `vpnc.conf` is never read or mounted. Test configuration writes and direct mounts are restricted to the runner's `tests/vpncsocks-integration-*` temporary tree; paths and symlinks resolving outside it are rejected. Helper tests create their own configuration files in that same tree. The test image replaces both `/usr/local/bin/vpnc` and `/usr/sbin/vpnc` with the fixture, leaving no executable native vpnc at either entry point. Before starting any test, the runner verifies both paths in a container with networking disabled and no credentials mounted.

The suite checks SOCKS5 remote DNS, HTTP and HTTPS CONNECT, HTTP CONNECT to SSH's custom port, real SSH through stdio, binary half-close behavior, loopback-only host port bindings, firewall rejection counters for target TCP and DNS bound to an underlay source, established-session termination on disconnect, new-connection blocking, automatic reconnect, container stop/start, missing-DNS behavior, configured DNS override, terminal authentication failure, log redaction and decimal normalization of a leading-zero MTU value. It also simulates vpnc's weak-3DES rejection: configurations containing `Enable weak encryption 0` stop without retrying; explicit `Enable weak encryption 1` passes the intended flag to vpnc and permits proxy traffic. The fixture checks actual gateway, group, MTU and encryption arguments against the mounted synthetic configuration and rejects weak-authentication or no-encryption flags. Authentication-failure logs must redact the gateway, group and all three secret fields.

Attached `stdio` mode is tested using foreground `podman run --rm -i`, without published ports or a prestarted VPN container. Cases include binary stdin queued and closed before VPN readiness and preserved across an initial network failure/retry, a real SSH `ProxyCommand` on port 2222, invalid arguments, authentication failure, disconnect without reconnecting an established stream, SIGTERM cancellation and automatic container removal. Runtime diagnostics must remain on stderr and remote bytes on stdout.

Host-helper tests use only synthetic configurations. They run a copied `vpncsocks.sh` beside a synthetic config from an unrelated working directory, exercise UTF-8/space paths and a relative configured path, and establish real SSH through the helper's `stdio` command. They also check daemon startup with custom ports and native Podman options, `exec-stdio`, status/logs, stop/restart/removal, explicit legacy-encryption settings and ignored old `VPN_*` environment overrides. Unit tests require the gateway, group and three secret fields in the file, verify optional MTU/encryption defaults of 1412/0, confirm private vpnc configuration contains only secrets, and check that DNS and exported hook settings follow the file rather than old environment variables.

This fixture tests local proxy, routing, firewall and lifecycle behavior. It does not validate real IKE/IPSec negotiation, VPN credentials, DPD timing or the institution's gateway and internal services.
