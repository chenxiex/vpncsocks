#!/bin/bash
set -eu
source /usr/local/lib/vpncsocks/common.sh

if ! valid_proxy_target "$@"; then
    printf 'Usage: proxy-stdio HOST PORT (IPv4 TCP, port 1-65535).\n' >&2
    exit 64
fi
if (( EUID != PROXY_UID )); then
    printf 'Run with: podman exec -i --user vpnproxy vpncsocks proxy-stdio HOST PORT\n' >&2
    exit 64
fi
if ! tunnel_connected; then
    printf 'VPN is not ready; inspect podman logs vpncsocks.\n' >&2
    exit 69
fi
# No TTY, line conversion, idle timeout, or intermediate proxy hop.
exec ncat -4 --wait 10 -- "$1" "$((10#$2))"
