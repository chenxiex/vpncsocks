#!/usr/bin/env bash
set -e

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
image=${VPNCS_IMAGE:-localhost/vpncsocks}
name=${VPNCS_NAME:-vpncsocks}
config=${VPNCS_CONFIG:-$script_dir/vpnc.conf}
[[ $config == /* ]] || config=$PWD/$config

run_options=(
    --pull="${VPNCS_PULL:-never}" --userns=host --user 0
    --device=/dev/net/tun:/dev/net/tun:rw --cap-add=NET_ADMIN
    --sysctl=net.ipv4.conf.all.rp_filter=2
    -v "$config:/run/secrets/vpnc.conf:ro"
)

command=${1:-help}
if (( $# )); then shift; fi
case $command in
    build)
        exec podman build -t "$image" "$@" "$script_dir"
        ;;
    pull)
        exec podman pull "$@" "$image"
        ;;
    start)
        exec podman run -d --name "$name" "${run_options[@]}" \
            --health-cmd=vpncsocks-healthcheck --health-interval=15s --health-timeout=5s \
            --health-start-period=60s --health-retries=3 \
            -p "127.0.0.1:${VPNCS_SOCKS_PORT:-1080}:1080/tcp" \
            -p "127.0.0.1:${VPNCS_HTTP_PORT:-8888}:8888/tcp" "$@" "$image"
        ;;
    stdio)
        exec podman run --rm -i "${run_options[@]}" "$image" stdio "$@"
        ;;
    exec-stdio)
        exec podman exec -i --user vpnproxy "$name" proxy-stdio "$@"
        ;;
    stop|restart|rm|logs)
        exec podman "$command" "$@" "$name"
        ;;
    status)
        exec podman ps -a --filter "name=$name" "$@"
        ;;
    help|-h|--help)
        printf 'Usage: %s {build|pull|start|stop|restart|rm|logs|status} [Podman options]\n       %s {stdio|exec-stdio} HOST PORT\n' "$0" "$0"
        ;;
    *)
        printf 'Unknown command: %s (use --help)\n' "$command" >&2
        exit 64
        ;;
esac
