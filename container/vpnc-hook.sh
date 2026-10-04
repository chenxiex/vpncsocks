#!/bin/bash
set -eu
umask 077
source /usr/local/lib/vpncsocks/network.sh

case ${reason:-} in
    pre-init) ;;
    connect)
        if ! configure_tunnel; then
            block_tunnel
            printf 'VPN hook configuration failed.\n' > "$RUN_DIR/private/fatal"
            exit 1
        fi
        ;;
    disconnect) block_tunnel ;;
    *) fail 'Unknown vpnc hook reason.'; exit 1 ;;
esac
