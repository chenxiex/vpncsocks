#!/bin/bash
set -eu
source /usr/local/lib/vpncsocks/common.sh

if ! connected; then
    printf 'VPN and proxy processes are not ready.\n' >&2
    exit 1
fi
if (( EUID == 0 )); then
    nft list table inet vpncsocks >/dev/null 2>&1 || exit 1
fi
