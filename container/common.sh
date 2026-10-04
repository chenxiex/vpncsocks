#!/bin/bash

# Runtime state is container-local. Only public readiness and PIDs are readable
# by the proxy user; credentials and raw VPN output stay in private/.
RUN_DIR=/run/vpncsocks
PROXY_UID=10001
PROXY_GID=10001
VPN_TABLE=100

log() {
    printf 'vpncsocks: %s\n' "$*" >&2
}

fail() {
    log "$*"
    return 1
}

valid_ipv4() {
    local address=$1 octet
    local -a octets
    [[ $address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r -a octets <<< "$address"
    for octet in "${octets[@]}"; do
        [[ ${#octet} -le 3 && ( $octet == 0 || $octet != 0* ) ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
}

valid_dns() {
    valid_ipv4 "$1" || return 1
    # Local and link-local resolvers can be Podman/pasta host forwarders.
    [[ $1 != 0.* && $1 != 127.* && $1 != 169.254.* && $1 != 255.* ]] || return 1
    local first=${1%%.*}
    (( 10#$first < 224 ))
}

validate_settings() {
    [[ $VPN_GATEWAY =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ && ${#VPN_GATEWAY} -le 253 ]] \
        || fail 'IPSec gateway must be an IPv4 address or hostname.' || return 1
    [[ $VPN_GATEWAY != *..* ]] || fail 'IPSec gateway contains an empty hostname label.' || return 1
    if [[ $VPN_GATEWAY =~ ^[0-9.]+$ ]]; then
        valid_ipv4 "$VPN_GATEWAY" || fail 'IPSec gateway contains an invalid IPv4 address.' || return 1
    fi
    [[ -n $VPN_IPSEC_ID && $VPN_IPSEC_ID != *$'\n'* && $VPN_IPSEC_ID != *$'\r'* ]] \
        || fail 'IPSec ID must be a nonempty single-line value.' || return 1
    [[ $VPN_MTU =~ ^[0-9]{3,4}$ ]] && (( 10#$VPN_MTU >= 576 && 10#$VPN_MTU <= 1500 )) \
        || fail 'Interface MTU must be an integer between 576 and 1500.' || return 1
    # iproute2 can interpret leading zeroes as octal; use decimal everywhere.
    VPN_MTU=$((10#$VPN_MTU))
    [[ $VPN_ENABLE_WEAK_ENCRYPTION == 0 || $VPN_ENABLE_WEAK_ENCRYPTION == 1 ]] \
        || fail 'Enable weak encryption must be 0 or 1.' || return 1
    local item
    local -a dns
    if [[ -n $VPN_DNS ]]; then
        [[ $VPN_DNS != ,* && $VPN_DNS != *, && $VPN_DNS != *,,* ]] \
            || fail 'VPN DNS must be comma-separated IPv4 addresses.' || return 1
        IFS=, read -r -a dns <<< "$VPN_DNS"
        for item in "${dns[@]}"; do
            valid_dns "$item" || fail 'VPN DNS contains an invalid or host-forwarded DNS address.' || return 1
        done
    fi
    export VPN_GATEWAY VPN_IPSEC_ID VPN_DNS VPN_MTU VPN_ENABLE_WEAK_ENCRYPTION
}

load_credentials() {
    local source=$1 destination=$2 line key value
    local -A values=()
    [[ -f $source && -r $source ]] || fail 'Mount a readable credentials file at /run/secrets/vpnc.conf.' || return 1
    [[ $(stat -c %s "$source") -le 65536 ]] || fail 'Credentials file is too large.' || return 1
    # Consume all output: grep -q can cause od to receive SIGPIPE, hiding a
    # detected NUL when the supervisor enables pipefail.
    if od -An -v -tx1 "$source" | grep -w 00 >/dev/null; then
        fail 'Credentials file must not contain NUL bytes.'
        return 1
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        [[ $line != *$'\r'* ]] || fail 'Credentials file must use LF line endings.' || return 1
        [[ -n $line && $line != \#* ]] || continue
        case $line in
            'IPSec gateway '*) key='IPSec gateway' ;;
            'IPSec ID '*) key='IPSec ID' ;;
            'Interface MTU '*) key='Interface MTU' ;;
            'Enable weak encryption '*) key='Enable weak encryption' ;;
            'VPN DNS '*) key='VPN DNS' ;;
            'IPSec secret '*) key='IPSec secret' ;;
            'Xauth username '*) key='Xauth username' ;;
            'Xauth password '*) key='Xauth password' ;;
            *) fail 'VPN configuration file contains an unsupported key.'; return 1 ;;
        esac
        value=${line#"$key "}
        [[ -n $value && $value != REPLACE_WITH_* ]] || fail 'Replace all credentials template values.' || return 1
        [[ ! -v 'values[$key]' ]] || fail 'Credentials file contains duplicate keys.' || return 1
        values[$key]=$value
    done < "$source"
    for key in 'IPSec gateway' 'IPSec ID' 'IPSec secret' 'Xauth username' 'Xauth password'; do
        [[ -v 'values[$key]' ]] || fail 'Credentials file is missing a required field.' || return 1
    done
    VPN_GATEWAY=${values['IPSec gateway']}
    VPN_IPSEC_ID=${values['IPSec ID']}
    VPN_MTU=${values['Interface MTU']-1412}
    VPN_ENABLE_WEAK_ENCRYPTION=${values['Enable weak encryption']-0}
    VPN_DNS=${values['VPN DNS']-}
    validate_settings || return 1
    # These remain shell variables, never exported or passed on a command line.
    IPSEC_SECRET=${values['IPSec secret']}
    XAUTH_USERNAME=${values['Xauth username']}
    XAUTH_PASSWORD=${values['Xauth password']}
    (umask 077; printf '%s %s\n' \
        'IPSec secret' "$IPSEC_SECRET" \
        'Xauth username' "$XAUTH_USERNAME" \
        'Xauth password' "$XAUTH_PASSWORD" > "$destination")
}

pid_alive() {
    local pid=$1 fields
    [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/stat ]] || return 1
    fields=$(cat "/proc/$pid/stat")
    fields=${fields##*) }
    [[ ${fields%% *} != Z && ${fields%% *} != X ]]
}

valid_proxy_target() {
    (( $# == 2 )) && [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
        && [[ $2 =~ ^[0-9]{1,5}$ ]] && (( 10#$2 >= 1 && 10#$2 <= 65535 ))
}

tunnel_connected() {
    local pid
    [[ -f $RUN_DIR/tunnel-ready && -r $RUN_DIR/vpnc.pid ]] || return 1
    read -r pid < "$RUN_DIR/vpnc.pid"
    pid_alive "$pid" || return 1
    ip -o link show tun0 2>/dev/null | grep -qE '<([^>]*,)?UP(,|>)' || return 1
    ip -4 route show table "$VPN_TABLE" | grep -q '^default dev tun0 ' || return 1
    ip -4 rule show | grep -q 'uidrange 10001-10001 lookup 100' || return 1
}

connected() {
    local name pid
    [[ -f $RUN_DIR/ready ]] && tunnel_connected || return 1
    for name in socks http; do
        [[ -r $RUN_DIR/$name.pid ]] || return 1
        read -r pid < "$RUN_DIR/$name.pid"
        pid_alive "$pid" || return 1
    done
}
