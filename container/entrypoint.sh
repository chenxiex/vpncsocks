#!/bin/bash
set -euo pipefail
umask 077
source /usr/local/lib/vpncsocks/network.sh

VPN_PID=
SOCKS_PID=
HTTP_PID=
SLEEP_PID=
STDIO_PID=

write_pid() {
    printf '%s\n' "$2" > "$RUN_DIR/$1.pid"
    chmod 644 "$RUN_DIR/$1.pid"
}

stop_process() {
    local pid=${1:-} tries=0
    [[ -n $pid ]] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    while pid_alive "$pid" && (( tries < 30 )); do
        sleep 0.1
        tries=$((tries + 1))
    done
    if pid_alive "$pid"; then kill -KILL "$pid" 2>/dev/null || true; fi
    wait "$pid" 2>/dev/null || true
}

stop_proxies() {
    rm -f "$RUN_DIR/ready"
    stop_process "$SOCKS_PID"
    stop_process "$HTTP_PID"
    SOCKS_PID=
    HTTP_PID=
    # Also terminate stdio sessions from podman exec: old TCP sessions cannot
    # reliably resume with the next VPN-assigned address.
    local stat_file pid uid
    for stat_file in /proc/[0-9]*/status; do
        [[ -r $stat_file ]] || continue
        uid=$(awk '$1 == "Uid:" { print $2; exit }' "$stat_file" 2>/dev/null) || continue
        if [[ $uid == "$PROXY_UID" ]]; then
            pid=${stat_file#/proc/}; pid=${pid%/status}
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    rm -f "$RUN_DIR/socks.pid" "$RUN_DIR/http.pid"
}

cleanup() {
    local status=$?
    trap - EXIT TERM INT
    [[ -z $SLEEP_PID ]] || kill "$SLEEP_PID" 2>/dev/null || true
    if [[ -d $RUN_DIR/private ]]; then
        block_tunnel
        stop_process "$STDIO_PID"
        stop_proxies
        stop_process "$VPN_PID"
        rm -f "$RUN_DIR/private/credentials.conf" "$RUN_DIR/private/vpnc.log" "$RUN_DIR/vpnc.pid"
    fi
    exit "$status"
}

redacted_vpn_log() {
    local line
    [[ -f $RUN_DIR/private/vpnc.log ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line//"$IPSEC_SECRET"/[redacted]}
        line=${line//"$XAUTH_USERNAME"/[redacted]}
        line=${line//"$XAUTH_PASSWORD"/[redacted]}
        line=${line//"$VPN_GATEWAY"/[redacted]}
        if [[ -n ${VPN_GATEWAY_ADDRESS:-} ]]; then
            line=${line//"$VPN_GATEWAY_ADDRESS"/[redacted]}
        fi
        line=${line//"$VPN_IPSEC_ID"/[redacted]}
        printf 'vpnc: %s\n' "$line" >&2
    done < <(tail -n 20 "$RUN_DIR/private/vpnc.log")
}

terminal_vpn_error() {
    local status=$1
    [[ $status == 2 || -f $RUN_DIR/private/fatal ]] && return 0
    grep -Eiq 'authentication unsuccessful|authentication.failed|hash comparison failed|considered too weak|no supported (hash|encryption)|server requested .*but none set|unknown (option|configuration)|can.t initialise tunnel|failed to execute.*script' \
        "$RUN_DIR/private/vpnc.log"
}

retry_pause() {
    sleep "$1" &
    SLEEP_PID=$!
    wait "$SLEEP_PID"
    SLEEP_PID=
}

start_proxies() {
    setpriv --reuid "$PROXY_UID" --regid "$PROXY_GID" --clear-groups --no-new-privs \
        microsocks -i 0.0.0.0 -p 1080 &
    SOCKS_PID=$!
    write_pid socks "$SOCKS_PID"
    setpriv --reuid "$PROXY_UID" --regid "$PROXY_GID" --clear-groups --no-new-privs \
        tinyproxy -d -c /usr/local/lib/vpncsocks/tinyproxy.conf 1>&2 &
    HTTP_PID=$!
    write_pid http "$HTTP_PID"
    local tries
    for (( tries=0; tries<50; tries++ )); do
        pid_alive "$SOCKS_PID" && pid_alive "$HTTP_PID" || return 1
        if [[ $(ss -H -lnt '( sport = :1080 or sport = :8888 )' | wc -l) == 2 ]]; then
            printf 'connected\n' > "$RUN_DIR/ready"
            chmod 644 "$RUN_DIR/ready"
            return 0
        fi
        sleep 0.1
    done
    return 1
}

RUN_MODE=daemon
if (( $# == 3 )) && [[ $1 == stdio ]] && valid_proxy_target "$2" "$3"; then
    RUN_MODE=stdio
    STDIO_HOST=$2
    STDIO_PORT=$3
    # Bash redirects asynchronous commands' stdin to /dev/null. Preserve the
    # attached input while VPN startup runs, then explicitly pass it to Ncat.
    exec 3<&0
elif (( $# != 0 )); then
    log 'Usage: image [stdio HOST PORT] (IPv4 TCP, port 1-65535).'
    exit 64
fi
(( EUID == 0 )) || { log 'Start rootless Podman with --userns=host --user 0.'; exit 78; }
mkdir -p "$RUN_DIR/private" "$RUN_DIR/proxy"
chmod 755 "$RUN_DIR"
chmod 700 "$RUN_DIR/private"
chown "$PROXY_UID:$PROXY_GID" "$RUN_DIR/proxy"
load_credentials /run/secrets/vpnc.conf "$RUN_DIR/private/credentials.conf" || exit 78
trap cleanup EXIT
trap 'exit 0' TERM INT
initialize_network || { log 'Network setup failed; check TUN, NET_ADMIN, and pasta prerequisites.'; exit 78; }
block_tunnel

delay=1
while true; do
    # Refresh an in-place updated bind mount before each attempt.
    load_credentials /run/secrets/vpnc.conf "$RUN_DIR/private/credentials.conf" || exit 78
    vpnc_options=()
    if [[ $VPN_ENABLE_WEAK_ENCRYPTION == 1 ]]; then
        vpnc_options+=(--enable-weak-encryption)
        log 'Legacy DES/3DES encryption is enabled for this VPN connection.'
    fi
    rm -f "$RUN_DIR/private/fatal"
    : > "$RUN_DIR/private/vpnc.log"
    if ! resolve_gateway; then
        block_tunnel
        log "Gateway resolution failed; retrying in ${delay}s."
        retry_pause "$delay"
        delay=$(( delay < 32 ? delay * 2 : 60 ))
        continue
    fi
    log 'Connecting using IPSec NAT-T.'
    vpnc "${vpnc_options[@]}" --gateway "$VPN_GATEWAY_ADDRESS" --id "$VPN_IPSEC_ID" \
        --no-detach --non-inter --debug 0 --ifname tun0 --ifmode tun \
        --ifmtu "$VPN_MTU" --natt-mode force-natt --local-port 0 --dpd-idle 30 \
        --script /usr/local/lib/vpncsocks/vpnc-hook.sh \
        --pid-file "$RUN_DIR/private/vpnc-daemon.pid" \
        "$RUN_DIR/private/credentials.conf" > "$RUN_DIR/private/vpnc.log" 2>&1 &
    VPN_PID=$!
    write_pid vpnc "$VPN_PID"
    attempt_started=$SECONDS
    while pid_alive "$VPN_PID" && [[ ! -f $RUN_DIR/tunnel-ready && ! -f $RUN_DIR/private/fatal ]]; do
        if (( SECONDS - attempt_started >= 90 )); then
            log 'VPN negotiation timed out.'
            kill -TERM "$VPN_PID" 2>/dev/null || true
            break
        fi
        sleep 0.2
    done
    was_connected=0
    if [[ -f $RUN_DIR/tunnel-ready ]] && pid_alive "$VPN_PID"; then
        if [[ $RUN_MODE == stdio ]]; then
            log 'VPN connected; starting stdio forwarding.'
            setpriv --reuid "$PROXY_UID" --regid "$PROXY_GID" --clear-groups --no-new-privs \
                proxy-stdio "$STDIO_HOST" "$STDIO_PORT" <&3 3<&- &
            STDIO_PID=$!
            exec 3<&-
            while tunnel_connected && pid_alive "$STDIO_PID"; do sleep 0.1; done
            if ! tunnel_connected; then
                block_tunnel
                log 'VPN disconnected; closing the stdio session. Reconnect SSH to start a new VPN.'
                exit 69
            fi
            status=0
            wait "$STDIO_PID" || status=$?
            STDIO_PID=
            exit "$status"
        fi
        if ! start_proxies; then
            log 'Proxy startup failed.'
            exit 70
        fi
        log 'VPN connected; SOCKS5 :1080 and HTTP :8888 are ready.'
        if [[ $(cat "$RUN_DIR/dns-mode") == disabled ]]; then
            log 'VPN supplied no DNS: IP targets work; configure VPN DNS in vpnc.conf for hostname resolution.'
        fi
        was_connected=1
        delay=1
        while connected && [[ ! -f $RUN_DIR/private/fatal ]]; do sleep 0.5; done
    fi
    block_tunnel
    stop_proxies
    # End a still-running daemon after an interface/hook/proxy failure.
    kill -TERM "$VPN_PID" 2>/dev/null || true
    for (( tries=0; tries<30; tries++ )); do
        pid_alive "$VPN_PID" || break
        sleep 0.1
    done
    pid_alive "$VPN_PID" && kill -KILL "$VPN_PID" 2>/dev/null || true
    status=0
    wait "$VPN_PID" || status=$?
    VPN_PID=
    rm -f "$RUN_DIR/vpnc.pid"
    redacted_vpn_log
    if terminal_vpn_error "$status"; then
        [[ ! -f $RUN_DIR/private/fatal ]] || cat "$RUN_DIR/private/fatal" >&2
        log 'VPN authentication or configuration failed; fix credentials/settings, then restart the container.'
        exit 78
    fi
    if (( was_connected )); then log 'VPN disconnected; existing sessions have been closed.'; fi
    log "VPN unavailable (exit $status); retrying in ${delay}s."
    retry_pause "$delay"
    delay=$(( delay < 32 ? delay * 2 : 60 ))
done
