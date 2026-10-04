#!/bin/bash

source /usr/local/lib/vpncsocks/common.sh

initialize_network() {
    [[ -c /dev/net/tun && -r /dev/net/tun && -w /dev/net/tun ]] \
        || fail 'A readable/writable /dev/net/tun device is required.' || return 1
    ip -4 route show default dev eth0 | grep -q '^default' \
        || fail 'Use an isolated IPv4 pasta network with interface eth0.' || return 1
    [[ $(cat /proc/sys/net/ipv4/conf/all/rp_filter) == 2 ]] \
        || fail 'Set --sysctl=net.ipv4.conf.all.rp_filter=2 for asymmetric VPN routing.' || return 1
    # /etc/resolv.conf is a Podman bind mount and can retain our VPN resolver
    # across stop/start. Preserve the original bootstrap DNS for this container.
    if [[ ! -s $RUN_DIR/private/bootstrap-resolv.conf ]]; then
        cp /etc/resolv.conf "$RUN_DIR/private/bootstrap-resolv.conf" || return 1
    fi
    local address
    local -a resolvers=()
    while read -r address; do
        valid_ipv4 "$address" && resolvers+=("$address")
    done < <(awk '$1 == "nameserver" { print $2 }' "$RUN_DIR/private/bootstrap-resolv.conf")
    local resolver_set
    resolver_set=$(IFS=,; printf '%s' "${resolvers[*]}")

    # Install the firewall before creating policy routes or any proxy process.
    nft -f - <<EOF || return 1
table inet vpncsocks {
    set gateways { type ipv4_addr; }
    set bootstrap_dns { type ipv4_addr; elements = { $resolver_set }; }
    chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid drop
        meta nfproto ipv6 drop
        ct state established,related accept
        iifname { "lo", "eth0" } tcp dport { 1080, 8888 } accept
    }
    chain output {
        type filter hook output priority filter; policy drop;
        meta nfproto ipv6 drop
        meta skuid $PROXY_UID ct direction reply ct state established tcp sport { 1080, 8888 } accept
        meta skuid $PROXY_UID oifname "tun0" accept
        meta skuid $PROXY_UID counter reject
        meta skuid 0 oifname "lo" accept
        meta skuid 0 ip daddr @bootstrap_dns udp dport 53 accept
        meta skuid 0 ip daddr @bootstrap_dns tcp dport 53 accept
        meta skuid 0 oifname "eth0" ip daddr @gateways udp dport { 500, 4500 } accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
EOF
    # Keep local client replies routable even when the VPN table is unreachable.
    # Target connections normally have an unspecified source until the UID rule
    # selects tun0. Binding an underlay source cannot bypass the firewall.
    while read -r address; do
        ip -4 rule add priority 100 from "$address/32" lookup main || return 1
    done < <(ip -o -4 addr show dev eth0 | awk '{ split($4,a,"/"); print a[1] }')
    ip -4 route add unreachable default table "$VPN_TABLE" metric 32767 || return 1
    ip -4 rule add priority 110 uidrange "$PROXY_UID-$PROXY_UID" lookup "$VPN_TABLE" || return 1
}

resolve_gateway() {
    # Only the root VPN control process uses the saved bootstrap resolver.
    # The proxy UID is still blocked by its route table and firewall.
    cat "$RUN_DIR/private/bootstrap-resolv.conf" > /etc/resolv.conf
    local resolved
    resolved=$(timeout 15 getent ahostsv4 "$VPN_GATEWAY" | awk 'NR == 1 { print $1 }') || return 1
    valid_ipv4 "$resolved" || return 1
    [[ $resolved != 0.* && $resolved != 127.* ]] || return 1
    nft -f - <<EOF || return 1
flush set inet vpncsocks gateways
add element inet vpncsocks gateways { $resolved }
EOF
    VPN_GATEWAY_ADDRESS=$resolved
}

block_tunnel() {
    rm -f "$RUN_DIR/ready" "$RUN_DIR/tunnel-ready"
    ip -4 route del default dev tun0 table "$VPN_TABLE" metric 10 2>/dev/null || true
    # Never restore the bootstrap resolver for proxy applications. Gateway
    # resolution temporarily restores it in a firewall-protected retry phase.
    printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
}

configure_tunnel() {
    [[ ${TUNDEV:-} == tun0 ]] || fail 'VPN supplied an unexpected tunnel device.' || return 1
    valid_ipv4 "${INTERNAL_IP4_ADDRESS:-}" || fail 'VPN did not supply a valid IPv4 tunnel address.' || return 1
    local local_address
    while read -r local_address; do
        [[ $local_address != "$INTERNAL_IP4_ADDRESS" ]] \
            || fail 'VPN address conflicts with the underlay address.' || return 1
    done < <(ip -o -4 addr show dev eth0 | awk '{ split($4,a,"/"); print a[1] }')
    local -a dns=()
    local address
    if [[ -n ${VPN_DNS:-} ]]; then
        IFS=, read -r -a dns <<< "$VPN_DNS"
    else
        read -r -a dns <<< "${INTERNAL_IP4_DNS:-}"
    fi
    for address in "${dns[@]}"; do
        valid_dns "$address" || fail 'VPN supplied an invalid or host-forwarded DNS address; configure VPN DNS in vpnc.conf.' || return 1
        [[ $address != "$INTERNAL_IP4_ADDRESS" ]] \
            || fail 'VPN DNS conflicts with the tunnel address.' || return 1
        # A VPN DNS server matching a guest-local address would bypass routing.
        ip -4 route show table local | grep -qE "^local ${address//./\\.} " \
            && { fail 'VPN DNS conflicts with a container-local address.'; return 1; }
    done
    ip -4 addr replace "$INTERNAL_IP4_ADDRESS/32" dev tun0 || return 1
    ip link set dev tun0 mtu "$VPN_MTU" up || return 1
    if (( ${#dns[@]} )); then
        {
            for address in "${dns[@]}"; do printf 'nameserver %s\n' "$address"; done
            printf 'options timeout:2 attempts:2\n'
        } > /etc/resolv.conf
        printf 'vpn\n' > "$RUN_DIR/dns-mode"
    else
        printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
        printf 'disabled\n' > "$RUN_DIR/dns-mode"
    fi
    ip -4 route replace default dev tun0 table "$VPN_TABLE" metric 10 || return 1
    printf '%s\n' "$INTERNAL_IP4_ADDRESS" > "$RUN_DIR/tunnel-ready"
    chmod 644 "$RUN_DIR/tunnel-ready" "$RUN_DIR/dns-mode"
}
