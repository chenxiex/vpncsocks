FROM docker.io/library/debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates iproute2 microsocks ncat nftables tini \
        tinyproxy-bin util-linux vpnc vpnc-scripts \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 vpnproxy \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin vpnproxy

COPY container/ /usr/local/lib/vpncsocks/
RUN chmod 755 /usr/local/lib/vpncsocks/*.sh \
    && ln -s /usr/local/lib/vpncsocks/proxy-stdio.sh /usr/local/bin/proxy-stdio \
    && ln -s /usr/local/lib/vpncsocks/healthcheck.sh /usr/local/bin/vpncsocks-healthcheck

ENV LC_ALL=C

EXPOSE 1080/tcp 8888/tcp
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/lib/vpncsocks/entrypoint.sh"]
