FROM localhost/vpncsocks:latest

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 openssh-server openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /test \
    && usermod -p '' root \
    && ssh-keygen -q -t ed25519 -N '' -f /test/ssh_host_ed25519_key \
    && ssh-keygen -q -t ed25519 -N '' -f /test/client \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
        -keyout /test/tls.key -out /test/tls.crt -subj /CN=internal.test

COPY fixture.py /test/fixture.py
RUN chmod 755 /test/fixture.py \
    && ln -s /test/fixture.py /usr/local/bin/vpnc \
    && ln -sf /test/fixture.py /usr/sbin/vpnc
