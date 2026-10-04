# vpnc VPN 代理容器

在容器内部运行 vpnc，将 VPN 中的 IPv4 TCP 服务提供给本机的 SOCKS5、HTTP 和 SSH stdio 客户端。镜像使用 `debian:trixie-slim`，安装 vpnc、vpnc-scripts、MicroSocks、Tinyproxy、Ncat、iproute2、nftables、tini、util-linux 和 Bash。

VPN 连接建立后才启动代理。代理的目标连接和 DNS 查询只能通过 VPN 隧道发送；未连接或断线时禁止通过容器的原网络直连。第一版使用固定账号密码，不支持交互式验证码、IPv6 或 UDP 代理。

## 构建与启动

以下命令面向 Linux 上的 **rootless Podman**。需要安装 Podman 和 pasta，配置当前用户的 subuid/subgid，并确保 `/dev/net/tun` 存在且当前用户可以访问。容器需要在自己的用户和网络命名空间内使用 `NET_ADMIN`，以创建隧道、策略路由和 nftables 规则；不需要 `--privileged`。运行参数的完整说明见 [Podman run 文档](https://docs.podman.io/en/latest/markdown/podman-run.1.html)。

在项目目录中准备凭据：

```sh
umask 077
cp config/vpnc.conf.example vpnc.conf
chmod 600 vpnc.conf
```

编辑 `vpnc.conf`，替换所有必填字段的占位符，填写自己的网关、组名、共享密钥、账号密码及连接选项：

```text
IPSec gateway REPLACE_WITH_VPN_GATEWAY
IPSec ID REPLACE_WITH_IPSEC_GROUP_ID
IPSec secret REPLACE_WITH_IPSEC_SECRET
Xauth username REPLACE_WITH_VPN_USERNAME
Xauth password REPLACE_WITH_VPN_PASSWORD
# Interface MTU 1412
# Enable weak encryption 0
```

全部 VPN 连接参数均从此文件读取。网关、组名、共享密钥、用户名和密码五项必填且没有默认值；MTU 默认 `1412`，弱加密默认禁用。需要改值时，取消对应注释并填写新值。可选的 `VPN DNS` 字段见下方配置说明。值写在配置项后的同一行，按字面值读取，不要给值添加 shell 引号或行尾注释。每项只能出现一次，允许空行和以 `#` 开头的整行注释，不接受其他字段。文件必须使用 LF 换行，大小不超过 64 KiB，不能包含 CR 或 NUL 字符，也不能保留模板占位符。文件包含明文凭据，保持 `600` 权限。镜像的构建上下文排除本机配置和 PDF，配置在运行时只读挂载到 `/run/secrets/vpnc.conf`，不写入镜像。

构建镜像并启动常驻代理：

```sh
./vpncsocks.sh build
./vpncsocks.sh start
./vpncsocks.sh logs -f
```

`vpncsocks.sh` 是 Podman 命令的简单封装，直接保留 Podman 的输出和退出码，不额外记录日志或重试。`start` 创建新的后台容器；容器名称已存在时会报错。已停止的容器使用 `./vpncsocks.sh restart` 或 `podman start vpncsocks`。

### 脚本命令与参数

| 命令 | 用途 |
| --- | --- |
| `build [Podman build 参数]` | 从脚本所在目录构建镜像。 |
| `start [Podman run 参数]` | 创建常驻容器，发布 SOCKS5/HTTP 端口并配置健康检查。 |
| `stdio HOST PORT` | 按需创建附着 stdin/stdout 的临时容器，不发布端口，结束后自动删除。 |
| `exec-stdio HOST PORT` | 使用已有常驻容器的 stdio 转发。 |
| `stop`、`restart`、`rm`、`logs [对应 Podman 参数]` | 操作指定的常驻容器，例如 `logs --tail 100`、`stop --time 5`。 |
| `status [Podman ps 参数]` | 显示匹配容器名称的容器，包括已停止的容器。 |
| `help`、`-h`、`--help` | 显示用法；不传命令时也显示用法。 |

通过环境变量配置脚本：

| 参数 | 默认值 | 用途 |
| --- | --- | --- |
| `VPNCS_IMAGE` | `localhost/vpncsocks` | 构建和运行的镜像名称。 |
| `VPNCS_NAME` | `vpncsocks` | 常驻容器名称；按需 stdio 不使用固定名称。 |
| `VPNCS_CONFIG` | 脚本所在目录的 `vpnc.conf` | 宿主凭据路径；显式指定相对路径时，按当前工作目录解析。 |
| `VPNCS_SOCKS_PORT` | `1080` | 常驻代理发布到宿主 `127.0.0.1` 的 SOCKS5 端口。 |
| `VPNCS_HTTP_PORT` | `8888` | 常驻代理发布到宿主 `127.0.0.1` 的 HTTP 端口。 |

例如，更改宿主 SOCKS5 端口：

```sh
VPNCS_SOCKS_PORT=11080 ./vpncsocks.sh start
```

脚本运行容器时使用 `--pull=never`，需要先构建镜像。修改镜像、脚本参数、端口或挂载路径后，执行 `rm` 再 `start`；`restart` 使用原来的容器参数。原地更新配置文件后可以 `restart` 重新读取。

### 原生 Podman 参数

脚本固定设置以下运行参数；也可以直接使用原生命令。

<details>
<summary>展开原生构建与启动命令</summary>

```sh
podman build --http-proxy=false -t localhost/vpncsocks .
```

```sh
podman run -d --name vpncsocks \
    --pull=never \
    --userns=host --user 0 \
    --device=/dev/net/tun:/dev/net/tun:rw \
    --cap-add=NET_ADMIN \
    --sysctl=net.ipv4.conf.all.rp_filter=2 \
    --network=pasta:-I,eth0,--ipv4-only,--mtu,1500 \
    --http-proxy=false \
    --health-cmd=vpncsocks-healthcheck \
    --health-interval=15s --health-timeout=5s \
    --health-start-period=60s --health-retries=3 \
    -p 127.0.0.1:1080:1080/tcp \
    -p 127.0.0.1:8888:8888/tcp \
    -v "$PWD/vpnc.conf:/run/secrets/vpnc.conf:ro" \
    localhost/vpncsocks
```

</details>

`--user 0` 指容器用户；以普通宿主用户运行 rootless Podman。`--userns=host` 使用 Podman 的 rootless 用户映射，使代理固定 UID 的策略路由和防火墙规则一致。独立的 pasta 网络为 vpnc 提供网关连接，固定接口名为 `eth0`，仅启用 IPv4。`--http-proxy=false` 避免自动继承宿主的代理环境变量，构建和运行时都需要设置。Podman 默认构建 OCI 格式镜像，因此通过运行参数配置健康检查：每 15 秒检查一次，单次超时 5 秒，启动宽限期 60 秒，连续失败 3 次标记为不健康。

`--sysctl=net.ipv4.conf.all.rp_filter=2` 只在容器网络命名空间内启用宽松反向路径检查。VPN 回包从 `tun0` 到达，而原网络仍保留自己的默认路由；严格检查会错误丢弃这些回包。此参数不会修改宿主网络配置。

在启用 SELinux 的宿主上，凭据挂载可能需要 `:ro,Z`，TUN 设备也需要允许容器访问的 SELinux 策略。如果 TUN 权限依赖宿主附加组，可以在支持此选项的 OCI runtime 上增加 `--group-add=keep-groups`。遇到拒绝访问时，先确认设备权限和宿主策略。

## VPN 配置文件

脚本和原生 Podman 命令都只读挂载 `/run/secrets/vpnc.conf`。VPN 参数通过文件字段设置：

| 字段 | 必填 | 含义 |
| --- | --- | --- |
| `IPSec gateway` | 是 | VPN 网关域名或 IPv4 地址。 |
| `IPSec ID` | 是 | IPSec 组名。 |
| `IPSec secret` | 是 | IPSec 共享密钥。 |
| `Xauth username` | 是 | VPN 用户名。 |
| `Xauth password` | 是 | VPN 密码。 |
| `Interface MTU` | 否 | VPN 隧道的 MTU，默认 `1412`，允许 `576`–`1500`；容器原网络的 MTU 由 pasta 参数设置为 `1500`。 |
| `Enable weak encryption` | 否 | 默认 `0`；严格接受 `0` 或 `1`；配置为 `1` 时向 vpnc 传入 `--enable-weak-encryption`，允许 DES/3DES；配置为 `0` 时禁用。 |
| `VPN DNS` | 否 | 如配置此项，必须填写非空的逗号分隔 IPv4 DNS 地址；省略此项使用 VPN 下发的 DNS。拒绝回环、链路本地和组播地址，避免 DNS 进入宿主转发路径。 |

固定凭据路径为 `/run/secrets/vpnc.conf`。容器固定监听 TCP `1080` 和 `8888`；脚本通过 `VPNCS_SOCKS_PORT` 和 `VPNCS_HTTP_PORT` 修改宿主端口，原生命令修改 `-p` 左侧端口。

SOCKS5 和 HTTP 入口没有代理认证。默认仅发布到宿主 `127.0.0.1`，本机其他用户也可能使用这些端口。SSH stdio 入口通过当前用户的 Podman 访问容器，不需要发布端口。

### 加密兼容选项

省略 `Enable weak encryption` 时默认禁用，脚本不会替用户启用。日志中的 `Peer has selected 3des` 和 `considered too weak` 表示网关要求新版 vpnc 默认禁用的旧算法；确有需要时，取消模板中的对应注释并配置 `Enable weak encryption 1`，然后重启常驻容器或重新连接按需 SSH。

此选项允许 DES/3DES，不会开启弱认证算法或无加密模式；不需要旧算法时省略该项或填写 `0`。

## 使用代理

将下列示例中的目标替换为实际可访问的内网服务。

### SOCKS5

使用 `socks5h`，让容器通过 VPN DNS 解析目标域名：

```sh
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 \
    --connect-timeout 10 http://internal.example/
```

使用普通 `socks5` 时，客户端可能在宿主解析域名。代理支持 TCP CONNECT，不支持 SOCKS5 UDP ASSOCIATE。

### HTTP 与 HTTPS

```sh
curl --noproxy '' --proxy http://127.0.0.1:8888 \
    --connect-timeout 10 http://internal.example/

curl --noproxy '' --proxy http://127.0.0.1:8888 \
    --connect-timeout 10 https://internal.example/
```

Tinyproxy 接收普通 HTTP 请求和 HTTP CONNECT。CONNECT 允许任意目标端口，可用于 SSH 的 `22` 或自定义端口；目标最终是否可达取决于 VPN 服务端。

### SSH stdio

#### SSH 按需启动容器

无需提前启动 `vpncsocks`。镜像接受 `stdio HOST PORT`：先建立 VPN，再以 UID `10001` 运行 Ncat，将 stdin/stdout 连接到目标。此模式不启动 SOCKS5/HTTP 服务，也不需要发布端口。所有启动信息和错误写入 stderr，stdout 只传输远端数据。

先执行 `./vpncsocks.sh build`，在宿主 `~/.ssh/config` 中添加以下配置，并替换主机名、SSH 用户名和脚本绝对路径。脚本默认读取自身目录旁的 `vpnc.conf`，不依赖 SSH 的工作目录，无需在 SSH 配置中重复凭据路径：

```sshconfig
Host supercomputer
    HostName <内网主机名或IP>
    User <SSH用户名>
    ProxyCommand /absolute/path/vpncsocks.sh stdio %h %p
```

然后执行 `ssh supercomputer`。临时容器读取同一份配置文件。按需模式内部使用 `podman run --rm -i`，不设置 `-d`、`-t`、固定容器名称或端口发布。每次 SSH 连接建立自己的 VPN，可与常驻容器并存；账号是否允许同时建立多个 VPN 会话由网关决定。

VPN 建立时间计入 SSH 的 `ConnectTimeout`，如设置该选项，应为 VPN 握手留出时间。VPN 建立前的网络故障会退避重试，认证或配置错误立即退出。开始转发后若 VPN 断线，命令关闭会话并退出，需要重新连接 SSH；临时容器不会重连已有字节流。stdin EOF 会先关闭目标的发送方向，继续接收远端数据，直到 Ncat 结束才清理 VPN 和容器。

#### 复用已启动的容器

如果需要多条 SSH 连接共用常驻 VPN，先执行 `./vpncsocks.sh start` 并确认 VPN 就绪，再添加：

```sshconfig
Host supercomputer
    HostName <内网主机名或IP>
    User <SSH用户名>
    ProxyCommand /absolute/path/vpncsocks.sh exec-stdio %h %p
```

两种方式都可以通过 `Port` 设置非默认 SSH 端口，`%p` 会自动使用对应端口。`exec-stdio` 封装 `podman exec -i --user vpnproxy vpncsocks proxy-stdio HOST PORT`；使用 `VPNCS_NAME` 时选择对应容器。容器内的 `proxy-stdio` 只能以 `vpnproxy` 用户运行。复用模式下，容器未就绪时命令失败并在 stderr 报告原因。

`-i` 保持 stdin 打开，**不要添加 `-t`**，TTY 会影响 SSH 字节流。Ncat 的连接超时为 10 秒，没有空闲超时；stdout 只传输远端数据，错误写入 stderr，并允许 stdin EOF 后继续接收远端响应。SOCKS5 和 HTTP 入口不保证与 stdio 相同的半关闭行为。参见 [Podman exec 文档](https://docs.podman.io/en/latest/markdown/podman-exec.1.html)。

## 状态与维护

```sh
./vpncsocks.sh logs --tail 100
./vpncsocks.sh logs -f
./vpncsocks.sh status
podman inspect --format '{{.State.Health.Status}}' "${VPNCS_NAME:-vpncsocks}"
```

健康检查确认本地 VPN 配置状态、隧道和代理进程已就绪，不能证明 VPN 服务端或某个内部目标实际可达。vpnc 使用 DPD 检测失联；断线处理并非瞬时，但防火墙始终阻断代理绕行原网络。

常驻模式遇到网络故障会停止代理并退避重连，最长重试间隔为 60 秒。明确的配置或认证错误会结束运行，修正后再启动容器。VPN 重连不会恢复原有 SSH 会话，需要重新连接。按需 stdio 模式开始转发后的退出行为见上面的 SSH 说明。

```sh
./vpncsocks.sh stop
./vpncsocks.sh restart
```

更新 VPN 配置或凭据时先停止容器，原地编辑宿主 `vpnc.conf`，然后执行 `restart`；入口程序会重新读取全部配置。如果编辑器通过原子替换生成新文件，或者要改变镜像、宿主端口或挂载路径，应删除容器后重新创建：

```sh
./vpncsocks.sh stop
./vpncsocks.sh rm
./vpncsocks.sh start
```

更换镜像版本也通过重新创建容器完成。

## VPN 路由与 DNS

vpnc 使用前台非交互模式、强制 NAT-T 和随机本地 IKE 端口，经原网络连接 VPN 网关；配置语法见 [vpnc 配置手册](https://manpages.debian.org/trixie/vpnc/vpnc.8.en.html)。

MicroSocks、Tinyproxy 和 stdio 转发统一使用 `vpnproxy` 用户，UID 为 `10001`。策略路由将该用户的目标连接送入专用 VPN 路由表，并保留不可达默认路由；隧道建立后添加 `tun0` 默认路由。客户端会话的回包使用原网络，nftables 仅允许目标连接从隧道发出，禁止 IPv6 外发。VPN 下发的分流路由不会使代理目标绕行原网络。

配置文件中的 `VPN DNS` 优先于 VPN 下发的 DNS。通过 SOCKS5h、HTTP 或 stdio 提交给容器的目标域名在容器内解析，查询通过隧道发送。两者都没有 DNS 时，IP 目标仍可使用，容器中的域名解析失败；容器不会退回宿主 DNS 解析代理目标。普通 SOCKS5 客户端可能先在宿主解析，再提交 IP 地址。启动 vpnc 所需的 VPN 网关域名解析使用原网络。

## 验证

宿主单元测试：

```sh
python3 -m unittest discover -s tests -v
```

在满足上述 rootless Podman 前提的宿主运行集成测试：

```sh
python3 tests/integration.py
```

集成测试使用 Podman 的正常存储，构建派生测试镜像，在其中添加 Python、SSH 服务端和模拟 vpnc，连接隔离的模拟 VPN 对端。它不需要真实 VPN 凭据，也不改变生产镜像。环境前提、测试范围和清理行为见 [测试说明](tests/README.md)。

当前宿主已验证 rootless TUN、nftables 和代理 UID 匹配能力。真实 VPN 验收需要有效凭据和实际内部服务，至少检查：

- SOCKS5h、HTTP 和 HTTPS CONNECT 能访问已知的内网服务，域名使用 VPN DNS。
- SSH stdio 能访问 `22` 和自定义端口，传输二进制数据，stdin EOF 后仍能接收远端响应。
- VPN 未连接、掉线和重连期间，目标连接及 DNS 查询不会通过原网络绕行。
- 宿主两个代理端口仅绑定 `127.0.0.1`，停止容器时子进程退出，镜像和日志不包含凭据。

未填写有效凭据前，不能确认真实网关的 NAT-T、认证、DNS 和内部 SSH 连通性。通过 VPN 访问公网的能力也由 VPN 服务端决定。
