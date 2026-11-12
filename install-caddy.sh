#!/usr/bin/env bash
# ============================================================
# Caddy（naive + trojan）一键安装 + Linux 服务器初始加固
#
# 适用：Debian/Ubuntu（apt）或 RHEL 系（dnf），linux/amd64
#
# 功能：
#   1. 从本仓库 Release 下载编译好的 caddy，安装为 systemd 服务并开机自启
#      仅在 Caddyfile 不存在时写入内置默认配置，已有配置不会被覆盖
#      并提供每日自动更新定时任务
#   2. 随机化 SSH 端口（兼容 ssh.socket 激活），允许 root 密码登录
#      fail2ban 防暴力破解，并追加 MaxAuthTries 等认证加固
#   3. 安装并启用 UFW：默认拒绝入站，仅放行 SSH / 80 / 443（TCP+UDP）
#   4. 启用 BBR + 常用内核网络加固参数
#   5. 配置系统自动更新（不自动重启）
#
# 用法：bash install-caddy.sh（无参数）
# ============================================================
set -Eeuo pipefail

# Caddy 二进制固定从本仓库 Release 获取，配置使用脚本内置默认值
CADDY_REPO="DoTheBetter/Caddyfile_forwardproxy"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_CONFIG="/etc/caddy/Caddyfile"
CADDY_SERVICE="/etc/systemd/system/caddy.service"
CADDY_HOME="/var/lib/caddy"
CADDY_LOG_DIR="/var/log/caddy"
CADDY_UPDATE_BIN="/usr/local/bin/caddy-update"
CADDY_RELEASE_MARKER="/var/lib/caddy/.installed-release"
CADDY_UPDATE_SERVICE="/etc/systemd/system/caddy-update.service"
CADDY_UPDATE_TIMER="/etc/systemd/system/caddy-update.timer"
SSHD_MAIN="/etc/ssh/sshd_config"
SSHD_DROPIN="/etc/ssh/sshd_config.d/00-caddy-hardening.conf"
SSH_SOCKET_OVERRIDE="/etc/systemd/system/ssh.socket.d/override.conf"
HARDEN_SYSCTL="/etc/sysctl.d/99-server-hardening.conf"
BBR_SYSCTL="/etc/sysctl.d/99-bbr.conf"

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_INFO=$'\033[36m'; C_OK=$'\033[32m'
    C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
else
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
fi

log()  { printf '%s[%s]%s %s\n' "$C_INFO" "$(date +%H:%M:%S)" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_OK" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; }
die()  { printf '%s[FAIL]%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2; exit 1; }

trap 'printf "[FAIL] 脚本在第 %s 行执行失败（退出码 %s）\n" "${LINENO}" "$?" >&2' ERR

# ---------------- 运行状态 ----------------
AUTO_UPDATE_STATE="未启用"
CADDY_UPDATE_STATE="未启用"
SSH_AUTH_STATE="PermitRootLogin=yes，允许密码登录"
INSTALLED_TAG=""

# ---------------- 系统检查 ----------------
PKG_MGR=""
ARCH=""
SSHD_BIN=""
SSH_SERVICE=""
CURRENT_SSH_PORT="22"

detect_ssh_units() {
    if command -v sshd >/dev/null 2>&1; then
        SSHD_BIN="$(command -v sshd)"
    elif [ -x /usr/sbin/sshd ]; then
        SSHD_BIN="/usr/sbin/sshd"
    fi

    if systemctl cat ssh.service >/dev/null 2>&1; then
        SSH_SERVICE="ssh"
    elif systemctl cat sshd.service >/dev/null 2>&1; then
        SSH_SERVICE="sshd"
    fi
}

preflight() {
    [ "$(id -u)" -eq 0 ] || die "请使用 root 运行（sudo bash $0）"
    command -v systemctl >/dev/null 2>&1 || die "未检测到 systemd，本脚本仅支持 systemd 系统"
    [ -f /etc/os-release ] || die "未检测到 /etc/os-release，无法识别系统"

    # shellcheck disable=SC1091
    . /etc/os-release
    case " ${ID:-} ${ID_LIKE:-} " in
        *" debian "*|*" ubuntu "*) PKG_MGR="apt" ;;
        *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*) PKG_MGR="dnf" ;;
        *) die "不支持的发行版: ${PRETTY_NAME:-unknown}（仅支持 Debian/Ubuntu 与 RHEL 系）" ;;
    esac

    ARCH="$(uname -m)"
    [ "$ARCH" = "x86_64" ] || die "当前架构为 ${ARCH}，本仓库仅构建 linux/amd64"

    detect_ssh_units
    ok "系统: ${PRETTY_NAME:-$ID}，包管理器: ${PKG_MGR}，架构: ${ARCH}"
}

install_packages() {
    [ $# -gt 0 ] || return 0
    if [ "$PKG_MGR" = "apt" ]; then
        # 等待自动更新释放 dpkg 锁，避免并发安装失败
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq "$@"
    else
        dnf install -y -q "$@"
    fi
}

install_base_packages() {
    log "安装基础依赖"
    if [ "$PKG_MGR" = "apt" ]; then
        apt-get -o DPkg::Lock::Timeout=120 update -qq
    fi
    install_packages ca-certificates curl tar iproute2 openssh-server || die "基础依赖安装失败"
    ok "基础依赖安装完成"
}

detect_current_ssh_port() {
    [ -n "$SSHD_BIN" ] || return 0
    local p
    p="$("$SSHD_BIN" -T 2>/dev/null | awk '/^port /{print $2; exit}' || true)"
    [ -n "$p" ] && CURRENT_SSH_PORT="$p"
    return 0
}

# ---------------- 内核参数 / BBR ----------------
configure_sysctl() {
    log "写入内核网络加固参数"

    cat > "$HARDEN_SYSCTL" <<'EOF'
# 由 install-caddy.sh 生成：基础网络加固
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
EOF

    local available
    available="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true)"
    if ! grep -qw bbr <<<"$available"; then
        modprobe tcp_bbr 2>/dev/null || true
        available="$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || true)"
    fi

    if grep -qw bbr <<<"$available"; then
        cat > "$BBR_SYSCTL" <<'EOF'
# 由 install-caddy.sh 生成：启用 BBR 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
        ok "内核支持 BBR，已写入配置"
    else
        rm -f "$BBR_SYSCTL"
        warn "当前内核不支持 BBR（需 ≥4.9），已跳过 BBR 配置"
    fi

    if ! sysctl --system >/dev/null 2>&1; then
        warn "部分 sysctl 参数应用失败（容器环境常见），请检查 $HARDEN_SYSCTL"
    fi

    if [ -f "$BBR_SYSCTL" ]; then
        local current
        current="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
        if [ "$current" = "bbr" ]; then
            ok "BBR 已生效"
        else
            warn "BBR 未生效（当前: ${current:-unknown}），内核模块可能被限制"
        fi
    fi
}

# ---------------- 系统自动更新 ----------------
configure_auto_updates() {
    log "配置系统自动更新（不自动重启）"

    if [ "$PKG_MGR" = "apt" ]; then
        if ! install_packages unattended-upgrades; then
            warn "unattended-upgrades 安装失败，已跳过自动更新配置"
            return 0
        fi

        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
# 由 install-caddy.sh 生成
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

        cat > /etc/apt/apt.conf.d/51-caddy-unattended-upgrades <<'EOF'
# 由 install-caddy.sh 生成：不自动重启，清理废弃依赖
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

        if systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1; then
            AUTO_UPDATE_STATE="已启用（unattended-upgrades 每日自动更新）"
            ok "已启用每日自动更新（不自动重启）"
        else
            warn "apt 定时器启用失败，请检查 systemctl status apt-daily-upgrade.timer"
        fi
    else
        if ! install_packages dnf-automatic; then
            warn "dnf-automatic 安装失败，已跳过自动更新配置"
            return 0
        fi

        if [ -f /etc/dnf/automatic.conf ]; then
            sed -ri 's/^[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = security/' /etc/dnf/automatic.conf
            sed -ri 's/^[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/' /etc/dnf/automatic.conf
            sed -ri 's/^[[:space:]]*reboot[[:space:]]*=.*/reboot = never/' /etc/dnf/automatic.conf
        fi

        if systemctl enable --now dnf-automatic.timer >/dev/null 2>&1; then
            AUTO_UPDATE_STATE="已启用（dnf-automatic，仅安全更新）"
            ok "已启用每日自动安全更新（不自动重启）"
        else
            warn "dnf-automatic.timer 启用失败，请检查 systemctl status dnf-automatic.timer"
        fi
    fi
}

# ---------------- UFW ----------------
configure_ufw() {
    local ssh_port="$1"

    if ! command -v ufw >/dev/null 2>&1; then
        log "安装 ufw"
        install_packages ufw || die "ufw 安装失败（RHEL 系可能需先启用 EPEL）"
    fi

    if systemctl is-active --quiet firewalld 2>/dev/null ||
       systemctl is-enabled --quiet firewalld 2>/dev/null; then
        warn "检测到 firewalld 已启用，将与 UFW 冲突，已停止并禁用 firewalld"
        systemctl disable --now firewalld >/dev/null 2>&1 || warn "firewalld 停止失败，请手动处理"
    fi

    log "配置 UFW 防火墙（默认拒绝入站）"
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "${ssh_port}/tcp" comment 'SSH' >/dev/null
    # 切换完成前同时保留当前 SSH 端口，避免新端口不可用后彻底无法登录
    if [ "$CURRENT_SSH_PORT" != "$ssh_port" ]; then
        ufw allow "${CURRENT_SSH_PORT}/tcp" comment 'SSH (old)' >/dev/null
    fi
    ufw allow 80/tcp comment 'HTTP' >/dev/null
    ufw allow 443/tcp comment 'HTTPS' >/dev/null
    ufw allow 443/udp comment 'HTTP/3 QUIC' >/dev/null

    ufw --force enable >/dev/null
    ok "UFW 已启用：允许 ${ssh_port}/tcp、80/tcp、443/tcp、443/udp"
}

# SSH 切换成功后再关闭旧端口，避免中途失败导致无法登录
cleanup_old_ssh_rules() {
    local new_port="$1"
    if [ "$new_port" != "$CURRENT_SSH_PORT" ]; then
        ufw delete allow "${CURRENT_SSH_PORT}/tcp" >/dev/null 2>&1 || true
        ufw delete allow OpenSSH >/dev/null 2>&1 || true
    fi
    if [ "$new_port" != "22" ]; then
        ufw delete allow 22/tcp >/dev/null 2>&1 || true
    fi
}

# ---------------- SSH ----------------
random_ssh_port() {
    local p i
    for i in $(seq 1 60); do
        p="$(shuf -i 20000-60000 -n 1)"
        if [ -z "$(ss -Htln "sport = :${p}" 2>/dev/null)" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    done
    return 1
}

resolve_ssh_port() {
    # 已由本脚本配置过则沿用，保证可重复执行
    if [ -s "$SSHD_DROPIN" ]; then
        local p
        p="$(sed -n 's/^[[:space:]]*Port[[:space:]]\+\([0-9]\+\).*/\1/p' "$SSHD_DROPIN" | head -n 1)"
        if [ -n "$p" ]; then
            printf '%s\n' "$p"
            return 0
        fi
    fi

    random_ssh_port || die "无法生成可用的随机 SSH 端口"
}

SSH_BACKUP_DIR=""

ssh_socket_enabled() {
    systemctl cat ssh.socket >/dev/null 2>&1 &&
        { systemctl is-enabled --quiet ssh.socket 2>/dev/null ||
          systemctl is-active --quiet ssh.socket 2>/dev/null; }
}

# 检查端口是否真的在监听（sshd 重启需要一点时间，最多等待数秒）
ssh_port_listening() {
    local port="$1" i
    for i in 1 2 3 4 5; do
        if ss -Htln 2>/dev/null | awk -v p=":${port}" '$4 ~ p "$" {found=1} END{exit found?0:1}'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

ssh_restore() {
    [ -n "$SSH_BACKUP_DIR" ] && [ -d "$SSH_BACKUP_DIR" ] || return 0
    log "还原 SSH 配置"
    [ -f "$SSH_BACKUP_DIR/sshd_config" ] && cp -a "$SSH_BACKUP_DIR/sshd_config" "$SSHD_MAIN"
    if [ -f "$SSH_BACKUP_DIR/dropin" ]; then
        cp -a "$SSH_BACKUP_DIR/dropin" "$SSHD_DROPIN"
    else
        rm -f "$SSHD_DROPIN"
    fi
    if [ -f "$SSH_BACKUP_DIR/socket_override" ]; then
        cp -a "$SSH_BACKUP_DIR/socket_override" "$SSH_SOCKET_OVERRIDE"
    else
        rm -f "$SSH_SOCKET_OVERRIDE"
    fi
    systemctl daemon-reload >/dev/null 2>&1 || true
    # 回滚时重新放行原 SSH 端口，避免被 UFW 拦在门外
    if command -v ufw >/dev/null 2>&1; then
        ufw allow "${CURRENT_SSH_PORT}/tcp" >/dev/null 2>&1 || true
    fi
    if ssh_socket_enabled; then
        systemctl restart ssh.socket >/dev/null 2>&1 || true
    elif [ -n "$SSH_SERVICE" ]; then
        systemctl restart "$SSH_SERVICE" >/dev/null 2>&1 || true
    fi
}

configure_ssh() {
    local port="$1"
    local use_socket=0
    local -a ssh_opts=(
        "Port ${port}"
        "MaxAuthTries 3"
        "LoginGraceTime 30"
        "MaxSessions 10"
        "PermitEmptyPasswords no"
        "UseDNS no"
        "X11Forwarding no"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
    )

    [ -n "$SSHD_BIN" ] || die "未找到 sshd，无法修改 SSH 配置"
    [ -f "$SSHD_MAIN" ] || die "未找到 $SSHD_MAIN"

    SSH_BACKUP_DIR="$(mktemp -d)"
    cp -a "$SSHD_MAIN" "$SSH_BACKUP_DIR/sshd_config"
    [ -f "$SSHD_DROPIN" ] && cp -a "$SSHD_DROPIN" "$SSH_BACKUP_DIR/dropin" || true
    [ -f "$SSH_SOCKET_OVERRIDE" ] && cp -a "$SSH_SOCKET_OVERRIDE" "$SSH_BACKUP_DIR/socket_override" || true

    log "修改 SSH 端口为 ${port}"
    # 注释主配置中的 Port，避免旧端口继续监听
    sed -ri 's/^[[:space:]]*Port[[:space:]]+/#Port /' "$SSHD_MAIN"

    # 允许 root 密码登录（部分云镜像默认关闭密码认证，需显式打开）
    ssh_opts+=("PermitRootLogin yes")
    ssh_opts+=("PasswordAuthentication yes")

    if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' "$SSHD_MAIN"; then
        install -d -m 0755 /etc/ssh/sshd_config.d
        {
            echo "# 由 install-caddy.sh 生成"
            printf '%s\n' "${ssh_opts[@]}"
        } > "$SSHD_DROPIN"
        chmod 0600 "$SSHD_DROPIN"
        # RHEL 系 SELinux 需要正确的文件上下文
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -F "$SSHD_DROPIN" >/dev/null 2>&1 || true
        fi
    else
        # 无 Include 时清掉本脚本上次追加的块，保证可重复执行
        sed -i '/^# >>> install-caddy.sh >>>$/,/^# <<< install-caddy.sh <<<$/d' "$SSHD_MAIN"
        {
            printf '\n# >>> install-caddy.sh >>>\n'
            printf '%s\n' "${ssh_opts[@]}"
            printf '# <<< install-caddy.sh <<<\n'
        } >> "$SSHD_MAIN"
    fi

    # Ubuntu 22.10+ 使用 ssh.socket 激活，sshd_config 中的 Port 不生效
    if ssh_socket_enabled; then
        use_socket=1
        install -d -m 0755 /etc/systemd/system/ssh.socket.d
        cat > "$SSH_SOCKET_OVERRIDE" <<EOF
[Socket]
ListenStream=
ListenStream=${port}
EOF
        if command -v restorecon >/dev/null 2>&1; then
            restorecon -F "$SSH_SOCKET_OVERRIDE" >/dev/null 2>&1 || true
        fi
        systemctl daemon-reload
    fi

    if ! "$SSHD_BIN" -t; then
        ssh_restore
        die "sshd 配置校验失败，已还原为原配置"
    fi

    warn "已允许 root 密码登录，请为 root 设置强密码并保留 fail2ban 防护"

    if [ "$use_socket" -eq 1 ]; then
        if ! systemctl restart ssh.socket; then
            ssh_restore
            die "ssh.socket 重启失败，已还原为原配置"
        fi
    elif [ -n "$SSH_SERVICE" ]; then
        if ! systemctl restart "$SSH_SERVICE"; then
            ssh_restore
            die "sshd 重启失败，已还原为原配置"
        fi
        # 确认配置真正生效的端口，避免被其他 sshd_config.d 文件覆盖
        local effective
        effective="$("$SSHD_BIN" -T 2>/dev/null | awk '/^port /{print $2}' | tr '\n' ' ' || true)"
        case " ${effective} " in
            *" ${port} "*) ;;
            *) warn "sshd 生效端口为 [${effective}]，未包含 ${port}，请检查 $SSHD_MAIN 与 /etc/ssh/sshd_config.d" ;;
        esac
    fi

    if ssh_port_listening "$port"; then
        ok "SSH 已在新端口 ${port} 监听"
    else
        log "未检测到 ${port} 端口监听，回滚 SSH 配置以保留现有登录方式"
        ssh_restore
        die "SSH 新端口 ${port} 未监听，已回滚为原配置；请检查 systemctl status ssh 与 $SSHD_MAIN"
    fi

    SSH_AUTH_STATE="PermitRootLogin=yes，密码登录已启用，MaxAuthTries=3 等已加固"
}

# ---------------- fail2ban ----------------
configure_fail2ban() {
    local port="$1"
    local banaction="ufw"

    log "安装并配置 fail2ban"
    if ! install_packages fail2ban; then
        warn "fail2ban 安装失败，已跳过"
        return 0
    fi
    # systemd 日志后端需要 python3-systemd，缺失时使用 auto 后端
    install_packages python3-systemd >/dev/null 2>&1 || warn "python3-systemd 安装失败"

    local backend="systemd" journalmatch=""
    if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import systemd.journal' >/dev/null 2>&1; then
        backend="auto"
        warn "未检测到 python3-systemd，fail2ban 改用 auto 后端（依赖 /var/log/auth.log）"
    else
        journalmatch="journalmatch = _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service"
    fi

    install -d -m 0755 /etc/fail2ban/jail.d

    local ignore_ip="127.0.0.1/8 ::1"
    local client_ip="${SSH_CONNECTION%% *}"
    if [ -n "$client_ip" ]; then
        ignore_ip="${ignore_ip} ${client_ip}"
    fi

    cat > /etc/fail2ban/jail.d/sshd.local <<EOF
# 由 install-caddy.sh 生成
[sshd]
enabled = true
port = ${port}
backend = ${backend}
${journalmatch}
banaction = ${banaction}
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = ${ignore_ip}
EOF

    if ! fail2ban-client -t >/dev/null 2>&1; then
        warn "fail2ban 配置校验失败，已移除新增配置"
        rm -f /etc/fail2ban/jail.d/sshd.local
        return 0
    fi

    systemctl enable fail2ban >/dev/null 2>&1 || true
    if systemctl restart fail2ban; then
        ok "fail2ban 已启用（sshd 防护，端口 ${port}，信任本机及当前客户端 IP）"
    else
        warn "fail2ban 启动失败，请执行 journalctl -u fail2ban 查看"
    fi
}

# ---------------- Caddy ----------------
github_latest_tag() {
    local repo="$1" json
    local headers=(-H 'Accept: application/vnd.github+json')
    if [ -n "${GH_TOKEN:-}" ]; then
        headers+=(-H "Authorization: Bearer ${GH_TOKEN}")
    fi

    json="$(curl -fsSL "${headers[@]}" "https://api.github.com/repos/${repo}/releases/latest" || true)"
    [ -n "$json" ] || die "无法获取 ${repo} 的最新 Release（可设置 GH_TOKEN 后重试）"

    local tag
    tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
    [ -n "$tag" ] || die "解析 Release 标签失败，请检查仓库 Release 是否正常"
    printf '%s\n' "$tag"
}

download_caddy() {
    local tag="$1" tmp asset url bin
    tmp="$(mktemp -d)"
    asset="${tag}-linux-amd64.tar"
    url="https://github.com/${CADDY_REPO}/releases/download/${tag}/${asset}"

    log "下载 ${url}"
    if ! curl -fL --retry 3 --connect-timeout 15 -o "$tmp/pkg.tar" "$url"; then
        rm -rf "$tmp"
        die "下载失败：请确认 Release ${tag} 存在 ${asset} 产物"
    fi

    tar -xf "$tmp/pkg.tar" -C "$tmp" || { rm -rf "$tmp"; die "解压失败"; }
    bin="$(find "$tmp" -type f -name caddy | head -n 1 || true)"
    [ -n "$bin" ] || { rm -rf "$tmp"; die "压缩包内未找到 caddy 二进制"; }
    # 先写临时文件再 rename，避免覆盖正在运行的二进制时出现 Text file busy
    install -m 0755 "$bin" "${CADDY_BIN}.new"
    "${CADDY_BIN}.new" version >/dev/null 2>&1 || {
        rm -f "${CADDY_BIN}.new"
        rm -rf "$tmp"
        die "下载的 caddy 无法执行（架构不匹配或文件损坏）"
    }
    mv -f "${CADDY_BIN}.new" "$CADDY_BIN"
    rm -rf "$tmp"
}

install_default_caddyfile() {
    if [ -f "$CADDY_CONFIG" ]; then
        ok "已存在 $CADDY_CONFIG，跳过写入默认配置"
        return 0
    fi

    log "写入 Caddy 默认配置"
    cat > "$CADDY_CONFIG" <<'EOF'
# 由 install-caddy.sh 生成的默认配置
# 请按需修改站点地址、域名与证书方式，修改后执行: systemctl reload caddy
:80 {
	respond "Caddy is running." 200
}
EOF

    chown root:caddy "$CADDY_CONFIG"
    chmod 0640 "$CADDY_CONFIG"
    ok "已应用 Caddy 默认配置"
}

configure_caddy_update_timer() {
    log "配置 Caddy 定时自动更新"

    cat > "$CADDY_UPDATE_BIN" <<'EOF'
#!/usr/bin/env bash
# 由 install-caddy.sh 生成：检查本仓库最新 Release 并自动更新 Caddy
set -Eeuo pipefail

REPO="DoTheBetter/Caddyfile_forwardproxy"
CADDY_BIN="/usr/local/bin/caddy"
CADDY_CONFIG="/etc/caddy/Caddyfile"
MARKER="/var/lib/caddy/.installed-release"

log() { printf '[caddy-update] %s\n' "$*"; }

headers=(-H 'Accept: application/vnd.github+json')
if [ -n "${GH_TOKEN:-}" ]; then
    headers+=(-H "Authorization: Bearer ${GH_TOKEN}")
fi

json="$(curl -fsSL "${headers[@]}" "https://api.github.com/repos/${REPO}/releases/latest")" || {
    log "获取最新 Release 失败，本次跳过"
    exit 0
}

tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
if [ -z "$tag" ]; then
    log "解析 Release 标签失败，本次跳过"
    exit 0
fi

current="$(cat "$MARKER" 2>/dev/null || true)"
if [ "$current" = "$tag" ]; then
    log "当前已是最新 ${tag}"
    exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/${REPO}/releases/download/${tag}/${tag}-linux-amd64.tar"
log "发现新版本 ${tag}（当前: ${current:-unknown}），开始下载"
if ! curl -fsSL --retry 3 --connect-timeout 15 -o "$tmp/pkg.tar" "$url"; then
    log "下载失败: ${url}"
    exit 1
fi

tar -xf "$tmp/pkg.tar" -C "$tmp" || { log "解压失败"; exit 1; }
newbin="$(find "$tmp" -type f -name caddy | head -n 1 || true)"
if [ -z "$newbin" ]; then
    log "压缩包内未找到 caddy 二进制"
    exit 1
fi
chmod 0755 "$newbin"

# 先放到 /usr/local/bin 再校验，避免 /tmp 为 noexec 时无法执行
install -m 0755 "$newbin" "${CADDY_BIN}.new"
if ! "${CADDY_BIN}.new" validate --config "$CADDY_CONFIG" --adapter caddyfile >/dev/null 2>&1; then
    rm -f "${CADDY_BIN}.new"
    log "新版本校验现有 Caddyfile 失败，放弃更新"
    exit 1
fi

cp -a "$CADDY_BIN" "${CADDY_BIN}.prev"
mv -f "${CADDY_BIN}.new" "$CADDY_BIN"
if ! systemctl restart caddy; then
    log "重启 caddy 失败，回滚旧版本"
    install -m 0755 "${CADDY_BIN}.prev" "${CADDY_BIN}.new"
    mv -f "${CADDY_BIN}.new" "$CADDY_BIN"
    systemctl restart caddy || log "回滚后仍重启失败，请手动检查"
    exit 1
fi
rm -f "${CADDY_BIN}.prev"

printf '%s\n' "$tag" > "$MARKER"
chmod 0644 "$MARKER"
log "已更新到 ${tag} 并重启 caddy"
EOF
    chmod 0755 "$CADDY_UPDATE_BIN"

    cat > "$CADDY_UPDATE_SERVICE" <<'EOF'
[Unit]
Description=Check and update Caddy from GitHub release
Documentation=https://github.com/DoTheBetter/Caddyfile_forwardproxy
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=600
ExecStart=/usr/local/bin/caddy-update
EOF

    cat > "$CADDY_UPDATE_TIMER" <<'EOF'
[Unit]
Description=Daily Caddy update check

[Timer]
OnCalendar=*-*-* 04:00:00
RandomizedDelaySec=30m
Persistent=true
Unit=caddy-update.service

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    if systemctl enable --now caddy-update.timer >/dev/null 2>&1; then
        CADDY_UPDATE_STATE="已启用（每日 04:00 检查本仓库 Release）"
        ok "已启用 Caddy 定时自动更新"
    else
        warn "caddy-update.timer 启用失败，请执行 systemctl status caddy-update.timer"
    fi
}

install_caddy_service() {
    cat > "$CADDY_SERVICE" <<'EOF'
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

install_caddy() {
    log "安装 Caddy"

    if ! id caddy >/dev/null 2>&1; then
        useradd --system --home-dir "$CADDY_HOME" --shell /usr/sbin/nologin --user-group caddy
    fi
    install -d -m 0750 -o root  -g caddy /etc/caddy
    install -d -m 0750 -o caddy -g caddy "$CADDY_HOME" "$CADDY_LOG_DIR"

    log "获取 ${CADDY_REPO} 最新 Release"
    local tag
    tag="$(github_latest_tag "$CADDY_REPO")"
    if [ -x "$CADDY_BIN" ] && [ "$(cat "$CADDY_RELEASE_MARKER" 2>/dev/null || true)" = "$tag" ]; then
        ok "已安装最新版本 ${tag}，跳过下载"
    else
        download_caddy "$tag"
    fi
    INSTALLED_TAG="$tag"

    install_default_caddyfile

    local vlog
    vlog="$(mktemp)"
    if ! "$CADDY_BIN" validate --config "$CADDY_CONFIG" --adapter caddyfile >"$vlog" 2>&1; then
        cat "$vlog" >&2
        rm -f "$vlog"
        die "Caddyfile 校验失败，未启动服务"
    fi
    rm -f "$vlog"

    install_caddy_service
    systemctl daemon-reload
    systemctl enable caddy >/dev/null 2>&1
    if ! systemctl restart caddy; then
        journalctl -u caddy -n 40 --no-pager >&2 || true
        die "Caddy 启动失败，请查看上面的日志"
    fi

    ok "Caddy 已启动并设置开机自启"

    printf '%s\n' "$INSTALLED_TAG" > "$CADDY_RELEASE_MARKER"
    chmod 0644 "$CADDY_RELEASE_MARKER"

    configure_caddy_update_timer
}

# ---------------- 汇总 ----------------
print_summary() {
    local ssh_port="$1"
    local ufw_state="未启用" bbr_state="未启用" f2b_state="未启用"
    local caddy_ver

    ufw_state="$(LC_ALL=C ufw status 2>/dev/null | head -n 1 | sed 's/^Status: //' || true)"
    [ -n "$ufw_state" ] || ufw_state="unknown"
    bbr_state="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
    [ -n "$bbr_state" ] || bbr_state="unknown"
    f2b_state="$(systemctl is-active fail2ban 2>/dev/null || true)"
    [ -n "$f2b_state" ] || f2b_state="未知"
    local ssh_state
    if ssh_port_listening "$ssh_port"; then
        ssh_state="已监听 ${ssh_port}/tcp"
    else
        ssh_state="未检测到 ${ssh_port}/tcp 监听"
    fi

    caddy_ver="$("$CADDY_BIN" version 2>/dev/null | head -n 1 || true)"

    cat <<EOF

================ 安装结果 ================
 Caddy 版本   : ${caddy_ver:-unknown}
 Caddy 服务   : systemctl status caddy
 Caddyfile    : ${CADDY_CONFIG}
 SSH 端口     : ${ssh_port}
 SSH 监听     : ${ssh_state}
 UFW          : ${ufw_state}
 BBR          : ${bbr_state}
 自动更新     : ${AUTO_UPDATE_STATE}
 Caddy 更新   : ${CADDY_UPDATE_STATE}
 SSH 认证     : ${SSH_AUTH_STATE}
 fail2ban     : ${f2b_state}
==========================================

注意：
1. 云服务器请在安全组中放行新的 SSH 端口 ${ssh_port} 以及 80/tcp、443/tcp、443/udp，
   否则断开当前会话后将无法通过新端口登录（服务器已在监听不代表外部可达）。
2. 请不要关闭当前 SSH 会话，先另开窗口用 "ssh -p ${ssh_port} 用户@服务器" 验证登录。
3. Caddyfile 仅在不存在时写入默认配置，已有配置保持不变，
   修改后执行: systemctl reload caddy 使配置生效
4. Caddy 定时更新日志: journalctl -u caddy-update
5. 当前 SSH 会话不会被脚本断开（仅重启 sshd 主进程），
   若新端口无法连接，请检查云安全组并执行: ss -tlnp | grep sshd; ufw status
EOF
}

# ---------------- 主流程 ----------------
main() {
    preflight
    install_base_packages
    detect_ssh_units

    detect_current_ssh_port

    configure_sysctl
    configure_auto_updates

    # 先装 Caddy：下载失败时不会影响后续 SSH 加固，避免半途中断
    install_caddy

    local target_ssh_port
    target_ssh_port="$(resolve_ssh_port)"
    [ -n "$SSH_SERVICE" ] || die "未找到 ssh/sshd 服务单元，无法修改 SSH 端口"
    [ -n "$SSHD_BIN" ] && [ -f "$SSHD_MAIN" ] || die "未找到 sshd 或配置文件，无法修改 SSH 端口"
    log "本次 SSH 端口: ${target_ssh_port}（当前: ${CURRENT_SSH_PORT}）"

    configure_ufw "$target_ssh_port"
    configure_ssh "$target_ssh_port"
    cleanup_old_ssh_rules "$target_ssh_port"
    configure_fail2ban "$target_ssh_port"

    if [ -n "$SSH_BACKUP_DIR" ]; then
        rm -rf "$SSH_BACKUP_DIR"
    fi

    print_summary "$target_ssh_port"
}

main
