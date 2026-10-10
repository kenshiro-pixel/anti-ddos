#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="0.1.0"
STATE_DIR="${KENSHI_STATE_DIR:-/var/lib/kenshi-shield}"
CONF_DIR="${KENSHI_CONF_DIR:-/etc/kenshi-shield}"
BACKUP_DIR="${STATE_DIR}/backups"
PLAN_FILE="${STATE_DIR}/plan.env"
LOG_FILE="${STATE_DIR}/operations.log"
NFT_FILE="${CONF_DIR}/firewall.nft"
GEO_FILE="${CONF_DIR}/geoblock-countries.txt"
SHAPER_FILE="${CONF_DIR}/shaping.conf"
DRY_RUN="${KENSHI_DRY_RUN:-0}"
OPT_FILE="${CONF_DIR}/optimize.env"
SYSCTL_FILE="/etc/sysctl.d/99-kenshi-shield-optimize.conf"
RPS_SCRIPT="/usr/local/sbin/kenshi-shield-rps"
RPS_UNIT="/etc/systemd/system/kenshi-shield-rps.service"
SAFETY_DELAY="${KENSHI_SAFETY_DELAY:-300}"
SELF_PATH="${KENSHI_SELF_PATH:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")}"
TXN_DIR="${STATE_DIR}/transaction"
TXN_PREV_NFT="${TXN_DIR}/previous.nft"
TXN_PREV_NFT_MISSING="${TXN_DIR}/previous.nft.missing"
TXN_STATE="${TXN_DIR}/state"
SAFETY_UNIT="kenshi-shield-safety.service"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[kenshi] %s\n' "$*"; }
need_root() { [[ ${EUID} -eq 0 || ${KENSHI_TEST_MODE:-0} == 1 ]] || die 'запустите от root или через sudo'; }
cmd() { command -v "$1" >/dev/null 2>&1; }
run() { printf '+ %q' "$@" >>"$LOG_FILE"; printf '\n' >>"$LOG_FILE"; "$@"; }

init_dirs() { mkdir -p "$STATE_DIR" "$BACKUP_DIR" "$CONF_DIR"; chmod 700 "$STATE_DIR" "$CONF_DIR"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"; }

capture_previous_nft() {
  mkdir -p "$TXN_DIR"; chmod 700 "$TXN_DIR"
  rm -f "$TXN_PREV_NFT" "$TXN_PREV_NFT_MISSING"
  if nft list table inet kenshi_shield >"$TXN_PREV_NFT" 2>/dev/null; then
    chmod 600 "$TXN_PREV_NFT"
    printf 'present\n' >"$TXN_STATE"
  else
    : >"$TXN_PREV_NFT_MISSING"
    printf 'missing\n' >"$TXN_STATE"
  fi
  chmod 600 "$TXN_STATE"
}

watchdog_recover() {
  need_root; init_dirs
  [[ -r $TXN_STATE ]] || { info 'No pending transaction'; return 0; }
  local state; state=$(<"$TXN_STATE")
  [[ $state == pending ]] || { info "Transaction state is $state; nothing to recover"; return 0; }
  nft delete table inet kenshi_shield 2>/dev/null || true
  if [[ -s $TXN_PREV_NFT ]]; then nft -f "$TXN_PREV_NFT"; fi
  printf 'recovered\n' >"$TXN_STATE"
  info 'Safety watchdog restored the previous Kenshi Shield table.'
}

arm_watchdog() {
  (( SAFETY_DELAY > 0 )) || return 0
  printf 'pending\n' >"$TXN_STATE"; chmod 600 "$TXN_STATE"
  systemd-run --quiet --unit="$SAFETY_UNIT" --on-active="${SAFETY_DELAY}s" \
    /usr/bin/env bash "$SELF_PATH" watchdog-recover >/dev/null 2>&1 || die 'failed to arm safety watchdog'
  info "Safety watchdog armed for ${SAFETY_DELAY}s; run '$SELF_PATH commit' after independent checks."
}

commit_transaction() {
  need_root; init_dirs
  [[ -r $TXN_STATE ]] || { info 'No pending transaction'; return 0; }
  local state; state=$(<"$TXN_STATE")
  [[ $state == pending ]] || { info "Transaction state is $state"; return 0; }
  systemctl stop "$SAFETY_UNIT" 2>/dev/null || true
  printf 'committed\n' >"$TXN_STATE"; chmod 600 "$TXN_STATE"
  info 'Firewall transaction committed; watchdog stopped.'
}

audit() {
  need_root; init_dirs
  printf 'Kenshi Shield %s\n\n' "$VERSION"
  printf 'OS: '; . /etc/os-release 2>/dev/null; printf '%s %s\n' "${ID:-unknown}" "${VERSION_ID:-unknown}"
  printf 'Kernel: '; uname -r
  printf 'Arch: '; uname -m
  printf 'Virtualization: '; systemd-detect-virt 2>/dev/null || printf 'unknown\n'
  printf '\nListeners:\n'; ss -H -lntup 2>/dev/null | sed -E 's/users:\(\("[^"]+"[^)]*\)?,?//g' | head -80 || true
  printf '\nFirewall backends:\n'
  for x in nft ufw firewall-cmd iptables; do if cmd "$x"; then printf '  %s: present\n' "$x"; else printf '  %s: absent\n' "$x"; fi; done
  printf '\nServices:\n'
  for x in docker remnanode nginx caddy crowdsec fail2ban; do
    if systemctl list-unit-files "${x}.service" --no-legend 2>/dev/null | grep -q "${x}.service"; then systemctl is-active --quiet "$x" && s=active || s=inactive; printf '  %-12s %s\n' "$x" "$s"; fi
  done
  printf '\nNetwork:\n'; ip -brief address 2>/dev/null || true
  printf '\nOutbound SMTP snapshot:\n'; ss -H -tnp 2>/dev/null | awk '$4 ~ /:25$/ || $5 ~ /:25$/ {print}' | head -20 || true
}

diagnose() {
  need_root; init_dirs
  printf 'Kenshi Shield %s - диагностика\n\n' "$VERSION"
  local ram_mb cpus virt bbr qdisc conntrack nofile
  ram_mb=$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || printf 0)
  cpus=$(nproc 2>/dev/null || printf 1)
  virt=$(systemd-detect-virt 2>/dev/null || printf none)
  bbr=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || printf unknown)
  qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || printf unknown)
  conntrack=$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || printf unavailable)
  nofile=$(ulimit -n 2>/dev/null || printf unavailable)
  printf '[%s] kernel: %s\n' "$([[ $bbr == bbr ]] && printf OK || printf WARN)" "$(uname -r)"
  printf '[%s] BBR: %s / qdisc: %s\n' "$([[ $bbr == bbr && $qdisc == fq ]] && printf OK || printf WARN)" "$bbr" "$qdisc"
  printf '[INFO] RAM: %s MiB, CPU: %s, virtualization: %s\n' "$ram_mb" "$cpus" "$virt"
  printf '[INFO] conntrack max: %s, open-file limit: %s\n' "$conntrack" "$nofile"
  if nft list table inet kenshi_shield >/dev/null 2>&1; then printf '[OK] kenshi_shield nftables table is active\n'; else printf '[WARN] kenshi_shield nftables table is not active\n'; fi
  if systemctl is-active --quiet crowdsec 2>/dev/null; then printf '[OK] CrowdSec active\n'; else printf '[INFO] CrowdSec not active\n'; fi
  if systemctl is-active --quiet fail2ban 2>/dev/null; then printf '[OK] Fail2Ban active\n'; else printf '[INFO] Fail2Ban not active\n'; fi
  printf '\nПроверка не изменяет систему. Для применения используйте пункт «Оптимизация» после просмотра плана.\n'
}

choose_ui() {
  if cmd whiptail; then UI=whiptail; elif cmd dialog; then UI=dialog; else UI=plain; fi
}
ask() { local prompt=$1 default=$2; if [[ $UI == plain ]]; then read -r -p "$prompt [$default]: " v; printf '%s' "${v:-$default}"; else "$UI" --inputbox "$prompt" 10 78 "$default" 3>&1 1>&2 2>&3; fi; }
yesno() { if [[ $UI == plain ]]; then read -r -p "$1 [y/N]: " v; [[ $v == y || $v == Y ]]; else "$UI" --yesno "$1" 10 78; fi; }

collect_plan() {
  SSH_PORT=$(ask 'SSH port' "${SSH_PORT:-$(ss -H -lnt 2>/dev/null | awk '$4 ~ /:22$/ {print 22; exit}' || true)}")
  SSH_PORT=${SSH_PORT:-22}
  TCP_PORTS=$(ask 'Public TCP ports (comma-separated)' '443')
  UDP_PORTS=$(ask 'Public UDP ports (comma-separated)' '')
  NODE_PORT=$(ask 'Remnanode API port (empty = no public allow)' '')
  PANEL_CIDRS=$(ask 'Panel/admin IPv4/IPv6 CIDRs (comma-separated)' '')
  INPUT_POLICY=$(ask 'Input policy (accept for compatibility, drop to close other ports)' 'accept')
  GEO_COUNTRIES=$(ask 'Allowed countries for geo policy' 'RU,UA,GE,BY,AM,KZ')
  SHAPER_MODE=$(ask 'Traffic shaping (off, per-user, per-ip)' 'off')
  ENABLE_XANMOD=0; ENABLE_SYNPROXY=0; BLOCK_SMTP25=1
  yesno 'Enable XanMod/BBR kernel profile? Requires reboot and separate rollback.' && ENABLE_XANMOD=1 || true
  yesno 'Enable SYNPROXY on selected TCP ports? Advanced and provider/kernel dependent.' && ENABLE_SYNPROXY=1 || true
  yesno 'Block outbound TCP/25 after checking active SMTP connections?' && BLOCK_SMTP25=1 || BLOCK_SMTP25=0
  cat >"$PLAN_FILE" <<EOF
SSH_PORT=$SSH_PORT
TCP_PORTS=$TCP_PORTS
UDP_PORTS=$UDP_PORTS
NODE_PORT=$NODE_PORT
PANEL_CIDRS=$PANEL_CIDRS
INPUT_POLICY=$INPUT_POLICY
GEO_COUNTRIES=$GEO_COUNTRIES
SHAPER_MODE=$SHAPER_MODE
ENABLE_XANMOD=$ENABLE_XANMOD
ENABLE_SYNPROXY=$ENABLE_SYNPROXY
BLOCK_SMTP25=$BLOCK_SMTP25
EOF
  chmod 600 "$PLAN_FILE"
}

valid_list() {
  [[ -z "$1" || "$1" =~ ^[0-9]+(,[0-9]+)*$ ]] || return 1
  local p; IFS=',' read -ra ports <<<"$1"
  for p in "${ports[@]}"; do (( p >= 1 && p <= 65535 )) || return 1; done
}
valid_cidrs() {
  local c; [[ -z ${1:-} ]] && return 0; IFS=',' read -ra cidrs <<<"$1"
  for c in "${cidrs[@]}"; do
    [[ $c =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ || $c =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] || return 1
  done
}
valid_countries() { [[ ${1:-} =~ ^[A-Z]{2}(,[A-Z]{2})*$ ]]; }
load_plan() {
  [[ -r $PLAN_FILE ]] || collect_plan
  . "$PLAN_FILE"
  valid_list "$TCP_PORTS" || die 'invalid TCP port list'
  valid_list "$UDP_PORTS" || die 'invalid UDP port list'
  [[ ${SSH_PORT:-} =~ ^[0-9]+$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || die 'invalid SSH port'
  valid_cidrs "${PANEL_CIDRS:-}" || die 'invalid panel/admin CIDR list'
  [[ ${INPUT_POLICY:-accept} =~ ^(accept|drop)$ ]] || die 'invalid input policy'
  valid_countries "${GEO_COUNTRIES:-}" || die 'invalid country allow-list (use CC,CC)'
  if [[ -n ${NODE_PORT:-} ]]; then [[ $NODE_PORT =~ ^[0-9]+$ ]] && (( NODE_PORT >= 1 && NODE_PORT <= 65535 )) || die 'invalid Remnanode port'; fi
  [[ ${SHAPER_MODE:-off} =~ ^(off|per-user|per-ip)$ ]] || die 'invalid shaping mode'
  [[ ${ENABLE_XANMOD:-0} =~ ^[01]$ && ${ENABLE_SYNPROXY:-0} =~ ^[01]$ && ${BLOCK_SMTP25:-0} =~ ^[01]$ ]] || die 'invalid feature flag'
}

backup_file() {
  local f=$1 base stamp
  base=$(basename "$f"); stamp=$(date +%s)
  if [[ -e $f ]]; then cp -a -- "$f" "$BACKUP_DIR/$base.$stamp"; else : >"$BACKUP_DIR/$base.missing.$stamp"; fi
}
restore_latest() {
  local target=$1 base; base=$(basename "$target")
  local latest; latest=$(ls -1t "$BACKUP_DIR"/"$base".* 2>/dev/null | head -1 || true)
  [[ -z $latest ]] && return 0
  if [[ $latest == *.missing.* ]]; then rm -f -- "$target"; else mkdir -p "$(dirname "$target")"; cp -a -- "$latest" "$target"; fi
}

compile_nft() {
  cmd nft || die 'nft is required; install it as a separate approved dependency step'
  local tcp="" udp=""; [[ -n ${TCP_PORTS:-} ]] && tcp="tcp dport { ${TCP_PORTS//,/ , } }"; [[ -n ${UDP_PORTS:-} ]] && udp="udp dport { ${UDP_PORTS//,/ , } }"
  local ssh="tcp dport ${SSH_PORT}" smtp_rule="" tcp_meters="" udp_meters="" p idx
  [[ ${BLOCK_SMTP25:-0} == 1 ]] && smtp_rule='tcp dport 25 counter reject with icmpx type admin-prohibited'
  if [[ -n ${TCP_PORTS:-} ]]; then
    IFS=',' read -ra tcp_ports <<<"$TCP_PORTS"
    idx=0
    for p in "${tcp_ports[@]}"; do
      tcp_meters+=$'    meter tcp_syn_'"${idx}"$' { ip saddr limit rate 60/second burst 120 packets } tcp dport '"${p}"$' tcp flags syn counter accept\n'
      idx=$((idx + 1))
    done
  fi
  if [[ -n ${UDP_PORTS:-} ]]; then
    IFS=',' read -ra udp_ports <<<"$UDP_PORTS"
    idx=0
    for p in "${udp_ports[@]}"; do
      udp_meters+=$'    meter udp_rate_'"${idx}"$' { ip saddr limit rate 120/second burst 240 packets } udp dport '"${p}"$' counter accept\n'
      idx=$((idx + 1))
    done
  fi
  cat >"$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
table inet kenshi_shield {
  set allow_v4 { type ipv4_addr; flags interval; elements = { 127.0.0.1 } }
  set allow_v6 { type ipv6_addr; flags interval; elements = { ::1 } }
  set scan_suspect_v4 { type ipv4_addr; flags dynamic,timeout; timeout 10m; size 65535; }
  set scan_confirmed_v4 { type ipv4_addr; flags dynamic,timeout; timeout 1h; size 65535; }
  set scan_suspect_v6 { type ipv6_addr; flags dynamic,timeout; timeout 10m; size 65535; }
  set scan_confirmed_v6 { type ipv6_addr; flags dynamic,timeout; timeout 1h; size 65535; }
  chain input {
    type filter hook input priority -5; policy ${INPUT_POLICY:-accept};
    ct state invalid counter drop
    iif lo accept
    tcp flags & (fin|syn|rst|ack) == (fin|syn) counter drop
    tcp flags & (fin|syn|rst|ack) == (fin|rst) counter drop
    tcp flags & (fin|syn|rst|ack) == (syn|rst) counter drop
    tcp flags & (fin|syn|rst|ack) == fin counter drop
    ip protocol icmp limit rate 10/second burst 20 packets accept
    ip6 nexthdr icmpv6 limit rate 10/second burst 20 packets accept
    ct state established,related accept
    ip saddr @allow_v4 accept
    ip6 saddr @allow_v6 accept
    ip saddr @scan_confirmed_v4 counter drop
    ip6 saddr @scan_confirmed_v6 counter drop
    $ssh accept
    ${NODE_PORT:+tcp dport $NODE_PORT ip saddr @allow_v4 accept}
${tcp_meters}${udp_meters}
    tcp flags syn add @scan_suspect_v4 { ip saddr timeout 10m } limit rate over 100/second burst 200 packets counter drop
    ip6 nexthdr tcp tcp flags syn add @scan_suspect_v6 { ip6 saddr timeout 10m } limit rate over 100/second burst 200 packets counter drop
    ip saddr @scan_suspect_v4 tcp flags syn add @scan_confirmed_v4 { ip saddr timeout 1h } counter drop
    ip6 saddr @scan_suspect_v6 ip6 nexthdr tcp tcp flags syn add @scan_confirmed_v6 { ip6 saddr timeout 1h } counter drop
  }
  chain output {
    type filter hook output priority -5; policy accept;
    $smtp_rule
  }
EOF
  if [[ -n ${PANEL_CIDRS:-} ]]; then
    local c; IFS=',' read -ra cs <<<"$PANEL_CIDRS"; for c in "${cs[@]}"; do if [[ $c == *:* ]]; then sed -i "/elements = { ::1 }/s/::1/::1, $c/" "$NFT_FILE"; else sed -i "/elements = { 127.0.0.1 }/s/127.0.0.1/127.0.0.1, $c/" "$NFT_FILE"; fi; done
  fi
  if [[ ${ENABLE_SYNPROXY:-0} == 1 && -n ${TCP_PORTS:-} ]]; then
    printf '  chain synproxy_guard { type filter hook input priority -10; policy accept; tcp dport { %s } tcp flags syn notrack synproxy mss 1460 wscale 7\n' "${TCP_PORTS//,/ , }" >>"$NFT_FILE"
    printf '  }\n' >>"$NFT_FILE"
  fi
  printf '}\n' >>"$NFT_FILE"
  nft -c -f "$NFT_FILE"
}

apply_firewall() {
  need_root; init_dirs; load_plan; backup_file "$NFT_FILE"; compile_nft
  [[ $DRY_RUN == 1 ]] && { info "DRY_RUN=1: nft rules validated but not applied"; return; }
  capture_previous_nft
  nft -f "$NFT_FILE"
  arm_watchdog
  cp -a "$PLAN_FILE" "$CONF_DIR/plan.env"
  printf '%s firewall applied\n' "$(date -Is)" >>"$LOG_FILE"
}

apply_geoblock() {
  need_root; init_dirs; load_plan
  [[ $DRY_RUN == 1 ]] && { info "DRY_RUN=1: GeoBlock policy not written"; return; }
  info 'GeoBlock is staged as an explicit policy; country databases are not downloaded from mutable URLs.'
  printf '%s\n' "$GEO_COUNTRIES" | tr ',' '\n' >"$GEO_FILE"; chmod 600 "$GEO_FILE"
  info "Allowed countries saved to $GEO_FILE. An ASN/IP database provider must be configured before enforcement."
}

apply_shaping() {
  need_root; init_dirs; load_plan
  [[ $DRY_RUN == 1 ]] && { info "DRY_RUN=1: shaping policy not written"; return; }
  printf 'mode=%s\n' "$SHAPER_MODE" >"$SHAPER_FILE"; chmod 600 "$SHAPER_FILE"
  if [[ $SHAPER_MODE != off ]]; then info 'Per-user shaping requires a verified Xray/eBPF identity adapter; no global bandwidth cap is applied by this MVP.'; fi
}

apply_xanmod() {
  need_root; [[ ${ENABLE_XANMOD:-0} == 1 ]] || { info 'XanMod disabled'; return; }
  backup_file /etc/sysctl.d/99-kenshi-shield.conf
  cat >/etc/sysctl.d/99-kenshi-shield.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=65535
net.ipv4.tcp_syncookies=1
EOF
  sysctl --system >/dev/null
  info 'BBR/sysctl applied. XanMod kernel installation is intentionally a separate operator-approved package step.'
}

optimize_plan() {
  need_root; init_dirs
  local ram_mb cpus conntrack
  ram_mb=$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || printf 1024)
  cpus=$(nproc 2>/dev/null || printf 1)
  if (( ram_mb < 2048 )); then conntrack=131072; elif (( ram_mb < 4096 )); then conntrack=262144; elif (( ram_mb < 8192 )); then conntrack=524288; else conntrack=1048576; fi
  cat >"$OPT_FILE" <<EOF
RAM_MB=$ram_mb
CPUS=$cpus
CONNTRACK_MAX=$conntrack
ENABLE_BBR=1
ENABLE_RPS=1
ENABLE_FILE_LIMITS=1
ENABLE_JOURNAL_LIMIT=1
XANMOD_KERNEL=0
EOF
  chmod 600 "$OPT_FILE"
  printf 'План оптимизации:\n  RAM: %s MiB\n  CPU: %s\n  conntrack: %s\n  BBR/fq: yes\n  RPS/RFS/XPS: yes\n  file limits: yes\n  XanMod kernel: отдельный шаг\n' "$ram_mb" "$cpus" "$conntrack"
}

apply_optimize() {
  need_root; init_dirs; [[ -r $OPT_FILE ]] || optimize_plan; . "$OPT_FILE"
  [[ $DRY_RUN == 1 ]] && { info "DRY_RUN=1: optimization files and services not changed"; return; }
  backup_file "$SYSCTL_FILE"
  cat >"$SYSCTL_FILE" <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=65535
net.core.netdev_max_backlog=250000
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_syncookies=1
net.netfilter.nf_conntrack_max=$CONNTRACK_MAX
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=600
fs.file-max=1048576
EOF
  sysctl --system >/dev/null
  mkdir -p /etc/systemd/system.conf.d /etc/systemd/journald.conf.d
  backup_file /etc/systemd/system.conf.d/99-kenshi-shield-limits.conf
  cat >/etc/systemd/system.conf.d/99-kenshi-shield-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultLimitNPROC=1048576
EOF
  backup_file /etc/systemd/journald.conf.d/99-kenshi-shield.conf
  cat >/etc/systemd/journald.conf.d/99-kenshi-shield.conf <<'EOF'
[Journal]
SystemMaxUse=500M
RuntimeMaxUse=100M
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF
  backup_file "$RPS_SCRIPT"
  cat >"$RPS_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -u
cpus=$(nproc 2>/dev/null || printf 1)
if (( cpus >= 64 )); then mask=ffffffffffffffff; else mask=$(printf '%x' $(( (1 << cpus) - 1 ))); fi
for dev in /sys/class/net/*; do
  name=${dev##*/}
  [[ $name == lo || -e "$dev/device" ]] || continue
  for f in "$dev"/queues/rx-*/rps_cpus; do [[ -e $f ]] && printf '%s\n' "$mask" >"$f"; done
  for f in "$dev"/queues/rx-*/rps_flow_cnt; do [[ -e $f ]] && printf '32768\n' >"$f"; done
  for f in "$dev"/queues/tx-*/xps_cpus; do [[ -e $f ]] && printf '%s\n' "$mask" >"$f"; done
done
EOF
  chmod 700 "$RPS_SCRIPT"
  backup_file "$RPS_UNIT"
  cat >"$RPS_UNIT" <<EOF
[Unit]
Description=Kenshi Shield RPS/RFS/XPS tuning
After=network-pre.target

[Service]
Type=oneshot
ExecStart=$RPS_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable --now kenshi-shield-rps.service >/dev/null 2>&1 || true
  info "Оптимизация применена: BBR/fq, conntrack=$CONNTRACK_MAX, limits и journald. RPS/XPS активируется отдельным service после проверки интерфейса."
}

rollback() {
  need_root; init_dirs
  local restored=0
  if [[ -r $TXN_STATE ]] && [[ $(<"$TXN_STATE") == pending ]]; then
    nft delete table inet kenshi_shield 2>/dev/null || true
    if [[ -s $TXN_PREV_NFT ]]; then nft -f "$TXN_PREV_NFT" && restored=1 || true; fi
  fi
  (( restored == 1 )) || nft delete table inet kenshi_shield 2>/dev/null || true
  rm -f "$NFT_FILE" "$SHAPER_FILE" "$GEO_FILE" "$CONF_DIR/plan.env"
  rm -f /etc/sysctl.d/99-kenshi-shield.conf
  rm -f "$SYSCTL_FILE" "$OPT_FILE" /etc/systemd/system.conf.d/99-kenshi-shield-limits.conf /etc/systemd/journald.conf.d/99-kenshi-shield.conf
  restore_latest "$SYSCTL_FILE" || true
  restore_latest /etc/systemd/system.conf.d/99-kenshi-shield-limits.conf || true
  restore_latest /etc/systemd/journald.conf.d/99-kenshi-shield.conf || true
  systemctl disable --now kenshi-shield-rps.service >/dev/null 2>&1 || true
  systemctl stop "$SAFETY_UNIT" 2>/dev/null || true
  rm -rf "$TXN_DIR"
  rm -f "$RPS_SCRIPT" "$RPS_UNIT"
  sysctl --system >/dev/null 2>&1 || true
  info 'Kenshi Shield resources rolled back; third-party firewall tables and kernels were not removed.'
}

status() {
  need_root; init_dirs
  printf 'Kenshi Shield %s status\n' "$VERSION"
  if nft list table inet kenshi_shield >/dev/null 2>&1; then printf 'firewall: active\n'; else printf 'firewall: inactive\n'; fi
  [[ -r $OPT_FILE ]] && printf 'optimization: planned (%s)\n' "$OPT_FILE" || printf 'optimization: not planned\n'
  [[ ${INPUT_POLICY:-} == drop ]] && printf 'input policy: drop\n' || printf 'input policy: accept/unknown\n'
  [[ -r $GEO_FILE ]] && printf 'geoblock policy: staged\n' || printf 'geoblock policy: not configured\n'
  [[ -r $SHAPER_FILE ]] && printf 'shaping: %s\n' "$(tr -d '\n' <"$SHAPER_FILE")" || printf 'shaping: not configured\n'
  systemctl is-enabled --quiet kenshi-shield-rps.service 2>/dev/null && printf 'rps/rfs/xps: enabled\n' || printf 'rps/rfs/xps: disabled\n'
}

menu() {
  choose_ui
  while true; do
    if [[ $UI == plain ]]; then printf '\n1 diagnose\n2 protect\n3 optimize\n4 plan\n5 apply geo/shaping\n6 rollback\n0 exit\n'; read -r -p '> ' choice; else choice=$($UI --menu 'Kenshi Shield' 18 90 8 1 'Диагностика - read-only audit' 2 'Защита от DDoS - nftables/CrowdSec profile' 3 'Оптимизация - BBR/sysctl/limits/RPS' 4 'План firewall' 5 'GeoBlock и traffic shaping' 6 'Rollback' 0 'Выход' 3>&1 1>&2 2>&3) || return; fi
    case $choice in 1) diagnose ;; 2) apply_firewall ;; 3) optimize_plan; yesno 'Применить оптимизацию сейчас?' && apply_optimize || true ;; 4) init_dirs; collect_plan; compile_nft; info "Plan: $PLAN_FILE" ;; 5) apply_geoblock; apply_shaping ;; 6) rollback ;; 0) return ;; esac
  done
}

case ${1:-menu} in audit|diagnose) diagnose ;; status) status ;; plan) init_dirs; if [[ ! -r $PLAN_FILE ]]; then choose_ui; collect_plan; fi; load_plan; compile_nft ;; protect|apply-firewall) apply_firewall ;; optimize) optimize_plan; apply_optimize ;; apply) apply_firewall; apply_geoblock; apply_shaping; apply_xanmod ;; commit) commit_transaction ;; watchdog-recover) watchdog_recover ;; rollback) rollback ;; menu) menu ;; *) die "usage: $0 [menu|status|diagnose|protect|optimize|plan|apply|commit|rollback]" ;; esac
