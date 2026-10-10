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

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[kenshi] %s\n' "$*"; }
need_root() { [[ ${EUID} -eq 0 ]] || die 'запустите от root или через sudo'; }
cmd() { command -v "$1" >/dev/null 2>&1; }
run() { printf '+ %q' "$@" >>"$LOG_FILE"; printf '\n' >>"$LOG_FILE"; "$@"; }

init_dirs() { mkdir -p "$STATE_DIR" "$BACKUP_DIR" "$CONF_DIR"; chmod 700 "$STATE_DIR" "$CONF_DIR"; touch "$LOG_FILE"; chmod 600 "$LOG_FILE"; }

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

choose_ui() {
  if cmd whiptail; then UI=whiptail; elif cmd dialog; then UI=dialog; else UI=plain; fi
}
ask() { local prompt=$1 default=$2; if [[ $UI == plain ]]; then read -r -p "$prompt [$default]: " v; printf '%s' "${v:-$default}"; else "$UI" --inputbox "$prompt" 10 78 "$default" 3>&1 1>&2 2>&3; fi; }
yesno() { if [[ $UI == plain ]]; then read -r -p "$1 [y/N]: " v; [[ $v == y || $v == Y ]]; else "$UI" --yesno "$1" 10 78; fi; }

collect_plan() {
  SSH_PORT=$(ask 'SSH port' "$(ss -H -lnt 2>/dev/null | awk '$4 ~ /:22$/ {print 22; exit}' || printf 22)")
  TCP_PORTS=$(ask 'Public TCP ports (comma-separated)' '443')
  UDP_PORTS=$(ask 'Public UDP ports (comma-separated)' '')
  NODE_PORT=$(ask 'Remnanode API port (empty = no public allow)' '')
  PANEL_CIDRS=$(ask 'Panel/admin IPv4/IPv6 CIDRs (comma-separated)' '')
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
GEO_COUNTRIES=$GEO_COUNTRIES
SHAPER_MODE=$SHAPER_MODE
ENABLE_XANMOD=$ENABLE_XANMOD
ENABLE_SYNPROXY=$ENABLE_SYNPROXY
BLOCK_SMTP25=$BLOCK_SMTP25
EOF
  chmod 600 "$PLAN_FILE"
}

valid_list() { [[ -z "$1" || "$1" =~ ^[0-9]+(,[0-9]+)*$ ]]; }
load_plan() { [[ -r $PLAN_FILE ]] || collect_plan; . "$PLAN_FILE"; valid_list "$TCP_PORTS" || die 'invalid TCP port list'; valid_list "$UDP_PORTS" || die 'invalid UDP port list'; }

backup_file() { local f=$1; [[ -e $f ]] && cp -a -- "$f" "$BACKUP_DIR/$(basename "$f").$(date +%s)" || true; }

compile_nft() {
  local tcp="" udp=""; [[ -n ${TCP_PORTS:-} ]] && tcp="tcp dport { ${TCP_PORTS//,/ , } }"; [[ -n ${UDP_PORTS:-} ]] && udp="udp dport { ${UDP_PORTS//,/ , } }"
  local ssh="tcp dport ${SSH_PORT}"
  cat >"$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
table inet kenshi_shield {
  set allow_v4 { type ipv4_addr; flags interval; elements = { 127.0.0.1 } }
  set allow_v6 { type ipv6_addr; flags interval; elements = { ::1 } }
  chain input {
    type filter hook input priority -5; policy accept;
    ct state invalid counter drop
    iif lo accept
    ip protocol icmp limit rate 10/second accept
    ip6 nexthdr icmpv6 limit rate 10/second accept
    ct state established,related accept
    ip saddr @allow_v4 accept
    ip6 saddr @allow_v6 accept
    $ssh accept
    ${tcp:+$tcp accept}
    ${udp:+$udp accept}
    ${NODE_PORT:+tcp dport $NODE_PORT ip saddr @allow_v4 accept}
    tcp flags & (fin|syn|rst|ack) == syn limit rate 100/second burst 200 packets counter drop
  }
  chain output {
    type filter hook output priority -5; policy accept;
    ${BLOCK_SMTP25:+tcp dport 25 counter reject with icmpx type admin-prohibited}
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
  nft -f "$NFT_FILE"
  cp -a "$PLAN_FILE" "$CONF_DIR/plan.env"
  printf '%s firewall applied\n' "$(date -Is)" >>"$LOG_FILE"
}

apply_geoblock() {
  need_root; init_dirs; load_plan
  info 'GeoBlock is staged as an explicit policy; country databases are not downloaded from mutable URLs.'
  printf '%s\n' "$GEO_COUNTRIES" | tr ',' '\n' >"$GEO_FILE"; chmod 600 "$GEO_FILE"
  info "Allowed countries saved to $GEO_FILE. An ASN/IP database provider must be configured before enforcement."
}

apply_shaping() {
  need_root; init_dirs; load_plan
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

rollback() {
  need_root; init_dirs
  nft delete table inet kenshi_shield 2>/dev/null || true
  rm -f "$NFT_FILE" "$SHAPER_FILE" "$GEO_FILE" "$CONF_DIR/plan.env"
  rm -f /etc/sysctl.d/99-kenshi-shield.conf
  sysctl --system >/dev/null 2>&1 || true
  info 'Kenshi Shield resources rolled back; third-party firewall tables and kernels were not removed.'
}

menu() {
  choose_ui
  while true; do
    if [[ $UI == plain ]]; then printf '\n1 audit\n2 plan\n3 apply firewall\n4 apply geo/shaping\n5 rollback\n0 exit\n'; read -r -p '> ' choice; else choice=$($UI --menu 'Kenshi Shield' 16 78 8 1 'Audit' 2 'Plan' 3 'Apply firewall' 4 'Apply geo/shaping' 5 'Rollback' 0 'Exit' 3>&1 1>&2 2>&3) || return; fi
    case $choice in 1) audit ;; 2) init_dirs; collect_plan; compile_nft; info "Plan: $PLAN_FILE" ;; 3) apply_firewall ;; 4) apply_geoblock; apply_shaping ;; 5) rollback ;; 0) return ;; esac
  done
}

case ${1:-menu} in audit) audit ;; plan) init_dirs; collect_plan; compile_nft ;; apply) apply_firewall; apply_geoblock; apply_shaping; apply_xanmod ;; rollback) rollback ;; menu) menu ;; *) die "usage: $0 [menu|audit|plan|apply|rollback]" ;; esac
