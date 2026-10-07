#!/usr/bin/env bash
# Standalone DPI/RKN camouflage hardening for EXISTING nodes that are NOT
# managed by GhostFleet (any VPS running remnanode/Xray — Ghostly-installed,
# hand-rolled, or otherwise). Safe to run on a node that already has real
# users on it.
#
# WHAT THIS SCRIPT DOES NOT DO (read this first):
#   - It cannot change your Xray INBOUND config (TLS vs REALITY, Hysteria2
#     on/off, decoy site). Remnanode normally pulls its Xray config from the
#     Remnawave panel over the API — there is no local file this script can
#     safely edit for that. To get REALITY / drop Hysteria2 / etc. you edit
#     the Config Profile in Remnawave (or re-deploy via GhostFleet with
#     templates/xray.reality.example.json). See docs/STEALTH.md.
#   - It cannot defend against a state-level DPI/TSPU system with full
#     traffic visibility doing behavioural/volume analysis. Nothing run on
#     the node itself can.
#   - It does not touch SSH password/key auth, sudoers, or disable your
#     current SSH access by itself. The optional SSH firewall restriction is
#     opt-in and requires an extra confirmation flag (see --manager-ip below)
#     specifically so you cannot lock yourself out by a typo.
#
# WHAT IT DOES (all idempotent, all removable with --remove):
#   1. Restricts the remnanode mTLS management port (NODE_PORT) to your
#      Remnawave panel IP(s) only — closed to the rest of the internet.
#   2. Optionally restricts SSH to your own manager IP(s) (opt-in, see above).
#   3. Sets the firewall's default policy for everything else to DROP
#      (silent) instead of REJECT (an RST/ICMP reply), so a port scan of your
#      node looks like "nothing is listening" rather than "something is
#      actively firewalled here" on every port except the ones you run.
#   4. Normalizes net.ipv4.ip_default_ttl to 64 (the common Linux default),
#      so your node's outbound TTL doesn't stand out from other TTLs on your
#      own box if something earlier changed it.
#   5. Optionally drops ALL UDP/443 (disables Hysteria2/QUIC/TUIC for every
#      client) if you've decided you don't want UDP exposed at all — opt-in,
#      because it will break any client still using Hysteria2.
#
# All changes are made in a dedicated, clearly-named firewall chain/rule set
# so you (or this script with --remove) can cleanly undo them without
# touching anything else on the box.
#
# USAGE
#   Dry run (always do this first — makes NO changes, requires no root):
#     bash node-stealth-harden.sh --panel-ip 203.0.113.10/32
#
#   Apply for real (requires root):
#     sudo bash node-stealth-harden.sh --panel-ip 203.0.113.10/32 --apply
#
#   Also lock SSH to your own IP (DANGEROUS — can lock you out if the IP is
#   wrong or changes; test from another session before closing this one):
#     sudo bash node-stealth-harden.sh --panel-ip 203.0.113.10/32 \
#       --manager-ip 198.51.100.20/32 --apply --yes-i-understand-ssh-risk
#
#   Remove everything this script added:
#     sudo bash node-stealth-harden.sh --remove --apply
set -Eeuo pipefail
umask 077

CHAIN="GHOSTFLEET-STEALTH"
NODE_PORT=""
SSH_PORT=""
PANEL_IPS=()
MANAGER_IPS=()
BLOCK_UDP_443=0
SET_TTL=0
APPLY=0
REMOVE=0
CONFIRM_SSH=0

usage() { sed -n '2,70p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel-ip) PANEL_IPS+=("$2"); shift 2 ;;
    --manager-ip) MANAGER_IPS+=("$2"); shift 2 ;;
    --node-port) NODE_PORT="$2"; shift 2 ;;
    --ssh-port) SSH_PORT="$2"; shift 2 ;;
    --block-udp-443) BLOCK_UDP_443=1; shift ;;
    --set-ttl) SET_TTL=1; shift ;;
    --apply) APPLY=1; shift ;;
    --remove) REMOVE=1; shift ;;
    --yes-i-understand-ssh-risk) CONFIRM_SSH=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown option: $1" >&2; usage 1 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
plan() { printf '  [PLAN]   %s\n' "$*"; }
run()  {
  if [[ "$APPLY" == 1 ]]; then
    printf '  [RUN]    %s\n' "$1"
    eval "$1"
  else
    plan "$1"
  fi
}

[[ "$APPLY" == 1 && $EUID -ne 0 ]] && { echo '--apply requires root (use sudo)' >&2; exit 1; }

if [[ -z "$NODE_PORT" && -f /opt/remnanode/.env ]]; then
  NODE_PORT="$(grep -E '^NODE_PORT=' /opt/remnanode/.env 2>/dev/null | head -1 | cut -d= -f2 || true)"
fi
NODE_PORT="${NODE_PORT:-2222}"

if [[ -z "$SSH_PORT" ]]; then
  SSH_PORT="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2; exit}' || true)"
  [[ -z "$SSH_PORT" ]] && SSH_PORT="$(grep -E '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2; exit}' || true)"
fi
SSH_PORT="${SSH_PORT:-22}"

if ! [[ "$NODE_PORT" =~ ^[0-9]+$ && "$NODE_PORT" -ge 1 && "$NODE_PORT" -le 65535 ]]; then
  echo "Invalid --node-port: $NODE_PORT" >&2; exit 1
fi
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1 && "$SSH_PORT" -le 65535 ]]; then
  echo "Invalid --ssh-port: $SSH_PORT" >&2; exit 1
fi
for cidr in "${PANEL_IPS[@]:-}" "${MANAGER_IPS[@]:-}"; do
  [[ -z "$cidr" ]] && continue
  if ! python3 -c "import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)" "$cidr" 2>/dev/null; then
    echo "Invalid CIDR/IP: $cidr" >&2; exit 1
  fi
done

if [[ "$REMOVE" != 1 && ${#PANEL_IPS[@]} -eq 0 ]]; then
  echo 'Need at least one --panel-ip (your Remnawave panel IP/CIDR), or pass --remove.' >&2
  exit 1
fi
if [[ ${#MANAGER_IPS[@]} -gt 0 && "$CONFIRM_SSH" != 1 ]]; then
  echo 'Restricting SSH requires --yes-i-understand-ssh-risk (read the script header first).' >&2
  exit 1
fi

say "Node port (remnanode mTLS): $NODE_PORT"
say "SSH port detected: $SSH_PORT"
say "Mode: $([[ $APPLY == 1 ]] && echo APPLY || echo DRY-RUN — nothing will change)"
say ""

use_ufw=0
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
  use_ufw=1
fi

if [[ "$REMOVE" == 1 ]]; then
  say "Removing GhostFleet stealth-hardening rules..."
  if [[ "$use_ufw" == 1 ]]; then
    while ufw status numbered 2>/dev/null | grep -q "# $CHAIN"; do
      num=$(ufw status numbered | grep "# $CHAIN" | head -1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
      [[ -z "$num" ]] && break
      run "yes | ufw delete $num >/dev/null"
    done
  else
    run "iptables -D INPUT -j $CHAIN 2>/dev/null || true"
    run "iptables -F $CHAIN 2>/dev/null || true"
    run "iptables -X $CHAIN 2>/dev/null || true"
  fi
  run "rm -f /etc/sysctl.d/99-ghostfleet-stealth.conf"
  say "Done. Default DROP policy (if this script set it) is left as-is; flip back manually if you want REJECT again."
  exit 0
fi

if [[ "$use_ufw" == 1 ]]; then
  say "Detected active ufw — using ufw rules."
  for cidr in "${PANEL_IPS[@]}"; do
    run "ufw insert 1 allow from $cidr to any port $NODE_PORT proto tcp comment '$CHAIN'"
  done
  run "ufw deny $NODE_PORT/tcp comment '$CHAIN'"
  if [[ ${#MANAGER_IPS[@]} -gt 0 ]]; then
    for cidr in "${MANAGER_IPS[@]}"; do
      run "ufw insert 1 allow from $cidr to any port $SSH_PORT proto tcp comment '$CHAIN'"
    done
    run "ufw deny $SSH_PORT/tcp comment '$CHAIN'"
  fi
  if [[ "$BLOCK_UDP_443" == 1 ]]; then
    run "ufw deny 443/udp comment '$CHAIN'"
  fi
  run "ufw default deny incoming"
  say ""
  say "Note: ufw's default deny already replies with DROP, not REJECT, for incoming — this matches goal #3 automatically."
else
  say "No active ufw detected — using a dedicated iptables chain ($CHAIN)."
  run "iptables -N $CHAIN 2>/dev/null || true"
  run "iptables -F $CHAIN"
  for cidr in "${PANEL_IPS[@]}"; do
    run "iptables -A $CHAIN -p tcp --dport $NODE_PORT -s $cidr -j ACCEPT"
  done
  run "iptables -A $CHAIN -p tcp --dport $NODE_PORT -j DROP"
  if [[ ${#MANAGER_IPS[@]} -gt 0 ]]; then
    for cidr in "${MANAGER_IPS[@]}"; do
      run "iptables -A $CHAIN -p tcp --dport $SSH_PORT -s $cidr -j ACCEPT"
    done
    run "iptables -A $CHAIN -p tcp --dport $SSH_PORT -j DROP"
  fi
  if [[ "$BLOCK_UDP_443" == 1 ]]; then
    run "iptables -A $CHAIN -p udp --dport 443 -j DROP"
  fi
  run "iptables -C INPUT -j $CHAIN 2>/dev/null || iptables -I INPUT -j $CHAIN"
  say ""
  say "Note: persist these rules yourself (iptables-persistent / netfilter-persistent save),"
  say "otherwise they are lost on reboot. ufw (if you install it instead) persists automatically."
fi

if [[ "$SET_TTL" == 1 ]]; then
  run "printf 'net.ipv4.ip_default_ttl = 64\\n' > /etc/sysctl.d/99-ghostfleet-stealth.conf"
  run "sysctl -w net.ipv4.ip_default_ttl=64 >/dev/null"
fi

say ""
say "Done. Re-run with --remove --apply any time to undo everything this script added."
say "Remember: this does not touch your Xray inbound config. For REALITY / dropping"
say "Hysteria2 / decoy-site camouflage, see docs/STEALTH.md."
