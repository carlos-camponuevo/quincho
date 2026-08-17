#!/usr/bin/env bash
# Install quincho-agent on a Docker Swarm manager (Debian/Ubuntu). Run as root.
#   ./install.sh /path/to/quincho-agent
set -euo pipefail
BIN="${1:?path to the quincho-agent binary}"
install -m 0755 "$BIN" /usr/local/bin/quincho-agent
getent group quincho >/dev/null || groupadd --system quincho
install -m 0644 "$(dirname "$0")/pam.d-quincho" /etc/pam.d/quincho
install -m 0644 "$(dirname "$0")/quincho-agent.service" /etc/systemd/system/quincho-agent.service
mkdir -p /dev/shm/quincho && chmod 0700 /dev/shm/quincho
# no live memory access to any process without a reboot (root included); loud if changed
sysctl -w kernel.yama.ptrace_scope=3 >/dev/null 2>&1 || true
grep -q '^kernel.yama.ptrace_scope' /etc/sysctl.d/90-quincho.conf 2>/dev/null || echo 'kernel.yama.ptrace_scope = 3' > /etc/sysctl.d/90-quincho.conf
systemctl daemon-reload
systemctl enable --now quincho-agent
echo "quincho-agent installed. Add operators to the 'quincho' group (usermod -aG quincho <user>);"
echo "BullDock's container must run with group_add: [\$(getent group quincho | cut -d: -f3)] and mount /run/quincho/quincho.sock."
