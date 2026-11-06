#!/usr/bin/env bash
# Désinstalle Marceau.
#   sudo ./uninstall.sh          # garde tes données (appareils connus, journal)
#   sudo ./uninstall.sh --purge  # efface aussi /var/lib/marceau
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo "Lance-moi avec sudo."; exit 1; fi

if command -v systemctl >/dev/null; then
  systemctl disable --now marceau.service 2>/dev/null || true
  rm -f /etc/systemd/system/marceau.service
  systemctl daemon-reload 2>/dev/null || true
fi
rm -rf /opt/marceau
rm -f /usr/local/bin/marceau

if [[ "${1:-}" == "--purge" ]]; then
  rm -rf /var/lib/marceau
  echo "✓ Marceau et toutes ses données ont été retirés."
else
  echo "✓ Marceau retiré. Données conservées dans /var/lib/marceau (--purge pour les effacer)."
fi
