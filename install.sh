#!/usr/bin/env bash
# Installe Marceau et le lance en mode AUTONOME au démarrage de l'ordinateur.
#   sudo ./install.sh              # installation complète + service systemd
#   sudo ./install.sh --no-service # installe seulement la commande « marceau »
set -euo pipefail

VERT=$'\033[92m'; JAUNE=$'\033[93m'; ROUGE=$'\033[91m'; RAZ=$'\033[0m'
DEST=/opt/marceau
DATA=/var/lib/marceau
BIN=/usr/local/bin/marceau
SERVICE=/etc/systemd/system/marceau.service
ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AVEC_SERVICE=1
[[ "${1:-}" == "--no-service" ]] && AVEC_SERVICE=0

if [[ $EUID -ne 0 ]]; then
  echo "${ROUGE}Lance-moi avec sudo : sudo ./install.sh${RAZ}"; exit 1
fi

echo "${VERT}==> Dépendances (python3, arp-scan, nmap)${RAZ}"
if command -v apt-get >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 arp-scan nmap >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 arp-scan nmap
elif command -v pacman >/dev/null; then
  pacman -S --noconfirm --needed python arp-scan nmap
else
  echo "${JAUNE}Gestionnaire de paquets inconnu : installe python3, arp-scan et nmap toi-même.${RAZ}"
fi

echo "${VERT}==> Copie dans $DEST${RAZ}"
install -d -m 0755 "$DEST"
install -m 0755 "$ICI/marceau.py" "$DEST/marceau.py"
install -m 0644 "$ICI/config.example.json" "$DEST/config.example.json"

echo "${VERT}==> Commande « marceau »${RAZ}"
cat > "$BIN" <<EOF
#!/bin/sh
# Même dossier de données que le service : le menu et le mode autonome partagent tout.
export MARCEAU_HOME=$DATA
exec /usr/bin/python3 $DEST/marceau.py "\$@"
EOF
chmod 0755 "$BIN"

install -d -m 0700 "$DATA"
CONFIG="$DATA/.marceau_config.json"
if [[ ! -f "$CONFIG" ]]; then
  echo "${VERT}==> Configuration ($CONFIG)${RAZ}"
  cp "$ICI/config.example.json" "$CONFIG"
  chmod 0600 "$CONFIG"   # peut contenir un mot de passe e-mail
  if [[ -t 0 ]]; then
    echo "${JAUNE}Les audits automatiques (ports/vulnérabilités) ne doivent viser QUE ton propre réseau."
    read -r -p "Ce réseau est-il le TIEN (ou l'administres-tu) ? (o/n) ${RAZ}" rep
    if [[ "$rep" == "o" ]]; then
      python3 - "$CONFIG" <<'PY'
import json, sys
p = sys.argv[1]; c = json.load(open(p))
c["network_owner_confirmed"] = True
c["auto"]["audit_new_devices"] = True
json.dump(c, open(p, "w"), indent=2, ensure_ascii=False)
PY
      echo "${VERT}Audit des nouveaux appareils activé.${RAZ}"
    fi
  fi
else
  echo "${JAUNE}Config existante conservée : $CONFIG${RAZ}"
fi

if [[ $AVEC_SERVICE -eq 1 ]] && [[ ! -d /run/systemd/system ]]; then
  echo "${JAUNE}systemd ne tourne pas ici : service non installé."
  echo "Lance le mode autonome à la main : sudo marceau --auto${RAZ}"
elif [[ $AVEC_SERVICE -eq 1 ]]; then
  echo "${VERT}==> Service systemd (démarrage automatique)${RAZ}"
  install -m 0644 "$ICI/systemd/marceau.service" "$SERVICE"
  systemctl daemon-reload
  systemctl enable --now marceau.service
  sleep 2
  systemctl --no-pager --lines=5 status marceau.service || true
fi

cat <<EOF

${VERT}✓ Marceau est installé.${RAZ}
  marceau               → menu interactif
  marceau --status      → état du mode autonome + dernières alertes
  journalctl -u marceau -f   → voir le service en direct
  sudo nano $CONFIG     → réglages (e-mail, intervalle, audits)
  sudo systemctl restart marceau  → appliquer après un changement d'intervalle
EOF
