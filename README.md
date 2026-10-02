# scan-info-id-espion

Découvre les appareils connectés à ton réseau local et signale ceux **jamais vus avant** — pratique pour repérer un intrus ou un appareil suspect sur ton wifi.

> ⚠️ À utiliser **uniquement** sur un réseau que tu possèdes ou administres (ton wifi maison, par exemple).

C'est un outil **défensif** : il observe et signale. Il n'attaque pas les appareils des autres (pas de déauthentification, pas de vol de secrets/identifiants). Pour retirer un appareil de ton réseau, passe par ton **routeur** : change le mot de passe wifi (WPA2/WPA3), utilise le filtrage MAC, ou mets les invités sur un réseau séparé.

## Prérequis

- Linux (Kali, Ubuntu, Debian…) avec Python 3
- `arp-scan` (recommandé) ou `nmap` :

```bash
sudo apt install arp-scan
# ou
sudo apt install nmap
```

## Utilisation

```bash
sudo python3 scan_info_id_espion.py                 # menu interactif
sudo python3 scan_info_id_espion.py --scan          # scan direct, sans menu
sudo python3 scan_info_id_espion.py --watch 60      # surveillance en boucle (toutes les 60 s)
sudo python3 scan_info_id_espion.py --report html   # exporte un rapport (html ou csv)
sudo python3 scan_info_id_espion.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
```

### Menu

1. Scanner le réseau maintenant
2. Surveillance en continu (intrus + connexion/déconnexion)
3. Voir les appareils déjà connus
4. Voir l'historique de présence
5. Renommer un appareil
6. Oublier un appareil (il sera de nouveau signalé comme nouveau)
7. Auditer un appareil (ports + vulnérabilités connues, lecture seule)
8. Vérifier le chiffrement de ton wifi
9. Exporter un rapport (HTML / CSV / sécurité)
10. Quitter

## Fonctions

- **Détection des nouveaux appareils** : tout appareil jamais vu est signalé `🆕 NOUVEAU`.
- **Alerte intrus** : bip sonore + alerte e-mail optionnelle quand un appareil inconnu apparaît.
- **Surveillance en continu** (`--watch`) : rescan automatique à intervalle régulier, avec
  détection des nouveaux appareils **et** des connexions/déconnexions des appareils connus.
- **Historique de présence** : première/dernière fois vu, nombre de fois vu, et journal horodaté.
- **Identification** : nom réseau (reverse DNS) et fabricant (via arp-scan/nmap).
- **Audit de sécurité (lecture seule)** : pour un appareil **de ton réseau**, liste les ports
  ouverts, estime le type d'appareil/OS et, en option, recherche des vulnérabilités connues
  (CVE) avec les scripts `nmap --script vuln`. C'est de la **détection** : l'outil ne se
  connecte à rien et n'exploite rien. Une confirmation que tu administres bien le réseau
  est demandée avant chaque audit.
- **Vérification du wifi** : détecte le chiffrement du réseau auquel **tu** es connecté
  (WPA3/WPA2/WPA/WEP/ouvert) via `nmcli` et explique s'il est sûr.
- **Notification bureau** : en plus du bip, une notification `notify-send` s'affiche quand
  un appareil inconnu apparaît (si disponible).
- **Export** : rapport HTML, CSV, ou rapport **sécurité** (texte : état du wifi, appareils,
  ports à risque et recommandations).

## Fichiers créés

Dans ton dossier personnel (`~`) :

- `~/.scan_info_id_espion_known_devices.json` — les appareils connus
- `~/.scan_info_id_espion_history.log` — le journal de présence
- `~/.scan_info_id_espion_config.json` — la configuration (voir ci-dessous)

> Note : avec `sudo`, `~` pointe vers le dossier de `root` (`/root/`), pas vers ton dossier personnel.

## Alerte e-mail (optionnelle)

Pour recevoir un e-mail quand un appareil inconnu apparaît, crée le fichier de config
`~/.scan_info_id_espion_config.json` (ou `/root/...` si tu lances avec `sudo`) :

```json
{
  "beep": true,
  "email": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "user": "ton.adresse@gmail.com",
    "password": "mot_de_passe_application",
    "from": "ton.adresse@gmail.com",
    "to": "ton.adresse@gmail.com"
  }
}
```

> Pour Gmail, utilise un **mot de passe d'application** (pas ton mot de passe principal).
> Mets `"beep": false` pour couper le bip sonore.
