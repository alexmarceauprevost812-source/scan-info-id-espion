# scan-info-id-espion

Découvre les appareils connectés à ton réseau local et signale ceux **jamais vus avant** — pratique pour repérer un intrus ou un appareil suspect sur ton wifi.

> ⚠️ À utiliser **uniquement** sur un réseau que tu possèdes ou administres (ton wifi maison, par exemple).

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
sudo python3 scan_info_id_espion.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
```

### Menu

1. Scanner le réseau maintenant
2. Voir les appareils déjà connus
3. Renommer un appareil
4. Oublier un appareil (il sera de nouveau signalé comme nouveau)
5. Quitter

Les appareils connus sont enregistrés dans `~/.scan_info_id_espion_known_devices.json`.

> Note : avec `sudo`, `~` pointe vers le dossier de `root`, donc le fichier se trouve dans `/root/`.
