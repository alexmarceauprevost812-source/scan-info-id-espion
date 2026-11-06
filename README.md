# Marceau

*(anciennement **scan-info-id-espion** / Prevost ID Scan)*

Découvre les appareils connectés à ton réseau local et signale ceux **jamais vus avant** : pratique pour repérer un intrus ou un appareil suspect sur ton wifi.
Depuis la v2, Marceau peut tourner **tout seul** en arrière-plan (mode autonome) : il surveille, détecte, alerte et écrit ses rapports sans que tu aies à ouvrir le menu.

> ⚠️ À utiliser **uniquement** sur un réseau que tu possèdes ou administres (ton wifi maison, par exemple).

C'est un outil **défensif** : il observe et signale. Il n'attaque pas les appareils des autres (pas de déauthentification, pas de vol de secrets/identifiants). Pour retirer un appareil de ton réseau, passe par ton **routeur** : change le mot de passe wifi (WPA2/WPA3), utilise le filtrage MAC, ou mets les invités sur un réseau séparé.

## Installation express (mode autonome au démarrage)

```bash
git clone https://github.com/alexmarceauprevost812-source/scan-info-id-espion
cd scan-info-id-espion
sudo ./install.sh
```

Le script :

1. installe `python3`, `arp-scan` et `nmap` ;
2. copie Marceau dans `/opt/marceau` et crée la commande **`marceau`** ;
3. crée la config `/var/lib/marceau/.marceau_config.json` et te demande si le réseau est **le tien** (sinon les audits automatiques restent coupés) ;
4. active le service **`marceau.service`**, qui démarre tout seul à chaque allumage.

```bash
marceau --status            # état du mode autonome + dernières alertes
journalctl -u marceau -f    # voir le service en direct
sudo systemctl restart marceau
sudo ./uninstall.sh         # désinstaller (garde tes données) ; --purge pour tout effacer
```

`sudo ./install.sh --no-service` installe juste la commande, sans démarrage automatique.

## Ce que fait le mode autonome

À chaque cycle (toutes les 120 s par défaut) :

| Étape | Par défaut | Réglage dans `"auto"` |
|---|---|---|
| Scan du réseau, nouveaux appareils, connexions/déconnexions | ✅ | `interval` (min 15 s) |
| Détection d'usurpation ARP (MITM) : la MAC du routeur change, ou 2 MAC pour 1 IP | ✅ | `arp_check` |
| Recherche de serveur DHCP pirate | 1×/heure | `dhcp_check_every` (s, 0 = jamais) |
| Scan de ports des **nouveaux** appareils | ❌ | `audit_new_devices` + propriétaire confirmé |
| Audit complet (ports + CVE) de tout le réseau | ❌ | `full_audit_every` (s) + propriétaire confirmé |
| Rapports HTML + sécurité | 1×/jour | `report_every` (s, 0 = jamais) |

- **Premier lancement** : Marceau *apprend* les appareils présents comme référence, sans alerte. Ensuite, tout inconnu déclenche une alerte.
- **Alertes** : journal, notification bureau, e-mail (si configuré) et les 20 dernières visibles avec `marceau --status`.
- **Increvable** : une panne réseau ou une erreur ne tue jamais le service ; le cycle suivant réessaie. Une seule instance à la fois (verrou). `systemctl stop` l'arrête proprement.
- **Config modifiable à chaud** : les changements sont pris en compte au cycle suivant (sauf `interval` : redémarre le service).
- **Service durci** : il ne voit que le réseau et `/var/lib/marceau`.

Sans installer, tu peux aussi lancer :

```bash
sudo python3 marceau.py --auto           # boucle autonome dans le terminal (Ctrl+C pour arrêter)
sudo python3 marceau.py --auto --once    # un seul cycle (test, cron)
sudo python3 marceau.py --auto --interval 60
```

## Configuration

Voir [`config.example.json`](config.example.json) :

```json
{
  "beep": true,
  "network_owner_confirmed": false,
  "auto": {
    "interval": 120,
    "arp_check": true,
    "dhcp_check_every": 3600,
    "audit_new_devices": false,
    "full_audit_every": 0,
    "report_every": 86400,
    "subnet": null
  },
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

- `network_owner_confirmed: true` signifie que tu confirmes que c'est **ton** réseau. Sans ça, aucun audit de ports/CVE n'est lancé automatiquement.
- Pour Gmail, utilise un **mot de passe d'application** (pas ton mot de passe principal). Laisse `smtp_host` vide pour ne pas envoyer d'e-mail.
- `subnet` sert à forcer le sous-réseau si la détection automatique échoue (ex. `"192.168.1.0/24"`).

## Utilisation manuelle (menu)

```bash
marceau                                   # (après install.sh) ou : sudo python3 marceau.py
sudo python3 marceau.py --scan            # scan direct, sans menu
sudo python3 marceau.py --watch 60        # surveillance en boucle dans le terminal
sudo python3 marceau.py --report html     # rapport html, csv ou securite
sudo python3 marceau.py --audit           # audit complet (demande confirmation)
sudo python3 marceau.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
```

Les anciennes commandes `scan_info_id_espion.py` fonctionnent toujours.

### Menu

1. Scanner le réseau maintenant
2. Surveillance en continu (intrus + connexion/déconnexion)
3. Voir les appareils déjà connus
4. Voir l'historique de présence
5. Renommer un appareil
6. Oublier un appareil (il sera de nouveau signalé comme nouveau)
7. Auditer un appareil (ports + vulnérabilités connues, lecture seule)
8. Vérifier le chiffrement de ton wifi
9. Détecter une attaque ARP / usurpation (MITM)
10. Détecter un serveur DHCP pirate
11. Auditer MA machine (services en écoute + pare-feu)
12. Audit AUTOMATIQUE complet du réseau (auto-pentest, lecture seule)
13. Exporter un rapport (HTML / CSV / sécurité)
14. **Mode AUTONOME** (Ctrl+C pour revenir au menu)
15. **État du mode autonome**
16. Quitter

## Fichiers créés

Dans `/var/lib/marceau` (installé avec `install.sh`), sinon dans ton dossier personnel (`~`, ou `/root` avec `sudo`), ou dans le dossier donné par `MARCEAU_HOME` :

- `.marceau_known_devices.json` : les appareils connus
- `.marceau_history.log` : le journal (rotation automatique à 5 Mo)
- `.marceau_config.json` : la configuration
- `.marceau_status.json` : l'état du mode autonome
- `marceau_rapport.html`, `marceau_securite.txt` : les rapports

Les fichiers de l'ancien nom (`.scan_info_id_espion_*`) sont repris automatiquement : tu ne perds pas tes appareils connus.

## Tests

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Les tests simulent le réseau (aucun vrai scan) : parseurs arp-scan/nmap/nmcli, détection ARP et DHCP, apprentissage initial, intrus, connexions/déconnexions, garde-fou propriétaire, rapports, verrou, arrêt par signal. Ils tournent aussi automatiquement sur GitHub (Actions) à chaque push.

## Portée & éthique

Cet outil est **défensif** et fonctionne **en lecture seule** : il observe, détecte et audite.
Il **n'inclut pas**, et n'inclura pas, de fonctions offensives comme la déauthentification (couper un appareil du wifi), le vol de secrets/identifiants ou le cassage de mots de passe, même contre tes propres appareils. Les audits de ports/vulnérabilités ne doivent viser que des appareils d'un réseau que **tu possèdes ou administres** : le menu demande une confirmation avant chaque audit, et le mode autonome exige `"network_owner_confirmed": true`.
