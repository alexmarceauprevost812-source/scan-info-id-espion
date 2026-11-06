#!/usr/bin/env python3
"""
Marceau — Découvre les appareils connectés à ton réseau local
et signale les appareils JAMAIS VUS AVANT (utile pour repérer un intrus
ou un appareil suspect sur ton wifi).

À utiliser UNIQUEMENT sur un réseau que tu possèdes ou administres
(ton wifi maison, par exemple).

C'est un outil DÉFENSIF, en lecture seule : il observe, signale et audite.
Il n'attaque pas les appareils des autres — pas de déauthentification,
pas de vol de secrets/identifiants. Pour retirer un appareil de ton
réseau, passe par ton routeur (mot de passe wifi, filtrage MAC, réseau
invité).

Prérequis (un des deux, arp-scan est préférable):
    sudo apt install arp-scan
    sudo apt install nmap

Usage:
    sudo python3 marceau.py                 # ouvre le menu interactif
    sudo python3 marceau.py --scan          # scan direct, sans menu
    sudo python3 marceau.py --watch 60      # surveille en boucle (toutes les 60 s)
    sudo python3 marceau.py --report html   # exporte un rapport (html ou csv)
    sudo python3 marceau.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"

Mode AUTONOME (tourne tout seul, sans menu ni question — idéal en service systemd):
    sudo python3 marceau.py --auto          # boucle autonome
    sudo python3 marceau.py --auto --once   # un seul cycle (test / cron)
    python3 marceau.py --status             # état du mode autonome
"""

import subprocess
import re
import json
import sys
import os
import argparse
import socket
import time
import csv
import shutil
import signal
import smtplib
import html as html_mod
from email.message import EmailMessage
from datetime import datetime

try:
    import fcntl  # Linux/macOS — verrou pour éviter deux instances autonomes
except ImportError:  # pragma: no cover — Windows
    fcntl = None

__version__ = "2.0.0"

HOME = os.path.expanduser("~")
# MARCEAU_HOME permet de choisir où vivent les données (ex: /var/lib/... en service).
DATA_DIR = os.environ.get("MARCEAU_HOME") or HOME
KNOWN_DEVICES_FILE = os.path.join(DATA_DIR, ".marceau_known_devices.json")
HISTORY_FILE = os.path.join(DATA_DIR, ".marceau_history.log")
CONFIG_FILE = os.path.join(DATA_DIR, ".marceau_config.json")
STATUS_FILE = os.path.join(DATA_DIR, ".marceau_status.json")
LOCK_FILE = os.path.join(DATA_DIR, ".marceau.lock")
HISTORY_MAX_BYTES = 5 * 1024 * 1024  # rotation du journal au-delà de 5 Mo


def _run(cmd, **kwargs):
    """Lance une commande système. Retire « sudo » si on est déjà root ou si
    sudo n'existe pas (ex: service systemd minimal). Point unique, facile à
    simuler dans les tests."""
    if cmd and cmd[0] == "sudo":
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root or shutil.which("sudo") is None:
            cmd = cmd[1:]
    return subprocess.run(cmd, **kwargs)

# Couleurs du terminal (codes ANSI — fonctionnent sur Linux/Kali/Ubuntu)
CYAN = "\033[96m"
LIME = "\033[38;2;50;205;50m"  # vert lime, pour le logo MARCEAU
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def disable_colors():
    """Coupe les couleurs ANSI (journal systemd, redirection vers un fichier)."""
    g = globals()
    for nom in ("CYAN", "LIME", "GREEN", "YELLOW", "RED", "MAGENTA", "BOLD", "DIM", "RESET"):
        g[nom] = ""


if os.environ.get("NO_COLOR"):
    disable_colors()

LOGO_MARCEAU = r"""
    __  ______    ____  _______________   __  __
   /  |/  /   |  / __ \/ ____/ ____/   | / / / /
  / /|_/ / /| | / /_/ / /   / __/ / /| |/ / / /
 / /  / / ___ |/ _, _/ /___/ /___/ ___ / /_/ /
/_/  /_/_/  |_/_/ |_|\____/_____/_/  |_\____/
"""

# Petite caméra de surveillance, affichée en rouge à droite du logo MARCEAU.
LOGO_CAMERA = r"""
   ______________
  |  ____         |))
  | | o  |  REC •  |
  | |____|        |
  |______________|
"""


def print_logo():
    # Logo MARCEAU (vert lime) et la caméra (rouge) côte à côte.
    logo_lines = LOGO_MARCEAU.strip("\n").splitlines()
    camera_lines = LOGO_CAMERA.strip("\n").splitlines()
    largeur = max((len(l) for l in logo_lines), default=0) + 4
    nb = max(len(logo_lines), len(camera_lines))
    print()
    for i in range(nb):
        gauche = logo_lines[i] if i < len(logo_lines) else ""
        droite = camera_lines[i] if i < len(camera_lines) else ""
        print(f"{LIME}{BOLD}{gauche:<{largeur}}{RESET}{RED}{BOLD}{droite}{RESET}")

    print(f"\n{BOLD}🛰️  Détection des appareils sur ton réseau wifi{RESET}")
    print(f"{DIM}   Repère les appareils inconnus en un coup d'œil{RESET}\n")


# --------------------------------------------------------------------------
# Persistance (appareils connus, config)
# --------------------------------------------------------------------------
def migrate_legacy_files():
    """Ancien nom : scan-info-id-espion. On reprend ses fichiers (appareils
    connus, journal, config) pour ne rien perdre après le renommage en Marceau."""
    for nouveau in (KNOWN_DEVICES_FILE, HISTORY_FILE, CONFIG_FILE):
        dossier, nom = os.path.split(nouveau)
        ancien = os.path.join(dossier, nom.replace(".marceau_", ".scan_info_id_espion_", 1))
        if ancien != nouveau and os.path.exists(ancien) and not os.path.exists(nouveau):
            try:
                os.replace(ancien, nouveau)
            except OSError:
                pass


def load_known_devices():
    migrate_legacy_files()
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"{YELLOW}⚠ Fichier des appareils connus illisible, on repart à zéro.{RESET}")
    return {}


def _atomic_write_json(path, data):
    """Écrit le JSON dans un fichier temporaire puis le remplace d'un coup :
    une coupure de courant pendant l'écriture ne corrompt jamais la liste."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def save_known_devices(devices):
    _atomic_write_json(KNOWN_DEVICES_FILE, devices)


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(cfg):
    _atomic_write_json(CONFIG_FILE, cfg)


# --------------------------------------------------------------------------
# Historique / journal
# --------------------------------------------------------------------------
def log_event(message):
    """Écrit une ligne horodatée dans le journal de présence."""
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {message}"
    try:
        # Rotation simple : au-delà de HISTORY_MAX_BYTES on garde une copie .1
        if os.path.exists(HISTORY_FILE) and os.path.getsize(HISTORY_FILE) > HISTORY_MAX_BYTES:
            os.replace(HISTORY_FILE, HISTORY_FILE + ".1")
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    return line


def show_history(lines=40):
    """Affiche les dernières lignes du journal."""
    if not os.path.exists(HISTORY_FILE):
        print(f"{YELLOW}\nAucun historique pour l'instant. Fais un scan d'abord (option 1).{RESET}")
        return
    with open(HISTORY_FILE, "r") as f:
        content = f.read().splitlines()
    print(f"\n{BOLD}Historique de présence ({len(content)} évènement(s), {min(lines, len(content))} derniers){RESET}")
    print(DIM + "-" * 70 + RESET)
    for ln in content[-lines:]:
        if "NOUVEAU" in ln or "intrus" in ln.lower():
            print(f"{RED}{ln}{RESET}")
        else:
            print(ln)


# --------------------------------------------------------------------------
# Alerte intrus (son + e-mail)
# --------------------------------------------------------------------------
def beep(times=3):
    """Bip sonore via le terminal (BEL)."""
    for _ in range(times):
        sys.stdout.write("\a")
        sys.stdout.flush()
        time.sleep(0.25)


def notify_desktop(title, message):
    """Notification visuelle sur le bureau (notify-send), si disponible.
    Pratique pour ne pas rater une détection quand tu n'es pas devant le terminal."""
    try:
        _run(
            ["notify-send", title, message],
            capture_output=True, timeout=5
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # pas de notify-send — le bip terminal suffit


def alert_new_devices(new_devices, cfg):
    """Centralise les alertes sur appareils inconnus : bip + notification + e-mail."""
    if cfg.get("beep", True):
        beep()
    for d in new_devices:
        nom = d.get("hostname") or d.get("vendor") or d["mac"]
        notify_desktop("⚠ Appareil inconnu détecté",
                       f"{nom} vient d'apparaître sur ton réseau ({d['ip']})")
    send_email_alert(new_devices, cfg)


def send_email_alert(new_devices, cfg):
    """Envoie une alerte e-mail si la config SMTP est renseignée.
    Config attendue dans ~/.marceau_config.json :
        {
          "email": {
            "smtp_host": "smtp.gmail.com", "smtp_port": 587,
            "user": "...", "password": "...",
            "from": "...", "to": "..."
          }
        }
    """
    email = cfg.get("email")
    if not email or not email.get("smtp_host"):
        return False

    lignes = "\n".join(
        f"  - {d['ip']}  {d['mac']}  ({d.get('vendor') or '?'})" for d in new_devices
    )
    body = (
        "Alerte Marceau\n\n"
        f"{len(new_devices)} appareil(s) jamais vu(s) détecté(s) sur ton réseau :\n\n"
        f"{lignes}\n\n"
        "Vérifie que tu les reconnais. Si ce n'est pas le cas, change le mot de "
        "passe wifi et utilise le filtrage MAC de ton routeur."
    )

    sujet = f"⚠ {len(new_devices)} appareil(s) inconnu(s) sur ton réseau"
    return send_email_text(sujet, body, cfg)


def send_email_text(subject, body, cfg):
    """Envoie un e-mail texte si la config SMTP est renseignée (sinon ne fait rien)."""
    email = cfg.get("email")
    if not email or not email.get("smtp_host"):
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email.get("from", email.get("user", ""))
    msg["To"] = email.get("to", "")
    msg.set_content(body)

    try:
        with smtplib.SMTP(email["smtp_host"], int(email.get("smtp_port", 587)), timeout=15) as s:
            s.starttls()
            if email.get("user"):
                s.login(email["user"], email.get("password", ""))
            s.send_message(msg)
        print(f"{GREEN}✓ Alerte e-mail envoyée à {email.get('to')}{RESET}")
        return True
    except Exception as e:  # noqa: BLE001 — on ne veut jamais faire planter le scan
        print(f"{YELLOW}⚠ Envoi de l'e-mail impossible : {e}{RESET}")
        return False


# --------------------------------------------------------------------------
# Scans réseau
# --------------------------------------------------------------------------
_IP = r"\d{1,3}(?:\.\d{1,3}){3}"


def parse_arp_scan(stdout):
    """Transforme la sortie d'arp-scan en liste d'appareils (doublons de MAC/IP
    conservés : ils servent à détecter l'usurpation ARP)."""
    devices = []
    pattern = re.compile(rf"^({_IP})\s+([0-9a-fA-F:]{{17}})\s*(.*)$")
    for line in (stdout or "").splitlines():
        m = pattern.match(line.strip())
        if m:
            ip, mac, vendor = m.groups()
            devices.append({"ip": ip, "mac": mac.lower(), "vendor": vendor.strip()})
    return devices


def parse_nmap_ping(stdout):
    """Transforme la sortie de « nmap -sn » en liste d'appareils."""
    devices = []
    ip = None
    for line in (stdout or "").splitlines():
        ip_match = re.search(rf"Nmap scan report for (?:\S+ \()?({_IP})\)?", line)
        mac_match = re.search(r"MAC Address: ([0-9A-Fa-f:]{17}) \((.+)\)", line)
        if ip_match:
            ip = ip_match.group(1)
        if mac_match and ip:
            devices.append({"ip": ip, "mac": mac_match.group(1).lower(), "vendor": mac_match.group(2)})
            ip = None
    return devices


def parse_ip_route(stdout):
    """Renvoie (sous_réseau, passerelle) à partir de « ip route »."""
    subnet = gateway = None
    for line in (stdout or "").splitlines():
        if line.startswith("default"):
            m = re.search(rf"default via ({_IP})", line)
            if m and not gateway:
                gateway = m.group(1)
        elif "/" in line and "src" in line and not subnet:
            subnet = line.split()[0]
    return subnet, gateway


def run_arp_scan():
    """Essaie arp-scan d'abord (plus rapide et précis sur un LAN)."""
    try:
        result = _run(
            ["sudo", "arp-scan", "--localnet"],
            capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ arp-scan a dépassé le délai d'attente.{RESET}")
        return None
    devices = parse_arp_scan(result.stdout)
    return devices if devices else None


def _ip_route():
    try:
        return parse_ip_route(_run(["ip", "route"], capture_output=True, text=True, timeout=10).stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, None


def get_local_subnet():
    """Détecte le sous-réseau local via la table de routage."""
    return _ip_route()[0]


def get_gateway():
    """Renvoie l'IP de la passerelle (le routeur) via la route par défaut."""
    return _ip_route()[1]


def run_nmap(subnet, interactive=True):
    """Repli sur nmap si arp-scan n'est pas installé.
    En mode autonome (interactive=False) on ne pose jamais de question et on
    ne quitte jamais le programme : on renvoie simplement une liste vide."""
    if not subnet:
        if not interactive:
            print(f"{YELLOW}⚠ Sous-réseau introuvable (réglable avec \"subnet\" dans la config).{RESET}")
            return []
        print("Impossible de détecter le sous-réseau automatiquement.")
        subnet = input("Entre ton sous-réseau (ex: 192.168.1.0/24): ").strip()

    try:
        result = _run(
            ["sudo", "nmap", "-sn", subnet],
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        print("Ni arp-scan ni nmap ne sont installés.")
        print("Installe-en un: sudo apt install arp-scan   (ou) sudo apt install nmap")
        if interactive:
            sys.exit(1)
        return []
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ nmap a dépassé le délai d'attente.{RESET}")
        return []
    return parse_nmap_ping(result.stdout)


def scan_network(interactive=True, subnet=None):
    """Renvoie la liste des appareils via arp-scan ou, à défaut, nmap."""
    devices = run_arp_scan()
    if devices is None:
        devices = run_nmap(subnet or get_local_subnet(), interactive=interactive)
    return devices or []


def get_hostname(ip):
    """Essaie de trouver le vrai nom réseau de l'appareil (reverse DNS local).
    Beaucoup de routeurs/appareils répondent à ça (ex: "iphone-de-marie.lan").
    Retourne None si rien n'est trouvé (normal pour certains appareils)."""
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# --------------------------------------------------------------------------
# Audit de sécurité (lecture seule) — ports + vulnérabilités connues
# --------------------------------------------------------------------------
# Ports historiquement à risque — liste informative, pas une liste exhaustive.
RISKY_PORTS = {
    "21": "FTP — souvent non chiffré, mots de passe en clair",
    "23": "Telnet — non chiffré, obsolète, fréquemment visé sur les appareils IoT",
    "139": "SMB/NetBIOS — a servi de porte d'entrée à plusieurs vers (ex: WannaCry)",
    "445": "SMB — a servi de porte d'entrée à plusieurs vers (ex: WannaCry/EternalBlue)",
    "512": "rexec — protocole non chiffré, obsolète",
    "513": "rlogin — protocole non chiffré, obsolète",
    "514": "rsh — protocole non chiffré, obsolète",
    "3389": "RDP — cible fréquente de tentatives de connexion automatisées si exposé",
    "5900": "VNC — souvent utilisé sans chiffrement ni mot de passe fort",
}


def confirm_ownership():
    """Avant un audit d'un appareil, on rappelle le cadre légal et on demande
    confirmation que l'utilisateur administre bien le réseau. Scanner les
    appareils d'autres personnes sans autorisation peut être illégal."""
    print(f"{YELLOW}⚠ L'audit de ports/vulnérabilités ne doit viser que des appareils")
    print(f"  d'un réseau que TU possèdes ou administres, avec l'accord de leur")
    print(f"  propriétaire. Scanner l'appareil de quelqu'un d'autre sans accord")
    print(f"  peut être illégal.{RESET}")
    rep = input("Confirmes-tu que c'est bien ton réseau/ton appareil ? (o/n): ").strip().lower()
    return rep == "o"


def parse_port_scan(stdout):
    """Extrait ports ouverts, OS estimé et type d'appareil d'une sortie « nmap -sV -O »."""
    ports = []
    os_info = None
    device_type = None
    port_pattern = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$")
    for line in (stdout or "").splitlines():
        line = line.strip()
        m = port_pattern.match(line)
        if m:
            port, service, version = m.groups()
            ports.append({"port": port, "service": service, "version": version.strip()})
        elif line.startswith("Running:"):
            os_info = line.replace("Running:", "").strip()
        elif line.startswith("OS details:") and not os_info:
            os_info = line.replace("OS details:", "").strip()
        elif line.startswith("Device type:"):
            device_type = line.replace("Device type:", "").strip()
    return {"ports": ports, "os": os_info, "device_type": device_type}


def risky_ports_of(ports):
    """Liste « port/service » des ports historiquement à risque."""
    return [f"{p['port']}/{p['service']}" for p in ports if p["port"] in RISKY_PORTS]


def parse_cves(text):
    return sorted(set(re.findall(r"(CVE-\d{4}-\d{4,7})", text or "")))


def run_port_scan(ip):
    """Scanne les ports ouverts, les services actifs ET essaie de deviner le type
    d'appareil / système d'exploitation (nmap -sV -O). C'est une estimation basée
    sur des empreintes réseau connues, pas une certitude. Détection seulement —
    n'essaie jamais de se connecter ou d'exploiter quoi que ce soit."""
    try:
        result = _run(
            ["sudo", "nmap", "-sV", "-O", "--osscan-guess", "--open", ip],
            capture_output=True, text=True, timeout=120
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return {"ports": [], "os": None, "device_type": None, "timeout": True}

    res = parse_port_scan(result.stdout)
    res["timeout"] = False
    return res


def run_vuln_script(ip):
    """Lance les scripts de détection de vulnérabilités connues (NSE 'vuln') de nmap.
    C'est un outil standard d'audit de sécurité : il détecte des failles connues (CVE)
    en comparant les versions de services — il n'exploite jamais rien."""
    try:
        result = _run(
            ["sudo", "nmap", "--script", "vuln", ip],
            capture_output=True, text=True, timeout=240
        )
        return result.stdout
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return "(scan abandonné après 4 minutes — trop long)"


def do_vuln_scan(known):
    """Analyse un appareil déjà connu : ports ouverts à risque, puis en option
    une recherche de vulnérabilités connues (CVE) avec les scripts nmap standards.
    Audit en lecture seule — ne se connecte à rien, n'exploite rien."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré pour l'instant. Fais un scan d'abord (option 1).{RESET}")
        return

    do_list(known)
    mac = input("\nAdresse MAC à analyser: ").strip().lower()
    if mac not in known or not known[mac].get("last_ip"):
        print(f"{RED}Appareil pas trouvé ou IP inconnue — refais un scan réseau (option 1) d'abord.{RESET}")
        return

    if not confirm_ownership():
        print(f"{DIM}Audit annulé.{RESET}")
        return

    ip = known[mac]["last_ip"]
    print(f"\n{CYAN}Analyse de {ip}...{RESET}\n")

    resultat_scan = run_port_scan(ip)
    if resultat_scan is None:
        print(f"{RED}nmap n'est pas installé. Installe-le: sudo apt install nmap{RESET}")
        return
    if resultat_scan.get("timeout"):
        print(f"{YELLOW}⚠ L'analyse des ports a dépassé le délai d'attente.{RESET}")
        return

    ports = resultat_scan["ports"]

    if resultat_scan["device_type"] or resultat_scan["os"]:
        print(f"{BOLD}Type d'appareil (estimation):{RESET} {resultat_scan['device_type'] or '?'}")
        print(f"{BOLD}Système probable:{RESET} {resultat_scan['os'] or '?'}\n")
    else:
        print(f"{DIM}Impossible de deviner le type d'appareil ou le système (normal, pas une erreur).{RESET}\n")

    risky_found = []
    if not ports:
        print(f"{GREEN}Aucun port ouvert détecté — bon signe.{RESET}")
    else:
        print(f"{BOLD}{'Port':<8}{'Service':<15}{'Version'}{RESET}")
        print(DIM + "-" * 70 + RESET)
        for p in ports:
            alerte = RISKY_PORTS.get(p["port"])
            couleur = RED if alerte else ""
            print(f"{couleur}{p['port']:<8}{p['service']:<15}{p['version']}{RESET}")
            if alerte:
                print(f"{YELLOW}   ⚠ {alerte}{RESET}")
                risky_found.append(f"{p['port']}/{p['service']}")

    # On garde ces infos pour le rapport de sécurité exportable
    known[mac]["device_type"] = resultat_scan["device_type"]
    known[mac]["os"] = resultat_scan["os"]
    known[mac]["risky_ports"] = risky_found
    save_known_devices(known)

    reponse = input(
        f"\n{DIM}Lancer aussi une recherche de vulnérabilités connues (CVE)? "
        f"Peut prendre 1-4 minutes. (o/n): {RESET}"
    ).strip().lower()

    if reponse == "o":
        print(f"\n{CYAN}Recherche de vulnérabilités en cours...{RESET}\n")
        resultat = run_vuln_script(ip)
        if resultat is None:
            print(f"{RED}nmap n'est pas installé.{RESET}")
        else:
            print(resultat)


# --------------------------------------------------------------------------
# Détection d'attaques (lecture seule) — ARP spoofing / MITM, DHCP pirate
# --------------------------------------------------------------------------
def detect_arp_anomalies(devices, gateway, known_gw_mac=None):
    """Analyse pure (sans réseau) des signes d'usurpation ARP.
    Renvoie (liste_d_alertes, mac_actuelle_de_la_passerelle_ou_None)."""
    ip_to_macs, mac_to_ips = {}, {}
    for d in devices:
        ip_to_macs.setdefault(d["ip"], set()).add(d["mac"])
        mac_to_ips.setdefault(d["mac"], set()).add(d["ip"])

    alertes = []
    gw_mac = None
    if gateway:
        gw_macs = ip_to_macs.get(gateway, set())
        if len(gw_macs) > 1:
            alertes.append(f"Plusieurs MAC répondent pour la passerelle {gateway} : "
                           f"{', '.join(sorted(gw_macs))} — signe classique d'usurpation ARP.")
        elif gw_macs:
            gw_mac = next(iter(gw_macs))
            if known_gw_mac and known_gw_mac != gw_mac:
                alertes.append(f"La MAC de la passerelle {gateway} a CHANGÉ : "
                               f"avant {known_gw_mac}, maintenant {gw_mac}. "
                               f"Cela peut indiquer une attaque (ou un changement de routeur).")

    for mac, ips in sorted(mac_to_ips.items()):
        if len(ips) > 1:
            alertes.append(f"La MAC {mac} répond pour plusieurs IP : {', '.join(sorted(ips))} "
                           f"— à vérifier (usurpation possible, ou routeur/pont légitime).")
    return alertes, gw_mac


def do_arp_spoof_check(known):
    """Repère les signes d'une attaque de type « usurpation ARP » (ARP spoofing /
    man-in-the-middle), où un attaquant se fait passer pour le routeur pour
    intercepter le trafic. Deux signaux :
      1) l'adresse MAC de la passerelle (routeur) a changé depuis la dernière fois ;
      2) une même MAC est associée à plusieurs IP, ou plusieurs MAC répondent
         pour l'IP du routeur.
    Détection uniquement — l'outil ne modifie rien sur le réseau."""
    print(f"\n{CYAN}Recherche de signes d'usurpation ARP (MITM)...{RESET}\n")

    gateway = get_gateway()
    if not gateway:
        print(f"{YELLOW}Impossible de déterminer l'IP de la passerelle.{RESET}")

    devices = scan_network()
    if not devices:
        print(f"{RED}Aucun appareil trouvé — impossible d'analyser.{RESET}")
        return

    cfg = load_config()
    alertes, gw_mac = detect_arp_anomalies(devices, gateway, cfg.get("gateway_mac"))
    if gw_mac:
        if not cfg.get("gateway_mac"):
            cfg["gateway_mac"] = gw_mac
            save_config(cfg)
            print(f"{DIM}MAC de la passerelle enregistrée comme référence : {gw_mac}{RESET}")
        print(f"{BOLD}Passerelle :{RESET} {gateway}  →  {gw_mac}")

    if alertes:
        print(f"\n{RED}{BOLD}⚠ Signes suspects détectés :{RESET}")
        for a in alertes:
            print(f"{RED} - {a}{RESET}")
            log_event(f"⚠ ARP suspect — {a}")
        print(f"\n{YELLOW}Que faire : déconnecte-toi du wifi, redémarre ton routeur, change")
        print(f"son mot de passe d'administration et le mot de passe wifi. Évite les sites")
        print(f"sensibles tant que ce n'est pas réglé.{RESET}")
        beep()
        notify_desktop("⚠ Attaque réseau possible", "Signes d'usurpation ARP détectés")
    else:
        print(f"\n{GREEN}✓ Aucun signe évident d'usurpation ARP.{RESET}")


def parse_dhcp_servers(stdout):
    """Liste triée (sans doublon) des serveurs DHCP ayant répondu."""
    return sorted(set(re.findall(rf"Server Identifier: ({_IP})", stdout or "")))


def run_dhcp_discover():
    """Renvoie la liste des serveurs DHCP, ou None si nmap est absent / trop long."""
    try:
        result = _run(["sudo", "nmap", "--script", "broadcast-dhcp-discover"],
                      capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return parse_dhcp_servers(result.stdout)


def do_rogue_dhcp_check():
    """Cherche un serveur DHCP « pirate » : un serveur DHCP non autorisé branché
    sur le réseau peut rediriger tout ton trafic (attaque MITM). On utilise le
    script nmap standard, en diffusion — détection uniquement."""
    print(f"\n{CYAN}Recherche de serveurs DHCP sur le réseau...{RESET}")
    print(f"{DIM}(un seul serveur DHCP est normal : c'est ton routeur){RESET}\n")
    try:
        result = _run(
            ["sudo", "nmap", "--script", "broadcast-dhcp-discover"],
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        print(f"{RED}nmap n'est pas installé. Installe-le : sudo apt install nmap{RESET}")
        return
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ Recherche trop longue, abandonnée.{RESET}")
        return

    print(result.stdout.strip() or "(aucune réponse)")
    serveurs_uniques = parse_dhcp_servers(result.stdout)

    if len(serveurs_uniques) > 1:
        print(f"\n{RED}{BOLD}⚠ Plusieurs serveurs DHCP détectés : {', '.join(serveurs_uniques)}{RESET}")
        print(f"{YELLOW}Un seul devrait exister (ton routeur). Un serveur DHCP en trop peut")
        print(f"être une attaque. Débranche les appareils suspects et préviens.{RESET}")
        log_event(f"⚠ DHCP multiples : {', '.join(serveurs_uniques)}")
        beep()
    elif serveurs_uniques:
        print(f"\n{GREEN}✓ Un seul serveur DHCP ({serveurs_uniques[0]}) — normal.{RESET}")
    else:
        print(f"\n{DIM}Aucun serveur DHCP identifié par le script (pas forcément un problème).{RESET}")


# --------------------------------------------------------------------------
# Audit de TA propre machine (lecture seule) — durcissement
# --------------------------------------------------------------------------
def do_self_audit():
    """Audit de sécurité de TA machine (celle qui lance le script) : services en
    écoute sur le réseau et état du pare-feu. Aide à réduire ta propre surface
    d'attaque. Lecture seule — ne modifie aucun réglage."""
    print(f"\n{CYAN}Audit de ta machine...{RESET}\n")

    # Services en écoute
    print(f"{BOLD}Services à l'écoute sur le réseau :{RESET}")
    try:
        result = _run(["ss", "-tulnp"], capture_output=True, text=True, timeout=15)
        lignes = result.stdout.splitlines()
        if len(lignes) <= 1:
            print(f"{GREEN}  Aucun service en écoute — très bien.{RESET}")
        else:
            expose = False
            print(DIM + lignes[0] + RESET)
            for ln in lignes[1:]:
                # On signale en rouge ce qui écoute sur toutes les interfaces (0.0.0.0 / *)
                if "0.0.0.0:" in ln or "*:" in ln or "[::]:" in ln:
                    print(f"{YELLOW}{ln}{RESET}")
                    expose = True
                else:
                    print(ln)
            if expose:
                print(f"\n{YELLOW}⚠ Les lignes en jaune écoutent sur TOUTES les interfaces :")
                print(f"  accessibles depuis le réseau. Si tu n'en as pas besoin, désactive")
                print(f"  ces services, ou limite-les à 127.0.0.1 (local).{RESET}")
    except FileNotFoundError:
        print(f"{RED}  Commande 'ss' absente (paquet iproute2).{RESET}")

    # État du pare-feu
    print(f"\n{BOLD}Pare-feu :{RESET}")
    try:
        ufw = _run(["sudo", "ufw", "status"], capture_output=True, text=True, timeout=10)
        sortie = ufw.stdout.strip()
        if "inactive" in sortie.lower():
            print(f"{RED}  ufw est INACTIF. Active-le pour bloquer les connexions entrantes :")
            print(f"    sudo ufw enable{RESET}")
        elif "active" in sortie.lower():
            print(f"{GREEN}  ✓ ufw est actif.{RESET}")
            print(DIM + sortie + RESET)
        else:
            print(sortie or "(pas d'information)")
    except FileNotFoundError:
        print(f"{DIM}  ufw non installé. Pour un pare-feu simple : sudo apt install ufw{RESET}")
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}  Vérification du pare-feu trop longue.{RESET}")


def do_full_audit(known, cfg=None, assume_yes=False):
    """Audit automatique de TOUT ton réseau (auto-pentest en lecture seule) :
    1) scan du réseau pour lister les appareils ;
    2) pour chaque appareil, scan des ports + estimation OS + recherche de
       vulnérabilités connues (CVE) avec les scripts nmap standards ;
    3) vérification du wifi et de ta propre machine ;
    4) rapport de sécurité écrit sur disque.
    Détection uniquement : aucune faille n'est exploitée, aucune attaque réelle
    (brute-force, déauthentification…) n'est lancée. À ne faire QUE sur ton réseau."""
    cfg = cfg if cfg is not None else load_config()

    print(f"\n{BOLD}Audit automatique complet du réseau{RESET}")
    # En mode autonome, la confirmation vient de la config
    # ("network_owner_confirmed": true) au lieu d'une question.
    if assume_yes:
        if not cfg.get("network_owner_confirmed"):
            print(f"{YELLOW}Audit ignoré : mets \"network_owner_confirmed\": true dans la config "
                  f"pour confirmer que c'est ton réseau.{RESET}")
            return
    elif not confirm_ownership():
        print(f"{DIM}Audit annulé.{RESET}")
        return

    # 1) Découverte
    print(f"\n{CYAN}[1/4] Découverte des appareils...{RESET}")
    devices = scan_network(interactive=not assume_yes,
                           subnet=(cfg.get("auto") or {}).get("subnet"))
    if not devices:
        print(f"{RED}Aucun appareil trouvé — audit interrompu.{RESET}")
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    update_from_devices(devices, known, now)
    save_known_devices(known)
    print(f"{GREEN}{len(devices)} appareil(s) à auditer.{RESET}")

    # 2) Audit de chaque appareil (ports + vulnérabilités)
    print(f"\n{CYAN}[2/4] Analyse de chaque appareil (peut être long)...{RESET}")
    for i, d in enumerate(devices, 1):
        ip, mac = d["ip"], d["mac"]
        print(f"\n{BOLD}── ({i}/{len(devices)}) {ip}  {mac}{RESET}")

        res = run_port_scan(ip)
        if res is None:
            print(f"{RED}nmap n'est pas installé — audit interrompu.{RESET}")
            return
        if res.get("timeout"):
            print(f"{YELLOW}  Délai dépassé, appareil ignoré.{RESET}")
            continue

        ports = res["ports"]
        risky = []
        if not ports:
            print(f"{GREEN}  Aucun port ouvert.{RESET}")
        else:
            for p in ports:
                alerte = RISKY_PORTS.get(p["port"])
                marque = f"{RED} ⚠ {alerte}{RESET}" if alerte else ""
                print(f"  {p['port']:<7}{p['service']:<14}{p['version']}{marque}")
                if alerte:
                    risky.append(f"{p['port']}/{p['service']}")

        known[mac]["device_type"] = res["device_type"]
        known[mac]["os"] = res["os"]
        known[mac]["risky_ports"] = risky

        # Recherche de vulnérabilités connues (CVE) — scripts nmap standards
        print(f"{DIM}  Recherche de vulnérabilités connues...{RESET}")
        vuln = run_vuln_script(ip)
        cves = parse_cves(vuln)
        if cves:
            print(f"{RED}  ⚠ Vulnérabilités référencées : {', '.join(cves)}{RESET}")
            known[mac]["cves"] = cves
            log_event(f"⚠ CVE sur {ip} ({mac}) : {', '.join(cves)}")
        else:
            print(f"{GREEN}  Aucune vulnérabilité connue repérée.{RESET}")
            known[mac].pop("cves", None)
        save_known_devices(known)

    # 3) Wifi + machine locale
    print(f"\n{CYAN}[3/4] Vérification du wifi et de ta machine...{RESET}")
    do_wifi_check()
    do_self_audit()

    # 4) Rapport
    print(f"\n{CYAN}[4/4] Génération du rapport de sécurité...{RESET}")
    export_security_report(known)
    print(f"\n{GREEN}{BOLD}✓ Audit complet terminé.{RESET}")


# --------------------------------------------------------------------------
# Vérification du wifi (lecture seule) — ton propre réseau
# --------------------------------------------------------------------------
def parse_nmcli_wifi(stdout):
    """Trouve le wifi actif (« * ») dans « nmcli -t -f IN-USE,SSID,SECURITY »."""
    for line in (stdout or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == "*":
            return {"ssid": parts[1], "security": parts[2] or "Ouvert (aucun chiffrement)"}
    return None


def check_wifi_security():
    """Vérifie le type de chiffrement du wifi auquel TU es actuellement connecté (nmcli)."""
    try:
        result = _run(
            ["nmcli", "-t", "-f", "IN-USE,SSID,SECURITY", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=15
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    return parse_nmcli_wifi(result.stdout)


def do_wifi_check():
    """Vérifie et explique le niveau de sécurité du wifi auquel tu es connecté."""
    print(f"\n{CYAN}Vérification du wifi actuel...{RESET}\n")
    info = check_wifi_security()
    if info is None:
        print(f"{RED}Impossible de vérifier — nmcli n'est pas installé ou aucun wifi actif.{RESET}")
        print(f"{DIM}Essaie: sudo apt install network-manager{RESET}")
        return

    ssid, sec = info["ssid"], info["security"]
    print(f"{BOLD}Réseau: {RESET}{ssid}")
    print(f"{BOLD}Sécurité: {RESET}{sec or 'aucune'}\n")

    sec_upper = (sec or "").upper()
    if "WEP" in sec_upper or sec_upper in ("", "OUVERT (AUCUN CHIFFREMENT)"):
        print(f"{RED}⚠ DANGER — ce chiffrement est faible ou absent. N'importe qui à proximité")
        print(f"peut intercepter ou se connecter facilement. Passe en WPA2 ou WPA3 dans")
        print(f"les paramètres de ton routeur dès que possible.{RESET}")
    elif "WPA3" in sec_upper:
        print(f"{GREEN}✓ Excellent — WPA3 est le standard le plus sécurisé actuellement.{RESET}")
    elif "WPA2" in sec_upper:
        print(f"{GREEN}✓ Correct — WPA2 est encore considéré comme sûr.{RESET}")
    elif "WPA" in sec_upper:
        print(f"{YELLOW}⚠ WPA (version 1) commence à dater — WPA2 ou WPA3 serait préférable")
        print(f"si ton routeur le supporte.{RESET}")
    else:
        print(f"{YELLOW}Type de sécurité non reconnu: {sec}{RESET}")

    return info


# --------------------------------------------------------------------------
# Cœur du scan : mise à jour de l'état + détection des nouveaux
# --------------------------------------------------------------------------
def update_from_devices(devices, known, now):
    """Met à jour `known` à partir des appareils vus. Renvoie la liste des nouveaux."""
    new_devices = []
    for d in devices:
        mac = d["mac"]
        hostname = get_hostname(d["ip"])
        d["hostname"] = hostname

        if mac not in known:
            known[mac] = {
                "first_seen": now, "last_seen": now, "times_seen": 1,
                "vendor": d["vendor"], "hostname": hostname,
                "last_ip": d["ip"], "name": None,
            }
            new_devices.append(d)
            log_event(f"🆕 NOUVEAU appareil — {d['ip']}  {mac}  ({d.get('vendor') or '?'})"
                      f"  nom réseau: {hostname or '(inconnu)'}")
        else:
            info = known[mac]
            info["last_seen"] = now
            info["times_seen"] = info.get("times_seen", 1) + 1
            info["last_ip"] = d["ip"]
            if hostname:
                info["hostname"] = hostname
            if d.get("vendor"):
                info["vendor"] = d["vendor"]
    return new_devices


def do_scan(known, cfg=None, quiet=False):
    """Scanne le réseau, affiche les résultats et met à jour la liste connue."""
    cfg = cfg if cfg is not None else load_config()

    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ Ce script a besoin de sudo pour lire les adresses MAC.{RESET}")
        print(f"{YELLOW}  Relance avec: sudo python3 marceau.py{RESET}\n")

    if not quiet:
        print(f"{CYAN}\nScan du réseau en cours...\n{RESET}")

    devices = scan_network()
    if not devices:
        print(f"{RED}Aucun appareil trouvé. Vérifie que arp-scan ou nmap sont installés{RESET}")
        print(f"{RED}et que tu es bien connecté au wifi à vérifier.{RESET}")
        return []

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    new_devices = update_from_devices(devices, known, now)

    print(f"{BOLD}{'IP':<16}{'MAC':<19}{'Nom réseau':<24}{'Fabricant':<20}{'Statut'}{RESET}")
    print(DIM + "-" * 100 + RESET)
    for d in devices:
        mac = d["mac"]
        info = known[mac]
        if d in new_devices:
            statut = f"{RED}{BOLD}🆕 NOUVEAU{RESET}"
        else:
            statut = f"{DIM}connu depuis {info['first_seen']} (vu {info.get('times_seen', 1)}×){RESET}"
        nom_reseau = info.get("name") or d.get("hostname") or "(inconnu)"
        print(f"{d['ip']:<16}{mac:<19}{nom_reseau[:23]:<24}{(d['vendor'] or '?')[:19]:<20}{statut}")

    save_known_devices(known)

    print(f"\n{GREEN}{len(devices)} appareil(s) trouvé(s), {len(new_devices)} nouveau(x).{RESET}")

    if new_devices:
        print(f"\n{YELLOW}⚠ Appareil(s) jamais vus avant — vérifie que tu les reconnais tous.{RESET}")
        print(f"{YELLOW}  Utilise l'option 5 du menu pour en renommer un.{RESET}")
        alert_new_devices(new_devices, cfg)

    return new_devices


# --------------------------------------------------------------------------
# Surveillance en continu (nouvel appareil + connexion/déconnexion)
# --------------------------------------------------------------------------
def do_watch(known, interval, cfg=None):
    """Scanne en boucle toutes les `interval` secondes. Alerte sur :
       - tout appareil JAMAIS VU (intrus potentiel) : bip + e-mail + journal ;
       - toute connexion / déconnexion d'un appareil connu (présence).
    Ne regarde jamais ce qu'un appareil fait — seulement s'il est présent.
    Ctrl+C pour arrêter."""
    cfg = cfg if cfg is not None else load_config()
    interval = max(15, int(interval))  # on évite de marteler le réseau
    print(f"{CYAN}Surveillance active — scan toutes les {interval} s. Ctrl+C pour arrêter.{RESET}")
    log_event(f"Surveillance démarrée (intervalle {interval}s)")

    presents_avant = None
    try:
        while True:
            print(f"\n{DIM}{'=' * 60}{RESET}")
            print(f"{DIM}Scan — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

            devices = scan_network()
            now = datetime.now().strftime("%Y-%m-%d %H:%M")
            heure = datetime.now().strftime("%H:%M:%S")

            new_devices = update_from_devices(devices, known, now)
            presents_maintenant = {d["mac"] for d in devices}

            # Connexions / déconnexions (seulement après le 1er tour de boucle)
            if presents_avant is not None:
                for mac in presents_maintenant - presents_avant:
                    if any(d["mac"] == mac for d in new_devices):
                        continue  # déjà annoncé comme NOUVEAU
                    nom = known.get(mac, {}).get("name") or known.get(mac, {}).get("hostname") or mac
                    print(f"{GREEN}[{heure}] 🟢 {nom} s'est connecté au réseau{RESET}")
                    log_event(f"🟢 connexion — {nom} ({mac})")
                for mac in presents_avant - presents_maintenant:
                    nom = known.get(mac, {}).get("name") or known.get(mac, {}).get("hostname") or mac
                    print(f"{YELLOW}[{heure}] 🔴 {nom} s'est déconnecté du réseau{RESET}")
                    log_event(f"🔴 déconnexion — {nom} ({mac})")

            if new_devices:
                for d in new_devices:
                    nom = d.get("hostname") or d["mac"]
                    print(f"{RED}{BOLD}[{heure}] 🆕 NOUVEL appareil : {d['ip']} {d['mac']} "
                          f"({d.get('vendor') or '?'}){RESET}")
                alert_new_devices(new_devices, cfg)
            else:
                print(f"{DIM}{len(devices)} appareil(s) présent(s), rien de nouveau.{RESET}")

            save_known_devices(known)
            presents_avant = presents_maintenant
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{LIME}Surveillance arrêtée.{RESET}")
        log_event("Surveillance arrêtée")


# --------------------------------------------------------------------------
# Rapport / export
# --------------------------------------------------------------------------
def export_csv(known, path=None):
    path = path or os.path.join(DATA_DIR, "marceau_rapport.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["mac", "nom_donne", "nom_reseau", "fabricant",
                    "premiere_fois", "derniere_fois", "fois_vu", "derniere_ip"])
        for mac, info in sorted(known.items(), key=lambda kv: kv[1].get("first_seen", "")):
            w.writerow([
                mac, info.get("name") or "", info.get("hostname") or "",
                info.get("vendor") or "", info.get("first_seen", ""),
                info.get("last_seen", ""), info.get("times_seen", 1),
                info.get("last_ip", ""),
            ])
    print(f"{GREEN}✓ Rapport CSV écrit : {path}{RESET}")
    return path


def export_html(known, path=None):
    path = path or os.path.join(DATA_DIR, "marceau_rapport.html")
    rows = []
    for mac, info in sorted(known.items(), key=lambda kv: kv[1].get("first_seen", "")):
        rows.append(
            "<tr>"
            f"<td>{html_mod.escape(mac)}</td>"
            f"<td>{html_mod.escape(info.get('name') or '')}</td>"
            f"<td>{html_mod.escape(info.get('hostname') or '')}</td>"
            f"<td>{html_mod.escape(info.get('vendor') or '')}</td>"
            f"<td>{html_mod.escape(info.get('first_seen', ''))}</td>"
            f"<td>{html_mod.escape(info.get('last_seen', ''))}</td>"
            f"<td>{info.get('times_seen', 1)}</td>"
            f"<td>{html_mod.escape(info.get('last_ip', ''))}</td>"
            "</tr>"
        )
    doc = f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>Marceau — rapport</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;background:#0d1117;color:#e6edf3}}
 h1{{color:#32cd32}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #30363d;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
 th{{background:#161b22}}
 tr:nth-child(even){{background:#161b22}}
 .meta{{color:#8b949e;font-size:.85rem}}
</style></head><body>
<h1>Marceau</h1>
<p class="meta">Rapport généré le {datetime.now().strftime('%Y-%m-%d %H:%M')} — {len(known)} appareil(s) connu(s)</p>
<table>
<tr><th>MAC</th><th>Nom donné</th><th>Nom réseau</th><th>Fabricant</th>
<th>1re fois</th><th>Dernière fois</th><th>Fois vu</th><th>Dernière IP</th></tr>
{''.join(rows)}
</table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"{GREEN}✓ Rapport HTML écrit : {path}{RESET}")
    return path


# --------------------------------------------------------------------------
# Actions du menu
# --------------------------------------------------------------------------
def do_list(known):
    """Affiche tous les appareils déjà vus, même sans scanner à nouveau."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré pour l'instant. Fais un scan d'abord (option 1).{RESET}")
        return

    print(f"\n{BOLD}{'MAC':<19}{'Nom donné':<18}{'Nom réseau':<22}{'Fabricant':<18}"
          f"{'1re fois':<18}{'Vu'}{RESET}")
    print(DIM + "-" * 100 + RESET)
    for mac, info in sorted(known.items(), key=lambda kv: kv[1].get("first_seen", "")):
        nom = (info.get("name") or "(sans nom)")[:17]
        hostname = (info.get("hostname") or "(inconnu)")[:21]
        vendor = (info.get("vendor") or "?")[:17]
        print(f"{mac:<19}{nom:<18}{hostname:<22}{vendor:<18}"
              f"{info.get('first_seen', '?'):<18}{info.get('times_seen', 1)}×")


def do_rename(known):
    """Demande une adresse MAC et un nom, puis enregistre le changement."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré pour l'instant. Fais un scan d'abord (option 1).{RESET}")
        return

    do_list(known)
    mac = input("\nAdresse MAC à renommer: ").strip().lower()
    if mac not in known:
        print(f"{RED}Appareil {mac} pas trouvé dans la liste.{RESET}")
        return
    name = input("Nouveau nom: ").strip()
    known[mac]["name"] = name
    save_known_devices(known)
    print(f"{GREEN}✓ {mac} renommé en « {name} »{RESET}")


def do_forget(known):
    """Retire un appareil de la liste connue (il sera signalé NOUVEAU au prochain scan)."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré pour l'instant.{RESET}")
        return

    do_list(known)
    mac = input("\nAdresse MAC à oublier: ").strip().lower()
    if mac in known:
        del known[mac]
        save_known_devices(known)
        print(f"{GREEN}✓ {mac} retiré de la liste.{RESET}")
    else:
        print(f"{RED}Appareil {mac} pas trouvé dans la liste.{RESET}")


def export_security_report(known, path=None):
    """Rapport texte résumant l'état de sécurité du réseau et des appareils."""
    path = path or os.path.join(DATA_DIR, "marceau_securite.txt")
    lignes = [
        "=== RAPPORT DE SÉCURITÉ — Marceau ===",
        f"Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
    ]

    wifi = check_wifi_security()
    if wifi:
        lignes.append(f"Wifi actuel: {wifi['ssid']} — sécurité: {wifi['security'] or 'aucune'}")
    else:
        lignes.append("Wifi actuel: impossible à vérifier (nmcli non disponible)")
    lignes.append("")

    lignes.append(f"Appareils connus: {len(known)}")
    lignes.append("-" * 60)
    for mac, info in sorted(known.items(), key=lambda kv: kv[1].get("first_seen", "")):
        nom = info.get("name") or info.get("hostname") or info.get("vendor") or mac
        lignes.append(f"- {nom} ({mac})")
        lignes.append(f"    Vu la 1re fois: {info.get('first_seen', '?')}  "
                      f"| dernière: {info.get('last_seen', '?')}  "
                      f"| fois vu: {info.get('times_seen', 1)}")
        if info.get("device_type") or info.get("os"):
            lignes.append(f"    Type/OS estimé: {info.get('device_type') or '?'} / {info.get('os') or '?'}")
        if info.get("risky_ports"):
            lignes.append(f"    ⚠ Ports à risque détectés: {', '.join(info['risky_ports'])}")
        if info.get("cves"):
            lignes.append(f"    ⚠ Vulnérabilités connues (CVE): {', '.join(info['cves'])}")
    lignes.append("")

    lignes.append("Recommandations générales:")
    lignes.append("- Utilise WPA2 ou WPA3 sur ton wifi, jamais WEP ou un réseau ouvert.")
    lignes.append("- Change les mots de passe par défaut de tes appareils (routeur, caméras, etc.).")
    lignes.append("- Désactive les services non utilisés (Telnet, FTP) sur tes appareils si possible.")
    lignes.append("- Mets à jour le firmware de tes appareils régulièrement.")
    lignes.append("- Si un appareil inconnu persiste malgré tes vérifications, change ton mot de passe wifi.")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lignes))
    print(f"{GREEN}✓ Rapport de sécurité écrit : {path}{RESET}")
    return path


def do_report_menu(known):
    """Choix du format d'export."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré. Fais un scan d'abord (option 1).{RESET}")
        return
    fmt = input("Format du rapport (html / csv / securite) [html]: ").strip().lower() or "html"
    if fmt == "csv":
        export_csv(known)
    elif fmt in ("securite", "sécurité", "secu", "txt"):
        export_security_report(known)
    else:
        export_html(known)


def do_watch_menu(known, cfg):
    raw = input("Intervalle entre les scans en secondes [60]: ").strip() or "60"
    try:
        interval = int(raw)
    except ValueError:
        print(f"{RED}Valeur invalide.{RESET}")
        return
    do_watch(known, interval, cfg=cfg)


# --------------------------------------------------------------------------
# Mode AUTONOME — tourne tout seul, sans menu ni question
# --------------------------------------------------------------------------
# Réglages par défaut, surchargés par la section "auto" de la config.
AUTO_DEFAULTS = {
    "interval": 120,            # secondes entre deux scans (minimum 15)
    "arp_check": True,          # détection d'usurpation ARP à chaque cycle
    "dhcp_check_every": 3600,   # recherche de DHCP pirate (s) — 0 = jamais
    "audit_new_devices": False, # scan de ports auto sur tout NOUVEL appareil
    "full_audit_every": 0,      # audit complet (s) — 0 = jamais, 604800 = 1×/semaine
    "report_every": 86400,      # rapports HTML + sécurité (s) — 0 = jamais
    "subnet": None,             # forcer un sous-réseau (ex: "192.168.1.0/24")
}

_stop_requested = False


def auto_settings(cfg):
    """Fusionne la config utilisateur avec les valeurs par défaut."""
    reglages = dict(AUTO_DEFAULTS)
    reglages.update((cfg or {}).get("auto") or {})
    reglages["interval"] = max(15, int(reglages.get("interval") or AUTO_DEFAULTS["interval"]))
    return reglages


def load_status():
    if os.path.exists(STATUS_FILE):
        try:
            with open(STATUS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_status(state):
    try:
        _atomic_write_json(STATUS_FILE, state)
    except OSError:
        pass


def _due(state, cle, every, now_ts):
    """Vrai si une tâche périodique doit être lancée maintenant."""
    if not every or every <= 0:
        return False
    return now_ts - state.get(cle, 0) >= every


def _nom(known, mac):
    info = known.get(mac, {})
    return info.get("name") or info.get("hostname") or info.get("vendor") or mac


def _alerte(state, message, cfg, sujet=None):
    """Journalise + notifie + e-mail. Garde les 20 dernières alertes dans l'état."""
    log_event(f"⚠ {message}")
    print(f"{RED}{BOLD}⚠ {message}{RESET}")
    notify_desktop("⚠ Marceau", message)
    if sujet:
        send_email_text(sujet, f"Alerte Marceau\n\n{message}\n", cfg)
    horodate = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state.setdefault("alerts", []).append(f"{horodate}  {message}")
    state["alerts"] = state["alerts"][-20:]


def auto_cycle(known, cfg, state, now_ts=None):
    """UN cycle autonome complet. Ne lève jamais d'exception pour une panne
    réseau : il note le problème dans l'état et le cycle suivant réessaiera.
    Renvoie un petit résumé (utile pour les tests et le journal)."""
    now_ts = time.time() if now_ts is None else now_ts
    reglages = auto_settings(cfg)
    resume = {"devices": 0, "new": [], "connected": [], "disconnected": [], "alerts": 0}
    alertes_avant = len(state.get("alerts", []))

    devices = scan_network(interactive=False, subnet=reglages.get("subnet"))
    state["last_cycle"] = datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S")
    state["cycles"] = state.get("cycles", 0) + 1
    if not devices:
        state["last_error"] = "Aucun appareil trouvé (arp-scan/nmap absent ou pas de réseau)"
        print(f"{YELLOW}⚠ {state['last_error']}{RESET}")
        return resume
    state.pop("last_error", None)

    # 1) Nouveaux appareils + présence
    now = datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M")
    # Toute première fois (aucun appareil connu) : on APPREND le réseau en
    # silence comme référence, au lieu de crier « intrus » pour chaque appareil.
    apprentissage = not known
    nouveaux = update_from_devices(devices, known, now)
    if apprentissage and nouveaux:
        log_event(f"Référence initiale : {len(nouveaux)} appareil(s) appris")
        print(f"{CYAN}Premier lancement : {len(nouveaux)} appareil(s) mémorisé(s) comme "
              f"référence. Les prochains appareils inconnus déclencheront une alerte.{RESET}")
        resume["learned"] = len(nouveaux)
        nouveaux = []
    nouveaux_macs = {d["mac"] for d in nouveaux}
    presents = {d["mac"] for d in devices}
    avant = state.get("present")
    if avant is not None:
        avant = set(avant)
        for mac in sorted(presents - avant - nouveaux_macs):
            log_event(f"🟢 connexion — {_nom(known, mac)} ({mac})")
            resume["connected"].append(mac)
        for mac in sorted(avant - presents):
            log_event(f"🔴 déconnexion — {_nom(known, mac)} ({mac})")
            resume["disconnected"].append(mac)
    state["present"] = sorted(presents)
    resume["devices"] = len(presents)
    resume["new"] = sorted(nouveaux_macs)

    if nouveaux:
        alert_new_devices(nouveaux, cfg)
        for d in nouveaux:
            _alerte(state, f"Nouvel appareil : {d['ip']} {d['mac']} ({d.get('vendor') or '?'})", cfg)

    # 2) Usurpation ARP
    if reglages.get("arp_check"):
        gateway = get_gateway()
        alertes, gw_mac = detect_arp_anomalies(devices, gateway, cfg.get("gateway_mac"))
        if gw_mac and not cfg.get("gateway_mac"):
            cfg["gateway_mac"] = gw_mac
            sur_disque = load_config()  # on n'écrit que cette clé dans le fichier
            sur_disque["gateway_mac"] = gw_mac
            save_config(sur_disque)
            log_event(f"MAC de référence de la passerelle {gateway} : {gw_mac}")
        for a in alertes:
            _alerte(state, f"ARP suspect — {a}", cfg, sujet="⚠ Attaque réseau possible (ARP)")

    # 3) DHCP pirate (périodique)
    if _due(state, "last_dhcp_ts", reglages.get("dhcp_check_every"), now_ts):
        serveurs = run_dhcp_discover()
        state["last_dhcp_ts"] = now_ts
        if serveurs and len(serveurs) > 1:
            _alerte(state, f"Plusieurs serveurs DHCP : {', '.join(serveurs)}", cfg,
                    sujet="⚠ Serveur DHCP pirate possible")

    proprio = bool(cfg.get("network_owner_confirmed"))

    # 4) Audit de ports des nouveaux appareils (seulement si c'est TON réseau)
    if nouveaux and reglages.get("audit_new_devices") and proprio:
        for d in nouveaux:
            res = run_port_scan(d["ip"])
            if not res or res.get("timeout"):
                continue
            risques = risky_ports_of(res["ports"])
            known[d["mac"]].update(device_type=res["device_type"], os=res["os"], risky_ports=risques)
            if risques:
                _alerte(state, f"Ports à risque sur {d['ip']} ({d['mac']}) : {', '.join(risques)}", cfg)

    # 5) Audit complet périodique (seulement si c'est TON réseau)
    if proprio and _due(state, "last_audit_ts", reglages.get("full_audit_every"), now_ts):
        state["last_audit_ts"] = now_ts
        do_full_audit(known, cfg=cfg, assume_yes=True)

    # 6) Rapports périodiques
    if _due(state, "last_report_ts", reglages.get("report_every"), now_ts):
        state["last_report_ts"] = now_ts
        try:
            export_html(known)
            export_security_report(known)
        except OSError as e:
            print(f"{YELLOW}⚠ Rapport impossible : {e}{RESET}")

    save_known_devices(known)
    resume["alerts"] = len(state.get("alerts", [])) - alertes_avant
    print(f"{DIM}[{state['last_cycle']}] {resume['devices']} appareil(s), "
          f"{len(resume['new'])} nouveau(x), {resume['alerts']} alerte(s){RESET}")
    return resume


def _acquire_lock():
    """Empêche deux instances autonomes en même temps. Renvoie le fichier
    verrouillé (à garder ouvert) ou None si une autre instance tourne déjà."""
    if fcntl is None:
        return open(LOCK_FILE, "w")
    f = open(LOCK_FILE, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        return None
    f.write(str(os.getpid()))
    f.flush()
    return f


def _on_signal(signum, frame):  # noqa: ARG001
    global _stop_requested
    _stop_requested = True


def run_auto(once=False, interval=None):
    """Boucle autonome. Arrêt propre avec Ctrl+C ou `systemctl stop`."""
    global _stop_requested
    _stop_requested = False
    if not sys.stdout.isatty():
        disable_colors()

    os.makedirs(DATA_DIR, exist_ok=True)
    verrou = _acquire_lock()
    if verrou is None:
        print(f"{RED}Une autre instance autonome de Marceau tourne déjà.{RESET}")
        return 1

    anciens = {sig: signal.signal(sig, _on_signal) for sig in (signal.SIGTERM, signal.SIGINT)}

    known = load_known_devices()
    cfg = load_config()
    reglages = auto_settings(cfg)
    if interval:
        reglages["interval"] = max(15, int(interval))
    state = load_status()
    state.update(pid=os.getpid(), version=__version__, mode="autonome",
                 started=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 interval=reglages["interval"], running=True)
    # Après un redémarrage on repart d'une présence vide pour ne pas
    # annoncer de fausses déconnexions.
    state.pop("present", None)

    if not cfg.get("network_owner_confirmed") and (reglages.get("audit_new_devices")
                                                   or reglages.get("full_audit_every")):
        print(f"{YELLOW}⚠ Audits auto désactivés : ajoute \"network_owner_confirmed\": true "
              f"dans {CONFIG_FILE} si c'est bien ton réseau.{RESET}")

    log_event(f"Mode autonome démarré (intervalle {reglages['interval']}s, v{__version__})")
    print(f"{CYAN}Marceau autonome — scan toutes les {reglages['interval']} s.{RESET}")

    code = 0
    try:
        while not _stop_requested:
            try:
                cfg = load_config()  # la config peut être modifiée à chaud
                cfg.setdefault("auto", {})
                cfg_cycle = dict(cfg)
                cfg_cycle["auto"] = dict(cfg["auto"], interval=reglages["interval"])
                auto_cycle(known, cfg_cycle, state)
            except Exception as e:  # noqa: BLE001 — un service ne doit jamais mourir
                state["last_error"] = f"{type(e).__name__}: {e}"
                log_event(f"Erreur pendant un cycle : {state['last_error']}")
                print(f"{RED}Erreur pendant un cycle : {state['last_error']}{RESET}")
                code = 2 if once else 0
            state["next_cycle"] = None if once else datetime.fromtimestamp(
                time.time() + reglages["interval"]).strftime("%Y-%m-%d %H:%M:%S")
            save_status(state)
            if once:
                break
            fin = time.time() + reglages["interval"]
            while not _stop_requested and time.time() < fin:
                time.sleep(min(1.0, max(0.0, fin - time.time())))
    finally:
        state["running"] = False
        state["next_cycle"] = None
        save_status(state)
        log_event("Mode autonome arrêté")
        verrou.close()
        for sig, ancien in anciens.items():  # Ctrl+C refonctionne dans le menu
            signal.signal(sig, ancien)
    print(f"{LIME}Marceau autonome arrêté.{RESET}")
    return code


def show_status():
    """Affiche l'état du mode autonome (lisible même sans sudo si les droits le permettent)."""
    state = load_status()
    if not state:
        print(f"{YELLOW}Le mode autonome n'a encore jamais tourné ici ({DATA_DIR}).{RESET}")
        return 1
    actif = state.get("running")
    print(f"{BOLD}Marceau — mode autonome{RESET}")
    print(f"  État          : {GREEN + 'en marche' if actif else YELLOW + 'arrêté'}{RESET}")
    for cle, libelle in (("version", "Version"), ("started", "Démarré le"),
                         ("interval", "Intervalle (s)"), ("cycles", "Cycles faits"),
                         ("last_cycle", "Dernier cycle"), ("next_cycle", "Prochain cycle"),
                         ("last_error", "Dernière erreur")):
        if state.get(cle) not in (None, ""):
            print(f"  {libelle:<14}: {state[cle]}")
    print(f"  Présents      : {len(state.get('present', []))} appareil(s)")
    alertes = state.get("alerts", [])
    if alertes:
        print(f"\n{BOLD}Dernières alertes :{RESET}")
        for a in alertes[-10:]:
            print(f"{RED}  {a}{RESET}")
    return 0


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------
def print_menu():
    print(f"\n{CYAN}{BOLD}=== Marceau ==={RESET}")
    print(f"{CYAN}1.{RESET} Scanner le réseau maintenant")
    print(f"{CYAN}2.{RESET} Surveillance en continu (intrus + connexion/déconnexion)")
    print(f"{CYAN}3.{RESET} Voir les appareils déjà connus")
    print(f"{CYAN}4.{RESET} Voir l'historique de présence")
    print(f"{CYAN}5.{RESET} Renommer un appareil")
    print(f"{CYAN}6.{RESET} Oublier un appareil (le retraiter comme nouveau)")
    print(f"{CYAN}7.{RESET} Auditer un appareil (ports + vulnérabilités connues, lecture seule)")
    print(f"{CYAN}8.{RESET} Vérifier le chiffrement de ton wifi")
    print(f"{CYAN}9.{RESET} Détecter une attaque ARP / usurpation (MITM)")
    print(f"{CYAN}10.{RESET} Détecter un serveur DHCP pirate")
    print(f"{CYAN}11.{RESET} Auditer MA machine (services en écoute + pare-feu)")
    print(f"{CYAN}12.{RESET} Audit AUTOMATIQUE complet du réseau (auto-pentest, lecture seule)")
    print(f"{CYAN}13.{RESET} Exporter un rapport (HTML / CSV / sécurité)")
    print(f"{CYAN}14.{RESET} Mode AUTONOME (tourne tout seul — Ctrl+C pour revenir)")
    print(f"{CYAN}15.{RESET} État du mode autonome")
    print(f"{CYAN}16.{RESET} Quitter")


def run_menu():
    known = load_known_devices()
    cfg = load_config()
    print_logo()

    while True:
        print_menu()
        choix = input("Choix (1-16): ").strip()
        if choix == "1":
            do_scan(known, cfg=cfg)
        elif choix == "2":
            do_watch_menu(known, cfg)
        elif choix == "3":
            do_list(known)
        elif choix == "4":
            show_history()
        elif choix == "5":
            do_rename(known)
        elif choix == "6":
            do_forget(known)
        elif choix == "7":
            do_vuln_scan(known)
        elif choix == "8":
            do_wifi_check()
        elif choix == "9":
            do_arp_spoof_check(known)
        elif choix == "10":
            do_rogue_dhcp_check()
        elif choix == "11":
            do_self_audit()
        elif choix == "12":
            do_full_audit(known, cfg=cfg)
        elif choix == "13":
            do_report_menu(known)
        elif choix == "14":
            run_auto()
            known = load_known_devices()
        elif choix == "15":
            show_status()
        elif choix == "16":
            print(f"{LIME}À la prochaine!{RESET}")
            break
        else:
            print(f"{RED}Choix invalide, essaie encore.{RESET}")


# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description="Marceau — scanner d'appareils sur ton réseau local")
    parser.add_argument("--version", action="version", version=f"Marceau {__version__}")
    parser.add_argument("--auto", action="store_true",
                         help="Mode autonome : scan + détections + rapports en boucle, sans menu")
    parser.add_argument("--once", action="store_true",
                         help="Avec --auto : un seul cycle puis quitter (test, cron)")
    parser.add_argument("--interval", type=int, metavar="SECONDES",
                         help="Avec --auto : intervalle entre deux cycles (min 15)")
    parser.add_argument("--status", action="store_true",
                         help="Afficher l'état du mode autonome puis quitter")
    parser.add_argument("--rename", nargs=2, metavar=("MAC", "NOM"),
                         help="Donner un nom personnalisé à un appareil déjà vu, sans passer par le menu")
    parser.add_argument("--scan", action="store_true",
                         help="Scanner directement sans passer par le menu")
    parser.add_argument("--watch", nargs="?", const=60, type=int, metavar="SECONDES",
                         help="Surveiller en boucle (par défaut toutes les 60 s) et alerter sur tout nouvel appareil")
    parser.add_argument("--report", choices=["html", "csv", "securite"], metavar="FORMAT",
                         help="Exporter un rapport des appareils connus (html, csv ou securite) puis quitter")
    parser.add_argument("--audit", action="store_true",
                         help="Lancer l'audit automatique complet du réseau (auto-pentest, lecture seule)")
    args = parser.parse_args(argv)

    if args.status:
        return show_status()

    if args.auto:
        if sys.stdout.isatty():
            print_logo()
        return run_auto(once=args.once, interval=args.interval)

    known = load_known_devices()
    cfg = load_config()

    if args.rename:
        mac, name = args.rename
        mac = mac.lower()
        if mac in known:
            known[mac]["name"] = name
            save_known_devices(known)
            print(f"{GREEN}✓ {mac} renommé en « {name} »{RESET}")
        else:
            print(f"{RED}Appareil {mac} pas encore vu — scanne d'abord.{RESET}")
        return

    if args.report:
        if args.report == "csv":
            export_csv(known)
        elif args.report == "securite":
            export_security_report(known)
        else:
            export_html(known)
        return

    if args.watch is not None:
        print_logo()
        do_watch(known, args.watch, cfg=cfg)
        return

    if args.audit:
        print_logo()
        do_full_audit(known, cfg=cfg)
        return

    if args.scan:
        print_logo()
        do_scan(known, cfg=cfg)
        return

    run_menu()


if __name__ == "__main__":
    sys.exit(main() or 0)
