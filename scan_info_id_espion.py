#!/usr/bin/env python3
"""
scan-info-id-espion — Découvre les appareils connectés à ton réseau local
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
    sudo python3 scan_info_id_espion.py                 # ouvre le menu interactif
    sudo python3 scan_info_id_espion.py --scan          # scan direct, sans menu
    sudo python3 scan_info_id_espion.py --watch 60      # temps réel : alerte instantanée + scan toutes les 60 s
    sudo python3 scan_info_id_espion.py --report html   # exporte un rapport (html ou csv)
    sudo python3 scan_info_id_espion.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
"""

import subprocess
import re
import json
import shutil
import sys
import os
import argparse
import socket
import time
import csv
import queue
import smtplib
import struct
import threading
import html as html_mod
from email.message import EmailMessage
from datetime import datetime

HOME = os.path.expanduser("~")
KNOWN_DEVICES_FILE = os.path.join(HOME, ".scan_info_id_espion_known_devices.json")
HISTORY_FILE = os.path.join(HOME, ".scan_info_id_espion_history.log")
CONFIG_FILE = os.path.join(HOME, ".scan_info_id_espion_config.json")

# Couleurs du terminal (codes ANSI — fonctionnent sur Linux/Kali/Ubuntu)
CYAN = "\033[96m"
LIME = "\033[38;2;50;205;50m"  # vert lime, pour le mot ESPION
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

LOGO_SCAN_INFO_ID = r"""
   _____ _________    _   __   _____   ____________     ________
  / ___// ____/   |  / | / /  /  _/ | / / ____/ __ \   /  _/ __ \
  \__ \/ /   / /| | /  |/ /   / //  |/ / /_  / / / /   / // / / /
 ___/ / /___/ ___ |/ /|  /  _/ // /|  / __/ / /_/ /  _/ // /_/ /
/____/\____/_/  |_/_/ |_/  /___/_/ |_/_/    \____/  /___/_____/"""

LOGO_ESPION = r"""
    ___________ ____  ________  _   __
   / ____/ ___// __ \/  _/ __ \/ | / /
  / __/  \__ \/ /_/ // // / / /  |/ /
 / /___ ___/ / ____// // /_/ / /|  /
/_____//____/_/   /___/\____/_/ |_/
"""

# Petite caméra de surveillance, affichée en rouge à droite du logo ESPION.
LOGO_CAMERA = r"""
   ______________
  |  ____         |))
  | | o  |  REC •  |
  | |____|        |
  |______________|
"""


def print_logo():
    print(f"{CYAN}{LOGO_SCAN_INFO_ID}{RESET}")

    # On affiche le logo ESPION (vert) et la caméra (rouge) côte à côte.
    espion_lines = LOGO_ESPION.strip("\n").splitlines()
    camera_lines = LOGO_CAMERA.strip("\n").splitlines()
    largeur = max((len(l) for l in espion_lines), default=0) + 4
    nb = max(len(espion_lines), len(camera_lines))
    for i in range(nb):
        gauche = espion_lines[i] if i < len(espion_lines) else ""
        droite = camera_lines[i] if i < len(camera_lines) else ""
        print(f"{LIME}{BOLD}{gauche:<{largeur}}{RESET}{RED}{BOLD}{droite}{RESET}")

    print(f"\n{BOLD}🛰️  Détection des appareils sur ton réseau wifi{RESET}")
    print(f"{DIM}   Repère les appareils inconnus en un coup d'œil{RESET}\n")


# --------------------------------------------------------------------------
# Persistance (appareils connus, config)
# --------------------------------------------------------------------------
def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        try:
            with open(KNOWN_DEVICES_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            print(f"{YELLOW}⚠ Fichier des appareils connus illisible, on repart à zéro.{RESET}")
    return {}


def save_known_devices(devices):
    # Écriture dans un fichier à part puis remplacement d'un coup : un Ctrl+C
    # en plein milieu ne laisse jamais un fichier tronqué (qui ferait oublier
    # tous les appareils connus et les re-signaler comme NOUVEAUX).
    tmp = KNOWN_DEVICES_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(devices, f, indent=2, ensure_ascii=False)
    os.replace(tmp, KNOWN_DEVICES_FILE)


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------
# Historique / journal
# --------------------------------------------------------------------------
def log_event(message):
    """Écrit une ligne horodatée dans le journal de présence."""
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {message}"
    try:
        with open(HISTORY_FILE, "a") as f:
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
        subprocess.run(
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
    Config attendue dans ~/.scan_info_id_espion_config.json :
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
        "Alerte scan-info-id-espion\n\n"
        f"{len(new_devices)} appareil(s) jamais vu(s) détecté(s) sur ton réseau :\n\n"
        f"{lignes}\n\n"
        "Vérifie que tu les reconnais. Si ce n'est pas le cas, change le mot de "
        "passe wifi et utilise le filtrage MAC de ton routeur."
    )

    msg = EmailMessage()
    msg["Subject"] = f"⚠ {len(new_devices)} appareil(s) inconnu(s) sur ton réseau"
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
def _outil(nom):
    """Chemin de l'outil s'il est installé, sinon None. Les outils réseau sont
    souvent dans /usr/sbin, absent du PATH d'un utilisateur normal."""
    chemin = os.pathsep.join([os.environ.get("PATH", ""), "/usr/local/sbin", "/usr/sbin", "/sbin"])
    return shutil.which(nom, path=chemin)


def _avec_sudo(cmd):
    """Ajoute sudo seulement si on n'est pas déjà root."""
    return cmd if os.geteuid() == 0 else ["sudo"] + cmd


def run_arp_scan(iface=None):
    """Essaie arp-scan d'abord (plus rapide et précis sur un LAN).
    `iface` force la carte à scanner (sinon arp-scan choisit lui-même).
    Renvoie None si arp-scan est absent ou n'a rien trouvé."""
    if not _outil("arp-scan"):
        return None
    cmd = _avec_sudo(["arp-scan", "--localnet"])
    if iface:
        cmd.append(f"--interface={iface}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ arp-scan a dépassé le délai d'attente.{RESET}")
        return None

    devices = []
    pattern = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s+(.*)$")
    for line in result.stdout.splitlines():
        m = pattern.match(line.strip())
        if m:
            ip, mac, vendor = m.groups()
            devices.append({"ip": ip, "mac": mac.lower(), "vendor": vendor.strip()})
    return devices if devices else None


def get_local_subnet():
    """Détecte le sous-réseau local via la table de routage."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "/" in line and "src" in line and "default" not in line:
                return line.split()[0]
    except FileNotFoundError:
        pass
    return None


def get_gateway():
    """Renvoie l'IP de la passerelle (le routeur) via la route par défaut."""
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", line)
                if m:
                    return m.group(1)
    except FileNotFoundError:
        pass
    return None


def run_nmap(subnet, interactif=True):
    """Repli sur nmap si arp-scan n'est pas installé.
    En mode non interactif (surveillance), ne pose jamais de question et ne
    quitte jamais : renvoie None si le scan est impossible."""
    if not subnet:
        if not interactif:
            return None
        print("Impossible de détecter le sous-réseau automatiquement.")
        subnet = input("Entre ton sous-réseau (ex: 192.168.1.0/24): ").strip()

    if not _outil("nmap"):
        if not interactif:
            return None
        print("Ni arp-scan ni nmap ne sont installés.")
        print("Installe-en un: sudo apt install arp-scan   (ou) sudo apt install nmap")
        sys.exit(1)
    try:
        result = subprocess.run(
            _avec_sudo(["nmap", "-sn", subnet]),
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        if not interactif:
            return None
        print("Ni arp-scan ni nmap ne sont installés.")
        print("Installe-en un: sudo apt install arp-scan   (ou) sudo apt install nmap")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ nmap a dépassé le délai d'attente.{RESET}")
        return []

    devices = []
    ip = None
    for line in result.stdout.splitlines():
        ip_match = re.search(r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?", line)
        mac_match = re.search(r"MAC Address: ([0-9A-F:]{17}) \((.+)\)", line)
        if ip_match:
            ip = ip_match.group(1)
        if mac_match and ip:
            devices.append({"ip": ip, "mac": mac_match.group(1).lower(), "vendor": mac_match.group(2)})
            ip = None
    return devices


def scan_network(interactif=True, subnet=None, iface=None):
    """Renvoie la liste des appareils via arp-scan ou, à défaut, nmap.
    En mode non interactif, renvoie None si aucun des deux n'a pu scanner."""
    devices = run_arp_scan(iface)
    if devices is None:
        devices = run_nmap(subnet or get_local_subnet(), interactif=interactif)
        if devices is None:
            return None
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


def run_port_scan(ip):
    """Scanne les ports ouverts, les services actifs ET essaie de deviner le type
    d'appareil / système d'exploitation (nmap -sV -O). C'est une estimation basée
    sur des empreintes réseau connues, pas une certitude. Détection seulement —
    n'essaie jamais de se connecter ou d'exploiter quoi que ce soit."""
    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sV", "-O", "--osscan-guess", "--open", ip],
            capture_output=True, text=True, timeout=120
        )
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return {"ports": [], "os": None, "device_type": None, "timeout": True}

    ports = []
    os_info = None
    device_type = None
    port_pattern = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$")

    for line in result.stdout.splitlines():
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

    return {"ports": ports, "os": os_info, "device_type": device_type, "timeout": False}


def run_vuln_script(ip):
    """Lance les scripts de détection de vulnérabilités connues (NSE 'vuln') de nmap.
    C'est un outil standard d'audit de sécurité : il détecte des failles connues (CVE)
    en comparant les versions de services — il n'exploite jamais rien."""
    try:
        result = subprocess.run(
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

    # MAC(s) répondant pour chaque IP et IP(s) par MAC
    ip_to_macs = {}
    mac_to_ips = {}
    for d in devices:
        ip_to_macs.setdefault(d["ip"], set()).add(d["mac"])
        mac_to_ips.setdefault(d["mac"], set()).add(d["ip"])

    alertes = []

    # 1) MAC de la passerelle
    if gateway:
        gw_macs = ip_to_macs.get(gateway, set())
        if len(gw_macs) > 1:
            alertes.append(f"Plusieurs MAC répondent pour la passerelle {gateway} : "
                           f"{', '.join(gw_macs)} — signe classique d'usurpation ARP.")
        elif gw_macs:
            gw_mac = next(iter(gw_macs))
            cfg = load_config()
            known_gw = cfg.get("gateway_mac")
            if known_gw and known_gw != gw_mac:
                alertes.append(f"La MAC de la passerelle {gateway} a CHANGÉ : "
                               f"avant {known_gw}, maintenant {gw_mac}. "
                               f"Cela peut indiquer une attaque (ou un changement de routeur).")
            elif not known_gw:
                cfg["gateway_mac"] = gw_mac
                save_config(cfg)
                print(f"{DIM}MAC de la passerelle enregistrée comme référence : {gw_mac}{RESET}")
            print(f"{BOLD}Passerelle :{RESET} {gateway}  →  {gw_mac}")

    # 2) Une même MAC sur plusieurs IP (hors passerelle), signe possible de spoof
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            alertes.append(f"La MAC {mac} répond pour plusieurs IP : {', '.join(sorted(ips))} "
                           f"— à vérifier (usurpation possible, ou routeur/pont légitime).")

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


def do_rogue_dhcp_check():
    """Cherche un serveur DHCP « pirate » : un serveur DHCP non autorisé branché
    sur le réseau peut rediriger tout ton trafic (attaque MITM). On utilise le
    script nmap standard, en diffusion — détection uniquement."""
    print(f"\n{CYAN}Recherche de serveurs DHCP sur le réseau...{RESET}")
    print(f"{DIM}(un seul serveur DHCP est normal : c'est ton routeur){RESET}\n")
    try:
        result = subprocess.run(
            ["sudo", "nmap", "--script", "broadcast-dhcp-discover"],
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
        print(f"{RED}nmap n'est pas installé. Installe-le : sudo apt install nmap{RESET}")
        return
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}⚠ Recherche trop longue, abandonnée.{RESET}")
        return

    serveurs = re.findall(r"Server Identifier: (\d{1,3}(?:\.\d{1,3}){3})", result.stdout)
    print(result.stdout.strip() or "(aucune réponse)")
    serveurs_uniques = sorted(set(serveurs))

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
        result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True, timeout=15)
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
        ufw = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True, timeout=10)
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


def do_full_audit(known, cfg=None):
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
    if not confirm_ownership():
        print(f"{DIM}Audit annulé.{RESET}")
        return

    # 1) Découverte
    print(f"\n{CYAN}[1/4] Découverte des appareils...{RESET}")
    devices = scan_network()
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
        cves = sorted(set(re.findall(r"(CVE-\d{4}-\d{4,7})", vuln or "")))
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
def check_wifi_security():
    """Vérifie le type de chiffrement du wifi auquel TU es actuellement connecté (nmcli)."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "IN-USE,SSID,SECURITY", "device", "wifi", "list"],
            capture_output=True, text=True, timeout=15
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    for line in result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] == "*":
            return {"ssid": parts[1], "security": parts[2] or "Ouvert (aucun chiffrement)"}
    return None


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
        print(f"{YELLOW}  Relance avec: sudo python3 scan_info_id_espion.py{RESET}\n")

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
# Temps réel : confirmation du réseau + écoute ARP passive
# --------------------------------------------------------------------------
ETH_P_ARP = 0x0806
PACKET_OUTGOING = 4      # trame envoyée par TA machine (pas par un autre appareil)
INTERVALLE_MIN = 15      # on évite de marteler le réseau avec les scans actifs
DELAI_FIN_SCAN = 0.5     # laisse l'écoute livrer ce qu'elle a entendu pendant le scan
INDISPONIBLE = "Indisponible"
ARPHRD_ETHER = 1         # wifi et câble : les seules cartes qui parlent ARP ici
TYPES_INTERFACE = {65534: "tunnel/VPN", 512: "PPP", 772: "boucle locale"}


def parse_arp_frame(frame):
    """Lit une trame Ethernet brute. Si c'est un paquet ARP (IPv4), renvoie
    (mac, ip) de l'appareil qui l'a émis, sinon None.

    Tout appareil qui rejoint ton réseau envoie de l'ARP : pour annoncer son
    adresse, vérifier qu'elle est libre (sonde) ou trouver le routeur. On ne
    fait qu'écouter : rien n'est envoyé."""
    if len(frame) < 14:
        return None
    offset = 12
    ethertype = struct.unpack("!H", frame[offset:offset + 2])[0]
    offset += 2
    while ethertype in (0x8100, 0x88A8):        # étiquette(s) VLAN
        if len(frame) < offset + 4:
            return None
        ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if ethertype != ETH_P_ARP:
        return None
    arp = frame[offset:offset + 28]
    if len(arp) < 28:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", arp[:8])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4 or oper not in (1, 2):
        return None
    sha, spa, tpa = arp[8:14], arp[14:18], arp[24:28]
    if sha[0] & 1 or sha == b"\x00" * 6:        # MAC nulle, de diffusion ou multicast
        return None
    mac = ":".join(f"{b:02x}" for b in sha)
    ip = socket.inet_ntoa(spa)
    if ip == "0.0.0.0":
        # Sonde ARP : l'appareil n'a pas encore d'IP, il vérifie que celle
        # qu'il veut prendre est libre. C'est souvent le tout premier signe.
        ip = socket.inet_ntoa(tpa)
        if ip == "0.0.0.0":
            return None
    return mac, ip


def _lire(chemin):
    try:
        with open(chemin, "r") as f:
            return f.read()
    except OSError:
        return None


def _routes(texte):
    """Lignes utiles de /proc/net/route : (iface, dest, passerelle, flags,
    métrique, masque). Les adresses y sont écrites dans l'ordre de la machine."""
    for ligne in (texte or "").splitlines()[1:]:
        champs = ligne.split()
        if len(champs) < 8:
            continue
        try:
            yield (champs[0], int(champs[1], 16), int(champs[2], 16), int(champs[3], 16),
                   int(champs[6]), int(champs[7], 16))
        except ValueError:
            continue


def _ip_texte(valeur):
    return socket.inet_ntoa(struct.pack("=L", valeur))


def parse_proc_routes(texte):
    """Routes par défaut de /proc/net/route, de la meilleure (plus petite
    métrique) à la moins bonne : liste de (interface, passerelle)."""
    routes = [(metrique, iface, _ip_texte(gw))
              for iface, dest, gw, flags, metrique, masque in _routes(texte)
              if dest == 0 and masque == 0 and flags & 0x1 and flags & 0x2]   # RTF_UP + RTF_GATEWAY
    routes.sort(key=lambda r: r[0])
    return [(iface, gw) for _, iface, gw in routes]


def parse_proc_route(texte):
    """(interface, passerelle) de la meilleure route par défaut, ou (None, None)."""
    routes = parse_proc_routes(texte)
    return routes[0] if routes else (None, None)


def subnet_from_proc_route(texte, iface, ip=None):
    """Sous-réseau local de `iface` (ex. 192.168.1.0/24), lu dans les routes
    sans passerelle de /proc/net/route. Préfère celui qui contient `ip` : un
    réseau Docker ou de VM sur une autre interface n'est jamais choisi."""
    candidats = sorted(
        (metrique, dest, masque)
        for nom, dest, gw, flags, metrique, masque in _routes(texte)
        if nom == iface and flags & 0x1 and not flags & 0x2 and gw == 0
        and masque not in (0, 0xFFFFFFFF))
    if not candidats:
        return None
    choix = candidats[0]
    if ip:
        try:
            ip_n = struct.unpack("=L", socket.inet_aton(ip))[0]
        except OSError:
            ip_n = None
        dedans = [c for c in candidats if ip_n is not None and ip_n & c[2] == c[1]]
        if dedans:
            choix = max(dedans, key=lambda c: bin(c[2]).count("1"))
    _, dest, masque = choix
    return f"{_ip_texte(dest)}/{bin(masque).count('1')}"


def parse_proc_arp(texte, ip, iface=None):
    """MAC connue pour `ip` dans /proc/net/arp (entrée complète, et sur
    `iface` si on la donne), ou None."""
    for ligne in (texte or "").splitlines()[1:]:
        champs = ligne.split()
        if len(champs) < 6 or champs[0] != ip:
            continue
        try:
            flags = int(champs[2], 16)
        except ValueError:
            continue
        if not flags & 0x2 or champs[3] == "00:00:00:00:00:00":   # ATF_COM : entrée complète
            continue
        if iface and champs[5] != iface:
            continue
        return champs[3].lower()
    return None


def parse_nmcli_wifi(texte):
    """Lit la sortie de `nmcli -t -f ACTIVE,SSID,SECURITY device wifi list`
    et renvoie {"ssid", "security"} du wifi actif, ou None. En mode -t,
    nmcli échappe les « : » d'un nom de wifi en « \\: »."""
    for ligne in (texte or "").splitlines():
        champs, courant, i = [], "", 0
        while i < len(ligne):
            c = ligne[i]
            if c == "\\" and i + 1 < len(ligne):
                courant += ligne[i + 1]
                i += 2
                continue
            if c == ":":
                champs.append(courant)
                courant = ""
            else:
                courant += c
            i += 1
        champs.append(courant)
        if len(champs) >= 3 and champs[0].lower() in ("yes", "oui"):
            return {"ssid": champs[1], "security": champs[2] or "Ouvert (aucun chiffrement)"}
    return None


def get_active_wifi(iface):
    """Nom et sécurité du wifi actif sur `iface`, sans relancer de recherche.
    Renvoie (infos, None) ou (None, raison)."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "device", "wifi", "list",
             "ifname", iface, "--rescan", "no"],
            capture_output=True, text=True, timeout=10,
            env={**os.environ, "LC_ALL": "C"},     # « yes » et pas « oui »/« ja »…
        )
    except FileNotFoundError:
        return None, "nmcli n'est pas installé"
    except subprocess.TimeoutExpired:
        return None, "nmcli ne répond pas"
    if result.returncode != 0:
        erreur = (result.stderr or "").strip().splitlines()
        return None, (f"nmcli : {erreur[0]}" if erreur else f"nmcli a échoué (code {result.returncode})")
    info = parse_nmcli_wifi(result.stdout)
    if info is None:
        return None, "aucun wifi actif trouvé par nmcli"
    return info, None


def get_own_ip(gateway):
    """Ton IP sur le réseau : celle que le système utiliserait pour joindre le
    routeur. Aucune donnée n'est envoyée (UDP sans envoi)."""
    if not gateway:
        return None
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gateway, 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        if s is not None:
            s.close()


def interface_hw_type(iface):
    """Type matériel de l'interface (1 = wifi/câble, 65534 = tunnel…), ou None."""
    try:
        return int((_lire(f"/sys/class/net/{iface}/type") or "").strip())
    except ValueError:
        return None


def get_own_macs():
    """MAC de toutes les cartes réseau de cette machine (sauf « lo ») : avec
    deux cartes sur le même réseau, l'autre n'est pas un « nouvel appareil »."""
    macs = set()
    try:
        noms = os.listdir("/sys/class/net")
    except OSError:
        return macs
    for nom in noms:
        if nom == "lo":
            continue
        mac = (_lire(f"/sys/class/net/{nom}/address") or "").strip().lower()
        if mac and mac != "00:00:00:00:00:00":
            macs.add(mac)
    return macs


def get_network_info():
    """Rassemble ce qui identifie le réseau surveillé. Chaque valeur absente
    est None, avec sa raison dans info["raisons"] — jamais une valeur inventée."""
    info = {"iface": None, "type": None, "arp": None, "ip": None, "subnet": None,
            "gateway": None, "gateway_mac": None, "ssid": None,
            "security": None, "own_mac": None, "raisons": {}}
    raisons = info["raisons"]

    texte_route = _lire("/proc/net/route")
    if texte_route is None:
        raisons["iface"] = "/proc/net/route illisible (Linux seulement)"
    else:
        routes = parse_proc_routes(texte_route)
        if routes:
            # Un VPN prend souvent la route par défaut : on préfère la vraie
            # carte (wifi ou câble), celle qui voit les appareils de la maison.
            info["iface"], info["gateway"] = next(
                (r for r in routes if interface_hw_type(r[0]) == ARPHRD_ETHER), routes[0])
        else:
            raisons["iface"] = "aucune route par défaut : es-tu connecté au réseau ?"
    if not info["gateway"]:
        raisons["gateway"] = raisons.get("iface", "aucune route par défaut")

    iface = info["iface"]
    if iface:
        hw = interface_hw_type(iface)
        if hw is None or hw == ARPHRD_ETHER:
            info["arp"] = True
            info["type"] = "wifi" if os.path.isdir(f"/sys/class/net/{iface}/wireless") else "filaire"
        else:
            info["arp"] = False
            info["type"] = TYPES_INTERFACE.get(hw, f"autre (type {hw})")
        mac = (_lire(f"/sys/class/net/{iface}/address") or "").strip().lower()
        info["own_mac"] = mac if mac and mac != "00:00:00:00:00:00" else None

    if info["gateway"]:
        if info["arp"]:
            info["gateway_mac"] = parse_proc_arp(_lire("/proc/net/arp"), info["gateway"], iface)
            if not info["gateway_mac"]:
                raisons["gateway_mac"] = "le routeur n'est pas encore dans la table ARP"
        else:
            raisons["gateway_mac"] = f"pas d'ARP sur une interface {info['type']}"
        info["ip"] = get_own_ip(info["gateway"])
        if not info["ip"]:
            raisons["ip"] = "adresse locale introuvable"

    if iface:
        info["subnet"] = subnet_from_proc_route(texte_route, iface, info["ip"])
        if not info["subnet"]:
            raisons["subnet"] = f"aucun sous-réseau local sur {iface} dans la table de routage"
    else:
        raisons["subnet"] = raisons.get("iface", "interface inconnue")

    if info["type"] == "wifi":
        wifi, raison = get_active_wifi(iface)
        if wifi:
            info["ssid"], info["security"] = wifi["ssid"], wifi["security"]
        else:
            raisons["ssid"] = raison
    elif info["type"] == "filaire":
        raisons["ssid"] = "réseau filaire (pas de wifi)"
    elif info["type"]:
        raisons["ssid"] = f"interface {info['type']} (pas de wifi)"
    else:
        raisons["ssid"] = raisons.get("iface", "interface inconnue")
    return info


def _valeur(info, cle):
    v = info.get(cle)
    if v:
        return v
    raison = info.get("raisons", {}).get(cle)
    return f"{INDISPONIBLE} ({raison})" if raison else INDISPONIBLE


def network_label(info):
    """Résumé court du réseau, pour le journal et les alertes."""
    nom = info.get("ssid") or (f"{info.get('type')} {info.get('iface')}" if info.get("iface") else None)
    return f"{nom or 'réseau inconnu'} (routeur {info.get('gateway') or '?'})"


def confirm_network(info):
    """Affiche le réseau réellement surveillé, pour que tu confirmes que c'est
    bien le tien avant de lancer la surveillance."""
    print(f"{BOLD}📡 Réseau surveillé :{RESET}")
    iface = info.get("iface")
    print(f"   Interface : {iface + ' (' + info['type'] + ')' if iface else _valeur(info, 'iface')}")
    if info.get("ssid"):
        print(f"   Wifi      : {info['ssid']} — sécurité : {info.get('security') or '?'}")
    else:
        print(f"   Wifi      : {_valeur(info, 'ssid')}")
    print(f"   Ton IP    : {_valeur(info, 'ip')}   sous-réseau : {_valeur(info, 'subnet')}")
    print(f"   Routeur   : {_valeur(info, 'gateway')}  →  MAC {_valeur(info, 'gateway_mac')}")
    if not iface:
        print(f"{YELLOW}⚠ Aucun réseau détecté — la surveillance ne verra rien tant que tu n'es pas connecté.{RESET}")
    elif info.get("arp") is False:
        print(f"{YELLOW}⚠ {iface} est une interface {info['type']} sans ARP : l'écoute instantanée "
              f"ne peut pas y voir les appareils de la maison.{RESET}")


def fusionner_reseau(ref, nouveau):
    """nmcli ou la table ARP peuvent rater une lecture. Sur la même interface
    et le même routeur, on garde la dernière valeur connue au lieu de croire
    que le wifi a changé."""
    if (not ref or not nouveau.get("iface") or ref.get("iface") != nouveau.get("iface")
            or ref.get("gateway") != nouveau.get("gateway")):
        return nouveau
    fusion = dict(nouveau)
    fusion["raisons"] = dict(nouveau.get("raisons", {}))
    for cle in ("ssid", "security", "gateway_mac", "subnet", "ip", "own_mac"):
        if not fusion.get(cle) and ref.get(cle):
            fusion[cle] = ref[cle]
            fusion["raisons"].pop(cle, None)
    return fusion


def network_changes(avant, apres):
    """Compare deux états du réseau. Renvoie la liste des changements notables.
    Le nom du wifi n'est comparé que si on le connaît des deux côtés."""
    changements = []
    if avant.get("iface") != apres.get("iface"):
        changements.append(f"interface {avant.get('iface') or 'aucune'} → {apres.get('iface') or 'aucune'}")
    if avant.get("ssid") and apres.get("ssid") and avant["ssid"] != apres["ssid"]:
        changements.append(f"wifi « {avant['ssid']} » → « {apres['ssid']} »")
    if avant.get("gateway") != apres.get("gateway"):
        changements.append(f"routeur {avant.get('gateway') or 'aucun'} → {apres.get('gateway') or 'aucun'}")
    return changements


def verifier_routeur(routeurs_vus, alertes_routeur, info):
    """Retient la MAC du routeur pour chaque réseau (même wifi, même IP de
    routeur). Si elle change, renvoie un message d'alerte — une seule fois par
    MAC suspecte — sinon None."""
    mac, gw = info.get("gateway_mac"), info.get("gateway")
    if not mac or not gw:
        return None
    cle = (info.get("ssid") or f"{info.get('type')}:{info.get('iface')}", gw)
    premiere = routeurs_vus.setdefault(cle, mac)
    if mac == premiere or (cle, mac) in alertes_routeur:
        return None
    alertes_routeur.add((cle, mac))
    return (f"MAC du routeur {gw} : {premiere} → {mac} sur le même réseau — possible "
            f"usurpation ARP (ou routeur remplacé), vérifie avec l'option 9")


def _ouvrir_socket_arp(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    try:
        s.bind((iface, ETH_P_ARP))     # Python fait lui-même le htons ici
        s.settimeout(1.0)
    except OSError:
        s.close()
        raise
    return s


def raison_ecoute(erreur, iface=None):
    """Explique en clair pourquoi l'écoute instantanée n'a pas pu démarrer."""
    if isinstance(erreur, PermissionError):
        return "il faut lancer le script avec sudo pour écouter le réseau"
    if isinstance(erreur, AttributeError):
        return "ce système ne permet pas l'écoute brute (Linux seulement)"
    if isinstance(erreur, OSError) and erreur.errno == 19:
        return f"interface {iface or '?'} introuvable"
    return f"erreur système : {erreur}"


class EcouteArp(threading.Thread):
    """Écoute passive de l'ARP sur une interface. Chaque appareil entendu est
    déposé dans la file `evenements` sous la forme (mac, ip). N'envoie rien."""

    def __init__(self, iface, evenements, ouvrir=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.evenements = evenements
        self._ouvrir = ouvrir or _ouvrir_socket_arp
        self._arret = threading.Event()
        self.prete = threading.Event()
        self.erreur = None

    def run(self):
        try:
            sock = self._ouvrir(self.iface)
        except (OSError, AttributeError) as e:
            self.erreur = raison_ecoute(e, self.iface)
            self.prete.set()
            return
        self.prete.set()
        try:
            while not self._arret.is_set():
                try:
                    trame, adresse = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError as e:
                    self.erreur = f"écoute interrompue : {e}"
                    break
                if len(adresse) >= 3 and adresse[2] == PACKET_OUTGOING:
                    continue    # c'est TA machine qui parle
                lu = parse_arp_frame(trame)
                if lu:
                    self.evenements.put(lu)
        finally:
            sock.close()

    def arreter(self):
        self._arret.set()


def demarrer_ecoute(iface, evenements, fabrique=None, arp=True):
    """Lance l'écoute sur `iface`. Renvoie (ecoute, None) si elle tourne,
    (None, raison) sinon."""
    if not iface:
        return None, "aucune interface réseau active"
    if not arp:
        return None, f"interface {iface} sans ARP (VPN ou tunnel ?)"
    ecoute = (fabrique or EcouteArp)(iface, evenements)
    ecoute.start()
    ecoute.prete.wait(3)
    if ecoute.erreur:
        return None, ecoute.erreur
    if not ecoute.prete.is_set():
        ecoute.arreter()
        return None, "l'écoute n'a pas démarré à temps"
    return ecoute, None


def handle_live_event(mac, ip, known, presents, own_macs, now):
    """Traite un appareil entendu en temps réel. Renvoie :
       ("nouveau", appareil) — jamais vu : à signaler tout de suite ;
       ("connexion", mac)    — connu, il revient sur le réseau ;
       ("maj", mac)          — déjà là, sa fiche a juste changé (heure, IP) ;
       None                  — rien à faire ni à enregistrer."""
    if mac in own_macs:
        return None
    if mac not in known:
        # Pas de recherche de nom ici : elle retarderait l'alerte. Le nom
        # réseau et le fabricant sont complétés au prochain scan.
        known[mac] = {"first_seen": now, "last_seen": now, "times_seen": 1,
                      "vendor": "", "hostname": None, "last_ip": ip, "name": None}
        log_event(f"🆕 NOUVEAU appareil (instantané) — {ip}  {mac}")
        presents.add(mac)
        return ("nouveau", {"ip": ip, "mac": mac, "vendor": "", "hostname": None})
    info = known[mac]
    modifie = info.get("last_seen") != now or info.get("last_ip") != ip
    info["last_seen"] = now
    info["last_ip"] = ip
    if mac not in presents:
        presents.add(mac)
        return ("connexion", mac)
    return ("maj", mac) if modifie else None


def _nom(known, mac):
    info = known.get(mac, {})
    return info.get("name") or info.get("hostname") or info.get("vendor") or mac


def _maintenant():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _heure():
    return datetime.now().strftime("%H:%M:%S")


def _vider(evenements):
    """Tout ce que l'écoute a déposé dans la file, sans attendre."""
    lus = []
    while True:
        try:
            lus.append(evenements.get_nowait())
        except queue.Empty:
            return lus


# --------------------------------------------------------------------------
# Surveillance en temps réel (nouvel appareil + connexion/déconnexion)
# --------------------------------------------------------------------------
class Surveillance:
    """État de la surveillance en temps réel (voir do_watch)."""

    def __init__(self, known, interval, cfg, fabrique_ecoute=None):
        self.known = known
        self.interval = interval
        self.cfg = cfg
        self.fabrique = fabrique_ecoute
        self.evenements = queue.Queue()
        self.ecoute = None
        self.raison_ecoute = None    # dernière raison d'indisponibilité affichée
        self.reseau = {}
        self.dernier_reseau = None   # dernier réseau connecté (pour « réseau retrouvé »)
        self.own_macs = set()
        self.presents_avant = None   # présents au dernier scan réussi (None : pas encore de base)
        self.presents = set()        # présents à l'instant (scan + écoute)
        self.entendus = set()        # entendus par l'écoute depuis le dernier scan réussi
        self.routeurs_vus = {}
        self.alertes_routeur = set()

    # --- écoute -----------------------------------------------------------
    def _lancer_ecoute(self, premiere=False):
        self.ecoute, raison = demarrer_ecoute(self.reseau.get("iface"), self.evenements,
                                              self.fabrique, arp=self.reseau.get("arp") is not False)
        if self.ecoute:
            if premiere:
                print(f"{GREEN}⚡ Écoute instantanée active sur {self.ecoute.iface} : un nouvel "
                      f"appareil est signalé dès qu'il se connecte.{RESET}")
            else:
                print(f"{GREEN}⚡ Écoute instantanée active sur {self.ecoute.iface}.{RESET}")
                log_event(f"écoute instantanée active sur {self.ecoute.iface}")
            self.raison_ecoute = None
        elif raison != self.raison_ecoute:
            print(f"{YELLOW}⚡ Écoute instantanée : {INDISPONIBLE} ({raison}).{RESET}")
            print(f"{YELLOW}  Détection seulement par scan, toutes les {self.interval} s.{RESET}")
            if not premiere:
                log_event(f"écoute instantanée indisponible — {raison}")
            self.raison_ecoute = raison
        return raison

    def _arreter_ecoute(self):
        if self.ecoute:
            self.ecoute.arreter()
            self.ecoute = None

    def _rebaser(self):
        """Autre réseau ou réseau perdu : on repart d'une présence vide (sinon
        tout le monde serait « déconnecté » puis « connecté » à tort) et d'une
        file neuve (rien de l'ancien réseau ne se mélange au nouveau)."""
        self._arreter_ecoute()
        self.evenements = queue.Queue()
        self.presents_avant = None
        self.presents = set()
        self.entendus = set()

    # --- réseau -----------------------------------------------------------
    def demarrer(self):
        self.reseau = get_network_info()
        confirm_network(self.reseau)
        if self.reseau.get("iface"):
            self.dernier_reseau = self.reseau
            verifier_routeur(self.routeurs_vus, self.alertes_routeur, self.reseau)
        self.own_macs = get_own_macs() | {m for m in (self.reseau.get("own_mac"),) if m}
        raison = self._lancer_ecoute(premiere=True)
        print(f"{CYAN}Scan de renfort toutes les {self.interval} s. Ctrl+C pour arrêter.{RESET}")
        log_event(f"Surveillance démarrée — {network_label(self.reseau)}, scan toutes les "
                  f"{self.interval}s, écoute instantanée "
                  f"{'active' if self.ecoute else 'indisponible (' + str(raison) + ')'}")

    def _verifier_reseau(self):
        avant = self.reseau
        nouveau = fusionner_reseau(avant, get_network_info())
        heure = _heure()
        if avant.get("iface") and not nouveau.get("iface"):
            label = network_label(avant)
            print(f"{RED}{BOLD}[{heure}] ⚠ Réseau perdu ({label}) — en attente de reconnexion.{RESET}")
            log_event(f"⚠ réseau perdu — {label}")
            notify_desktop("⚠ Réseau perdu", label)
            self._rebaser()
        elif nouveau.get("iface"):
            reference = avant if avant.get("iface") else self.dernier_reseau
            changements = network_changes(reference, nouveau) if reference else []
            if changements:
                texte = "; ".join(changements)
                print(f"{RED}{BOLD}[{heure}] ⚠ Le réseau a changé : {texte}{RESET}")
                log_event(f"⚠ réseau changé — {texte}")
                notify_desktop("⚠ Réseau changé", texte)
                confirm_network(nouveau)
                self._rebaser()
            elif not avant.get("iface"):
                etat = "retrouvé" if reference else "détecté"
                print(f"{GREEN}[{heure}] ✅ Réseau {etat} : {network_label(nouveau)}{RESET}")
                log_event(f"réseau {etat} — {network_label(nouveau)}")
                if not reference:
                    confirm_network(nouveau)
            alerte = verifier_routeur(self.routeurs_vus, self.alertes_routeur, nouveau)
            if alerte:
                print(f"{RED}{BOLD}[{heure}] ⚠ {alerte}{RESET}")
                log_event(f"⚠ {alerte}")
                notify_desktop("⚠ Routeur suspect", alerte)
            self.dernier_reseau = nouveau
        self.reseau = nouveau
        self.own_macs = get_own_macs() | {m for m in (nouveau.get("own_mac"),) if m}

        if self.ecoute and not self.ecoute.is_alive():
            erreur = self.ecoute.erreur or "raison inconnue"
            print(f"{YELLOW}⚡ Écoute instantanée arrêtée ({erreur}) — nouvel essai.{RESET}")
            log_event(f"écoute instantanée arrêtée — {erreur}")
            self.ecoute = None
        if self.ecoute is None and nouveau.get("iface"):
            self._lancer_ecoute()

    # --- appareils --------------------------------------------------------
    def traiter(self, lus):
        """Traite ce que l'écoute a entendu. Renvoie True si la base a changé."""
        annoncer = self.presents_avant is not None   # pas de « connexion » avant la 1re base
        now, heure = _maintenant(), _heure()
        nouveaux, modifie = [], False
        for mac, ip in lus:
            if mac in self.own_macs:
                continue
            self.entendus.add(mac)
            resultat = handle_live_event(mac, ip, self.known, self.presents, self.own_macs, now)
            if resultat is None:
                continue
            modifie = True
            genre, valeur = resultat
            if genre == "nouveau":
                print(f"{RED}{BOLD}[{heure}] 🆕 NOUVEL appareil (instantané) : {valeur['ip']} "
                      f"{valeur['mac']} — nom et fabricant complétés au prochain scan{RESET}")
                nouveaux.append(valeur)
            elif genre == "connexion" and annoncer:
                print(f"{GREEN}[{heure}] 🟢 {_nom(self.known, valeur)} s'est connecté au réseau{RESET}")
                log_event(f"🟢 connexion — {_nom(self.known, valeur)} ({valeur})")
        if nouveaux:
            alert_new_devices(nouveaux, self.cfg)
        return modifie

    def tour_de_scan(self):
        print(f"\n{DIM}{'=' * 60}{RESET}")
        print(f"{DIM}Scan — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
        self._verifier_reseau()
        reseau = self.reseau
        if not reseau.get("iface"):
            print(f"{YELLOW}Pas de réseau : nouvel essai dans {self.interval} s.{RESET}")
            return

        devices = scan_network(interactif=False, subnet=reseau.get("subnet"),
                               iface=reseau["iface"] if reseau.get("arp") is not False else None)
        heure = _heure()
        if not devices:
            # Un scan raté n'est pas « tout le monde est parti » : la présence
            # reste telle quelle, et ce que l'écoute entend compte toujours.
            if devices is None:
                print(f"{YELLOW}[{heure}] ⚠ Scan impossible : ni arp-scan ni nmap n'ont pu scanner "
                      f"(sudo apt install arp-scan). L'écoute instantanée continue.{RESET}")
            else:
                print(f"{YELLOW}[{heure}] ⚠ Scan sans résultat — présence inchangée.{RESET}")
            if self.traiter(_vider(self.evenements)):
                save_known_devices(self.known)
            return

        devices = [d for d in devices if d["mac"] not in self.own_macs]
        new_devices = update_from_devices(devices, self.known, _maintenant())
        nouveaux_macs = {d["mac"] for d in new_devices}
        self.presents |= nouveaux_macs
        for d in new_devices:
            print(f"{RED}{BOLD}[{heure}] 🆕 NOUVEL appareil : {d['ip']} {d['mac']} "
                  f"({d.get('vendor') or '?'}){RESET}")
        if new_devices:
            alert_new_devices(new_devices, self.cfg)

        # Ce que l'écoute a entendu pendant le scan compte pour CE scan.
        if DELAI_FIN_SCAN:
            time.sleep(DELAI_FIN_SCAN)
        self.traiter(_vider(self.evenements))

        presents_maintenant = {d["mac"] for d in devices} | self.entendus
        if self.presents_avant is not None:
            for mac in sorted(presents_maintenant - self.presents - nouveaux_macs):
                print(f"{GREEN}[{heure}] 🟢 {_nom(self.known, mac)} s'est connecté au réseau{RESET}")
                log_event(f"🟢 connexion — {_nom(self.known, mac)} ({mac})")
            for mac in sorted(self.presents_avant - presents_maintenant):
                print(f"{YELLOW}[{heure}] 🔴 {_nom(self.known, mac)} s'est déconnecté du réseau{RESET}")
                log_event(f"🔴 déconnexion — {_nom(self.known, mac)} ({mac})")
        if not new_devices:
            print(f"{DIM}{len(presents_maintenant)} appareil(s) présent(s), rien de nouveau.{RESET}")

        save_known_devices(self.known)
        self.presents_avant = set(presents_maintenant)
        self.presents = set(presents_maintenant)
        self.entendus = set()

    def boucle(self):
        prochain_scan = 0.0
        while True:
            if time.monotonic() >= prochain_scan:
                self.tour_de_scan()
                prochain_scan = time.monotonic() + self.interval
            # Entre deux scans : on traite tout de suite ce que l'écoute entend.
            attente = max(0.0, prochain_scan - time.monotonic())
            try:
                premier = self.evenements.get(timeout=attente)
            except queue.Empty:
                continue
            if self.traiter([premier] + _vider(self.evenements)):
                save_known_devices(self.known)

    def arreter(self):
        self._arreter_ecoute()


def do_watch(known, interval, cfg=None, fabrique_ecoute=None):
    """Surveille le réseau en temps réel. Alerte sur :
       - tout appareil JAMAIS VU (intrus potentiel), dès son premier paquet ARP :
         bip + notification + e-mail + journal ;
       - toute connexion / déconnexion d'un appareil connu (présence) ;
       - tout changement de réseau (autre wifi, autre routeur, réseau perdu)
         et toute nouvelle MAC pour le routeur d'un même réseau.
    Un scan actif a lieu toutes les `interval` secondes en renfort (appareils
    silencieux, déconnexions). Ne regarde jamais ce qu'un appareil fait —
    seulement s'il est présent. Ctrl+C pour arrêter."""
    cfg = cfg if cfg is not None else load_config()
    interval = max(INTERVALLE_MIN, int(interval))
    surveillance = Surveillance(known, interval, cfg, fabrique_ecoute)
    try:
        surveillance.demarrer()
        surveillance.boucle()
    except KeyboardInterrupt:
        print(f"\n{LIME}Surveillance arrêtée.{RESET}")
        log_event("Surveillance arrêtée")
    finally:
        surveillance.arreter()


# --------------------------------------------------------------------------
# Rapport / export
# --------------------------------------------------------------------------
def export_csv(known, path=None):
    path = path or os.path.join(HOME, "scan_info_id_espion_rapport.csv")
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
    path = path or os.path.join(HOME, "scan_info_id_espion_rapport.html")
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
<title>scan-info-id-espion — rapport</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;background:#0d1117;color:#e6edf3}}
 h1{{color:#32cd32}}
 table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #30363d;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
 th{{background:#161b22}}
 tr:nth-child(even){{background:#161b22}}
 .meta{{color:#8b949e;font-size:.85rem}}
</style></head><body>
<h1>scan-info-id-espion</h1>
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
    path = path or os.path.join(HOME, "scan_info_id_espion_securite.txt")
    lignes = [
        "=== RAPPORT DE SÉCURITÉ — scan-info-id-espion ===",
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
    raw = input(f"Intervalle entre les scans de renfort en secondes (minimum {INTERVALLE_MIN}) [60]: ").strip() or "60"
    try:
        interval = int(raw)
    except ValueError:
        print(f"{RED}Valeur invalide.{RESET}")
        return
    do_watch(known, interval, cfg=cfg)


# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------
def print_menu():
    print(f"\n{CYAN}{BOLD}=== scan-info-id-espion ==={RESET}")
    print(f"{CYAN}1.{RESET} Scanner le réseau maintenant")
    print(f"{CYAN}2.{RESET} Surveillance en temps réel (nouvel appareil instantané + connexion/déconnexion)")
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
    print(f"{CYAN}14.{RESET} Quitter")


def run_menu():
    known = load_known_devices()
    cfg = load_config()
    print_logo()

    while True:
        print_menu()
        choix = input("Choix (1-14): ").strip()
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
            print(f"{LIME}À la prochaine!{RESET}")
            break
        else:
            print(f"{RED}Choix invalide, essaie encore.{RESET}")


# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="scan-info-id-espion — scanner d'appareils sur ton réseau local")
    parser.add_argument("--rename", nargs=2, metavar=("MAC", "NOM"),
                         help="Donner un nom personnalisé à un appareil déjà vu, sans passer par le menu")
    parser.add_argument("--scan", action="store_true",
                         help="Scanner directement sans passer par le menu")
    parser.add_argument("--watch", nargs="?", const=60, type=int, metavar="SECONDES",
                         help="Surveiller en temps réel : alerte dès qu'un nouvel appareil se connecte, "
                              "plus un scan de renfort toutes les SECONDES (60 par défaut, 15 minimum)")
    parser.add_argument("--report", choices=["html", "csv", "securite"], metavar="FORMAT",
                         help="Exporter un rapport des appareils connus (html, csv ou securite) puis quitter")
    parser.add_argument("--audit", action="store_true",
                         help="Lancer l'audit automatique complet du réseau (auto-pentest, lecture seule)")
    args = parser.parse_args()

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
    main()
