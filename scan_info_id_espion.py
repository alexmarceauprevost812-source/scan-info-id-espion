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
    sudo python3 scan_info_id_espion.py --watch 60      # surveille en boucle (toutes les 60 s)
    sudo python3 scan_info_id_espion.py --report html   # exporte un rapport (html ou csv)
    sudo python3 scan_info_id_espion.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
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
import smtplib
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


def print_logo():
    print(f"{CYAN}{LOGO_SCAN_INFO_ID}{RESET}")
    print(f"{LIME}{BOLD}{LOGO_ESPION}{RESET}")
    print(f"{BOLD}🛰️  Détection des appareils sur ton réseau wifi{RESET}")
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
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=2, ensure_ascii=False)


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
def run_arp_scan():
    """Essaie arp-scan d'abord (plus rapide et précis sur un LAN)."""
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet"],
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


def run_nmap(subnet):
    """Repli sur nmap si arp-scan n'est pas installé."""
    if not subnet:
        print("Impossible de détecter le sous-réseau automatiquement.")
        subnet = input("Entre ton sous-réseau (ex: 192.168.1.0/24): ").strip()

    try:
        result = subprocess.run(
            ["sudo", "nmap", "-sn", subnet],
            capture_output=True, text=True, timeout=60
        )
    except FileNotFoundError:
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


def scan_network():
    """Renvoie la liste des appareils via arp-scan ou, à défaut, nmap."""
    devices = run_arp_scan()
    if devices is None:
        subnet = get_local_subnet()
        devices = run_nmap(subnet)
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
# Menu
# --------------------------------------------------------------------------
def print_menu():
    print(f"\n{CYAN}{BOLD}=== scan-info-id-espion ==={RESET}")
    print(f"{CYAN}1.{RESET} Scanner le réseau maintenant")
    print(f"{CYAN}2.{RESET} Surveillance en continu (intrus + connexion/déconnexion)")
    print(f"{CYAN}3.{RESET} Voir les appareils déjà connus")
    print(f"{CYAN}4.{RESET} Voir l'historique de présence")
    print(f"{CYAN}5.{RESET} Renommer un appareil")
    print(f"{CYAN}6.{RESET} Oublier un appareil (le retraiter comme nouveau)")
    print(f"{CYAN}7.{RESET} Auditer un appareil (ports + vulnérabilités connues, lecture seule)")
    print(f"{CYAN}8.{RESET} Vérifier le chiffrement de ton wifi")
    print(f"{CYAN}9.{RESET} Exporter un rapport (HTML / CSV / sécurité)")
    print(f"{CYAN}10.{RESET} Quitter")


def run_menu():
    known = load_known_devices()
    cfg = load_config()
    print_logo()

    while True:
        print_menu()
        choix = input("Choix (1-10): ").strip()
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
            do_report_menu(known)
        elif choix == "10":
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
                         help="Surveiller en boucle (par défaut toutes les 60 s) et alerter sur tout nouvel appareil")
    parser.add_argument("--report", choices=["html", "csv", "securite"], metavar="FORMAT",
                         help="Exporter un rapport des appareils connus (html, csv ou securite) puis quitter")
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

    if args.scan:
        print_logo()
        do_scan(known, cfg=cfg)
        return

    run_menu()


if __name__ == "__main__":
    main()
