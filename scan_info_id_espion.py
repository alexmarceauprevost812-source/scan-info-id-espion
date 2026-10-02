#!/usr/bin/env python3
"""
scan-info-id-espion — Découvre les appareils connectés à ton réseau local
et signale les appareils JAMAIS VUS AVANT (utile pour repérer un intrus
ou un appareil suspect sur ton wifi).

À utiliser UNIQUEMENT sur un réseau que tu possèdes ou administres
(ton wifi maison, par exemple).

Prérequis (un des deux, arp-scan est préférable):
    sudo apt install arp-scan
    sudo apt install nmap

Usage:
    sudo python3 scan_info_id_espion.py                 # ouvre le menu interactif
    sudo python3 scan_info_id_espion.py --scan           # scan direct, sans menu
    sudo python3 scan_info_id_espion.py --rename AA:BB:CC:DD:EE:FF "Mon téléphone"
"""

import subprocess
import re
import json
import sys
import os
import argparse
import socket
from datetime import datetime

KNOWN_DEVICES_FILE = os.path.expanduser("~/.scan_info_id_espion_known_devices.json")

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


def load_known_devices():
    if os.path.exists(KNOWN_DEVICES_FILE):
        with open(KNOWN_DEVICES_FILE, "r") as f:
            return json.load(f)
    return {}


def save_known_devices(devices):
    with open(KNOWN_DEVICES_FILE, "w") as f:
        json.dump(devices, f, indent=2, ensure_ascii=False)


def run_arp_scan():
    """Essaie arp-scan d'abord (plus rapide et précis sur un LAN)."""
    try:
        result = subprocess.run(
            ["sudo", "arp-scan", "--localnet"],
            capture_output=True, text=True, timeout=30
        )
    except FileNotFoundError:
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


def get_hostname(ip):
    """Essaie de trouver le vrai nom réseau de l'appareil (reverse DNS local).
    Beaucoup de routeurs/appareils répondent à ça (ex: "iphone-de-marie.lan").
    Retourne None si rien n'est trouvé (normal pour certains appareils)."""
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def do_scan(known):
    """Scanne le réseau, affiche les résultats et met à jour la liste connue."""
    if os.geteuid() != 0:
        print(f"{YELLOW}⚠ Ce script a besoin de sudo pour lire les adresses MAC.{RESET}")
        print(f"{YELLOW}  Relance avec: sudo python3 scan_info_id_espion.py{RESET}\n")

    print(f"{CYAN}\nScan du réseau en cours...\n{RESET}")

    devices = run_arp_scan()
    if devices is None:
        subnet = get_local_subnet()
        devices = run_nmap(subnet)

    if not devices:
        print(f"{RED}Aucun appareil trouvé. Vérifie que arp-scan ou nmap sont installés{RESET}")
        print(f"{RED}et que tu es bien connecté au wifi à vérifier.{RESET}")
        return

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    new_devices = []

    print(f"{BOLD}{'IP':<16}{'MAC':<19}{'Nom réseau':<24}{'Fabricant':<20}{'Statut'}{RESET}")
    print(DIM + "-" * 100 + RESET)

    for d in devices:
        mac = d["mac"]
        hostname = get_hostname(d["ip"])

        if mac not in known:
            known[mac] = {"first_seen": now, "vendor": d["vendor"], "hostname": hostname, "name": None}
            new_devices.append(d)
            statut = f"{RED}{BOLD}🆕 NOUVEAU{RESET}"
        else:
            if hostname:
                known[mac]["hostname"] = hostname
            statut = f"{DIM}connu depuis {known[mac]['first_seen']}{RESET}"

        nom_reseau = known[mac].get("name") or hostname or "(inconnu)"
        print(f"{d['ip']:<16}{mac:<19}{nom_reseau:<24}{(d['vendor'] or '?'):<20}{statut}")

    save_known_devices(known)

    print(f"\n{GREEN}{len(devices)} appareil(s) trouvé(s), {len(new_devices)} nouveau(x).{RESET}")
    if new_devices:
        print(f"\n{YELLOW}⚠ Appareil(s) jamais vus avant — vérifie que tu les reconnais tous.{RESET}")
        print(f"{YELLOW}  Utilise l'option 3 du menu pour en renommer un.{RESET}")


def do_list(known):
    """Affiche tous les appareils déjà vus, même sans scanner à nouveau."""
    if not known:
        print(f"{YELLOW}\nAucun appareil enregistré pour l'instant. Fais un scan d'abord (option 1).{RESET}")
        return

    print(f"\n{BOLD}{'MAC':<19}{'Nom donné':<18}{'Nom réseau':<24}{'Fabricant':<20}{'Vu la 1re fois'}{RESET}")
    print(DIM + "-" * 100 + RESET)
    for mac, info in sorted(known.items(), key=lambda kv: kv[1].get("first_seen", "")):
        nom = info.get("name") or "(sans nom)"
        hostname = info.get("hostname") or "(inconnu)"
        print(f"{mac:<19}{nom:<18}{hostname:<24}{(info.get('vendor') or '?'):<20}{info.get('first_seen', '?')}")


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


def print_menu():
    print(f"\n{CYAN}{BOLD}=== scan-info-id-espion ==={RESET}")
    print(f"{CYAN}1.{RESET} Scanner le réseau maintenant")
    print(f"{CYAN}2.{RESET} Voir les appareils déjà connus")
    print(f"{CYAN}3.{RESET} Renommer un appareil")
    print(f"{CYAN}4.{RESET} Oublier un appareil (le retraiter comme nouveau)")
    print(f"{CYAN}5.{RESET} Quitter")


def run_menu():
    known = load_known_devices()
    print_logo()
    actions = {"1": do_scan, "2": do_list, "3": do_rename, "4": do_forget}

    while True:
        print_menu()
        choix = input("Choix (1-5): ").strip()
        if choix == "5":
            print(f"{LIME}À la prochaine!{RESET}")
            break
        action = actions.get(choix)
        if action:
            action(known)
        else:
            print(f"{RED}Choix invalide, essaie encore.{RESET}")


def main():
    parser = argparse.ArgumentParser(description="scan-info-id-espion — scanner d'appareils sur ton réseau local")
    parser.add_argument("--rename", nargs=2, metavar=("MAC", "NOM"),
                         help="Donner un nom personnalisé à un appareil déjà vu, sans passer par le menu")
    parser.add_argument("--scan", action="store_true",
                         help="Scanner directement sans passer par le menu")
    args = parser.parse_args()

    known = load_known_devices()

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

    if args.scan:
        print_logo()
        do_scan(known)
        return

    run_menu()


if __name__ == "__main__":
    main()
