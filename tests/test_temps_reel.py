#!/usr/bin/env python3
"""Banc du mode temps réel de scan-info-id-espion.

Lancer :  python3 -m unittest discover -s tests -v

Tout tourne sans réseau réel : les commandes système (nmcli, arp-scan…) et
l'écoute ARP sont remplacées par des faux. Seul le dernier test ouvre une
vraie écoute, sur l'interface locale « lo », et seulement si on est root.
"""

import contextlib
import importlib.util
import io
import os
import queue
import socket
import struct
import threading
import time
import unittest
from unittest import mock

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "scan_info_id_espion", os.path.join(RACINE, "scan_info_id_espion.py"))
sie = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sie)


def mac_octets(mac):
    return bytes.fromhex(mac.replace(":", ""))


def trame_arp(sha, spa, tpa, oper=1, ethertype=0x0806, vlan=False,
              htype=1, ptype=0x0800, hlen=6, plen=4):
    """Fabrique une trame Ethernet + ARP comme celles qui circulent sur un wifi."""
    eth = b"\xff" * 6 + mac_octets(sha)
    if vlan:
        eth += struct.pack("!HH", 0x8100, 42)
    eth += struct.pack("!H", ethertype)
    arp = struct.pack("!HHBBH", htype, ptype, hlen, plen, oper)
    arp += mac_octets(sha) + socket.inet_aton(spa) + b"\x00" * 6 + socket.inet_aton(tpa)
    return eth + arp


class TestTrameArp(unittest.TestCase):
    def test_requete(self):
        t = trame_arp("AA:BB:CC:00:11:22", "192.168.1.50", "192.168.1.1")
        self.assertEqual(sie.parse_arp_frame(t), ("aa:bb:cc:00:11:22", "192.168.1.50"))

    def test_reponse(self):
        t = trame_arp("02:00:00:00:00:01", "10.0.0.7", "10.0.0.2", oper=2)
        self.assertEqual(sie.parse_arp_frame(t), ("02:00:00:00:00:01", "10.0.0.7"))

    def test_sonde_sans_ip_donne_l_ip_demandee(self):
        t = trame_arp("02:00:00:00:00:02", "0.0.0.0", "192.168.1.88")
        self.assertEqual(sie.parse_arp_frame(t), ("02:00:00:00:00:02", "192.168.1.88"))

    def test_sonde_vide_ignoree(self):
        self.assertIsNone(sie.parse_arp_frame(trame_arp("02:00:00:00:00:02", "0.0.0.0", "0.0.0.0")))

    def test_vlan(self):
        t = trame_arp("02:00:00:00:00:03", "192.168.5.9", "192.168.5.1", vlan=True)
        self.assertEqual(sie.parse_arp_frame(t), ("02:00:00:00:00:03", "192.168.5.9"))

    def test_pas_de_l_arp(self):
        t = trame_arp("02:00:00:00:00:04", "1.2.3.4", "1.2.3.5", ethertype=0x0800)
        self.assertIsNone(sie.parse_arp_frame(t))

    def test_trames_tronquees(self):
        t = trame_arp("02:00:00:00:00:05", "1.2.3.4", "1.2.3.5")
        for n in (0, 5, 13, 14, 20, len(t) - 1):
            self.assertIsNone(sie.parse_arp_frame(t[:n]), n)

    def test_mac_nulle_diffusion_multicast(self):
        for mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"):
            self.assertIsNone(sie.parse_arp_frame(trame_arp(mac, "1.2.3.4", "1.2.3.5")), mac)

    def test_arp_non_ipv4_ou_operation_inconnue(self):
        self.assertIsNone(sie.parse_arp_frame(trame_arp("02:00:00:00:00:06", "1.2.3.4", "1.2.3.5", ptype=0x86DD)))
        self.assertIsNone(sie.parse_arp_frame(trame_arp("02:00:00:00:00:06", "1.2.3.4", "1.2.3.5", hlen=8)))
        self.assertIsNone(sie.parse_arp_frame(trame_arp("02:00:00:00:00:06", "1.2.3.4", "1.2.3.5", oper=3)))


ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
    "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
    "eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
)


class TestReseau(unittest.TestCase):
    def test_route_par_defaut_plus_petite_metrique(self):
        self.assertEqual(sie.parse_proc_route(ROUTE), ("eth0", "10.0.0.1"))

    def test_route_wifi_seule(self):
        texte = "\n".join(ROUTE.splitlines()[:3])
        self.assertEqual(sie.parse_proc_route(texte), ("wlan0", "192.168.1.1"))

    def test_sans_route_par_defaut(self):
        texte = "\n".join([ROUTE.splitlines()[0], ROUTE.splitlines()[2]])
        self.assertEqual(sie.parse_proc_route(texte), (None, None))
        self.assertEqual(sie.parse_proc_route(""), (None, None))
        self.assertEqual(sie.parse_proc_route(None), (None, None))

    def test_route_baissee_ignoree(self):
        texte = ROUTE.splitlines()[0] + "\nwlan0\t00000000\t0101A8C0\t0002\t0\t0\t1\t00000000\t0\t0\t0\n"
        self.assertEqual(sie.parse_proc_route(texte), (None, None))

    def test_demi_routes_vpn_ignorees(self):
        # OpenVPN pose 0.0.0.0/1 et 128.0.0.0/1 : ce ne sont pas des routes par défaut
        texte = (ROUTE.splitlines()[0] + "\n"
                 "tun0\t00000000\t0108080A\t0003\t0\t0\t0\t00000080\t0\t0\t0\n"
                 + ROUTE.splitlines()[1] + "\n")
        self.assertEqual(sie.parse_proc_route(texte), ("wlan0", "192.168.1.1"))

    def test_toutes_les_routes_par_defaut_triees(self):
        self.assertEqual(sie.parse_proc_routes(ROUTE), [("eth0", "10.0.0.1"), ("wlan0", "192.168.1.1")])

    def test_sous_reseau_depuis_la_table_de_routage(self):
        texte = (ROUTE + "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
                 "wlan0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n")
        self.assertEqual(sie.subnet_from_proc_route(texte, "wlan0", "192.168.1.42"), "192.168.1.0/24")
        self.assertEqual(sie.subnet_from_proc_route(texte, "wlan0"), "192.168.1.0/24")    # plus petite métrique
        self.assertEqual(sie.subnet_from_proc_route(texte, "wlan0", "169.254.3.4"), "169.254.0.0/16")
        self.assertEqual(sie.subnet_from_proc_route(texte, "docker0"), "172.17.0.0/16")
        self.assertIsNone(sie.subnet_from_proc_route(texte, "eth0"))    # eth0 n'a ici qu'une route par défaut
        self.assertIsNone(sie.subnet_from_proc_route(None, "wlan0"))

    def test_table_arp(self):
        texte = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                 "192.168.1.1      0x1         0x2         A4:2B:B0:11:22:33     *        wlan0\n"
                 "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n")
        self.assertEqual(sie.parse_proc_arp(texte, "192.168.1.1"), "a4:2b:b0:11:22:33")
        self.assertIsNone(sie.parse_proc_arp(texte, "192.168.1.9"))
        self.assertIsNone(sie.parse_proc_arp(texte, "192.168.1.2"))
        self.assertIsNone(sie.parse_proc_arp(None, "192.168.1.1"))
        # entrée incomplète (flags 0x0) ou sur une autre carte : ignorée
        texte2 = ("IP address       HW type     Flags       HW address            Mask     Device\n"
                  "192.168.1.1      0x1         0x0         A4:2B:B0:11:22:33     *        wlan0\n"
                  "192.168.1.1      0x1         0x2         02:42:AC:11:00:02     *        docker0\n")
        self.assertIsNone(sie.parse_proc_arp(texte2, "192.168.1.1", "wlan0"))
        self.assertEqual(sie.parse_proc_arp(texte2, "192.168.1.1", "docker0"), "02:42:ac:11:00:02")

    def test_nmcli(self):
        texte = "no:Voisin:WPA2\nyes:Maison\\:Alex:WPA2 WPA3\n"
        self.assertEqual(sie.parse_nmcli_wifi(texte), {"ssid": "Maison:Alex", "security": "WPA2 WPA3"})
        self.assertEqual(sie.parse_nmcli_wifi("oui:Cafe:\n"),
                         {"ssid": "Cafe", "security": "Ouvert (aucun chiffrement)"})
        self.assertIsNone(sie.parse_nmcli_wifi("no:Voisin:WPA2\n"))
        self.assertIsNone(sie.parse_nmcli_wifi(""))

    def test_changements(self):
        a = {"iface": "wlan0", "ssid": "Maison", "gateway": "192.168.1.1", "gateway_mac": "aa:aa:aa:aa:aa:aa"}
        self.assertEqual(sie.network_changes(a, dict(a)), [])
        b = dict(a, ssid="Voisin")
        self.assertTrue(any("Voisin" in c for c in sie.network_changes(a, b)))
        c = dict(a, gateway="10.0.0.1")
        self.assertTrue(any("10.0.0.1" in x for x in sie.network_changes(a, c)))
        # la MAC du routeur n'est plus comparée ici (voir verifier_routeur)
        self.assertEqual(sie.network_changes(a, dict(a, gateway_mac="bb:bb:bb:bb:bb:bb")), [])
        # nom du wifi illisible d'un côté (nmcli a raté) : pas un changement
        self.assertEqual(sie.network_changes(a, dict(a, ssid=None)), [])
        self.assertEqual(sie.network_changes(dict(a, ssid=None), a), [])

    def test_mac_du_routeur(self):
        vus, alertes = {}, set()
        a = {"iface": "wlan0", "type": "wifi", "ssid": "Maison", "gateway": "192.168.1.1",
             "gateway_mac": "aa:aa:aa:aa:aa:aa"}
        self.assertIsNone(sie.verifier_routeur(vus, alertes, a))
        self.assertIsNone(sie.verifier_routeur(vus, alertes, dict(a, gateway_mac=None)))
        msg = sie.verifier_routeur(vus, alertes, dict(a, gateway_mac="bb:bb:bb:bb:bb:bb"))
        self.assertIn("usurpation", msg)
        self.assertIn("aa:aa:aa:aa:aa:aa → bb:bb:bb:bb:bb:bb", msg)
        # une seule alerte par MAC suspecte, et le retour à la vraie MAC ne dit rien
        self.assertIsNone(sie.verifier_routeur(vus, alertes, dict(a, gateway_mac="bb:bb:bb:bb:bb:bb")))
        self.assertIsNone(sie.verifier_routeur(vus, alertes, a))
        # un autre wifi a son propre routeur : pas une alerte
        self.assertIsNone(sie.verifier_routeur(vus, alertes, dict(a, ssid="Chalet", gateway_mac="cc:cc:cc:cc:cc:cc")))

    def test_fusion_garde_la_derniere_valeur_connue(self):
        ref = {"iface": "wlan0", "gateway": "192.168.1.1", "ssid": "Maison", "security": "WPA2",
               "gateway_mac": "aa:aa:aa:aa:aa:aa", "raisons": {}}
        rate = dict(ref, ssid=None, security=None, gateway_mac=None,
                    raisons={"ssid": "nmcli ne répond pas", "gateway_mac": "pas encore dans la table ARP"})
        f = sie.fusionner_reseau(ref, rate)
        self.assertEqual((f["ssid"], f["security"], f["gateway_mac"], f["raisons"]),
                         ("Maison", "WPA2", "aa:aa:aa:aa:aa:aa", {}))
        self.assertIsNone(rate["ssid"])                       # l'original n'est pas modifié
        autre = dict(rate, iface="wlan1")
        self.assertIs(sie.fusionner_reseau(ref, autre), autre)  # autre carte : on ne mélange pas
        self.assertIs(sie.fusionner_reseau(None, rate), rate)

    def test_confirmation_dit_indisponible_avec_raison(self):
        info = {"iface": None, "type": None, "ip": None, "subnet": None, "gateway": None,
                "gateway_mac": None, "ssid": None, "security": None, "own_mac": None,
                "raisons": {"iface": "aucune route par défaut : es-tu connecté au réseau ?",
                            "gateway": "aucune route par défaut"}}
        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            sie.confirm_network(info)
        texte = sortie.getvalue()
        self.assertIn("Indisponible (aucune route par défaut : es-tu connecté au réseau ?)", texte)
        self.assertIn("Aucun réseau détecté", texte)

    def test_confirmation_complete(self):
        info = {"iface": "wlan0", "type": "wifi", "ip": "192.168.1.42", "subnet": "192.168.1.0/24",
                "gateway": "192.168.1.1", "gateway_mac": "a4:2b:b0:11:22:33", "ssid": "Maison",
                "security": "WPA2", "own_mac": "02:00:00:00:00:99", "raisons": {}}
        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            sie.confirm_network(info)
        texte = sortie.getvalue()
        for attendu in ("wlan0 (wifi)", "Maison", "WPA2", "192.168.1.42", "192.168.1.0/24",
                        "192.168.1.1", "a4:2b:b0:11:22:33"):
            self.assertIn(attendu, texte)
        self.assertNotIn("Indisponible", texte)

    def test_get_network_info_sans_proc(self):
        with mock.patch.object(sie, "_lire", return_value=None), \
             mock.patch.object(sie, "get_local_subnet", return_value=None):
            info = sie.get_network_info()
        self.assertIsNone(info["iface"])
        self.assertIn("iface", info["raisons"])
        self.assertIn("gateway", info["raisons"])
        self.assertIn("ssid", info["raisons"])

    def test_get_network_info_wifi(self):
        fichiers = {"/proc/net/route": "\n".join(ROUTE.splitlines()[:3]),
                    "/proc/net/arp": ("IP address HW type Flags HW address Mask Device\n"
                                      "192.168.1.1 0x1 0x2 a4:2b:b0:11:22:33 * wlan0\n"),
                    "/sys/class/net/wlan0/address": "02:00:00:00:00:99\n"}
        nmcli = mock.Mock(stdout="yes:Maison:WPA2\n", stderr="", returncode=0)
        with mock.patch.object(sie, "_lire", side_effect=lambda c: fichiers.get(c)), \
             mock.patch.object(sie.os.path, "isdir", side_effect=lambda c: c == "/sys/class/net/wlan0/wireless"), \
             mock.patch.object(sie, "get_own_ip", return_value="192.168.1.42"), \
             mock.patch.object(sie.subprocess, "run", return_value=nmcli) as run:
            info = sie.get_network_info()
        self.assertEqual((info["iface"], info["type"], info["gateway"], info["gateway_mac"],
                          info["ssid"], info["security"], info["own_mac"], info["ip"], info["subnet"]),
                         ("wlan0", "wifi", "192.168.1.1", "a4:2b:b0:11:22:33",
                          "Maison", "WPA2", "02:00:00:00:00:99", "192.168.1.42", "192.168.1.0/24"))
        self.assertTrue(info["arp"])
        self.assertEqual(info["raisons"], {})
        cmd = run.call_args[0][0]
        self.assertIn("--rescan", cmd)        # pas de recherche wifi à chaque tour
        self.assertIn("wlan0", cmd)
        self.assertEqual(run.call_args[1]["env"]["LC_ALL"], "C")   # « yes » quelle que soit la langue

    def test_vpn_on_garde_la_vraie_carte(self):
        route = (ROUTE.splitlines()[0] + "\n"
                 "tun0\t00000000\t0108080A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
                 + "\n".join(ROUTE.splitlines()[1:3]) + "\n")
        fichiers = {"/proc/net/route": route, "/sys/class/net/tun0/type": "65534\n",
                    "/sys/class/net/wlan0/type": "1\n", "/sys/class/net/wlan0/address": "02:00:00:00:00:99\n"}
        with mock.patch.object(sie, "_lire", side_effect=lambda c: fichiers.get(c)), \
             mock.patch.object(sie.os.path, "isdir", return_value=True), \
             mock.patch.object(sie, "get_own_ip", return_value="192.168.1.42"), \
             mock.patch.object(sie, "get_active_wifi", return_value=({"ssid": "Maison", "security": "WPA2"}, None)):
            info = sie.get_network_info()
        self.assertEqual((info["iface"], info["type"], info["arp"]), ("wlan0", "wifi", True))

    def test_vpn_seul_le_dit(self):
        route = ROUTE.splitlines()[0] + "\ntun0\t00000000\t0108080A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
        fichiers = {"/proc/net/route": route, "/sys/class/net/tun0/type": "65534\n",
                    "/sys/class/net/tun0/address": "\n"}
        with mock.patch.object(sie, "_lire", side_effect=lambda c: fichiers.get(c)), \
             mock.patch.object(sie, "get_own_ip", return_value="10.8.0.6"), \
             mock.patch.object(sie.subprocess, "run") as run:
            info = sie.get_network_info()
        run.assert_not_called()                                # pas de nmcli sur un tunnel
        self.assertEqual((info["iface"], info["type"], info["arp"], info["own_mac"], info["gateway_mac"]),
                         ("tun0", "tunnel/VPN", False, None, None))
        self.assertIn("ARP", info["raisons"]["gateway_mac"])
        self.assertIn("pas de wifi", info["raisons"]["ssid"])
        sortie = io.StringIO()
        with contextlib.redirect_stdout(sortie):
            sie.confirm_network(info)
        self.assertIn("sans ARP", sortie.getvalue())
        self.assertEqual(sie.demarrer_ecoute("tun0", queue.Queue(), arp=False),
                         (None, "interface tun0 sans ARP (VPN ou tunnel ?)"))

    def test_nmcli_absent(self):
        with mock.patch.object(sie.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(sie.get_active_wifi("wlan0"), (None, "nmcli n'est pas installé"))

    def test_nmcli_en_erreur_donne_sa_raison(self):
        echec = mock.Mock(stdout="", stderr="Error: NetworkManager is not running.\n", returncode=8)
        with mock.patch.object(sie.subprocess, "run", return_value=echec):
            self.assertEqual(sie.get_active_wifi("wlan0"), (None, "nmcli : Error: NetworkManager is not running."))
        echec = mock.Mock(stdout="", stderr="", returncode=10)
        with mock.patch.object(sie.subprocess, "run", return_value=echec):
            self.assertEqual(sie.get_active_wifi("wlan0"), (None, "nmcli a échoué (code 10)"))

    def test_toutes_mes_cartes(self):
        fichiers = {"/sys/class/net/wlan0/address": "02:00:00:00:00:99\n",
                    "/sys/class/net/eth0/address": "02:00:00:00:00:98\n",
                    "/sys/class/net/lo/address": "00:00:00:00:00:00\n",
                    "/sys/class/net/tun0/address": "\n"}
        with mock.patch.object(sie.os, "listdir", return_value=["lo", "wlan0", "eth0", "tun0"]), \
             mock.patch.object(sie, "_lire", side_effect=lambda c: fichiers.get(c)):
            self.assertEqual(sie.get_own_macs(), {"02:00:00:00:00:99", "02:00:00:00:00:98"})
        with mock.patch.object(sie.os, "listdir", side_effect=OSError):
            self.assertEqual(sie.get_own_macs(), set())


class TestScan(unittest.TestCase):
    def test_outils_absents(self):
        with mock.patch.object(sie, "_outil", return_value=None), \
             mock.patch.object(sie.subprocess, "run") as run:
            self.assertIsNone(sie.run_arp_scan("wlan0"))
            self.assertIsNone(sie.run_nmap("192.168.1.0/24", interactif=False))
            self.assertIsNone(sie.scan_network(interactif=False, subnet="192.168.1.0/24"))
            self.assertIsNone(sie.run_nmap(None, interactif=False))     # jamais de question en surveillance
        run.assert_not_called()

    def test_arp_scan_sur_la_bonne_carte_sans_sudo_inutile(self):
        sortie = mock.Mock(stdout="192.168.1.10\t02:00:00:00:00:0A\tFabricant X\n", returncode=0)
        with mock.patch.object(sie, "_outil", return_value="/usr/sbin/arp-scan"), \
             mock.patch.object(sie.os, "geteuid", return_value=0), \
             mock.patch.object(sie.subprocess, "run", return_value=sortie) as run:
            self.assertEqual(sie.run_arp_scan("wlan0"),
                             [{"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Fabricant X"}])
        self.assertEqual(run.call_args[0][0], ["arp-scan", "--localnet", "--interface=wlan0"])
        with mock.patch.object(sie, "_outil", return_value="/usr/sbin/arp-scan"), \
             mock.patch.object(sie.os, "geteuid", return_value=1000), \
             mock.patch.object(sie.subprocess, "run", return_value=sortie) as run:
            sie.run_arp_scan()
        self.assertEqual(run.call_args[0][0], ["sudo", "arp-scan", "--localnet"])


class TestEvenements(unittest.TestCase):
    def setUp(self):
        self.patches = [mock.patch.object(sie, "get_hostname", return_value=None),
                        mock.patch.object(sie, "log_event")]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_nouvel_appareil_une_seule_fois(self):
        known, presents = {}, set()
        r = sie.handle_live_event("02:00:00:00:00:01", "192.168.1.50", known, presents, set(), "2026-11-06 08:00")
        self.assertEqual(r[0], "nouveau")
        self.assertIn("02:00:00:00:00:01", known)
        self.assertEqual(known["02:00:00:00:00:01"]["last_ip"], "192.168.1.50")
        sie.get_hostname.assert_not_called()          # l'alerte n'attend pas une recherche de nom
        self.assertTrue(any("NOUVEAU" in str(c) for c in sie.log_event.call_args_list))
        # même minute, même IP : rien à faire ni à enregistrer
        self.assertIsNone(sie.handle_live_event("02:00:00:00:00:01", "192.168.1.50", known, presents,
                                                set(), "2026-11-06 08:00"))
        # une minute plus tard : simple mise à jour, pas une nouvelle alerte
        self.assertEqual(sie.handle_live_event("02:00:00:00:00:01", "192.168.1.50", known, presents,
                                               set(), "2026-11-06 08:01"), ("maj", "02:00:00:00:00:01"))

    def test_appareil_connu_qui_revient(self):
        known = {"02:00:00:00:00:01": {"first_seen": "a", "last_seen": "a", "times_seen": 4,
                                        "vendor": "Apple", "hostname": None, "last_ip": "1.1.1.1", "name": "Téléphone"}}
        presents = set()
        r = sie.handle_live_event("02:00:00:00:00:01", "192.168.1.51", known, presents, set(), "b")
        self.assertEqual(r, ("connexion", "02:00:00:00:00:01"))
        info = known["02:00:00:00:00:01"]
        self.assertEqual((info["last_seen"], info["last_ip"], info["times_seen"]), ("b", "192.168.1.51", 4))
        self.assertIsNone(sie.handle_live_event("02:00:00:00:00:01", "192.168.1.51", known, presents, set(), "b"))
        self.assertEqual(sie.handle_live_event("02:00:00:00:00:01", "192.168.1.52", known, presents, set(), "b"),
                         ("maj", "02:00:00:00:00:01"))           # nouvelle IP : à enregistrer
        self.assertEqual(known["02:00:00:00:00:01"]["times_seen"], 4)   # pas gonflé par chaque paquet

    def test_ma_machine_ignoree(self):
        known = {}
        self.assertIsNone(sie.handle_live_event("02:00:00:00:00:99", "192.168.1.42", known, set(),
                                                {"02:00:00:00:00:99"}, "x"))
        self.assertEqual(known, {})


class FauxSocket:
    def __init__(self, paquets):
        self.paquets = list(paquets)
        self.ferme = False

    def recvfrom(self, _taille):
        if self.paquets:
            p = self.paquets.pop(0)
            if isinstance(p, Exception):
                raise p
            return p
        time.sleep(0.01)
        raise socket.timeout()

    def close(self):
        self.ferme = True


class TestEcoute(unittest.TestCase):
    def test_garde_les_appareils_et_ignore_ma_machine(self):
        dehors = trame_arp("02:00:00:00:00:01", "192.168.1.50", "192.168.1.1")
        moi = trame_arp("02:00:00:00:00:99", "192.168.1.42", "192.168.1.1")
        faux = FauxSocket([(dehors, ("wlan0", 0x0806, 1, 1, b"")),
                           (moi, ("wlan0", 0x0806, sie.PACKET_OUTGOING, 1, b"")),
                           (b"pas une trame", ("wlan0", 0x0806, 0, 1, b""))])
        q = queue.Queue()
        e, raison = sie.demarrer_ecoute("wlan0", q, lambda i, ev: sie.EcouteArp(i, ev, ouvrir=lambda _: faux))
        self.assertIsNone(raison)
        self.assertEqual(q.get(timeout=2), ("02:00:00:00:00:01", "192.168.1.50"))
        time.sleep(0.1)
        self.assertTrue(q.empty())
        e.arreter()
        e.join(2)
        self.assertFalse(e.is_alive())
        self.assertTrue(faux.ferme)

    def test_sans_sudo(self):
        def refuse(_):
            raise PermissionError(1, "Operation not permitted")
        e, raison = sie.demarrer_ecoute("wlan0", queue.Queue(),
                                        lambda i, ev: sie.EcouteArp(i, ev, ouvrir=refuse))
        self.assertIsNone(e)
        self.assertIn("sudo", raison)

    def test_sans_interface(self):
        self.assertEqual(sie.demarrer_ecoute(None, queue.Queue()), (None, "aucune interface réseau active"))

    def test_raisons(self):
        self.assertIn("sudo", sie.raison_ecoute(PermissionError()))
        self.assertIn("Linux", sie.raison_ecoute(AttributeError()))
        self.assertIn("wlan9", sie.raison_ecoute(OSError(19, "No such device"), "wlan9"))

    def test_erreur_en_cours_de_route(self):
        faux = FauxSocket([OSError(100, "Network is down")])
        e = sie.EcouteArp("wlan0", queue.Queue(), ouvrir=lambda _: faux)
        e.start()
        e.join(2)
        self.assertFalse(e.is_alive())
        self.assertIn("Network is down", e.erreur)
        self.assertTrue(faux.ferme)


class FausseEcoute:
    """Remplace EcouteArp dans do_watch : on choisit ce qu'elle « entend »."""
    instances = []

    def __init__(self, iface, evenements):
        self.iface = iface
        self.evenements = evenements
        self.prete = threading.Event()
        self.erreur = None
        self.arretee = False
        FausseEcoute.instances.append(self)

    def start(self):
        self.prete.set()

    def is_alive(self):
        return not self.arretee

    def arreter(self):
        self.arretee = True


def reseau(ssid="Maison", iface="wlan0"):
    return {"iface": iface, "type": "wifi", "ip": "192.168.1.42", "subnet": "192.168.1.0/24",
            "gateway": "192.168.1.1", "gateway_mac": "a4:2b:b0:11:22:33", "ssid": ssid,
            "security": "WPA2", "own_mac": "02:00:00:00:00:99", "raisons": {}}


class TestSurveillance(unittest.TestCase):
    def setUp(self):
        FausseEcoute.instances = []
        self.alertes = []
        self.journal = []
        self.notifs = []
        patches = {
            "get_hostname": mock.Mock(return_value=None),
            "save_known_devices": mock.Mock(),
            "log_event": mock.Mock(side_effect=self.journal.append),
            "notify_desktop": mock.Mock(side_effect=lambda t, m: self.notifs.append((t, m))),
            "alert_new_devices": mock.Mock(side_effect=lambda d, c: self.alertes.append([x["mac"] for x in d])),
            "INTERVALLE_MIN": 0,
            "DELAI_FIN_SCAN": 0,
            "get_own_macs": mock.Mock(return_value=set()),
        }
        self.patches = [mock.patch.object(sie, k, v) for k, v in patches.items()]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def lancer(self, scans, reseaux, avant_scan=None, fabrique=FausseEcoute):
        """scans : liste des appareils renvoyés à chaque scan (le dernier coupe
        la surveillance comme un Ctrl+C). avant_scan(n, ecoute) peut injecter
        ce que l'écoute « entend »."""
        compteur = {"n": 0}
        self.appels_scan = []

        def faux_scan(*args, **kwargs):
            self.appels_scan.append(kwargs)
            n = compteur["n"]
            compteur["n"] += 1
            if avant_scan:
                avant_scan(n, FausseEcoute.instances[-1] if FausseEcoute.instances else None)
            if n >= len(scans):
                raise KeyboardInterrupt
            if scans[n] is None:
                return None
            return [dict(d) for d in scans[n]]

        sortie = io.StringIO()
        with mock.patch.object(sie, "scan_network", side_effect=faux_scan), \
             mock.patch.object(sie, "get_network_info", side_effect=reseaux), \
             contextlib.redirect_stdout(sortie):
            known = {}
            sie.do_watch(known, 0, cfg={}, fabrique_ecoute=fabrique)
        return known, sortie.getvalue()

    def test_alerte_instantanee_puis_connexion_deconnexion(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        B = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:0b", "vendor": "Apple"}

        def entend(n, ecoute):
            if n == 0:
                # pendant le 1er scan : un intrus se connecte, et ma machine parle
                ecoute.evenements.put(("02:00:00:00:00:0c", "192.168.1.66"))
                ecoute.evenements.put(("02:00:00:00:00:99", "192.168.1.42"))
            if n == 2:
                # l'intrus reparle pendant un scan qui le rate : il reste présent
                ecoute.evenements.put(("02:00:00:00:00:0c", "192.168.1.66"))

        known, texte = self.lancer(
            scans=[[A, B], [A, {"ip": "192.168.1.66", "mac": "02:00:00:00:00:0c", "vendor": "Inconnu"}], [A]],
            reseaux=[reseau()] * 10, avant_scan=entend)

        # 1er scan : A et B nouveaux (base vide) ; puis l'intrus, en instantané, une seule fois
        self.assertEqual(self.alertes[0], ["02:00:00:00:00:0a", "02:00:00:00:00:0b"])
        self.assertEqual(self.alertes[1], ["02:00:00:00:00:0c"])
        self.assertEqual(len(self.alertes), 2)
        self.assertIn("NOUVEL appareil (instantané) : 192.168.1.66 02:00:00:00:00:0c", texte)
        self.assertNotIn("02:00:00:00:00:99", known)          # ma machine n'est pas un appareil
        self.assertIn("02:00:00:00:00:0c", known)
        self.assertEqual(known["02:00:00:00:00:0c"]["vendor"], "Inconnu")   # complété par le scan
        # B absent du 2e scan : déconnecté ; l'intrus, déjà annoncé, n'est pas re-« connecté »
        self.assertIn("Apple s'est déconnecté", texte)
        self.assertEqual(texte.count("s'est connecté"), 0)
        # L'intrus, raté par le 3e scan, a été entendu pendant ce scan : il reste
        # présent (pas de fausse déconnexion).
        self.assertEqual(texte.count("s'est déconnecté"), 1)
        # le scan vise la carte et le sous-réseau du réseau confirmé
        self.assertEqual(self.appels_scan[0], {"interactif": False, "subnet": "192.168.1.0/24", "iface": "wlan0"})
        self.assertIn("Réseau surveillé", texte)
        self.assertIn("Maison", texte)
        self.assertIn("Écoute instantanée active sur wlan0", texte)
        self.assertTrue(FausseEcoute.instances[-1].arretee)    # écoute arrêtée au Ctrl+C
        self.assertTrue(any("Surveillance démarrée" in j and "Maison" in j for j in self.journal))

    def test_connu_revient_entre_deux_scans(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        B = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:0b", "vendor": "Apple"}

        def entend(n, ecoute):
            if n == 2:
                ecoute.evenements.put(("02:00:00:00:00:0b", "192.168.1.11"))

        # B présent, puis absent, puis entendu pendant un scan qui le rate
        _, texte = self.lancer(scans=[[A, B], [A], [A]], reseaux=[reseau()] * 10, avant_scan=entend)
        self.assertEqual(texte.count("s'est déconnecté"), 1)
        self.assertEqual(texte.count("s'est connecté"), 1)

    def test_changement_de_reseau(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        _, texte = self.lancer(scans=[[A], [A]],
                               reseaux=[reseau(), reseau(), reseau(ssid="Voisin", iface="wlan1")] + [reseau("Voisin", "wlan1")] * 5)
        self.assertIn("Le réseau a changé", texte)
        self.assertIn("Voisin", texte)
        self.assertTrue(any("Réseau changé" in t for t, _ in self.notifs))
        # l'écoute est relancée sur la nouvelle interface
        self.assertEqual([e.iface for e in FausseEcoute.instances], ["wlan0", "wlan1"])
        self.assertTrue(FausseEcoute.instances[0].arretee)

    def test_reseau_perdu_puis_retrouve(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        B = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:0b", "vendor": "Apple"}
        perdu = {"iface": None, "type": None, "ip": None, "subnet": None, "gateway": None,
                 "gateway_mac": None, "ssid": None, "security": None, "own_mac": None,
                 "raisons": {"iface": "aucune route par défaut"}}
        _, texte = self.lancer(scans=[[A, B], [A, B], [A, B]],
                               reseaux=[reseau(), reseau(), perdu, perdu, reseau()] + [reseau()] * 5)
        self.assertIn("Réseau perdu", texte)
        self.assertIn("Pas de réseau", texte)
        self.assertIn("Réseau retrouvé", texte)
        self.assertNotIn("Le réseau a changé", texte)
        self.assertTrue(any("Réseau perdu" in t for t, _ in self.notifs))
        # pas de scan sans réseau, et pas de fausse déconnexion / connexion
        self.assertEqual(len(self.appels_scan), 4)            # 3 scans + le Ctrl+C
        self.assertNotIn("déconnecté", texte)
        self.assertNotIn("s'est connecté", texte)
        # écoute arrêtée à la perte, relancée au retour
        self.assertEqual([e.iface for e in FausseEcoute.instances], ["wlan0", "wlan0"])
        self.assertTrue(FausseEcoute.instances[0].arretee)

    def test_scan_rate_ne_vide_pas_la_presence(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        B = {"ip": "192.168.1.11", "mac": "02:00:00:00:00:0b", "vendor": "Apple"}

        def entend(n, ecoute):
            if n == 1:
                ecoute.evenements.put(("02:00:00:00:00:0c", "192.168.1.66"))

        _, texte = self.lancer(scans=[[A, B], None, [], [A, B]], reseaux=[reseau()] * 10, avant_scan=entend)
        self.assertIn("Scan impossible", texte)
        self.assertIn("arp-scan", texte)
        self.assertIn("Scan sans résultat", texte)
        self.assertNotIn("déconnecté", texte)                 # personne n'est « parti »
        # l'écoute marche toujours pendant un scan raté
        self.assertEqual(self.alertes[-1], ["02:00:00:00:00:0c"])

    def test_wifi_illisible_un_instant_pas_de_fausse_alerte(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        rate = dict(reseau(), ssid=None, security=None, gateway_mac=None,
                    raisons={"ssid": "nmcli ne répond pas"})
        _, texte = self.lancer(scans=[[A], [A], [A]], reseaux=[reseau(), reseau(), rate] + [reseau()] * 5)
        self.assertNotIn("Le réseau a changé", texte)
        self.assertNotIn("usurpation", texte)
        self.assertEqual(self.notifs, [])

    def test_mac_du_routeur_qui_change(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        faux = dict(reseau(), gateway_mac="66:66:66:66:66:66")
        _, texte = self.lancer(scans=[[A], [A], [A]], reseaux=[reseau(), reseau(), faux, faux] + [reseau()] * 5)
        self.assertEqual(texte.count("usurpation"), 1)         # une seule alerte, pas à chaque scan
        self.assertIn("a4:2b:b0:11:22:33 → 66:66:66:66:66:66", texte)
        self.assertTrue(any("Routeur suspect" in t for t, _ in self.notifs))
        self.assertNotIn("Le réseau a changé", texte)

    def test_ma_deuxieme_carte_n_est_pas_un_intrus(self):
        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        moi_cable = {"ip": "192.168.1.43", "mac": "02:00:00:00:00:98", "vendor": "Intel"}

        def entend(n, ecoute):
            if n == 0:
                ecoute.evenements.put(("02:00:00:00:00:98", "192.168.1.43"))

        with mock.patch.object(sie, "get_own_macs", return_value={"02:00:00:00:00:98"}):
            known, _ = self.lancer(scans=[[A, moi_cable]], reseaux=[reseau()] * 5, avant_scan=entend)
        self.assertNotIn("02:00:00:00:00:98", known)
        self.assertEqual(self.alertes, [["02:00:00:00:00:0a"]])

    def test_relance_ratee_le_dit_une_fois(self):
        class MeurtPuisRefuse(FausseEcoute):
            def start(self):
                if len(FausseEcoute.instances) > 1:
                    self.erreur = "interface wlan0 introuvable"
                self.prete.set()

        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}

        def entend(n, ecoute):
            if n == 0:      # la carte tombe pendant le 1er scan
                ecoute.erreur = "écoute interrompue : Network is down"
                ecoute.arretee = True

        _, texte = self.lancer(scans=[[A]] * 4, reseaux=[reseau()] * 10, avant_scan=entend,
                               fabrique=MeurtPuisRefuse)
        self.assertIn("Écoute instantanée arrêtée (écoute interrompue : Network is down)", texte)
        self.assertEqual(texte.count("Indisponible (interface wlan0 introuvable)"), 1)
        self.assertTrue(any("indisponible — interface wlan0 introuvable" in j for j in self.journal))

    def test_ecoute_indisponible_le_dit(self):
        class Refusee(FausseEcoute):
            def start(self):
                self.erreur = "il faut lancer le script avec sudo pour écouter le réseau"
                self.prete.set()

        A = {"ip": "192.168.1.10", "mac": "02:00:00:00:00:0a", "vendor": "Routeur"}
        with mock.patch.object(sie, "scan_network", side_effect=[[A], KeyboardInterrupt]), \
             mock.patch.object(sie, "get_network_info", return_value=reseau()):
            sortie = io.StringIO()
            with contextlib.redirect_stdout(sortie):
                sie.do_watch({}, 0, cfg={}, fabrique_ecoute=Refusee)
        texte = sortie.getvalue()
        self.assertIn("Écoute instantanée : Indisponible (il faut lancer le script avec sudo", texte)
        self.assertIn("Détection seulement par scan", texte)
        self.assertTrue(any("indisponible" in j for j in self.journal))

    def test_intervalle_minimum(self):
        with mock.patch.object(sie, "INTERVALLE_MIN", 15), \
             mock.patch.object(sie, "scan_network", side_effect=KeyboardInterrupt), \
             mock.patch.object(sie, "get_network_info", return_value=reseau()):
            sortie = io.StringIO()
            with contextlib.redirect_stdout(sortie):
                sie.do_watch({}, 1, cfg={}, fabrique_ecoute=FausseEcoute)
        self.assertIn("toutes les 15 s", sortie.getvalue())


@unittest.skipUnless(hasattr(socket, "AF_PACKET") and hasattr(os, "geteuid") and os.geteuid() == 0,
                     "écoute réelle : Linux et root seulement")
class TestEcouteReelle(unittest.TestCase):
    def test_entend_une_trame_sur_lo(self):
        q = queue.Queue()
        e, raison = sie.demarrer_ecoute("lo", q)
        self.assertIsNotNone(e, raison)
        try:
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            tx.bind(("lo", 0))
            tx.send(trame_arp("02:11:22:33:44:55", "192.168.1.77", "192.168.1.1"))
            tx.close()
            self.assertEqual(q.get(timeout=3), ("02:11:22:33:44:55", "192.168.1.77"))
            time.sleep(0.3)
            self.assertTrue(q.empty(), "la copie sortante ne doit pas compter")
        finally:
            e.arreter()
            e.join(3)


if __name__ == "__main__":
    unittest.main()
