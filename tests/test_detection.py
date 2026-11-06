import json
import os

import marceau as m

ROUTEUR = {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01", "vendor": "Routeur"}
TEL = {"ip": "192.168.1.20", "mac": "aa:aa:aa:aa:aa:02", "vendor": "Samsung"}


def test_arp_rien_de_suspect():
    alertes, gw = m.detect_arp_anomalies([ROUTEUR, TEL], "192.168.1.1")
    assert alertes == [] and gw == ROUTEUR["mac"]


def test_arp_mac_passerelle_changee():
    alertes, _ = m.detect_arp_anomalies([ROUTEUR], "192.168.1.1", known_gw_mac="ff:ff:ff:ff:ff:ff")
    assert len(alertes) == 1 and "CHANGÉ" in alertes[0]


def test_arp_deux_mac_pour_le_routeur():
    pirate = {"ip": "192.168.1.1", "mac": "de:ad:be:ef:00:00", "vendor": "?"}
    alertes, gw = m.detect_arp_anomalies([ROUTEUR, pirate], "192.168.1.1")
    assert gw is None
    assert any("Plusieurs MAC" in a for a in alertes)


def test_arp_meme_mac_plusieurs_ip():
    clone = dict(TEL, ip="192.168.1.21")
    alertes, _ = m.detect_arp_anomalies([ROUTEUR, TEL, clone], "192.168.1.1")
    assert any("plusieurs IP" in a for a in alertes)


def test_update_from_devices_nouveau_puis_connu():
    known = {}
    nouveaux = m.update_from_devices([dict(TEL)], known, "2026-11-06 10:00")
    assert [d["mac"] for d in nouveaux] == [TEL["mac"]]
    assert known[TEL["mac"]]["times_seen"] == 1

    nouveaux = m.update_from_devices([dict(TEL, ip="192.168.1.99")], known, "2026-11-06 11:00")
    assert nouveaux == []
    info = known[TEL["mac"]]
    assert info["times_seen"] == 2 and info["last_ip"] == "192.168.1.99"
    assert info["first_seen"] == "2026-11-06 10:00"


def test_sauvegarde_atomique_et_relecture():
    m.save_known_devices({"x": {"name": "Téléphone"}})
    assert m.load_known_devices() == {"x": {"name": "Téléphone"}}
    assert not os.path.exists(m.KNOWN_DEVICES_FILE + ".tmp")


def test_fichier_corrompu_ne_plante_pas():
    with open(m.KNOWN_DEVICES_FILE, "w") as f:
        f.write("{pas du json")
    assert m.load_known_devices() == {}


def test_migration_ancien_nom(tmp_path):
    ancien = tmp_path / ".scan_info_id_espion_known_devices.json"
    ancien.write_text(json.dumps({"aa": {"name": "vieux"}}))
    assert m.load_known_devices() == {"aa": {"name": "vieux"}}
    assert not ancien.exists()


def test_rotation_du_journal(monkeypatch):
    monkeypatch.setattr(m, "HISTORY_MAX_BYTES", 50)
    for i in range(10):
        m.log_event(f"évènement numéro {i}")
    assert os.path.exists(m.HISTORY_FILE + ".1")
    assert os.path.getsize(m.HISTORY_FILE) < 200


def test_exports(monkeypatch):
    known = {TEL["mac"]: {"name": "<script>", "first_seen": "a", "last_seen": "b",
                          "times_seen": 3, "last_ip": TEL["ip"], "vendor": "Samsung",
                          "risky_ports": ["23/telnet"], "cves": ["CVE-2017-0144"]}}
    html = open(m.export_html(known), encoding="utf-8").read()
    assert "&lt;script&gt;" in html and "<script>" not in html  # échappé
    assert TEL["mac"] in open(m.export_csv(known), encoding="utf-8").read()

    monkeypatch.setattr(m, "check_wifi_security", lambda: None)
    secu = open(m.export_security_report(known), encoding="utf-8").read()
    assert "23/telnet" in secu and "CVE-2017-0144" in secu


def test_atomic_write_preserve_les_permissions_restreintes():
    import os
    import stat
    # Fichier neuf (peut contenir un mot de passe) → 0600 par défaut
    m.save_config({"email": {"password": "secret"}})
    mode = stat.S_IMODE(os.stat(m.CONFIG_FILE).st_mode)
    assert mode == 0o600
    # Si la cible est déjà restreinte, une réécriture NE l'élargit pas
    os.chmod(m.CONFIG_FILE, 0o600)
    m.save_config({"email": {"password": "secret"}, "gateway_mac": "aa:bb:cc:dd:ee:ff"})
    assert stat.S_IMODE(os.stat(m.CONFIG_FILE).st_mode) == 0o600
    assert not os.path.exists(m.CONFIG_FILE + ".tmp")


def test_atomic_write_preserve_un_mode_large_existant():
    import os
    import stat
    # Si l'admin a volontairement mis 0644, on le garde tel quel
    m.save_known_devices({})
    os.chmod(m.KNOWN_DEVICES_FILE, 0o644)
    m.save_known_devices({"aa": {"name": "x"}})
    assert stat.S_IMODE(os.stat(m.KNOWN_DEVICES_FILE).st_mode) == 0o644
