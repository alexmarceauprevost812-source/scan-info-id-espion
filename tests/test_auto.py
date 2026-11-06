"""Tests du mode autonome : on simule le réseau, on vérifie les décisions."""
import json

import pytest

import marceau as m

ROUTEUR = {"ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01", "vendor": "Routeur"}
TEL = {"ip": "192.168.1.20", "mac": "aa:aa:aa:aa:aa:02", "vendor": "Samsung"}
INTRUS = {"ip": "192.168.1.66", "mac": "de:ad:be:ef:00:66", "vendor": "Inconnu"}


@pytest.fixture
def reseau(monkeypatch):
    """Réseau simulé : modifie reseau["devices"] pour changer qui est présent."""
    etat = {"devices": [ROUTEUR, TEL], "dhcp": ["192.168.1.1"], "ports": [],
            "appels": {"dhcp": 0, "ports": 0, "audit": 0, "mail": []}}

    monkeypatch.setattr(m, "scan_network",
                        lambda interactive=True, subnet=None: [dict(d) for d in etat["devices"]])
    monkeypatch.setattr(m, "get_gateway", lambda: "192.168.1.1")

    def dhcp():
        etat["appels"]["dhcp"] += 1
        return etat["dhcp"]
    monkeypatch.setattr(m, "run_dhcp_discover", dhcp)

    def ports(ip):
        etat["appels"]["ports"] += 1
        return {"ports": etat["ports"], "os": "Linux", "device_type": "phone", "timeout": False}
    monkeypatch.setattr(m, "run_port_scan", ports)

    def audit(known, cfg=None, assume_yes=False):
        assert assume_yes is True  # jamais de question en mode autonome
        etat["appels"]["audit"] += 1
    monkeypatch.setattr(m, "do_full_audit", audit)

    monkeypatch.setattr(m, "send_email_text",
                        lambda sujet, corps, cfg: etat["appels"]["mail"].append(sujet) or True)
    monkeypatch.setattr(m, "check_wifi_security", lambda: None)
    return etat


DEJA_VU = {"00:00:00:00:00:00": {"first_seen": "x", "times_seen": 1}}


def test_premier_lancement_apprend_sans_alerter(reseau):
    known, state = {}, {}
    r = m.auto_cycle(known, {}, state, now_ts=1000)
    assert r["devices"] == 2 and r["new"] == [] and r["learned"] == 2
    assert state.get("alerts", []) == [] and reseau["appels"]["mail"] == []
    assert r["connected"] == [] and r["disconnected"] == []
    assert set(known) == {ROUTEUR["mac"], TEL["mac"]}
    assert state["present"] == sorted([ROUTEUR["mac"], TEL["mac"]])


def test_intrus_detecte_puis_deconnexion(reseau):
    known, state = {}, {}
    m.auto_cycle(known, {}, state, now_ts=1000)

    reseau["devices"] = [ROUTEUR, TEL, INTRUS]
    r = m.auto_cycle(known, {}, state, now_ts=1200)
    assert r["new"] == [INTRUS["mac"]]
    assert r["connected"] == []  # déjà annoncé comme NOUVEAU
    assert any("Nouvel appareil" in a for a in state["alerts"])

    reseau["devices"] = [ROUTEUR, TEL]
    r = m.auto_cycle(known, {}, state, now_ts=1400)
    assert r["disconnected"] == [INTRUS["mac"]] and r["new"] == []

    reseau["devices"] = [ROUTEUR, TEL, INTRUS]
    r = m.auto_cycle(known, {}, state, now_ts=1600)
    assert r["connected"] == [INTRUS["mac"]] and r["new"] == []  # connu maintenant


def test_reference_passerelle_puis_usurpation(reseau):
    known, state, cfg = {}, {}, {}
    m.auto_cycle(known, cfg, state, now_ts=1000)
    assert json.load(open(m.CONFIG_FILE))["gateway_mac"] == ROUTEUR["mac"]

    reseau["devices"] = [dict(ROUTEUR, mac="66:66:66:66:66:66"), TEL]
    m.auto_cycle(known, cfg, state, now_ts=1200)
    assert any("ARP suspect" in a and "CHANGÉ" in a for a in state["alerts"])
    assert any("ARP" in s for s in reseau["appels"]["mail"])


def test_dhcp_periodique_et_pirate(reseau):
    cfg = {"auto": {"dhcp_check_every": 3600}}
    known, state = {}, {}
    m.auto_cycle(known, cfg, state, now_ts=10_000)
    m.auto_cycle(known, cfg, state, now_ts=10_100)  # trop tôt → pas relancé
    assert reseau["appels"]["dhcp"] == 1

    reseau["dhcp"] = ["192.168.1.1", "192.168.1.66"]
    m.auto_cycle(known, cfg, state, now_ts=14_000)
    assert reseau["appels"]["dhcp"] == 2
    assert any("DHCP" in a for a in state["alerts"])


def test_audits_bloques_sans_confirmation_du_proprietaire(reseau):
    cfg = {"auto": {"audit_new_devices": True, "full_audit_every": 60}}
    m.auto_cycle(dict(DEJA_VU), cfg, {}, now_ts=1000)
    assert reseau["appels"]["ports"] == 0 and reseau["appels"]["audit"] == 0


def test_audits_autorises_si_proprietaire(reseau):
    reseau["ports"] = [{"port": "23", "service": "telnet", "version": ""}]
    cfg = {"network_owner_confirmed": True,
           "auto": {"audit_new_devices": True, "full_audit_every": 60}}
    known, state = dict(DEJA_VU), {}
    m.auto_cycle(known, cfg, state, now_ts=1000)
    assert reseau["appels"]["ports"] == 2  # les 2 nouveaux appareils
    assert reseau["appels"]["audit"] == 1
    assert known[TEL["mac"]]["risky_ports"] == ["23/telnet"]
    assert any("Ports à risque" in a for a in state["alerts"])


def test_rapports_periodiques(reseau, tmp_path):
    m.auto_cycle({}, {"auto": {"report_every": 86400}}, {}, now_ts=100_000)
    assert (tmp_path / "marceau_rapport.html").exists()
    assert (tmp_path / "marceau_securite.txt").exists()


def test_reseau_injoignable_ne_plante_pas(reseau):
    reseau["devices"] = []
    state = {}
    r = m.auto_cycle({}, {}, state, now_ts=1000)
    assert r["devices"] == 0 and "last_error" in state


def test_alertes_limitees_a_20(reseau):
    state = {"alerts": [f"vieille {i}" for i in range(25)]}
    reseau["devices"] = [ROUTEUR, TEL, INTRUS]
    m.auto_cycle(dict(DEJA_VU), {}, state, now_ts=1000)
    assert len(state["alerts"]) == 20


def test_settings_par_defaut_et_minimum():
    assert m.auto_settings({})["interval"] == 120
    assert m.auto_settings({"auto": {"interval": 1}})["interval"] == 15


def test_run_auto_once_ecrit_le_statut(reseau, capsys):
    assert m.run_auto(once=True) == 0
    st = json.load(open(m.STATUS_FILE))
    assert st["cycles"] == 1 and st["running"] is False and st["version"] == m.__version__
    assert m.main(["--status"]) == 0
    assert "Cycles faits" in capsys.readouterr().out


def test_run_auto_survit_a_une_erreur(reseau, monkeypatch):
    def boum(*a, **k):
        raise RuntimeError("panne simulée")
    monkeypatch.setattr(m, "auto_cycle", boum)
    assert m.run_auto(once=True) == 2
    assert "panne simulée" in json.load(open(m.STATUS_FILE))["last_error"]


def test_deux_instances_impossible(reseau):
    verrou = m._acquire_lock()
    try:
        assert m.run_auto(once=True) == 1
    finally:
        verrou.close()


def test_status_sans_historique():
    assert m.main(["--status"]) == 1


def test_cli_rename(capsys):
    m.save_known_devices({"aa:bb:cc:dd:ee:ff": {"name": None}})
    m.main(["--rename", "AA:BB:CC:DD:EE:FF", "Téléphone de REA"])
    assert m.load_known_devices()["aa:bb:cc:dd:ee:ff"]["name"] == "Téléphone de REA"


def test_signaux_restaures(reseau):
    import signal
    avant = signal.getsignal(signal.SIGINT)
    m.run_auto(once=True)
    assert signal.getsignal(signal.SIGINT) is avant


def test_sigterm_arrete_la_boucle(reseau, monkeypatch):
    """Simule `systemctl stop` pendant l'attente entre deux cycles."""
    import signal
    tours = {"n": 0}
    vrai_cycle = m.auto_cycle

    def cycle(*a, **k):
        tours["n"] += 1
        signal.raise_signal(signal.SIGTERM)
        return vrai_cycle(*a, **k)
    monkeypatch.setattr(m, "auto_cycle", cycle)
    assert m.run_auto(once=False, interval=15) == 0
    assert tours["n"] == 1


def test_run_auto_relit_les_appareils_a_chaque_cycle(reseau, monkeypatch):
    """La boucle doit relire known sur le disque (et non garder une copie en
    mémoire) pour qu'un --rename/forget manuel ne soit pas écrasé."""
    m.save_known_devices({"99:99:99:99:99:99": {"name": "ajouté à la main",
                                                "first_seen": "x", "times_seen": 1}})
    vus = {}

    def capture(known, cfg, state, now_ts=None):
        vus["known"] = dict(known)
    monkeypatch.setattr(m, "auto_cycle", capture)
    m.run_auto(once=True)
    assert "99:99:99:99:99:99" in vus["known"]  # relu depuis le disque dans la boucle
