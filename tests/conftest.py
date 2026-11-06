import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import marceau  # noqa: E402

REAL_RUN = marceau._run  # gardée avant que la fixture la remplace


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Chaque test a son propre dossier de données et aucun effet de bord
    (pas de bip, pas de notification, pas d'e-mail, pas de vraie commande)."""
    d = str(tmp_path)
    for nom, fichier in (("KNOWN_DEVICES_FILE", ".marceau_known_devices.json"),
                         ("HISTORY_FILE", ".marceau_history.log"),
                         ("CONFIG_FILE", ".marceau_config.json"),
                         ("STATUS_FILE", ".marceau_status.json"),
                         ("LOCK_FILE", ".marceau.lock")):
        monkeypatch.setattr(marceau, nom, os.path.join(d, fichier))
    monkeypatch.setattr(marceau, "DATA_DIR", d)
    monkeypatch.setattr(marceau, "HOME", d)
    monkeypatch.setattr(marceau, "beep", lambda times=3: None)
    monkeypatch.setattr(marceau, "notify_desktop", lambda *a, **k: None)
    monkeypatch.setattr(marceau, "get_hostname", lambda ip: None)

    def interdit(*a, **k):
        raise AssertionError(f"commande système non simulée : {a}")
    monkeypatch.setattr(marceau, "_run", interdit)
    return tmp_path
