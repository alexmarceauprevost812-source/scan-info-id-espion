#!/usr/bin/env python3
"""Ancien nom de l'outil (scan-info-id-espion). Il s'appelle maintenant Marceau.
Ce petit fichier garde les anciennes commandes fonctionnelles :
    sudo python3 scan_info_id_espion.py --scan   →   identique à marceau.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from marceau import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main() or 0)
