"""Altère une base de DÉMONSTRATION pour tester la détection.

  python demo_tamper.py modify 3      modifie l'entrée 3
  python demo_tamper.py delete 3      supprime l'entrée 3
  python demo_tamper.py truncate 2    supprime les 2 dernières entrées
"""
import os
import sqlite3
import sys

path = os.environ.get("DATABASE_PATH", "")
if "demo" not in path:
    sys.exit("Refus : DATABASE_PATH doit pointer vers une base de "
             "démonstration (chemin contenant 'demo').")

action, value = sys.argv[1], int(sys.argv[2])
c = sqlite3.connect(path)
if action == "modify":
    c.execute("UPDATE security_logs SET event_type='LOGIN_SUCCESS', "
              "ip='10.9.9.9' WHERE id = ?", (value,))
elif action == "delete":
    c.execute("DELETE FROM security_logs WHERE id = ?", (value,))
elif action == "truncate":
    c.execute("DELETE FROM security_logs WHERE id > "
              "(SELECT MAX(id) FROM security_logs) - ?", (value,))
else:
    sys.exit("Action inconnue.")
c.commit()
print("Base de démonstration altérée :", action, value)