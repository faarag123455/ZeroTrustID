import os
import sqlite3
import sys

path = os.environ.get("DATABASE_PATH") or "instance/zerotrustid.db"
c = sqlite3.connect(path)
c.execute("UPDATE users SET role_id = 2 WHERE email = ?", (sys.argv[1],))
c.commit()
print("ok", c.total_changes, "ligne(s) modifiée(s)")