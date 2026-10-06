import sqlite3, sys

c = sqlite3.connect("instance/zerotrustid.db")
c.execute("UPDATE users SET role_id = 2 WHERE email = ?", (sys.argv[1],))
c.commit()
print("ok", c.total_changes, "ligne(s) modifiée(s)")