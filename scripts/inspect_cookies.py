import sqlite3

path = "/data/runtime-persistence-local/profiles/user-persist/Default/Cookies"
with sqlite3.connect(path) as database:
    print(
        database.execute(
            "select host_key,name,creation_utc,expires_utc,length(encrypted_value),value from cookies"
        ).fetchall()
    )
