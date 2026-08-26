import sqlite3
from pathlib import Path

profile = Path("/data/runtime-persistence-js/profiles/user-persist/Default")
print("default_exists", profile.exists())
queries = [
    (
        "History",
        "select url, title, last_visit_time from urls order by last_visit_time desc limit 10",
    ),
    ("Cookies", "select host_key, name, length(encrypted_value), is_secure from cookies limit 20"),
]
for name, query in queries:
    database = profile / name
    print(
        name,
        "exists=",
        database.exists(),
        "size=",
        database.stat().st_size if database.exists() else None,
    )
    if database.exists():
        with sqlite3.connect(database) as connection:
            print(connection.execute(query).fetchall())
