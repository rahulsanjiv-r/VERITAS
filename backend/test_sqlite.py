import sqlite3

conn = sqlite3.connect(":memory:")
try:
    conn.execute("""
    CREATE TABLE facilities (id TEXT PRIMARY KEY);
    """)
    conn.execute("""
    CREATE TABLE arrivals (id TEXT PRIMARY KEY);
    """)
    conn.execute("""
    CREATE TABLE certificates (
        id              TEXT PRIMARY KEY,
        arrival_id      TEXT NOT NULL UNIQUE REFERENCES arrivals(id),
        facility_id     TEXT NOT NULL REFERENCES facilities(id)
    );
    """)
    print("Schema is valid!")
except Exception as e:
    print(f"Error: {e}")
