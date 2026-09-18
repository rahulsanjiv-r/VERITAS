import re

with open("database.py", "r") as f:
    content = f.read()

# Replace SAVEPOINT sp
content = re.sub(
    r'    sp = f"sp_mint_\{uuid\.uuid4\(\)\.hex\}"  # unique savepoint name\n    db\.execute\(f"SAVEPOINT \{sp\};"\)',
    r'    db.execute("BEGIN IMMEDIATE;")',
    content
)

# Replace ROLLBACK TO SAVEPOINT sp; RELEASE SAVEPOINT sp;
content = re.sub(
    r'            db\.execute\(f"ROLLBACK TO SAVEPOINT \{sp\};"\)\n            db\.execute\(f"RELEASE SAVEPOINT \{sp\};"\)',
    r'            db.execute("ROLLBACK;")',
    content
)

content = re.sub(
    r'        db\.execute\(f"ROLLBACK TO SAVEPOINT \{sp\};"\)\n        db\.execute\(f"RELEASE SAVEPOINT \{sp\};"\)',
    r'        db.execute("ROLLBACK;")',
    content
)

# Replace RELEASE SAVEPOINT sp; with COMMIT;
content = re.sub(
    r'        db\.execute\(f"RELEASE SAVEPOINT \{sp\};"\)',
    r'        db.execute("COMMIT;")',
    content
)

with open("database.py", "w") as f:
    f.write(content)

