import database
db_path = "test_mint.db"
database.init_db(db_path)
with database.get_db(db_path) as db:
    fac = database.register_facility(db, "Fac1", 1000, "plastic", "pubkey")
    arrival = database.insert_arrival(db, fac["id"], "dev1", 10.0, "photo", "2023", "rechash", "sig1", [])
    db.commit()

with database.get_db(db_path) as db:
    cert = database.atomic_mint(db, arrival["id"], 10.0, "plastic", "ledger")
    print(cert["quantity_kg"] if cert else "Failed")

    cert2 = database.atomic_mint(db, arrival["id"], 10.0, "plastic", "ledger")
    print("Should be None:", cert2)
