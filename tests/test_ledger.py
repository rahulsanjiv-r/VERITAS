"""
VERITAS — test_ledger.py

10 tests covering Phase 4: hash chain and Merkle tree implementation in ledger.py.

Test list
---------
1.  test_merkle_single_leaf               — one leaf → root == leaf hash
2.  test_merkle_even_leaves               — 4 leaves → valid tree, proof verifies
3.  test_merkle_odd_leaves                — 3 leaves → valid tree, proof verifies
4.  test_merkle_tampered_leaf             — modified leaf → proof fails
5.  test_merkle_tampered_proof_node       — modified proof node → proof fails
6.  test_merkle_tampered_root             — correct leaf+proof, wrong root → False
7.  test_hash_chain_sequential            — 3 certs appended → verify_chain True
8.  test_hash_chain_tampered              — corrupt middle cert hash → verify_chain False
9.  test_certificate_bytes_deterministic  — same cert dict → identical bytes
10. test_certificate_proof_roundtrip      — insert cert, get_certificate_proof, valid=True
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from backend.ledger import (
    append_to_chain,
    build_merkle_tree,
    certificate_bytes,
    get_certificate_proof,
    get_merkle_proof,
    get_merkle_root,
    hash_chain_entry,
    verify_chain,
    verify_merkle_proof,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(text: str) -> bytes:
    """Produce a deterministic 32-byte leaf hash from a short string."""
    return _sha256(text.encode())


def _make_db(tmp_path: Any) -> sqlite3.Connection:
    """Create a minimal SQLite database with the VERITAS schema."""
    db_path = tmp_path / "veritas_test.db"
    db = sqlite3.connect(str(db_path))
    db.row_factory = sqlite3.Row
    db.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS facilities (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            capacity_kg  REAL NOT NULL,
            waste_category TEXT NOT NULL,
            pubkey_hex   TEXT NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS arrivals (
            id              TEXT PRIMARY KEY,
            facility_id     TEXT NOT NULL REFERENCES facilities(id),
            device_id       TEXT NOT NULL,
            weight_kg       REAL NOT NULL,
            photo_hash_hex  TEXT NOT NULL,
            timestamp_iso   TEXT NOT NULL,
            record_hash_hex TEXT NOT NULL,
            signature_hex   TEXT NOT NULL,
            used            INTEGER NOT NULL DEFAULT 0,
            fraud_flags     TEXT,
            submitted_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id              TEXT PRIMARY KEY,
            arrival_id      TEXT NOT NULL UNIQUE REFERENCES arrivals(id),
            facility_id     TEXT NOT NULL REFERENCES facilities(id),
            quantity_kg     REAL NOT NULL,
            waste_category  TEXT NOT NULL,
            ledger_hash_hex TEXT NOT NULL DEFAULT '',
            minted_at       TEXT NOT NULL
        );
        """
    )
    return db


def _insert_facility(db: sqlite3.Connection) -> str:
    """Insert a test facility and return its id."""
    fid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO facilities (id, name, capacity_kg, waste_category, pubkey_hex, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (fid, "Test Facility", 10000.0, "plastic", "a" * 64, now),
    )
    db.commit()
    return fid


def _insert_cert(
    db: sqlite3.Connection,
    facility_id: str,
    *,
    quantity_kg: float = 100.0,
    minted_at: str | None = None,
) -> str:
    """Insert a bare certificate (ledger_hash_hex='') and return its id."""
    cert_id = str(uuid.uuid4())
    arrival_id = str(uuid.uuid4())
    now = minted_at or datetime.now(timezone.utc).isoformat()

    # Insert a matching arrival first (FK constraint)
    db.execute(
        "INSERT INTO arrivals "
        "(id, facility_id, device_id, weight_kg, photo_hash_hex, timestamp_iso, "
        " record_hash_hex, signature_hex, used, submitted_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
        (
            arrival_id,
            facility_id,
            "device-test",
            quantity_kg,
            "b" * 64,
            now,
            "c" * 64,
            "d" * 128,
            now,
        ),
    )
    db.execute(
        "INSERT INTO certificates "
        "(id, arrival_id, facility_id, quantity_kg, waste_category, ledger_hash_hex, minted_at) "
        "VALUES (?, ?, ?, ?, ?, '', ?)",
        (cert_id, arrival_id, facility_id, quantity_kg, "plastic", now),
    )
    db.commit()
    return cert_id


# ---------------------------------------------------------------------------
# 1. Single leaf — root equals the leaf hash
# ---------------------------------------------------------------------------


def test_merkle_single_leaf() -> None:
    """A tree with exactly one leaf must have root == that leaf's hash."""
    leaf = _leaf("only-one")
    root = get_merkle_root([leaf])
    assert root == leaf, "Single-leaf root must equal the leaf itself"


# ---------------------------------------------------------------------------
# 2. Even leaves (4) — valid tree, proof verifies for every leaf
# ---------------------------------------------------------------------------


def test_merkle_even_leaves() -> None:
    """Four leaves → Merkle tree is valid and proofs verify for all indices."""
    leaves = [_leaf(f"leaf-{i}") for i in range(4)]
    root = get_merkle_root(leaves)

    for idx in range(4):
        proof = get_merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaves[idx], proof, root), (
            f"Proof for leaf {idx} failed to verify"
        )


# ---------------------------------------------------------------------------
# 3. Odd leaves (3) — valid tree, proof verifies for every leaf
# ---------------------------------------------------------------------------


def test_merkle_odd_leaves() -> None:
    """Three leaves (odd count) → Merkle tree is valid and proofs verify."""
    leaves = [_leaf(f"odd-{i}") for i in range(3)]
    root = get_merkle_root(leaves)

    for idx in range(3):
        proof = get_merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaves[idx], proof, root), (
            f"Proof for odd-count leaf {idx} failed to verify"
        )


# ---------------------------------------------------------------------------
# 4. Tampered leaf → verify_merkle_proof returns False
# ---------------------------------------------------------------------------


def test_merkle_tampered_leaf() -> None:
    """A modified leaf must not verify against the original proof + root."""
    leaves = [_leaf(f"t-{i}") for i in range(4)]
    root = get_merkle_root(leaves)
    proof = get_merkle_proof(leaves, 2)

    # Flip one bit in the leaf
    tampered = bytes([leaves[2][0] ^ 0xFF]) + leaves[2][1:]
    assert not verify_merkle_proof(tampered, proof, root), (
        "Tampered leaf must not verify"
    )


# ---------------------------------------------------------------------------
# 5. Tampered proof node → verify_merkle_proof returns False
# ---------------------------------------------------------------------------


def test_merkle_tampered_proof_node() -> None:
    """A corrupted sibling in the proof path must fail verification."""
    leaves = [_leaf(f"p-{i}") for i in range(4)]
    root = get_merkle_root(leaves)
    proof = get_merkle_proof(leaves, 1)

    # Corrupt the first sibling hash in the proof
    bad_proof = [{"hash": "ff" * 32, "direction": proof[0]["direction"]}] + proof[1:]
    assert not verify_merkle_proof(leaves[1], bad_proof, root), (
        "Tampered proof node must not verify"
    )


# ---------------------------------------------------------------------------
# 6. Tampered root → verify_merkle_proof returns False
# ---------------------------------------------------------------------------


def test_merkle_tampered_root() -> None:
    """Correct leaf and proof against a wrong root must return False."""
    leaves = [_leaf(f"r-{i}") for i in range(3)]
    root = get_merkle_root(leaves)
    proof = get_merkle_proof(leaves, 0)

    bad_root = bytes([root[0] ^ 0x01]) + root[1:]
    assert not verify_merkle_proof(leaves[0], proof, bad_root), (
        "Correct proof against wrong root must not verify"
    )


# ---------------------------------------------------------------------------
# 7. Sequential hash chain — 3 certs → verify_chain True
# ---------------------------------------------------------------------------


def test_hash_chain_sequential(tmp_path: Any) -> None:
    """Appending three certificates and verifying the full chain must succeed."""
    db = _make_db(tmp_path)
    fid = _insert_facility(db)

    # Insert certs with explicitly ordered timestamps so ordering is stable
    cert_ids: list[str] = []
    for i in range(3):
        ts = f"2026-09-18T{10 + i:02d}:00:00+00:00"
        cid = _insert_cert(db, fid, quantity_kg=float(100 + i * 10), minted_at=ts)
        cert_ids.append(cid)
        append_to_chain(db, cid)

    # Verify the full chain (from genesis)
    assert verify_chain(db) is True, "Full chain must verify after sequential appends"

    # Verify a sub-range
    assert verify_chain(db, from_cert_id=cert_ids[0], to_cert_id=cert_ids[2]) is True


# ---------------------------------------------------------------------------
# 8. Tampered chain — corrupt middle cert → verify_chain False
# ---------------------------------------------------------------------------


def test_hash_chain_tampered(tmp_path: Any) -> None:
    """Manually corrupting a stored ledger_hash_hex must cause verify_chain to fail."""
    db = _make_db(tmp_path)
    fid = _insert_facility(db)

    cert_ids: list[str] = []
    for i in range(3):
        ts = f"2026-09-18T{10 + i:02d}:00:00+00:00"
        cid = _insert_cert(db, fid, quantity_kg=float(50 + i * 5), minted_at=ts)
        cert_ids.append(cid)
        append_to_chain(db, cid)

    # Corrupt the second certificate's stored hash
    db.execute(
        "UPDATE certificates SET ledger_hash_hex = ? WHERE id = ?",
        ("dead" * 16, cert_ids[1]),  # 64 hex chars of garbage
    )
    db.commit()

    assert verify_chain(db) is False, (
        "Chain verification must fail when a stored hash is corrupted"
    )


# ---------------------------------------------------------------------------
# 9. certificate_bytes deterministic
# ---------------------------------------------------------------------------


def test_certificate_bytes_deterministic() -> None:
    """The same certificate dict must always produce the same byte sequence."""
    cert: dict[str, object] = {
        "id": "cert-abc",
        "arrival_id": "arr-xyz",
        "facility_id": "fac-123",
        "quantity_kg": 250.5,
        "waste_category": "plastic",
        "minted_at": "2026-09-18T12:00:00+00:00",
    }

    first = certificate_bytes(cert)
    second = certificate_bytes(cert)
    assert first == second, "certificate_bytes must be deterministic"

    # Sanity-check format
    expected_str = (
        "cert-abc|arr-xyz|fac-123|250.500000|plastic|2026-09-18T12:00:00+00:00"
    )
    assert first == expected_str.encode("utf-8")


# ---------------------------------------------------------------------------
# 10. Certificate proof roundtrip
# ---------------------------------------------------------------------------


def test_certificate_proof_roundtrip(tmp_path: Any) -> None:
    """Insert a certificate, build its proof bundle, and confirm valid=True."""
    db = _make_db(tmp_path)
    fid = _insert_facility(db)

    # Insert and append multiple certs so the Merkle tree has depth
    cert_ids: list[str] = []
    for i in range(4):
        ts = f"2026-09-18T{10 + i:02d}:00:00+00:00"
        cid = _insert_cert(db, fid, quantity_kg=float(200 + i * 25), minted_at=ts)
        cert_ids.append(cid)
        append_to_chain(db, cid)

    # Prove each certificate individually
    for cid in cert_ids:
        bundle = get_certificate_proof(db, cid)

        assert bundle["certificate_id"] == cid
        assert isinstance(bundle["leaf_hash"], str) and len(str(bundle["leaf_hash"])) == 64
        assert isinstance(bundle["merkle_root"], str) and len(str(bundle["merkle_root"])) == 64
        assert bundle["valid"] is True, (
            f"Proof for cert {cid} must be valid after append_to_chain"
        )

        # Cross-check: manually verify the proof
        leaf_bytes = bytes.fromhex(str(bundle["leaf_hash"]))
        root_bytes = bytes.fromhex(str(bundle["merkle_root"]))
        proof_list: list[dict[str, str]] = bundle["proof"]  # type: ignore[assignment]
        assert verify_merkle_proof(leaf_bytes, proof_list, root_bytes), (
            "Manual verify_merkle_proof must agree with bundle['valid']"
        )
