"""GxP kernel shared by every module.

Controls implemented here map to 21 CFR Part 11 / EU GMP Annex 11:
  - unique users, salted PBKDF2 passwords, lockout after repeated failures (11.10(d), 11.300)
  - secure, computer-generated, time-stamped audit trail recording who/what/when/why,
    append-only (enforced by DB triggers) and SHA-256 hash-chained so tampering is detectable (11.10(e))
  - every change creates an immutable version snapshot; prior values are never overwritten (11.10(e))
  - electronic signatures re-authenticate with password, carry name/time/meaning and are
    bound to a hash of the signed record content (11.50, 11.70, 11.200)
  - workflows enforce permitted sequencing of steps and role-based authority checks (11.10(f), 11.10(g))
  - optional separation of duties: the author may not approve their own record
"""
import datetime
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

MAX_FAILED_LOGINS = 3
PBKDF2_ROUNDS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, full_name TEXT NOT NULL, roles TEXT NOT NULL,
  salt BLOB NOT NULL, pw_hash BLOB NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS counters(prefix TEXT PRIMARY KEY, n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS records(
  id TEXT PRIMARY KEY, module TEXT NOT NULL, rtype TEXT NOT NULL, number TEXT UNIQUE NOT NULL,
  state TEXT NOT NULL, version INTEGER NOT NULL, data TEXT NOT NULL,
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS record_versions(
  record_id TEXT NOT NULL, version INTEGER NOT NULL, state TEXT NOT NULL, data TEXT NOT NULL,
  saved_by TEXT NOT NULL, saved_at TEXT NOT NULL, PRIMARY KEY(record_id, version));
CREATE TABLE IF NOT EXISTS links(
  src TEXT NOT NULL, dst TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY(src, dst, kind));
CREATE TABLE IF NOT EXISTS signatures(
  id INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL, version INTEGER NOT NULL,
  username TEXT NOT NULL, full_name TEXT NOT NULL, meaning TEXT NOT NULL,
  signed_at TEXT NOT NULL, content_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_trail(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, username TEXT NOT NULL,
  action TEXT NOT NULL, record_id TEXT, detail TEXT NOT NULL, reason TEXT,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""

# GxP evidence tables are write-once: the database itself refuses edits and deletes.
for _table in ("audit_trail", "signatures", "record_versions"):
    for _op in ("UPDATE", "DELETE"):
        SCHEMA += (
            f"CREATE TRIGGER IF NOT EXISTS {_table}_no_{_op.lower()} BEFORE {_op} ON {_table} "
            f"BEGIN SELECT RAISE(ABORT, '{_table} is append-only'); END;\n"
        )


class GxPError(Exception):
    """A business or compliance rule refused the operation."""


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


@dataclass
class Transition:
    name: str
    src: tuple
    dst: str
    roles: tuple
    signature: Optional[str] = None      # signature meaning, e.g. "Approved by QA"; None = no e-sig
    separation_of_duties: bool = False   # signer must not be the record author
    guard: Optional[Callable] = None     # guard(system, record) -> error message or None
    requires_reason: bool = False


@dataclass
class RecordType:
    module: str
    rtype: str
    prefix: str
    initial: str
    transitions: list
    editable_states: tuple = ()
    required: tuple = ()
    create_roles: tuple = ()
    on_enter: dict = field(default_factory=dict)  # state -> hook(system, user, record)


class GxP:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.types = {}

    # ---------- infrastructure ----------
    def register(self, rt: RecordType):
        self.types[rt.rtype] = rt

    def _tx(self):
        return _Transaction(self.db)

    def _audit(self, username, action, record_id, detail, reason=None):
        last = self.db.execute("SELECT hash FROM audit_trail ORDER BY seq DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else "0" * 64
        ts = now()
        detail_json = canonical(detail)
        digest = sha256(canonical([prev, ts, username, action, record_id, detail_json, reason]))
        self.db.execute(
            "INSERT INTO audit_trail(ts, username, action, record_id, detail, reason, prev_hash, hash)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ts, username, action, record_id, detail_json, reason, prev, digest),
        )

    def verify_audit_chain(self):
        """Recompute the hash chain; returns (ok, first_bad_seq)."""
        prev = "0" * 64
        for row in self.db.execute("SELECT * FROM audit_trail ORDER BY seq"):
            expected = sha256(canonical([prev, row["ts"], row["username"], row["action"],
                                         row["record_id"], row["detail"], row["reason"]]))
            if row["prev_hash"] != prev or row["hash"] != expected:
                return False, row["seq"]
            prev = row["hash"]
        return True, None

    def audit(self, record_id=None):
        if record_id:
            rows = self.db.execute("SELECT * FROM audit_trail WHERE record_id=? ORDER BY seq", (record_id,))
        else:
            rows = self.db.execute("SELECT * FROM audit_trail ORDER BY seq")
        return [dict(r, detail=json.loads(r["detail"])) for r in rows]

    # ---------- users & authentication ----------
    def create_user(self, username, full_name, roles, password, actor="system"):
        if len(password) < 8:
            raise GxPError("password must be at least 8 characters")
        salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
        with self._tx():
            self.db.execute(
                "INSERT INTO users(username, full_name, roles, salt, pw_hash) VALUES (?,?,?,?,?)",
                (username, full_name, ",".join(roles), salt, pw_hash),
            )
            self._audit(actor, "user.create", None, {"username": username, "roles": list(roles)})

    def authenticate(self, username, password):
        """Verify credentials; locks the account after MAX_FAILED_LOGINS consecutive failures."""
        row = self.db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            with self._tx():
                self._audit(username, "auth.fail", None, {"why": "unknown user"})
            raise GxPError("invalid credentials")
        if not row["active"]:
            raise GxPError("account locked")
        attempt = hashlib.pbkdf2_hmac("sha256", password.encode(), row["salt"], PBKDF2_ROUNDS)
        with self._tx():
            if not hmac.compare_digest(attempt, row["pw_hash"]):
                failed = row["failed_attempts"] + 1
                locked = failed >= MAX_FAILED_LOGINS
                self.db.execute("UPDATE users SET failed_attempts=?, active=? WHERE username=?",
                                (failed, 0 if locked else 1, username))
                self._audit(username, "auth.lock" if locked else "auth.fail", None, {"failed": failed})
                ok = False
            else:
                self.db.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
                ok = True
        if not ok:
            raise GxPError("invalid credentials")
        return self.user(username)

    def user(self, username):
        row = self.db.execute("SELECT username, full_name, roles, active FROM users WHERE username=?",
                              (username,)).fetchone()
        if row is None:
            raise GxPError(f"unknown user {username}")
        return {"username": row["username"], "full_name": row["full_name"],
                "roles": set(row["roles"].split(",")), "active": bool(row["active"])}

    def _require_role(self, user, roles):
        if roles and not (user["roles"] & set(roles)) and "admin" not in user["roles"]:
            raise GxPError(f"{user['username']} lacks role {'/'.join(roles)}")

    # ---------- records ----------
    def _next_number(self, prefix):
        self.db.execute("INSERT OR IGNORE INTO counters VALUES (?, 0)", (prefix,))
        self.db.execute("UPDATE counters SET n = n + 1 WHERE prefix=?", (prefix,))
        n = self.db.execute("SELECT n FROM counters WHERE prefix=?", (prefix,)).fetchone()["n"]
        return f"{prefix}-{n:05d}"

    def _snapshot(self, rid, version, state, data, username, ts):
        self.db.execute("INSERT INTO record_versions VALUES (?,?,?,?,?,?)",
                        (rid, version, state, canonical(data), username, ts))

    def create(self, user, rtype, data):
        rt = self.types[rtype]
        self._require_role(user, rt.create_roles)
        missing = [f for f in rt.required if data.get(f) in (None, "", [])]
        if missing:
            raise GxPError(f"missing required fields: {', '.join(missing)}")
        rid, ts = str(uuid.uuid4()), now()
        with self._tx():
            number = self._next_number(rt.prefix)
            self.db.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (rid, rt.module, rtype, number, rt.initial, 1, canonical(data),
                             user["username"], ts, ts))
            self._snapshot(rid, 1, rt.initial, data, user["username"], ts)
            self._audit(user["username"], "record.create", rid, {"number": number, "data": data})
        return self.get(rid)

    def get(self, rid):
        row = self.db.execute("SELECT * FROM records WHERE id=? OR number=?", (rid, rid)).fetchone()
        if row is None:
            raise GxPError(f"no record {rid}")
        return dict(row, data=json.loads(row["data"]))

    def find(self, rtype=None, state=None):
        sql, args = "SELECT id FROM records WHERE 1=1", []
        if rtype:
            sql, args = sql + " AND rtype=?", args + [rtype]
        if state:
            sql, args = sql + " AND state=?", args + [state]
        return [self.get(r["id"]) for r in self.db.execute(sql + " ORDER BY number", args)]

    def versions(self, rid):
        rows = self.db.execute("SELECT * FROM record_versions WHERE record_id=? ORDER BY version", (rid,))
        return [dict(r, data=json.loads(r["data"])) for r in rows]

    def update(self, user, rid, changes, reason, _system=False):
        """Change record data. A reason is mandatory; the old value survives in record_versions."""
        rec = self.get(rid)
        rt = self.types[rec["rtype"]]
        if not _system:
            if rec["state"] not in rt.editable_states:
                raise GxPError(f"{rec['number']} is not editable in state '{rec['state']}'")
            if not reason:
                raise GxPError("a reason for change is required")
        data = {**rec["data"], **changes}
        self._write(user, rec, rec["state"], data, "record.update",
                    {"changes": changes, "old": {k: rec["data"].get(k) for k in changes}}, reason)
        return self.get(rec["id"])

    def _write(self, user, rec, state, data, action, detail, reason):
        version, ts = rec["version"] + 1, now()
        with self._tx():
            cur = self.db.execute(
                "UPDATE records SET state=?, version=?, data=?, updated_at=? WHERE id=? AND version=?",
                (state, version, canonical(data), ts, rec["id"], rec["version"]))
            if cur.rowcount != 1:
                raise GxPError("record was changed concurrently; reload and retry")
            self._snapshot(rec["id"], version, state, data, user["username"], ts)
            self._audit(user["username"], action, rec["id"], detail, reason)

    # ---------- workflow & e-signatures ----------
    def available_transitions(self, rid):
        rec = self.get(rid)
        return [t.name for t in self.types[rec["rtype"]].transitions if rec["state"] in t.src]

    def transition(self, user, rid, name, password=None, reason=None):
        rec = self.get(rid)
        rt = self.types[rec["rtype"]]
        t = next((t for t in rt.transitions if t.name == name), None)
        if t is None:
            raise GxPError(f"unknown transition '{name}' for {rec['rtype']}")
        if rec["state"] not in t.src:
            raise GxPError(f"cannot '{name}' {rec['number']} from state '{rec['state']}'")
        self._require_role(user, t.roles)
        if t.requires_reason and not reason:
            raise GxPError(f"'{name}' requires a reason")
        if t.separation_of_duties and user["username"] == rec["created_by"]:
            raise GxPError("separation of duties: the author cannot perform this step")
        if t.guard:
            problem = t.guard(self, rec)
            if problem:
                raise GxPError(problem)
        if t.signature:
            # Authenticate outside the transaction so a failed attempt still counts toward lockout.
            self._reauthenticate(user, password)
        with self._tx():
            if t.signature:
                self._record_signature(user, rec, t.signature)
            self._write(user, rec, t.dst, rec["data"], "record.transition",
                        {"transition": name, "from": rec["state"], "to": t.dst}, reason)
        rec = self.get(rid)
        hook = rt.on_enter.get(t.dst)
        if hook:
            hook(self, user, rec)
        return self.get(rid)

    def sign(self, user, rec, meaning, password):
        """Part 11 signature: re-authenticate, then bind name/time/meaning to the record content hash."""
        self._reauthenticate(user, password)
        self._record_signature(user, rec, meaning)

    def _reauthenticate(self, user, password):
        if not password:
            raise GxPError("electronic signature requires password re-entry")
        return self.authenticate(user["username"], password)

    def _record_signature(self, user, rec, meaning):
        signer = self.user(user["username"])
        content_hash = sha256(canonical([rec["id"], rec["version"], rec["state"], rec["data"]]))
        ts = now()
        with self._tx():
            self.db.execute(
                "INSERT INTO signatures(record_id, version, username, full_name, meaning, signed_at, content_hash)"
                " VALUES (?,?,?,?,?,?,?)",
                (rec["id"], rec["version"], signer["username"], signer["full_name"], meaning, ts, content_hash))
            self._audit(signer["username"], "esign", rec["id"],
                        {"meaning": meaning, "version": rec["version"], "content_hash": content_hash})

    def signatures(self, rid):
        return [dict(r) for r in self.db.execute(
            "SELECT * FROM signatures WHERE record_id=? ORDER BY id", (self.get(rid)["id"],))]

    def verify_signatures(self, rid):
        """Each signature must still match the immutable snapshot of the version it signed."""
        rid = self.get(rid)["id"]
        snaps = {v["version"]: v for v in self.versions(rid)}
        for s in self.signatures(rid):
            snap = snaps[s["version"]]
            if sha256(canonical([rid, s["version"], snap["state"], snap["data"]])) != s["content_hash"]:
                return False
        return True

    # ---------- relationships ----------
    def link(self, user, src, dst, kind):
        with self._tx():
            self.db.execute("INSERT OR IGNORE INTO links VALUES (?,?,?)", (src, dst, kind))
            self._audit(user["username"], "record.link", src, {"dst": dst, "kind": kind})

    def linked(self, rid, kind=None, reverse=False):
        col, other = ("src", "dst") if reverse else ("dst", "src")
        sql, args = f"SELECT {col} AS id FROM links WHERE {other}=?", [rid]
        if kind:
            sql, args = sql + " AND kind=?", args + [kind]
        return [self.get(r["id"]) for r in self.db.execute(sql, args)]


class _Transaction:
    """Re-entrant BEGIN/COMMIT so nested kernel calls share one atomic transaction."""

    def __init__(self, db):
        self.db = db
        self.outer = False

    def __enter__(self):
        if not self.db.in_transaction:
            self.db.execute("BEGIN IMMEDIATE")
            self.outer = True

    def __exit__(self, exc_type, *_):
        if self.outer:
            self.db.execute("ROLLBACK" if exc_type else "COMMIT")
        return False
