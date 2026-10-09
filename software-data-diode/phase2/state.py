"""Single-process SQLite security state and bounded pending outbox per service."""

import sqlite3
import time

from .security import Rejected


class SecurityState:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS devices (device TEXT PRIMARY KEY, sequence INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, body TEXT NOT NULL,
                status TEXT NOT NULL, created REAL NOT NULL, arrival TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
        """)

    def check(self, message, digest):
        row = self.db.execute("SELECT * FROM messages WHERE id=?", (str(message.message_id),)).fetchone()
        if row:
            if row["fingerprint"] != digest:
                raise Rejected("DUPLICATE_MESSAGE", 409)
            return dict(row)
        row = self.db.execute("SELECT sequence FROM devices WHERE device=?", (message.device_id,)).fetchone()
        if row and message.sequence_number <= row["sequence"]:
            raise Rejected("REPLAY_DETECTED", 409)
        return None

    def accept(self, message, digest, body, arrival, *, receiver=False, retention=150):
        with self.db:
            self.db.execute("INSERT INTO messages VALUES (?, ?, ?, ?, ?, ?)",
                            (str(message.message_id), digest, body, "received" if receiver else "pending",
                             time.time(), arrival.isoformat()))
            self.db.execute("INSERT INTO devices VALUES (?, ?) ON CONFLICT(device) DO UPDATE SET sequence=excluded.sequence",
                            (message.device_id, message.sequence_number))
            self.db.execute("DELETE FROM messages WHERE status != 'pending' AND created < ?", (time.time() - retention,))
            self.increment("accepted_messages", commit=False)

    def complete(self, identifier, status):
        with self.db:
            self.db.execute("UPDATE messages SET status=? WHERE id=?", (status, str(identifier)))

    def pending(self):
        return self.db.execute("SELECT * FROM messages WHERE status='pending' ORDER BY rowid").fetchall()

    def recent(self):
        return self.db.execute("SELECT body FROM messages WHERE status='received' ORDER BY rowid DESC LIMIT 100").fetchall()

    def increment(self, name, *, commit=True):
        self.db.execute("INSERT INTO counters VALUES (?, 1) ON CONFLICT(name) DO UPDATE SET value=value+1", (name,))
        if commit:
            self.db.commit()

    def counters(self):
        return {row[0]: row[1] for row in self.db.execute("SELECT name, value FROM counters")}

    def close(self):
        self.db.close()
