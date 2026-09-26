"""SQLite 持久化：确认版审查保存规范差异与复演请求。

ThreadingHTTPServer 每个请求一个线程，因此每个线程持有独立连接
（check_same_thread=False 下多线程写仍需串行化，写操作本身很短）。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
    id           TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    origin       TEXT NOT NULL,
    safe         INTEGER NOT NULL,
    diff_sha256  TEXT NOT NULL,
    digest       TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json  TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self.in_memory = path == ":memory:"
        if not self.in_memory:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.Lock()
        if self.in_memory:
            # 内存库通过 file::memory URI 共享，服务存活期间持有一个保持连接
            self._mem_uri = (
                f"file:reviews_{id(self):x}?mode=memory&cache=shared"
            )
            keeper = self._new_connect()
            keeper.executescript(_SCHEMA)
            keeper.commit()
            self._keeper = keeper
        else:
            init = sqlite3.connect(path)
            try:
                init.executescript(_SCHEMA)
                init.commit()
            finally:
                init.close()

    def _new_connect(self) -> sqlite3.Connection:
        if self.in_memory:
            conn = sqlite3.connect(self._mem_uri, uri=True, timeout=30)
        else:
            conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def save_review(self, request: dict, result: dict) -> str:
        review_id = uuid.uuid4().hex
        created = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            conn = self._new_connect()
            try:
                conn.execute(
                    """
                    INSERT INTO reviews
                        (id, created_at, origin, safe, diff_sha256, digest,
                         request_json, result_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        review_id,
                        created,
                        result["origin"],
                        1 if result["safe"] else 0,
                        result["diff_sha256"],
                        result["digest"],
                        json.dumps(request, ensure_ascii=False, sort_keys=True),
                        json.dumps(result, ensure_ascii=False, sort_keys=True),
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        return review_id

    def get_review(self, review_id: str) -> dict | None:
        conn = self._new_connect()
        try:
            row = conn.execute(
                "SELECT * FROM reviews WHERE id = ?", (review_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_reviews(self, limit: int = 100) -> list[dict]:
        conn = self._new_connect()
        try:
            rows = conn.execute(
                """
                SELECT id, created_at, origin, safe, diff_sha256, digest
                FROM reviews ORDER BY created_at DESC, id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        finally:
            conn.close()
        return [dict(row) for row in rows]

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "origin": row["origin"],
            "safe": bool(row["safe"]),
            "diff_sha256": row["diff_sha256"],
            "digest": row["digest"],
            "replay_request": json.loads(row["request_json"]),
            "review": json.loads(row["result_json"]),
        }
