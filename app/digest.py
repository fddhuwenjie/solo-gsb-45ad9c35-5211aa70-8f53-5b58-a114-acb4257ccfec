"""规范化摘要。

摘要的输入是解析、排序、去重后的结构，因此：
- 区域文本中记录顺序打乱 -> 同一摘要；
- 同一 RDATA 重复书写 -> 同一摘要；
- TTL/时长的等价写法（3600 / 1h）-> 同一摘要；
- 相对名、``@``、省略属名等等价写法 -> 同一摘要。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> str:
    """RFC 8785 风格的紧凑确定性 JSON：键排序、无空白、原样保留 UTF-8。"""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def diff_digest(diff_entries: list[dict]) -> str:
    """对规范化 RRset 差异列表计算 SHA-256。"""
    return sha256_hex(canonical_json(diff_entries))


def review_digest(payload: dict) -> str:
    """对完整审查负载（源点、两侧规范文本、差异、序列号判定）计算摘要。"""
    return sha256_hex(canonical_json(payload))
