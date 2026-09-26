"""NSEC 否认证明离线校验（RFC 4034 规范名称序；不校验 RRSIG）。

输入一个区的完整 NSEC 链（每条 ``{owner, next, types}``）与一条查询
``{name, type, expected}``（``expected`` 取 ``nodata`` / ``nxdomain``）。

链校验（违反返回 422）：
- owner 唯一；owner 与 next 均在区内；
- types 去重（重复项不报错）且必须含 NSEC；
- 按 RFC 4034 规范名称序，每条 next 必须指向后继 owner，
  最大 owner 的 next 绕回最小 owner，构成闭合环。

证明规则：
- NODATA：同名 NSEC 的 types 同时缺少查询类型与 CNAME；
- NXDOMAIN：覆盖查询名的环形区间 NSEC，并证明 ``*.<closest-encloser>``
  不存在（最近封闭名取 owner 集合中查询名的最长真祖先）。

响应逐条（每个证明步骤）给出 valid / 最小证明记录 / reason；
NSEC 列表与 types 的书写顺序不影响结果。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import compare_name
from .review import ReviewError

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,14}$")
EXPECTED_KINDS = ("nodata", "nxdomain")


@dataclass(frozen=True)
class NsecRecord:
    """一条规范化 NSEC：owner/next 为小写绝对名，types 去重排序。"""

    owner: str
    next: str
    types: tuple[str, ...]

    def to_json(self) -> dict:
        return {"owner": self.owner, "next": self.next,
                "types": list(self.types)}


# ---------------------------------------------------------------------------
# 名称与类型规范化
# ---------------------------------------------------------------------------

def _validate_name(name: str) -> None:
    """校验小写绝对名；允许最左标签为通配符 ``*``。"""
    if name == ".":
        return
    bare = name[:-1]
    if len(bare) > 253:
        raise ValueError(f"名称超过 253 字节: {name!r}")
    for idx, label in enumerate(bare.split(".")):
        if label == "*" and idx == 0:
            continue
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(f"非法名称标签: {label!r}（来自 {name!r}）")


def _normalize_name(token, origin: str, code: str, status: int,
                    what: str) -> str:
    """把名称记号规范化为小写绝对 FQDN（相对名相对 origin 补全）。"""
    if not isinstance(token, str) or not token.strip():
        raise ReviewError(code, f"{what} 必须是非空字符串", status)
    name = token.strip().lower()
    if name == "@":
        name = origin
    elif name == ".":
        pass
    elif not name.endswith("."):
        name = f"{name}.{origin}" if origin != "." else f"{name}."
    try:
        _validate_name(name)
    except ValueError as exc:
        raise ReviewError(code, f"{what} 非法: {exc}", status) from exc
    return name


def _normalize_origin(token) -> str:
    if not isinstance(token, str) or not token.strip():
        raise ReviewError("invalid_request", "zone_origin 必须是非空字符串",
                          400)
    origin = token.strip().lower()
    if origin != "." and not origin.endswith("."):
        origin += "."
    try:
        _validate_name(origin)
    except ValueError as exc:
        raise ReviewError("invalid_request", f"zone_origin 非法: {exc}",
                          400) from exc
    return origin


def _normalize_types(value, index: int) -> tuple[str, ...]:
    """types 去重并排序；必须含 NSEC。"""
    if not isinstance(value, list) or not value:
        raise ReviewError("invalid_nsec_record",
                          f"第 {index} 条 NSEC 的 types 必须是非空数组", 422)
    types: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not _TYPE_RE.fullmatch(item.strip()):
            raise ReviewError(
                "invalid_nsec_record",
                f"第 {index} 条 NSEC 含非法类型记号: {item!r}",
                422,
            )
        types.add(item.strip().upper())
    if "NSEC" not in types:
        raise ReviewError("missing_nsec_type",
                          f"第 {index} 条 NSEC 的 types 缺少 NSEC", 422)
    return tuple(sorted(types))


def _canon_key(name: str) -> tuple:
    """RFC 4034 规范名称序的排序键（标签逆序元组）。"""
    if name == ".":
        return ()
    return tuple(reversed(name.rstrip(".").split(".")))


def _in_zone(name: str, origin: str) -> bool:
    if origin == ".":
        return True
    return name == origin or name.endswith("." + origin)


# ---------------------------------------------------------------------------
# 链校验
# ---------------------------------------------------------------------------

def _build_chain(items: list, origin: str) -> list[NsecRecord]:
    """规范化 NSEC 列表并按 RFC 4034 规范名称序校验闭合链。"""
    records: list[NsecRecord] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ReviewError("invalid_nsec_record",
                              f"第 {index} 条 NSEC 必须是对象", 422)
        owner = _normalize_name(item.get("owner"), origin,
                                "invalid_nsec_record", 422,
                                f"第 {index} 条 NSEC 的 owner")
        next_ = _normalize_name(item.get("next"), origin,
                                "invalid_nsec_record", 422,
                                f"第 {index} 条 NSEC 的 next")
        types = _normalize_types(item.get("types"), index)
        records.append(NsecRecord(owner, next_, types))

    records.sort(key=lambda rec: _canon_key(rec.owner))

    for prev, cur in zip(records, records[1:]):
        if prev.owner == cur.owner:
            raise ReviewError(
                "duplicate_owner",
                f"NSEC owner {cur.owner} 出现多次，owner 必须唯一",
                422,
                [{"owner": cur.owner}],
            )

    for rec in records:
        for what, name in (("owner", rec.owner), ("next", rec.next)):
            if not _in_zone(name, origin):
                raise ReviewError(
                    "name_out_of_zone",
                    f"NSEC 的 {what} {name} 不在区 {origin} 内",
                    422,
                    [{"owner": rec.owner, "name": name, "zone": origin}],
                )

    for i, rec in enumerate(records):
        expected_next = records[(i + 1) % len(records)].owner
        if rec.next != expected_next:
            raise ReviewError(
                "nsec_chain_error",
                f"NSEC 链断裂: {rec.owner} 的 next 为 {rec.next}，"
                f"规范序后继应为 {expected_next}",
                422,
                [{"owner": rec.owner, "next": rec.next,
                  "expected_next": expected_next}],
            )
    return records


# ---------------------------------------------------------------------------
# 证明原语
# ---------------------------------------------------------------------------

def _covers(rec: NsecRecord, name: str) -> bool:
    """name（不等于任何 owner）是否落在 (owner, next) 环形区间内。"""
    if compare_name(rec.owner, rec.next) < 0:
        return (compare_name(rec.owner, name) < 0
                and compare_name(name, rec.next) < 0)
    # 绕回区间：最大 owner -> 最小 owner（单记录链时 owner == next，
    # 覆盖除自身外全部名字）
    return (compare_name(rec.owner, name) < 0
            or compare_name(name, rec.next) < 0)


def _find_covering(records: list[NsecRecord], name: str) -> NsecRecord | None:
    for rec in records:
        if _covers(rec, name):
            return rec
    return None


def _parent(name: str) -> str | None:
    if name == ".":
        return None
    bare = name[:-1]
    if "." not in bare:
        return "."
    return bare.split(".", 1)[1] + "."


def _closest_encloser(qname: str, origin: str,
                      owners: set[str]) -> str | None:
    """owner 集合中 qname 的最长真祖先（最近封闭名）。"""
    parent = _parent(qname)
    while parent is not None and _in_zone(parent, origin):
        if parent in owners:
            return parent
        parent = _parent(parent)
    return None


def _wildcard(ce: str) -> str:
    return f"*.{ce}" if ce != "." else "*."


def _prove_nodata(qname: str, qtype: str,
                  by_owner: dict[str, NsecRecord]) -> list[dict]:
    rec = by_owner.get(qname)
    if rec is None:
        return [{
            "check": "nodata",
            "valid": False,
            "reason": f"查询名 {qname} 没有同名 NSEC（名字不存在），"
                      "NODATA 不成立",
            "records": [],
        }]
    types = set(rec.types)
    if qtype in types:
        valid = False
        reason = f"同名 NSEC 的 types 已包含查询类型 {qtype}，NODATA 不成立"
    elif "CNAME" in types:
        valid = False
        reason = "同名 NSEC 的 types 含 CNAME，应按别名展开，NODATA 不成立"
    else:
        valid = True
        reason = (f"同名 NSEC 的 types 同时缺少 {qtype} 与 CNAME，"
                  "NODATA 成立")
    return [{
        "check": "nodata",
        "valid": valid,
        "reason": reason,
        "records": [rec.to_json()],
    }]


def _prove_nxdomain(qname: str, origin: str, records: list[NsecRecord],
                    by_owner: dict[str, NsecRecord]) -> list[dict]:
    checks: list[dict] = []
    owners = set(by_owner)

    existing = by_owner.get(qname)
    if existing is not None:
        checks.append({
            "check": "qname_cover",
            "valid": False,
            "reason": f"查询名 {qname} 存在同名 NSEC（名字存在），"
                      "NXDOMAIN 不成立",
            "records": [existing.to_json()],
        })
    else:
        cover = _find_covering(records, qname)
        if cover is None:  # 链校验通过后理论上不可达
            raise ReviewError("nsec_chain_error",
                              "NSEC 链未覆盖全部名字空间", 422)
        checks.append({
            "check": "qname_cover",
            "valid": True,
            "reason": f"NSEC {cover.owner} -> {cover.next} 的环形区间"
                      f"覆盖查询名 {qname}",
            "records": [cover.to_json()],
        })

    ce = _closest_encloser(qname, origin, owners)
    if ce is None:
        checks.append({
            "check": "wildcard_cover",
            "valid": False,
            "reason": f"owner 集合中没有 {qname} 的任何祖先，"
                      "无法确定最近封闭名",
            "records": [],
        })
    else:
        wildcard = _wildcard(ce)
        wrec = by_owner.get(wildcard)
        if wrec is not None:
            checks.append({
                "check": "wildcard_cover",
                "valid": False,
                "reason": f"通配符 {wildcard}（最近封闭名 {ce}）"
                          "存在同名 NSEC，NXDOMAIN 不成立",
                "records": [wrec.to_json()],
            })
        else:
            wcover = _find_covering(records, wildcard)
            if wcover is None:  # 链校验通过后理论上不可达
                raise ReviewError("nsec_chain_error",
                                  "NSEC 链未覆盖全部名字空间", 422)
            checks.append({
                "check": "wildcard_cover",
                "valid": True,
                "reason": f"NSEC {wcover.owner} -> {wcover.next} 覆盖通配符 "
                          f"{wildcard}（最近封闭名 {ce}），通配符不存在",
                "records": [wcover.to_json()],
            })
    return checks


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def verify_nsec_proof(payload: dict) -> dict:
    """校验 NSEC 链并判定一条 NODATA/NXDOMAIN 否认证明。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    origin = _normalize_origin(payload.get("zone_origin"))

    query = payload.get("query")
    if not isinstance(query, dict):
        raise ReviewError("invalid_request",
                          "query 必须是对象 {name, type, expected}", 400)
    qname = _normalize_name(query.get("name"), origin,
                            "invalid_request", 400, "查询名 name")
    qtype_raw = query.get("type")
    if not isinstance(qtype_raw, str) or not _TYPE_RE.fullmatch(
            qtype_raw.strip()):
        raise ReviewError("invalid_request",
                          f"查询类型 type 非法: {qtype_raw!r}", 400)
    qtype = qtype_raw.strip().upper()
    expected_raw = query.get("expected")
    if (not isinstance(expected_raw, str)
            or expected_raw.strip().lower() not in EXPECTED_KINDS):
        raise ReviewError(
            "invalid_request",
            f"expected 必须是 {'/'.join(EXPECTED_KINDS)} 之一", 400)
    expected = expected_raw.strip().lower()

    items = payload.get("nsec")
    if not isinstance(items, list):
        raise ReviewError("invalid_request", "nsec 必须是 NSEC 记录数组", 400)
    if not items:
        raise ReviewError("nsec_chain_error",
                          "NSEC 列表为空，无法构成闭合链", 422)

    records = _build_chain(items, origin)
    by_owner = {rec.owner: rec for rec in records}

    normalized_query = {"name": qname, "type": qtype, "expected": expected}

    if not _in_zone(qname, origin):
        return {
            "zone_origin": origin,
            "query": normalized_query,
            "valid": False,
            "reason": f"查询名 {qname} 不在区 {origin} 内，"
                      "本区 NSEC 链无法证明",
            "proof": [],
            "checks": [],
        }

    if expected == "nodata":
        checks = _prove_nodata(qname, qtype, by_owner)
    else:
        checks = _prove_nxdomain(qname, origin, records, by_owner)

    valid = all(check["valid"] for check in checks)
    if valid:
        merged: dict[str, dict] = {}
        for check in checks:
            for record in check["records"]:
                merged[record["owner"]] = record
        proof = [merged[key] for key in sorted(merged, key=_canon_key)]
        reason = "NODATA 证明成立" if expected == "nodata" \
            else "NXDOMAIN 证明成立"
    else:
        proof = []
        reason = next(check["reason"] for check in checks
                      if not check["valid"])

    return {
        "zone_origin": origin,
        "query": normalized_query,
        "valid": valid,
        "reason": reason,
        "proof": proof,
        "checks": checks,
    }
