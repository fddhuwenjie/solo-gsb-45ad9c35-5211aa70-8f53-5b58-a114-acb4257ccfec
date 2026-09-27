"""离线 DNS 缓存复演（POST /api/dns/cache/replay）。

不发起任何真实 DNS 查询：输入一串**按时间非递减排列**的查询事件
（每项含 ``time`` / ``name`` / ``type``，未命中时可附离线权威响应
``response``），在纯内存缓存上逐项复演：

1. **每次查询前清除到期项**——``expire_at <= now`` 即删，恰在到期时刻
   的条目算 miss（TTL=0 的学习结果只对同一时刻其后的事件可见）；
2. 先查负缓存（NXDOMAIN 同名覆盖全部类型，NODATA 仅覆盖该类型），
   再查正向；非 CNAME 查询命中 CNAME 时**沿缓存 CNAME 链**取答案，
   链上任一节缺失（链断）或成环都是 miss；
3. miss 且事件附 ``response`` 时按离线权威响应学习，否则 miss 无答案。

正向 RRset 与 CNAME **分别按自身 TTL 衰减**（链上每跳 TTL 独立）。
负缓存只接纳 **AA=1 且授权区 SOA 覆盖查询名（终名）** 的
NXDOMAIN / NODATA：负 TTL 取 **SOA RR TTL 与 SOA MINIMUM 的较小值**
（RFC 2308 §5）；NXDOMAIN 适用于同名全部类型，NODATA 只适用于该类型。

写入冲突规则：

- 写入正向结果（含 CNAME）时删除同名冲突负项（NXDOMAIN / 该类型
  NODATA）；查询命中后事件自带响应一律忽略，故存活条目不被覆盖
  （刷新只能在条目到期后的 miss 上发生）；
- 写入 NXDOMAIN 时删除**同名**全部正向 RRset 与 CNAME；
- 写入 NXDOMAIN 不删除同名 NODATA：NXDOMAIN 存活期内遮蔽它们，
  到期后未到期的 NODATA 重新生效。

``hit`` / ``miss`` 都是 **HTTP 200** 下的复演终态；只有请求格式错误
（400）与离线响应内容错误（422，含非法记录、CNAME 环、回答不可达、
否认应答缺 AA/覆盖 SOA 等）走错误响应；422 时本次复演不产生任何缓存
变更。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

QUERY_TYPES = ("A", "AAAA", "NS", "CNAME")
_ANSWER_TYPES = frozenset(QUERY_TYPES)
_MAX_TTL = 2**31 - 1
_MAX_U32 = 2**32 - 1
# 接受并显式分类的 RCODE；NXDOMAIN 可作负缓存，其余非 NOERROR 不可缓存
_RCODES = {
    0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED",
    "NOERROR": "NOERROR", "SERVFAIL": "SERVFAIL",
    "NXDOMAIN": "NXDOMAIN", "REFUSED": "REFUSED",
}


# ---------------------------------------------------------------------------
# 缓存数据模型
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Positive:
    """正向 RRset（CNAME 同样以正向条目存储，独立 TTL）。"""

    name: str
    rtype: str
    ttl: int
    born_at: int
    expire_at: int
    rdata: tuple[str, ...] = field(default_factory=tuple)

    def remaining(self, now: int) -> int:
        return self.expire_at - now


@dataclass(frozen=True)
class _Negative:
    """负缓存条目；rtype 为 None 表示 NXDOMAIN（同名覆盖全部类型）。"""

    name: str
    rtype: str | None
    kind: str  # "nxdomain" | "nodata"
    ttl: int
    born_at: int
    expire_at: int
    soa: str

    def remaining(self, now: int) -> int:
        return self.expire_at - now


def _name_sort_key(name: str):
    return tuple(reversed(name.rstrip(".").split("."))) if name != "." else ()


class _Cache:
    def __init__(self):
        self.positive: dict[tuple[str, str], _Positive] = {}
        self.negative: dict[tuple[str, str | None], _Negative] = {}

    @staticmethod
    def _is_expired(entry, now: int) -> bool:
        """恰在到期时刻（expire_at == now）算 miss——除非条目是在当前时刻
        才写入的：同一时刻的多个事件按输入顺序处理，TTL=0 的学习结果对
        同刻其后的事件仍可见。"""
        if entry.expire_at < now:
            return True
        return entry.expire_at == now and entry.born_at < now

    # -- 到期清理 ----
    def evict(self, now: int) -> list[dict]:
        """删除查询前已到期的全部条目，返回删除明细（确定顺序）。"""
        removed: list[tuple[int, tuple, object]] = []
        for key, entry in list(self.positive.items()):
            if self._is_expired(entry, now):
                removed.append((0, key, entry))
                del self.positive[key]
        for key, entry in list(self.negative.items()):
            if self._is_expired(entry, now):
                # NXDOMAIN（rtype=None）排在 NODATA 前
                removed.append((1 if key[1] is not None else 0, key, entry))
                del self.negative[key]
        removed.sort(key=lambda item: (
            _name_sort_key(item[1][0]), item[0], item[1][1] or "",
        ))
        return [_deleted_json(entry) for _, _key, entry in removed]

    # -- 查询 ----
    def lookup(self, name: str, rtype: str):
        """查缓存；不做到期清理（调用方须先 evict）。

        同名 NXDOMAIN 与 NODATA 同时存活时（NODATA 先学、NXDOMAIN 后到
        且未删除前者），NXDOMAIN 遮蔽 NODATA；NXDOMAIN 到期后 NODATA
        重新生效。
        """
        nxdomain = self.negative.get((name, None))
        nodata = self.negative.get((name, rtype))
        if nxdomain is not None:
            return _Lookup(hit=True, reason="hit_nxdomain",
                           negative=nxdomain)
        if nodata is not None:
            return _Lookup(hit=True, reason="hit_nodata", negative=nodata)

        if rtype == "CNAME":
            cname = self.positive.get((name, "CNAME"))
            if cname is not None:
                return _Lookup(hit=True, reason="hit_positive",
                               records=[cname])
            return _Lookup(hit=False, reason="miss_no_data")

        direct = self.positive.get((name, rtype))
        cname = self.positive.get((name, "CNAME"))
        if direct is not None:
            return _Lookup(hit=True, reason="hit_positive", records=[direct])
        if cname is None:
            return _Lookup(hit=False, reason="miss_no_data")

        # 沿缓存 CNAME 链行走；每节独立 TTL，缺失成环均为 miss
        chain: list[_Positive] = [cname]
        seen = {name}
        current = cname.rdata[0]
        while True:
            if current in seen:
                return _Lookup(
                    hit=False, reason="miss_cname_loop",
                    chain=chain,
                    detail={"loop_at": current,
                            "chain": [c.name for c in chain]},
                )
            seen.add(current)
            nxdomain = self.negative.get((current, None))
            if nxdomain is not None:
                return _Lookup(hit=True, reason="hit_nxdomain",
                               negative=nxdomain, chain=chain)
            nodata = self.negative.get((current, rtype))
            if nodata is not None:
                return _Lookup(hit=True, reason="hit_nodata",
                               negative=nodata, chain=chain)
            data = self.positive.get((current, rtype))
            next_cname = self.positive.get((current, "CNAME"))
            if data is not None:
                return _Lookup(hit=True, reason="hit_positive",
                               records=[data], chain=chain)
            if next_cname is None:
                return _Lookup(
                    hit=False, reason="miss_cname_broken_chain",
                    chain=chain,
                    detail={"missing_at": current,
                            "chain": [c.name for c in chain]},
                )
            chain.append(next_cname)
            current = next_cname.rdata[0]

    # -- 写入 ----
    def put_positive(self, name: str, rtype: str, ttl: int,
                     rdata: tuple[str, ...], now: int,
                     changes: "_Changes") -> _Positive:
        # 能走到写入时，同 (name,type) 存活正向条目必不存在（否则查询已
        # 命中、响应被忽略）；到期残留已在查询前清除。
        entry = _Positive(name, rtype, ttl, now, now + ttl, rdata)
        self.positive[(name, rtype)] = entry
        changes.added.append(_added_json(entry, reason="learned"))
        # 写入正向结果须删除冲突负项
        for key in ((name, None), (name, rtype)):
            neg = self.negative.pop(key, None)
            if neg is not None:
                changes.deleted.append(
                    _deleted_json(neg, reason="positive_removes_negative"))
        return entry

    def put_nxdomain(self, name: str, ttl: int, soa: str, now: int,
                     changes: "_Changes") -> _Negative:
        # 写入 NXDOMAIN 须删除同名正向与 CNAME
        for key in [k for k in self.positive if k[0] == name]:
            changes.deleted.append(
                _deleted_json(self.positive.pop(key),
                              reason="nxdomain_removes_positive"))
        return self._put_negative(name, None, "nxdomain", ttl, soa, now,
                                  changes)

    def put_nodata(self, name: str, rtype: str, ttl: int, soa: str,
                   now: int, changes: "_Changes") -> _Negative:
        return self._put_negative(name, rtype, "nodata", ttl, soa, now,
                                  changes)

    def _put_negative(self, name: str, rtype: str | None, kind: str,
                      ttl: int, soa: str, now: int,
                      changes: "_Changes") -> _Negative:
        # 能走到写入时同键存活负项必不存在（NXDOMAIN/NODATA 命中都会
        # 忽略响应；到期残留已清除）。
        entry = _Negative(name, rtype, kind, ttl, now, now + ttl, soa)
        self.negative[(name, rtype)] = entry
        changes.added.append(_added_json(entry, reason="learned"))
        return entry

    # -- 快照 ----
    def snapshot(self, now: int) -> dict:
        positives = sorted(self.positive.values(),
                           key=lambda e: (_name_sort_key(e.name), e.rtype))
        negatives = sorted(
            self.negative.values(),
            key=lambda e: (_name_sort_key(e.name),
                           0 if e.rtype is None else 1, e.rtype or ""),
        )
        return {
            "time": now,
            "positive": [_positive_json(e, now) for e in positives],
            "negative": [_negative_json(e, now) for e in negatives],
        }


@dataclass
class _Lookup:
    hit: bool
    reason: str
    negative: _Negative | None = None
    records: list[_Positive] = field(default_factory=list)
    chain: list[_Positive] = field(default_factory=list)
    detail: dict | None = None


@dataclass
class _Changes:
    added: list[dict] = field(default_factory=list)
    deleted: list[dict] = field(default_factory=list)

    def sort(self) -> None:
        self.added.sort(key=lambda e: (
            _name_sort_key(e["name"]),
            0 if e["kind"] == "negative" and e.get("type") is None else 1,
            e.get("type") or "",
        ))
        self.deleted.sort(key=lambda e: (
            _name_sort_key(e["name"]),
            0 if e["kind"] == "negative" and e.get("type") is None else 1,
            e.get("type") or "",
        ))


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------

def _positive_json(entry: _Positive, now: int | None = None) -> dict:
    body = {
        "kind": "positive",
        "name": entry.name,
        "type": entry.rtype,
        "ttl": entry.ttl,
        "rdata": list(entry.rdata),
    }
    if now is not None:
        body["ttl_remaining"] = entry.remaining(now)
    return body


def _negative_json(entry: _Negative, now: int | None = None) -> dict:
    body = {
        "kind": "negative",
        "negative": entry.kind,
        "name": entry.name,
        "type": entry.rtype,
        "ttl": entry.ttl,
        "soa": entry.soa,
    }
    if now is not None:
        body["ttl_remaining"] = entry.remaining(now)
    return body


def _added_json(entry, reason: str) -> dict:
    if isinstance(entry, _Positive):
        body = _positive_json(entry)
    else:
        body = _negative_json(entry)
    body["reason"] = reason
    return body


def _deleted_json(entry, reason: str = "expired") -> dict:
    if isinstance(entry, _Positive):
        body = {"kind": "positive", "name": entry.name,
                "type": entry.rtype}
    else:
        body = {"kind": "negative", "negative": entry.kind,
                "name": entry.name, "type": entry.rtype}
    body["reason"] = reason
    return body


def _chain_json(chain: list[_Positive], now: int) -> list[dict]:
    return [
        {"name": c.name, "target": c.rdata[0],
         "ttl_remaining": c.remaining(now)}
        for c in chain
    ]


def _answer_json(lookup: _Lookup, now: int) -> dict | None:
    if lookup.negative is not None:
        neg = lookup.negative
        body = {
            "kind": "negative",
            "negative": neg.kind,
            "name": neg.name,
            "type": neg.rtype,
            "soa": neg.soa,
            "cname_chain": _chain_json(lookup.chain, now),
            "ttl_remaining": neg.remaining(now),
        }
        ttls = [neg.remaining(now)]
        ttls.extend(c.remaining(now) for c in lookup.chain)
        body["ttl_remaining"] = min(ttls)
        return body
    if lookup.records:
        terminal = lookup.records[0]
        body = {
            "kind": "positive",
            "name": terminal.name,
            "type": terminal.rtype,
            "cname_chain": _chain_json(lookup.chain, now),
            "records": [_positive_json(terminal, now)],
        }
        ttls = [terminal.remaining(now)]
        ttls.extend(c.remaining(now) for c in lookup.chain)
        body["ttl_remaining"] = min(ttls)
        return body
    return None


# ---------------------------------------------------------------------------
# 请求解析
# ---------------------------------------------------------------------------

def _normalize_name(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError("invalid_request",
                          f"{field} 必须是非空字符串", 400)
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError("invalid_request",
                          f"{field} 非法: {exc}", 400) from exc
    return name


def _normalize_qtype(value) -> str:
    if not isinstance(value, str) or value.strip().upper() not in QUERY_TYPES:
        raise ReviewError(
            "invalid_request",
            f"type 必须是 {'/'.join(QUERY_TYPES)} 之一: {value!r}",
            400,
        )
    return value.strip().upper()


def _normalize_time(value, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReviewError(
            "invalid_request", f"{field} 必须是非负整数", 400
        )
    return value


def _normalize_ttl(value, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 0 <= value <= _MAX_TTL:
        raise ReviewError(
            "invalid_request",
            f"{where}.ttl 必须是 0..2^31-1 的整数", 400,
        )
    return value


def _record_error(where: str, message: str) -> ReviewError:
    return ReviewError(
        "invalid_record", f"{where} 内容非法: {message}", 422,
        [{"record": where, "message": message}],
    )


def _normalize_rdata(rtype: str, text: str, where: str) -> str:
    value = text.strip()
    try:
        if rtype == "A":
            return str(ipaddress.IPv4Address(value))
        if rtype == "AAAA":
            return str(ipaddress.IPv6Address(value)).lower()
        # NS / CNAME：目标为域名
        target = value.lower()
        if target != "." and not target.endswith("."):
            target += "."
        validate_name(target)
        return target
    except (ValueError, ZoneParseError) as exc:
        raise _record_error(where, f"{rtype} RDATA 非法: {exc}") from exc


@dataclass(frozen=True)
class _RawRecord:
    name: str
    rtype: str
    ttl: int
    rdata: str


def _parse_record(value, where: str) -> _RawRecord:
    if not isinstance(value, dict):
        raise ReviewError("invalid_request",
                          f"{where} 必须是记录对象", 400)
    name = _normalize_name(value.get("name"), f"{where}.name")
    rtype = value.get("type")
    if not isinstance(rtype, str) or not rtype.strip():
        raise ReviewError("invalid_request",
                          f"{where}.type 必须是非空字符串", 400)
    rtype = rtype.strip().upper()
    if rtype not in _ANSWER_TYPES:
        raise _record_error(
            where, f"回答区不支持的记录类型: {rtype}")
    rdata = value.get("rdata")
    if not isinstance(rdata, str) or not rdata.strip():
        raise ReviewError("invalid_request",
                          f"{where}.rdata 必须是非空字符串", 400)
    ttl = _normalize_ttl(value.get("ttl", 0), where)
    canonical = _normalize_rdata(rtype, rdata, where)
    return _RawRecord(name, rtype, ttl, canonical)


@dataclass(frozen=True)
class _Soa:
    owner: str
    ttl: int
    minimum: int
    rdata: str


def _parse_soa(value, where: str) -> _Soa:
    if not isinstance(value, dict):
        raise ReviewError("invalid_request",
                          f"{where} 必须是记录对象", 400)
    owner = _normalize_name(value.get("name"), f"{where}.name")
    rtype = str(value.get("type") or "").strip().upper()
    if rtype != "SOA":
        raise _record_error(where, f"不是 SOA 记录: {rtype}")
    ttl = _normalize_ttl(value.get("ttl", 0), where)
    rdata = value.get("rdata")
    if not isinstance(rdata, str) or not rdata.strip():
        raise ReviewError("invalid_request",
                          f"{where}.rdata 必须是非空字符串", 400)
    fields = rdata.split()
    if len(fields) != 7:
        raise _record_error(
            where,
            f"SOA RDATA 必须恰有 7 个字段（mname rname serial refresh "
            f"retry expire minimum），实际 {len(fields)} 个",
        )
    mname, rname = fields[0], fields[1]
    canonical_names = []
    for label, raw in (("mname", mname), ("rname", rname)):
        target = raw.strip().lower()
        if target != "." and not target.endswith("."):
            target += "."
        try:
            validate_name(target)
        except ZoneParseError as exc:
            raise _record_error(where, f"SOA {label} 非法: {exc}") from exc
        canonical_names.append(target)
    numbers = {}
    for label, raw in zip(
            ("serial", "refresh", "retry", "expire", "minimum"),
            fields[2:]):
        try:
            num = int(raw)
        except ValueError as exc:
            raise _record_error(
                where, f"SOA {label} 必须是整数: {raw!r}") from exc
        upper = _MAX_TTL if label == "minimum" else _MAX_U32
        if not 0 <= num <= upper:
            raise _record_error(
                where, f"SOA {label} 超出范围: {num}")
        numbers[label] = num
    canonical = " ".join(
        canonical_names + [
            str(numbers["serial"]), str(numbers["refresh"]),
            str(numbers["retry"]), str(numbers["expire"]),
            str(numbers["minimum"]),
        ]
    )
    return _Soa(owner, ttl, numbers["minimum"], canonical)


def _parse_response(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise ReviewError("invalid_request",
                          f"{where} 必须是对象", 400)
    aa = value.get("aa", False)
    if not isinstance(aa, bool):
        raise ReviewError("invalid_request",
                          f"{where}.aa 必须是布尔值", 400)
    rcode_raw = value.get("rcode", "NOERROR")
    if isinstance(rcode_raw, bool) or rcode_raw not in _RCODES:
        raise ReviewError(
            "invalid_request",
            f"{where}.rcode 只支持 NOERROR(0)/SERVFAIL(2)/"
            f"NXDOMAIN(3)/REFUSED(5): {rcode_raw!r}",
            400,
        )
    rcode = _RCODES[rcode_raw]

    for section in ("answer", "authority"):
        raw = value.get(section, [])
        if not isinstance(raw, list):
            raise ReviewError(
                "invalid_request",
                f"{where}.{section} 必须是记录数组", 400,
            )

    raw_answers = value.get("answer", [])
    raw_authority = value.get("authority", [])
    answers = [
        _parse_record(rec, f"{where}.answer[{i}]")
        for i, rec in enumerate(raw_answers)
    ]
    # 授权区只读取 SOA（用于负 TTL 与覆盖判定），其余记录一律忽略
    soas: list[_Soa] = []
    ignored_authority: list[str] = []
    for i, rec in enumerate(raw_authority):
        if not isinstance(rec, dict):
            raise ReviewError(
                "invalid_request",
                f"{where}.authority[{i}] 必须是记录对象", 400,
            )
        if str(rec.get("type") or "").strip().upper() == "SOA":
            soas.append(_parse_soa(rec, f"{where}.authority[{i}]"))
        else:
            ignored_authority.append(
                str(rec.get("type") or "?").strip().upper())
    return {
        "aa": aa, "rcode": rcode, "answers": answers, "soas": soas,
        "ignored_authority": ignored_authority,
    }


def _parse_events(payload: dict) -> list[dict]:
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)
    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise ReviewError(
            "invalid_request", "events 必须是非空事件数组", 400)
    events: list[dict] = []
    last_time: int | None = None
    for i, item in enumerate(raw_events):
        where = f"events[{i}]"
        if not isinstance(item, dict):
            raise ReviewError("invalid_request",
                              f"{where} 必须是对象", 400)
        time = _normalize_time(item.get("time"), f"{where}.time")
        if last_time is not None and time < last_time:
            raise ReviewError(
                "invalid_request",
                f"{where}.time={time} 早于前一事件时间 {last_time}："
                "事件必须按时间非递减排列",
                400,
            )
        last_time = time
        name = _normalize_name(item.get("name"), f"{where}.name")
        rtype = _normalize_qtype(item.get("type"))
        response = None
        if item.get("response") is not None:
            response = _parse_response(item["response"],
                                       f"{where}.response")
        events.append({"time": time, "name": name, "type": rtype,
                       "response": response})
    return events


# ---------------------------------------------------------------------------
# 离线响应学习
# ---------------------------------------------------------------------------

def _covers(zone_owner: str, name: str) -> bool:
    """SOA owner 是否覆盖 name（同名或为其祖先）。"""
    return name == zone_owner or name.endswith("." + zone_owner)


def _covering_soa(soas: list[_Soa], name: str) -> _Soa | None:
    candidates = [soa for soa in soas if _covers(soa.owner, name)]
    if not candidates:
        return None
    # 取最长（最具体）匹配的 SOA；并列时保留输入顺序首个
    best = candidates[0]
    for soa in candidates[1:]:
        if len(soa.owner) > len(best.owner):
            best = soa
    return best


def _group_answers(answers: list[_RawRecord], where: str,
                   notices: list[dict]) -> dict[tuple[str, str], dict]:
    """按 (name,type) 分组；同 RRset 多 TTL 取最小值（RFC 2181）。"""
    groups: dict[tuple[str, str], dict] = {}
    for rec in answers:
        key = (rec.name, rec.rtype)
        group = groups.get(key)
        if group is None:
            groups[key] = {"ttl": rec.ttl, "rdata": {rec.rdata}}
            continue
        if rec.ttl != group["ttl"]:
            notices.append({
                "code": "rrset_ttl_mismatch_min_used",
                "name": rec.name, "type": rec.rtype,
                "detail": f"同一 RRset TTL 不一致（{group['ttl']} 与 "
                          f"{rec.ttl}），按较小值缓存",
            })
            group["ttl"] = min(group["ttl"], rec.ttl)
        group["rdata"].add(rec.rdata)
    for (name, rtype), group in groups.items():
        if rtype == "CNAME" and len(group["rdata"]) > 1:
            raise _record_error(
                where,
                f"CNAME RRset {name} 含多个不同目标: "
                f"{sorted(group['rdata'])}",
            )
    return groups


def _walk_response(qname: str, qtype: str,
                   amap: dict[tuple[str, str], dict]):
    """在离线响应内沿 CNAME 行走，返回 (结局, 链, 终名, 可达名字集合)。

    结局：``data``（终名有 qtype 数据）/ ``none``（终名无数据无 CNAME，
    即 NODATA）/ ``loop``（CNAME 成环）。
    """
    chain: list[dict] = []
    seen = {qname}
    current = qname
    while True:
        if (current, qtype) in amap:
            return "data", chain, current, seen
        cname_group = amap.get((current, "CNAME"))
        if cname_group is None:
            return "none", chain, current, seen
        target = next(iter(cname_group["rdata"]))
        chain.append({"name": current, "target": target,
                      "ttl": cname_group["ttl"]})
        if target in seen:
            return "loop", chain, target, seen
        seen.add(target)
        current = target


def _require_authoritative_negative(resp: dict, terminal: str,
                                    where: str) -> tuple[_Soa, int]:
    """否认响应的准入：AA=1 且存在覆盖终名的 SOA；返回 (SOA, 负 TTL)。"""
    if not resp["aa"]:
        raise ReviewError(
            "negative_not_authoritative",
            f"{where} 否认应答必须 AA=1 才能进入负缓存（终名 {terminal}）",
            422,
            [{"terminal": terminal}],
        )
    soa = _covering_soa(resp["soas"], terminal)
    if soa is None:
        raise ReviewError(
            "negative_missing_soa",
            f"{where} 否认应答授权区缺少覆盖 {terminal} 的 SOA",
            422,
            [{"terminal": terminal}],
        )
    return soa, min(soa.ttl, soa.minimum)


def _ingest(event: dict, cache: _Cache, now: int) -> dict:
    """用事件自带离线响应学习；全部校验通过后才修改缓存。"""
    resp = event["response"]
    qname, qtype = event["name"], event["type"]
    where = "response"
    notices: list[dict] = []
    if resp["ignored_authority"]:
        notices.append({
            "code": "authority_non_soa_ignored",
            "detail": "授权区中非 SOA 记录不参与缓存复演",
            "types": sorted(set(resp["ignored_authority"])),
        })

    changes = _Changes()
    rcode = resp["rcode"]
    if rcode != "NOERROR" and rcode != "NXDOMAIN":
        return {
            "hit": False, "answer": None, "ttl_remaining": None,
            "reason": "miss_uncacheable_rcode",
            "changes": changes, "notices": notices,
            "detail": {"rcode": rcode},
        }

    amap = _group_answers(resp["answers"], where, notices)

    # 无论 NOERROR/NXDOMAIN，先在响应内沿 CNAME 行走并校验可达性
    ending, chain_spec, terminal, reachable = _walk_response(
        qname, qtype, amap)
    unreachable = sorted(
        {(n, t) for (n, t) in amap if n not in reachable},
        key=lambda k: (_name_sort_key(k[0]), k[1]),
    )
    if unreachable:
        raise ReviewError(
            "answer_unreachable",
            "回答区存在无法从查询名经 CNAME 链到达的记录",
            422,
            [{"name": n, "type": t} for (n, t) in unreachable],
        )
    if ending == "loop":
        chain_names = [c["name"] for c in chain_spec]
        raise ReviewError(
            "cname_loop",
            f"离线响应中的 CNAME 链成环: "
            f"{' -> '.join(chain_names + [terminal])}",
            422,
            [{"loop_at": terminal, "chain": chain_names}],
        )

    if rcode == "NXDOMAIN":
        # RFC 2308：NXDOMAIN 可随附指向不存在终名的 CNAME 链——链上
        # CNAME 照常缓存，负缓存以终名为键；链上/终名出现任何其它
        # （正向）记录都不是合法 NXDOMAIN。
        allowed = {(c["name"], "CNAME") for c in chain_spec}
        extra = sorted(
            set(amap) - allowed,
            key=lambda k: (_name_sort_key(k[0]), k[1]),
        )
        if extra:
            raise ReviewError(
                "nxdomain_with_answers",
                "NXDOMAIN 应答回答区只允许指向不存在终名的 CNAME 链，"
                "不得随附正向数据记录",
                422,
                [{"name": n, "type": t} for (n, t) in extra],
            )
        _soa, neg_ttl = _require_authoritative_negative(
            resp, terminal, where)

        # 所有 422 校验已过，开始写入
        learned_chain: list[_Positive] = []
        for spec in chain_spec:
            group = amap[(spec["name"], "CNAME")]
            learned_chain.append(cache.put_positive(
                spec["name"], "CNAME", group["ttl"],
                tuple(sorted(group["rdata"])), now, changes))
        entry = cache.put_nxdomain(terminal, neg_ttl, _soa.owner, now,
                                   changes)
        ttls = [entry.remaining(now)]
        ttls.extend(c.remaining(now) for c in learned_chain)
        answer = {
            "kind": "negative",
            "negative": "nxdomain",
            "name": entry.name,
            "type": None,
            "soa": entry.soa,
            "cname_chain": _chain_json(learned_chain, now),
            "ttl_remaining": min(ttls),
        }
        changes.sort()
        return {
            "hit": False, "answer": answer,
            "ttl_remaining": answer["ttl_remaining"],
            "reason": "learned_nxdomain",
            "changes": changes, "notices": notices,
        }

    # NOERROR
    # 所有 422 校验必须在任何写入之前完成（不合法响应不产生变更）。
    nodata_soa: _Soa | None = None
    nodata_ttl: int | None = None
    if ending == "none":
        # 负缓存只接纳 AA=1 且授权区 SOA 覆盖终名的 NODATA
        nodata_soa, nodata_ttl = _require_authoritative_negative(
            resp, terminal, where)
    elif not resp["aa"]:
        notices.append({
            "code": "non_authoritative_positive_accepted",
            "detail": "正向结果不要求 AA=1，响应已照常缓存",
        })

    learned_chain: list[_Positive] = []
    for spec in chain_spec:
        group = amap[(spec["name"], "CNAME")]
        learned_chain.append(cache.put_positive(
            spec["name"], "CNAME", group["ttl"],
            tuple(sorted(group["rdata"])), now, changes))

    if ending == "data":
        group = amap[(terminal, qtype)]
        terminal_entry = cache.put_positive(
            terminal, qtype, group["ttl"],
            tuple(sorted(group["rdata"])), now, changes)
        # 同响应中链上/终名的其余可达 RRset 一并缓存
        handled = {(c.name, "CNAME") for c in learned_chain}
        handled.add((terminal, qtype))
        coexisting_cname_at_terminal = (
            terminal != qname or ending == "data") and \
            (terminal, "CNAME") in amap and \
            (terminal, "CNAME") not in handled
        if coexisting_cname_at_terminal:
            notices.append({
                "code": "cname_coexists_with_data",
                "detail": f"{terminal} 同时携带 CNAME 与 {qtype} 数据"
                          "（RFC 1035 不建议）；查询按直接数据命中，"
                          "CNAME 仍照常缓存",
            })
        for (name, rtype), g in sorted(
                amap.items(), key=lambda kv: (_name_sort_key(kv[0][0]),
                                              kv[0][1])):
            if (name, rtype) in handled:
                continue
            cache.put_positive(name, rtype, g["ttl"],
                               tuple(sorted(g["rdata"])), now, changes)
        ttls = [terminal_entry.remaining(now)]
        ttls.extend(c.remaining(now) for c in learned_chain)
        answer = {
            "kind": "positive",
            "name": terminal_entry.name,
            "type": terminal_entry.rtype,
            "cname_chain": _chain_json(learned_chain, now),
            "records": [_positive_json(terminal_entry, now)],
            "ttl_remaining": min(ttls),
        }
        changes.sort()
        return {
            "hit": False, "answer": answer,
            "ttl_remaining": answer["ttl_remaining"],
            "reason": "learned_positive",
            "changes": changes, "notices": notices,
        }

    # ending == "none" 且校验已通过：学习 NODATA（可能带 CNAME 链前缀）
    entry = cache.put_nodata(terminal, qtype, nodata_ttl, nodata_soa.owner,
                             now, changes)
    ttls = [entry.remaining(now)]
    ttls.extend(c.remaining(now) for c in learned_chain)
    answer = {
        "kind": "negative",
        "negative": "nodata",
        "name": entry.name,
        "type": entry.rtype,
        "soa": entry.soa,
        "cname_chain": _chain_json(learned_chain, now),
        "ttl_remaining": min(ttls),
    }
    changes.sort()
    return {
        "hit": False, "answer": answer,
        "ttl_remaining": answer["ttl_remaining"],
        "reason": "learned_nodata",
        "changes": changes, "notices": notices,
    }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def replay_cache(payload: dict) -> dict:
    """复演一串离线 DNS 查询事件，逐项返回结论与最终缓存快照。"""
    events = _parse_events(payload)
    cache = _Cache()
    results: list[dict] = []
    for seq, event in enumerate(events, start=1):
        now, name, rtype = event["time"], event["name"], event["type"]
        notices: list[dict] = []

        # 1) 查询前清除到期项（恰在到期时算 miss）
        evicted = cache.evict(now)

        # 2) 查缓存
        lookup = cache.lookup(name, rtype)
        if lookup.hit:
            answer = _answer_json(lookup, now)
            result = {
                "seq": seq, "time": now, "name": name, "type": rtype,
                "hit": True, "answer": answer,
                "ttl_remaining": answer["ttl_remaining"],
                "reason": lookup.reason,
                "changes": {"added": [], "deleted": evicted},
            }
            if event["response"] is not None:
                notices.append({
                    "code": "response_ignored_on_hit",
                    "detail": "缓存已命中，事件自带响应不参与学习",
                })
        elif event["response"] is not None:
            learned = _ingest(event, cache, now)
            notices.extend(learned.pop("notices"))
            deleted = evicted + learned["changes"].deleted
            deleted.sort(key=lambda e: (
                _name_sort_key(e["name"]),
                0 if e["kind"] == "negative" and e.get("type") is None
                else 1,
                e.get("type") or "",
            ))
            result = {
                "seq": seq, "time": now, "name": name, "type": rtype,
                "hit": False,
                "answer": learned["answer"],
                "ttl_remaining": learned["ttl_remaining"],
                "reason": learned["reason"],
                "changes": {
                    "added": learned["changes"].added,
                    "deleted": deleted,
                },
            }
            if "detail" in learned:
                result["detail"] = learned["detail"]
        else:
            evicted.sort(key=lambda e: (
                _name_sort_key(e["name"]),
                0 if e["kind"] == "negative" and e.get("type") is None
                else 1,
                e.get("type") or "",
            ))
            result = {
                "seq": seq, "time": now, "name": name, "type": rtype,
                "hit": False, "answer": None, "ttl_remaining": None,
                "reason": lookup.reason,
                "changes": {"added": [], "deleted": evicted},
            }
            if lookup.detail is not None:
                result["detail"] = lookup.detail

        result["notices"] = notices
        results.append(result)

    return {
        "events": results,
        "snapshot": cache.snapshot(events[-1]["time"]),
    }
