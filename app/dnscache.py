"""离线 DNS 缓存复演（cache replay）。

不发起任何真实 DNS 查询：输入一串**按时间非递减排列**的查询事件
（每项含 ``time``、``name``、``type``），逐项在一个进程内缓存上模拟
解析器行为；查询未命中时可在事件上附一条**离线权威响应**
（``response``，含 ``aa``/``rcode``/``answer``/``authority``），缓存只
从这些随请求提供的响应学习，绝不联网。

缓存语义：

- 每次查询前先清除到期项（``expire_at <= time`` 即删），故**恰在到期
  时刻的查询算 miss**；同一时刻的多个事件按输入顺序处理，TTL=0 的
  学习结果对随后同一时刻的事件已属到期；
- 正向 RRset 与 CNAME 分别以**自身 TTL** 衰减：CNAME 链每一节、末端
  RRset 都是独立缓存项；命中时沿缓存中的 CNAME 链取答案，链节缺失
  （``cname_chain_missing``）或成环（``cname_chain_cycle``）均为 miss；
- 仅接纳 ``AA=1`` 且权威 SOA **覆盖查询名**（同名或为其祖先）的
  NXDOMAIN/NODATA；负 TTL 取 SOA RR TTL 与 SOA MINIMUM 的较小值；
  NXDOMAIN 适用于同名的全部查询类型，NODATA 只适用于该查询类型；
- 缓存一致性：写入正向结果删除冲突负项；写入 CNAME 删除同名全部
  NODATA；写入 NXDOMAIN 删除同名全部正向项（含 CNAME）与 NODATA；
  写入 NODATA 删除同名 NXDOMAIN。

每个事件返回 hit/miss、（命中）答案与剩余 TTL、增删项及原因；响应
整体给出**最终快照**。只有请求格式错误（``400``）与响应记录内容错误
（``422``，``invalid_record``）走错误响应；AA/SOA 不符的否定响应不
被接纳（事件仍为 miss，原因在 ``response.decision`` 中给出）。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

_TYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,9}$")
# RDATA 为单个域名的类型（需要补全/校验目标名）
_NAME_RDATA_TYPES = frozenset({"CNAME", "NS", "PTR", "DNAME"})
_RCODES = {"NOERROR": 0, "NXDOMAIN": 3}
WILDCARD_TYPE = "*"  # NXDOMAIN 负项的类型键：覆盖同名全部类型


# ---------------------------------------------------------------------------
# 缓存项
# ---------------------------------------------------------------------------

@dataclass
class _Positive:
    """正向 RRset（CNAME 同样按正向项存储，独立 TTL）。"""

    name: str
    rtype: str
    ttl: int
    expire_at: int
    rdata: tuple[str, ...]  # 已去重、排序


@dataclass
class _Negative:
    """否定项：NXDOMAIN（qtype 为 ``*``）或 NODATA（qtype 为具体类型）。"""

    name: str
    qtype: str  # "*" 表示 NXDOMAIN
    ttl: int
    expire_at: int
    soa: dict  # {name, ttl, minimum, rdata}

    @property
    def kind(self) -> str:
        return "nxdomain" if self.qtype == WILDCARD_TYPE else "nodata"


# ---------------------------------------------------------------------------
# 请求校验 / 规范化
# ---------------------------------------------------------------------------

def _normalize_name(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", f"{field} 必须是非空字符串", 400
        )
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"{field} 非法: {exc}", 400
        ) from exc
    return name


def _normalize_type(value, field: str) -> str:
    if not isinstance(value, str) or not _TYPE_RE.fullmatch(value.strip()):
        raise ReviewError(
            "invalid_request", f"{field} 必须是 DNS 类型助记符: {value!r}",
            400,
        )
    return value.strip().upper()


def _normalize_ttl(value, field: str, default: int | None = None) -> int:
    if value is None:
        if default is not None:
            return default
        raise ReviewError("invalid_request", f"{field} 缺失", 400)
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 0 <= value < 2**31:
        raise ReviewError(
            "invalid_request", f"{field} 必须是 0..2^31-1 的整数", 400
        )
    return value


def _record_error(where: str, message: str) -> ReviewError:
    return ReviewError(
        "invalid_record",
        f"{where} 内容非法: {message}",
        422,
        [{"record": where, "message": message}],
    )


def _parse_rr(value, where: str) -> dict:
    """解析响应记录 ``{name,type,ttl?,rdata}`` 为规范化字典。"""
    if not isinstance(value, dict):
        raise ReviewError(
            "invalid_request", f"{where} 必须是记录对象", 400
        )
    name = _normalize_name(value.get("name"), f"{where}.name")
    rtype = _normalize_type(value.get("type"), f"{where}.type")
    ttl = _normalize_ttl(value.get("ttl"), f"{where}.ttl", default=0)
    rdata = value.get("rdata")
    if not isinstance(rdata, str) or not rdata.strip():
        raise _record_error(where, "rdata 必须是非空字符串")

    text = rdata.strip()
    try:
        if rtype == "A":
            canonical = str(ipaddress.IPv4Address(text))
        elif rtype == "AAAA":
            canonical = str(ipaddress.IPv6Address(text)).lower()
        elif rtype in _NAME_RDATA_TYPES:
            canonical = text.lower()
            if canonical != "." and not canonical.endswith("."):
                canonical += "."
            validate_name(canonical)
        else:
            # 不透明 RDATA（MX/TXT/SOA/...）：SOA 在否定响应处单独解析
            canonical = text
    except ValueError as exc:
        raise _record_error(where, f"{rtype} RDATA 非法: {exc}") from exc
    except ZoneParseError as exc:
        raise _record_error(where, f"{rtype} RDATA 名称非法: {exc}") from exc
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": canonical}


def _parse_soa(record: dict, where: str) -> dict:
    """解析权威区中的 SOA 记录，返回供负 TTL 计算的字段。"""
    fields = record["rdata"].split()
    if len(fields) != 7:
        raise _record_error(
            where,
            "SOA RDATA 必须是 7 个字段（mname rname serial refresh "
            f"retry expire minimum），实际 {len(fields)} 个",
        )
    numbers: list[int] = []
    for offset, label in ((2, "serial"), (3, "refresh"), (4, "retry"),
                          (5, "expire"), (6, "minimum")):
        token = fields[offset]
        if not token.isdigit():
            raise _record_error(where, f"SOA {label} 必须是非负整数: {token}")
        number = int(token)
        if not 0 <= number < 2**31:
            raise _record_error(where, f"SOA {label} 超出 0..2^31-1: {token}")
        numbers.append(number)
    return {
        "name": record["name"],
        "ttl": record["ttl"],
        "minimum": numbers[4],
        "rdata": record["rdata"],
    }


def _parse_response(value, where: str) -> dict:
    if not isinstance(value, dict):
        raise ReviewError(
            "invalid_request", f"{where} 必须是响应对象", 400
        )
    aa = value.get("aa", False)
    if not isinstance(aa, bool):
        raise ReviewError(
            "invalid_request", f"{where}.aa 必须是布尔值", 400
        )
    raw_rcode = value.get("rcode", "NOERROR")
    if isinstance(raw_rcode, str):
        if raw_rcode.strip().upper() not in _RCODES:
            raise ReviewError(
                "invalid_request",
                f"{where}.rcode 仅支持 NOERROR/NXDOMAIN: {raw_rcode!r}",
                400,
            )
        rcode = _RCODES[raw_rcode.strip().upper()]
    elif isinstance(raw_rcode, bool) or not isinstance(raw_rcode, int) \
            or not 0 <= raw_rcode <= 65535:
        raise ReviewError(
            "invalid_request", f"{where}.rcode 非法: {raw_rcode!r}", 400
        )
    else:
        rcode = raw_rcode

    sections: dict[str, list[dict]] = {}
    for section in ("answer", "authority"):
        raw = value.get(section, [])
        if not isinstance(raw, list):
            raise ReviewError(
                "invalid_request", f"{where}.{section} 必须是记录数组", 400
            )
        records = [
            _parse_rr(item, f"{where}.{section}[{pos}]")
            for pos, item in enumerate(raw)
        ]
        if section == "authority":
            for pos, record in enumerate(records):
                if record["type"] == "SOA":
                    records[pos] = {
                        **record,
                        "soa": _parse_soa(
                            record, f"{where}.authority[{pos}]"
                        ),
                    }
        sections[section] = records
    return {"aa": aa, "rcode": rcode, **sections}


# ---------------------------------------------------------------------------
# 排序工具
# ---------------------------------------------------------------------------

def _name_key(name: str):
    labels = () if name == "." else tuple(
        reversed(name.rstrip(".").split("."))
    )
    return labels, name


# ---------------------------------------------------------------------------
# 视图（序列化给客户端的结构）
# ---------------------------------------------------------------------------

def _positive_view(entry: _Positive, now: int) -> dict:
    return {
        "name": entry.name,
        "type": entry.rtype,
        "ttl": entry.ttl,
        "ttl_remaining": entry.expire_at - now,
        "expire_at": entry.expire_at,
        "rdata": list(entry.rdata),
    }


def _negative_view(entry: _Negative, now: int) -> dict:
    return {
        "name": entry.name,
        "kind": entry.kind,
        "qtype": None if entry.qtype == WILDCARD_TYPE else entry.qtype,
        "ttl": entry.ttl,
        "ttl_remaining": entry.expire_at - now,
        "expire_at": entry.expire_at,
        "soa": entry.soa,
    }


# ---------------------------------------------------------------------------
# 缓存
# ---------------------------------------------------------------------------

class _Cache:
    def __init__(self):
        self.positive: dict[tuple[str, str], _Positive] = {}
        self.negative: dict[tuple[str, str], _Negative] = {}

    def sweep(self, now: int) -> list[dict]:
        """删除所有到期项（含恰在 now 到期），返回变更记录。"""
        changes: list[dict] = []
        for key in sorted(self.positive):
            entry = self.positive[key]
            if entry.expire_at <= now:
                changes.append({
                    "action": "remove",
                    "entry": _positive_view(entry, now),
                    "reason": "ttl_expired",
                })
                del self.positive[key]
        for key in sorted(self.negative, key=lambda k: (*_name_key(k[0]),
                                                        k[1])):
            entry = self.negative[key]
            if entry.expire_at <= now:
                changes.append({
                    "action": "remove",
                    "entry": _negative_view(entry, now),
                    "reason": "ttl_expired",
                })
                del self.negative[key]
        return changes

    def _remove_negative(self, key, now: int, reason: str,
                         changes: list[dict]) -> None:
        old = self.negative.pop(key, None)
        if old is not None:
            changes.append({
                "action": "remove",
                "entry": _negative_view(old, now),
                "reason": reason,
            })

    def write_positive(self, entry: _Positive, now: int,
                       changes: list[dict]) -> None:
        """写入正向 RRset：删除冲突负项，同键刷新或新增。"""
        name, rtype = entry.name, entry.rtype
        # 正向结果与同名 NXDOMAIN 冲突
        self._remove_negative((name, WILDCARD_TYPE), now,
                              "positive_overrides_nxdomain", changes)
        # 与同类型 NODATA 冲突；CNAME 排他性还覆盖同名全部类型 NODATA
        types_to_clear = {rtype}
        if rtype == "CNAME":
            types_to_clear.update(
                qt for (owner, qt) in self.negative
                if owner == name and qt != WILDCARD_TYPE
            )
        for qtype in sorted(types_to_clear):
            self._remove_negative((name, qtype), now,
                                  "positive_overrides_nodata", changes)
        old = self.positive.get((name, rtype))
        reason = "answer_refreshed" if old is not None else "answer_learned"
        self.positive[(name, rtype)] = entry
        changes.append({
            "action": "store",
            "entry": _positive_view(entry, now),
            "reason": reason,
        })

    def write_nxdomain(self, name: str, ttl: int, now: int, soa: dict,
                       changes: list[dict]) -> None:
        """写入 NXDOMAIN：删除同名全部正向项（含 CNAME）与负项。"""
        for key in sorted(k for k in self.positive if k[0] == name):
            old = self.positive.pop(key)
            reason = ("nxdomain_overrides_cname" if old.rtype == "CNAME"
                      else "nxdomain_overrides_positive")
            changes.append({
                "action": "remove",
                "entry": _positive_view(old, now),
                "reason": reason,
            })
        for key in sorted(k for k in self.negative if k[0] == name):
            self._remove_negative(key, now, "nxdomain_overrides_nodata",
                                  changes)
        entry = _Negative(name, WILDCARD_TYPE, ttl, now + ttl, soa)
        self.negative[(name, WILDCARD_TYPE)] = entry
        changes.append({
            "action": "store",
            "entry": _negative_view(entry, now),
            "reason": "negative_learned",
        })

    def write_nodata(self, name: str, qtype: str, ttl: int, now: int,
                     soa: dict, changes: list[dict]) -> None:
        """写入 NODATA：删除同名 NXDOMAIN，同键刷新或新增。"""
        self._remove_negative((name, WILDCARD_TYPE), now,
                              "nodata_overrides_nxdomain", changes)
        old = self.negative.get((name, qtype))
        reason = ("negative_refreshed" if old is not None
                  else "negative_learned")
        entry = _Negative(name, qtype, ttl, now + ttl, soa)
        self.negative[(name, qtype)] = entry
        changes.append({
            "action": "store",
            "entry": _negative_view(entry, now),
            "reason": reason,
        })

    def lookup(self, qname: str, qtype: str):
        """沿 CNAME 链解析，返回 (状态, 链上 CNAME 项, 末端项/原因)。

        每个名字上的查找顺序：NXDOMAIN → 该类型 NODATA → 该类型正向
        RRset → CNAME 下一节；查询类型本身即 CNAME 时不沿链行走。
        """
        current = qname
        seen = {qname}
        chain: list[_Positive] = []
        while True:
            nxdomain = self.negative.get((current, WILDCARD_TYPE))
            if nxdomain is not None:
                return "negative", chain, nxdomain
            nodata = self.negative.get((current, qtype))
            if nodata is not None:
                return "negative", chain, nodata
            terminal = self.positive.get((current, qtype))
            if terminal is not None:
                return "positive", chain, terminal
            if qtype == "CNAME":
                return "miss", chain, ("not_cached", current)
            cname = self.positive.get((current, "CNAME"))
            if cname is None:
                # 链尚未起步（首名就什么都没有）与链节中途缺失区分
                reason = "cname_chain_missing" if chain else "not_cached"
                return "miss", chain, (reason, current)
            target = cname.rdata[0]
            if target in seen:
                return "miss", chain, ("cname_chain_cycle", current)
            seen.add(target)
            chain.append(cname)
            current = target

    def snapshot(self, now: int) -> dict:
        return {
            "time": now,
            "positive": [
                _positive_view(self.positive[key], now)
                for key in sorted(
                    self.positive,
                    key=lambda k: (*_name_key(k[0]), k[1]),
                )
            ],
            "negative": [
                _negative_view(self.negative[key], now)
                for key in sorted(
                    self.negative,
                    key=lambda k: (*_name_key(k[0]), k[1]),
                )
            ],
        }


# ---------------------------------------------------------------------------
# 响应分组与学习
# ---------------------------------------------------------------------------

def _group_answer(records: list[dict], where: str) -> list[dict]:
    """把 answer 记录按 (name,type) 聚成 RRset，校验同组 TTL 一致与
    CNAME 单点性，按 (name,type) 确定性排序。"""
    groups: dict[tuple[str, str], dict] = {}
    for record in records:
        key = (record["name"], record["type"])
        group = groups.get(key)
        if group is None:
            groups[key] = {
                "name": record["name"],
                "type": record["type"],
                "ttl": record["ttl"],
                "rdata": {record["rdata"]},
            }
            continue
        if group["ttl"] != record["ttl"]:
            raise _record_error(
                where,
                f"同一 RRset {record['name']} {record['type']} 的 TTL "
                f"不一致: {group['ttl']} != {record['ttl']}",
            )
        group["rdata"].add(record["rdata"])

    result = []
    for key in sorted(groups, key=lambda k: (*_name_key(k[0]), k[1])):
        group = groups[key]
        rdata = tuple(sorted(group["rdata"]))
        if group["type"] == "CNAME" and len(rdata) != 1:
            raise _record_error(
                where,
                f"CNAME {group['name']} 必须是单点 RRset，"
                f"实际 {len(rdata)} 个不同目标",
            )
        result.append({**group, "rdata": rdata})
    return result


def _covers(owner: str, name: str) -> bool:
    """SOA owner 是否覆盖 name（同名或 name 为其子域；根覆盖一切）。"""
    if owner == ".":
        return True
    return name == owner or name.endswith("." + owner)


def _covering_soa(authority: list[dict], qname: str,
                  where: str) -> dict | None:
    """选取覆盖 qname 的最长匹配 SOA（并列取最先出现者）。"""
    choice = None
    for record in authority:
        if record["type"] != "SOA":
            continue
        soa = record["soa"]
        if _covers(soa["name"], qname) and (
            choice is None
            or len(_name_key(soa["name"])[0])
            > len(_name_key(choice["name"])[0])
        ):
            choice = soa
    return choice


def _soa_view(soa: dict) -> dict:
    return {
        "name": soa["name"],
        "ttl": soa["ttl"],
        "minimum": soa["minimum"],
        "rdata": soa["rdata"],
    }


def _follow_answer(groups: list[dict], qname: str, qtype: str) -> tuple:
    """在响应 answer 的 RRset 集合内从 qname 沿 CNAME 行走。

    返回 ``("positive", terminal_name)``（链上某名字存在 qtype RRset）或
    ``("nodata", terminal_name)``（链停在一个没有 qtype RRset 的名字）；
    查询类型本身为 CNAME 时不沿链。仅检查从 qname 可达的链，answer 中
    与查询无关的 CNAME（含自指）按普通 RRset 学习、不影响判定。
    """
    by_key = {(g["name"], g["type"]): g for g in groups}
    if qtype == "CNAME":
        if (qname, "CNAME") in by_key:
            return "positive", qname
        return "nodata", qname
    current = qname
    seen = {qname}
    while True:
        if (current, qtype) in by_key:
            return "positive", current
        cname = by_key.get((current, "CNAME"))
        if cname is None:
            return "nodata", current
        target = cname["rdata"][0]
        if target in seen:
            # 成环的 CNAME 仍是合法单点 RRset：照常学习；环检测交给
            # 缓存查找（沿链成环为 miss），此处链终止于 current。
            return "nodata", current
        seen.add(target)
        current = target


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def replay_cache(payload: dict) -> dict:
    """按时间复演一串查询事件，返回逐项结果与最终快照。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)
    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        raise ReviewError(
            "invalid_request", "events 必须是查询事件数组", 400
        )

    events: list[dict] = []
    previous_time = 0
    for index, item in enumerate(raw_events):
        where = f"events[{index}]"
        if not isinstance(item, dict):
            raise ReviewError(
                "invalid_request", f"{where} 必须是对象", 400
            )
        time = _normalize_ttl(item.get("time"), f"{where}.time")
        if index > 0 and time < previous_time:
            raise ReviewError(
                "invalid_request",
                f"{where}.time={time} 早于上一事件时间 {previous_time}，"
                "事件必须按时间非递减排列",
                400,
            )
        previous_time = time
        name = _normalize_name(item.get("name"), f"{where}.name")
        qtype = _normalize_type(item.get("type"), f"{where}.type")
        response = None
        if "response" in item and item["response"] is not None:
            response = _parse_response(item["response"],
                                       f"{where}.response")
        events.append({
            "seq": index,
            "time": time,
            "name": name,
            "type": qtype,
            "response": response,
        })

    cache = _Cache()
    results: list[dict] = []
    last_time: int | None = None

    for event in events:
        now = event["time"]
        qname, qtype = event["name"], event["type"]
        last_time = now

        # 1) 查询前清除到期项（恰在到期也算 miss）
        changes = cache.sweep(now)

        # 2) 沿缓存 CNAME 链查找
        status, chain, outcome = cache.lookup(qname, qtype)
        answer: list[dict] = []
        negative = None
        if status == "positive":
            answer = [
                _positive_view(item, now) for item in [*chain, outcome]
            ]
            result_status, reason = "hit", (
                "cname_chain_hit" if chain else "positive_hit"
            )
        elif status == "negative":
            answer = [_positive_view(item, now) for item in chain]
            negative = _negative_view(outcome, now)
            result_status, reason = "hit", f"{outcome.kind}_hit"
        else:
            miss_reason, at_name = outcome
            reason = (miss_reason if miss_reason == "not_cached"
                      and at_name == qname
                      else f"{miss_reason}:{at_name}")
            result_status = "miss"

        result = {
            "seq": event["seq"],
            "time": now,
            "name": qname,
            "type": qtype,
            "status": result_status,
            "hit": ("positive" if status == "positive"
                    else "negative" if status == "negative" else None),
            "reason": reason,
            "answer": answer,
            "negative": negative,
            "changes": changes,
            "response": None,
        }

        # 3) miss 时若附有离线权威响应，则校验并（可能）学习
        response = event["response"]
        if response is not None and result_status == "miss":
            result["response"] = _learn(response, qname, qtype, now,
                                        cache, changes)

        results.append(result)

    return {
        "events": results,
        "snapshot": cache.snapshot(last_time) if last_time is not None
        else {"time": None, "positive": [], "negative": []},
    }


def _learn(response: dict, qname: str, qtype: str, now: int,
           cache: _Cache, changes: list[dict]) -> dict:
    """根据离线响应学习；返回该响应的接纳决策说明。"""
    aa, rcode = response["aa"], response["rcode"]
    base = {"aa": aa, "rcode": ("NXDOMAIN" if rcode == 3 else "NOERROR")}

    if rcode not in _RCODES.values():
        return {**base, "decision": "ignored", "learned": False,
                "reason": "unsupported_rcode", "negative": None}

    groups = _group_answer(response["answer"], "response.answer")

    if rcode == 3:
        # NXDOMAIN：answer 不参与正向缓存；仅接纳 AA=1 且 SOA 覆盖查询名者
        soa = _covering_soa(response["authority"], qname,
                            "response.authority")
        if not aa:
            return {**base, "decision": "ignored", "learned": False,
                    "reason": "aa_not_set", "negative": None}
        if soa is None:
            return {**base, "decision": "ignored", "learned": False,
                    "reason": "soa_not_covering", "negative": None}
        ttl = min(soa["ttl"], soa["minimum"])
        cache.write_nxdomain(qname, ttl, now, _soa_view(soa), changes)
        return {
            **base,
            "decision": "negative",
            "learned": True,
            "reason": None,
            "negative": {"kind": "nxdomain", "qtype": None, "ttl": ttl,
                         "soa": _soa_view(soa)},
        }

    # NOERROR：在 answer 集合内从查询名沿 CNAME 行走
    verdict, terminal = _follow_answer(groups, qname, qtype)
    if verdict == "positive":
        # 正向应答：answer 中全部 RRset 以各自 TTL 学习
        for group in groups:
            cache.write_positive(
                _Positive(group["name"], group["type"], group["ttl"],
                          now + group["ttl"], group["rdata"]),
                now, changes,
            )
        return {**base, "decision": "positive", "learned": True,
                "reason": None, "negative": None}

    # NODATA（链终止于 terminal）：answer（如 CNAME 链）照常正向学习，
    # 否定项需要 AA=1 且覆盖查询名的 SOA 才接纳，键为 (terminal, qtype)
    for group in groups:
        cache.write_positive(
            _Positive(group["name"], group["type"], group["ttl"],
                      now + group["ttl"], group["rdata"]),
            now, changes,
        )
    soa = _covering_soa(response["authority"], qname,
                        "response.authority")
    if not aa:
        return {**base, "decision": "ignored",
                "learned": bool(groups), "reason": "aa_not_set",
                "negative": None}
    if soa is None:
        return {**base, "decision": "ignored",
                "learned": bool(groups), "reason": "soa_not_covering",
                "negative": None}
    ttl = min(soa["ttl"], soa["minimum"])
    cache.write_nodata(terminal, qtype, ttl, now, _soa_view(soa), changes)
    return {
        **base,
        "decision": "negative",
        "learned": True,
        "reason": None,
        "negative": {"kind": "nodata", "name": terminal, "qtype": qtype,
                     "ttl": ttl, "soa": _soa_view(soa)},
    }
