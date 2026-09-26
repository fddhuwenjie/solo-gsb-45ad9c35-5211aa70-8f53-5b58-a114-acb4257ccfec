"""离线 SVCB/HTTPS（RFC 9460）解析。

不发起任何真实 DNS 查询：所有数据来自请求里给出的“本地区域文本集合”
（由 :mod:`app.zoneparse` 解析，SVCB/HTTPS RDATA 在区域解析阶段即完成
结构化校验）。

解析规则要点：
- ``priority=0`` 为 AliasMode：沿**同类型**（SVCB 或 HTTPS）别名链解析；
  同一 RRset 中别名记录与其它记录共存（多个别名）``422``、链成环
  ``422``、超过 8 跳 ``422``；别名目标 ``.`` 表示服务不可用；
- ``priority>0`` 为 ServiceMode：目标 ``.`` 回落为记录属名（owner）；
- 按客户端能力过滤 ServiceMode 记录：``mandatory`` 含客户端不支持的
  参数键、或记录的 ``alpn`` 与客户端 ALPN 列表无交集的记录被丢弃；
- 存活记录按 ``(priority, target)`` 稳定排序输出端点，并给出逐跳轨迹。

终态 ``ok`` / ``unavailable`` / ``nodata`` / ``filtered`` /
``unresolvable`` 都是 HTTP 200 下的解析结论；只有请求格式错误（400）
与记录/别名链错误（422）走错误响应。
"""

from __future__ import annotations

from .review import ReviewError
from .validity import find_cuts
from .zoneparse import (
    SVCB_KNOWN_KEYS,
    SvcbRdata,
    ZoneParseError,
    normalize_svcb_key,
    parse_svcb_rdata,
    parse_zone,
    validate_name,
)

MAX_ALIAS_HOPS = 8
QTYPES = ("SVCB", "HTTPS")
# 客户端参数键缺省值：本服务结构化支持的全部键
DEFAULT_CLIENT_KEYS = frozenset(SVCB_KNOWN_KEYS)

_DOMAIN_LABEL_SEP = "."


# ---------------------------------------------------------------------------
# 请求校验
# ---------------------------------------------------------------------------

def _parse_zones(value) -> dict[str, object]:
    if not isinstance(value, list) or not value:
        raise ReviewError(
            "invalid_request", "zones 必须是非空的区域文本字符串数组", 400
        )
    zones: dict[str, object] = {}
    parse_errors = []
    for position, text in enumerate(value):
        if not isinstance(text, str) or not text.strip():
            raise ReviewError(
                "invalid_request",
                f"zones[{position}] 必须是非空区域文本字符串",
                400,
            )
        try:
            zone = parse_zone(text)
        except ZoneParseError as exc:
            parse_errors.append({"index": position, "message": str(exc)})
            continue
        if zone.origin in zones:
            raise ReviewError(
                "invalid_request",
                f"zones 中源点 {zone.origin} 的区域出现多次",
                400,
            )
        zones[zone.origin] = zone
    if parse_errors:
        raise ReviewError(
            "zone_parse_error", "本地区域文本解析失败", 422, parse_errors
        )
    return zones


def _normalize_qname(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError("invalid_request", "qname 必须是非空字符串", 400)
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"qname 非法: {exc}", 400
        ) from exc
    return name


def _normalize_qtype(value) -> str:
    if not isinstance(value, str) or value.strip().upper() not in QTYPES:
        raise ReviewError(
            "invalid_request",
            f"qtype 必须是 {'/'.join(QTYPES)} 之一: {value!r}",
            400,
        )
    return value.strip().upper()


def _normalize_client_keys(value) -> frozenset[str]:
    """客户端支持的 SvcParamKey 集合；缺省为本服务已知的全部键。"""
    if value is None:
        return DEFAULT_CLIENT_KEYS
    if not isinstance(value, list):
        raise ReviewError(
            "invalid_request", "client_keys 必须是参数键字符串数组", 400
        )
    keys: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise ReviewError(
                "invalid_request",
                f"client_keys 元素必须是字符串: {item!r}",
                400,
            )
        try:
            keys.add(normalize_svcb_key(item))
        except ZoneParseError as exc:
            raise ReviewError(
                "invalid_request", f"client_keys 含非法参数键: {exc}", 400
            ) from exc
    return frozenset(keys)


def _normalize_client_alpn(value) -> list[str] | None:
    """客户端 ALPN 列表；缺省（null）表示不做 ALPN 交集过滤。"""
    if value is None:
        return None
    if not isinstance(value, list):
        raise ReviewError(
            "invalid_request", "client_alpn 必须是非空字符串数组", 400
        )
    for item in value:
        if not isinstance(item, str) or not item:
            raise ReviewError(
                "invalid_request",
                f"client_alpn 元素必须是非空字符串: {item!r}",
                400,
            )
    return list(value)


# ---------------------------------------------------------------------------
# 本地区域解析
# ---------------------------------------------------------------------------

def _enclosing_zone(zones: dict[str, object], cuts: dict[str, list[str]],
                    qname: str):
    """返回覆盖 qname 的已提供区域；区域缺失/越过未提供委派返回 None。"""
    best: str | None = None
    for apex in zones:
        if qname == apex or qname.endswith(_DOMAIN_LABEL_SEP + apex):
            if best is None or len(apex) > len(best):
                best = apex
    if best is None:
        return None
    for cut in cuts[best]:
        # 切点自身由父区回答；只有严格位于切点之下才需要被委派区
        if qname != cut and qname.endswith(_DOMAIN_LABEL_SEP + cut):
            return None
    return zones[best]


# ---------------------------------------------------------------------------
# ServiceMode 过滤与端点
# ---------------------------------------------------------------------------

def _endpoint(record: SvcbRdata, effective_target: str) -> dict:
    return {
        "priority": record.priority,
        "target": effective_target,
        "mandatory": list(record.mandatory),
        "alpn": list(record.alpn) if record.alpn is not None else None,
        "no_default_alpn": record.no_default_alpn,
        "port": record.port,
        "ipv4hint": list(record.ipv4hint),
        "ipv6hint": list(record.ipv6hint),
        "params": {
            key: (value if value is not None else True)
            for key, value in record.params
        },
    }


def _filter_records(records: list[SvcbRdata], owner: str,
                    client_keys: frozenset[str],
                    client_alpn: list[str] | None) -> tuple[list[dict], list[dict]]:
    """过滤 ServiceMode 记录，返回 (按 priority/target 稳定排序的端点, 逐记录轨迹)。"""
    endpoints: list[dict] = []
    entries: list[dict] = []
    for record in records:
        effective_target = owner if record.target == "." else record.target
        entry: dict = {
            "priority": record.priority,
            "target": record.target,
            "effective_target": effective_target,
            "rdata": record.canonical,
        }
        reason = None
        detail = None
        for key in record.mandatory:
            if key not in client_keys:
                reason = "mandatory_unknown_key"
                detail = key
                break
        if reason is None and record.alpn is not None \
                and client_alpn is not None:
            if not set(record.alpn) & set(client_alpn):
                reason = "alpn_no_overlap"
                detail = ",".join(record.alpn)
        if reason is None:
            entry["usable"] = True
            endpoints.append(_endpoint(record, effective_target))
        else:
            entry["usable"] = False
            entry["reason"] = reason
            entry["detail"] = detail
        entries.append(entry)
    # 按 (priority, target) 稳定排序；输入顺序本身确定（规范 rdata 序）
    endpoints.sort(key=lambda ep: (ep["priority"], ep["target"]))
    return endpoints, entries


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def resolve_svcb(payload: dict) -> dict:
    """执行一次离线 SVCB/HTTPS 解析，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones = _parse_zones(payload.get("zones"))
    qname = _normalize_qname(payload.get("qname"))
    qtype = _normalize_qtype(payload.get("qtype"))
    client_keys = _normalize_client_keys(payload.get("client_keys"))
    client_alpn = _normalize_client_alpn(payload.get("client_alpn"))

    cuts = {apex: find_cuts(zone, apex) for apex, zone in zones.items()}

    trace: list[dict] = []
    endpoints: list[dict] = []
    status = ""
    current = qname
    visited = {qname}
    hops = 0

    while True:
        hop: dict = {"hop": len(trace), "owner": current, "qtype": qtype}
        zone = _enclosing_zone(zones, cuts, current)
        if zone is None:
            hop["action"] = "unresolvable"
            hop["reason"] = "missing_local_zone"
            trace.append(hop)
            status = "unresolvable"
            break
        rrset = zone.get(current, qtype)
        if rrset is None:
            hop["action"] = "nodata"
            trace.append(hop)
            status = "nodata"
            break
        records = [
            parse_svcb_rdata(element, ".", None) for element in rrset.rdata
        ]
        aliases = [record for record in records if record.priority == 0]
        if aliases:
            if len(records) > 1:
                raise ReviewError(
                    "multiple_aliases",
                    f"{current} 的 {qtype} RRset 含 AliasMode（优先级 0）"
                    f"记录，不得再与其它 {len(records) - 1} 条记录共存",
                    422,
                    [{"owner": current, "qtype": qtype,
                      "records": [r.canonical for r in records]}],
                )
            alias = aliases[0]
            hop["record"] = alias.canonical
            if alias.target == ".":
                hop["action"] = "unavailable"
                trace.append(hop)
                status = "unavailable"
                break
            hops += 1
            if hops > MAX_ALIAS_HOPS:
                raise ReviewError(
                    "alias_too_many_hops",
                    f"AliasMode 链超过 {MAX_ALIAS_HOPS} 跳"
                    f"（第 {hops} 跳指向 {alias.target}）",
                    422,
                    [{"owner": current, "target": alias.target,
                      "hops": hops, "max_hops": MAX_ALIAS_HOPS}],
                )
            if alias.target in visited:
                chain = " -> ".join(
                    [name for name in trace_names(trace, qname)]
                    + [alias.target]
                )
                raise ReviewError(
                    "alias_loop",
                    f"AliasMode 链成环: {chain}",
                    422,
                    [{"owner": current, "target": alias.target}],
                )
            hop["action"] = "alias"
            hop["target"] = alias.target
            trace.append(hop)
            visited.add(alias.target)
            current = alias.target
            continue
        # ServiceMode
        endpoints, entries = _filter_records(
            records, current, client_keys, client_alpn
        )
        hop["action"] = "service"
        hop["records"] = entries
        trace.append(hop)
        status = "ok" if endpoints else "filtered"
        break

    return {
        "qname": qname,
        "qtype": qtype,
        "status": status,
        "alias_hops": hops,
        "endpoints": endpoints,
        "trace": trace,
    }


def trace_names(trace: list[dict], qname: str) -> list[str]:
    """从轨迹还原别名链上的名字序列（用于环报告）。"""
    names = [qname]
    for event in trace:
        if event.get("action") == "alias":
            names.append(event["target"])
    return names
