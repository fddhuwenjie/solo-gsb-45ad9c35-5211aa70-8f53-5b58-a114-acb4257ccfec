"""离线迭代解析轨迹校验（delegation trace）。

不发起任何真实 DNS 查询：输入查询名 ``qname``、类型 ``qtype``（仅
``A``/``AAAA``/``NS``/``CNAME``）、根服务器地址 ``root_addresses`` 与一串
``hops``（每跳给出 ``server``、``question`` 与 ``answer``/``authority``/
``additional`` 三个记录区），按迭代解析的结构规则离线校验整条轨迹。

结构规则（违反即 ``invalid`` 并给出首个失败跳 ``failed_hop``）：

- 首跳只能发往 ``root_addresses`` 之一；CNAME 重启与地址子查询同样
  从根开始；
- 转介（authority 中的 NS）必须来自当前委派区：子区名位于当前区内、
  严格更长、且包含查询名，否则为越权转介；
- ``additional`` 只接纳子区内 NS 的 A/AAAA 胶水；区外 NS 的地址必须由
  独立的地址子查询（从根开始的 A/AAAA 查询）取得；后续每一跳的
  ``server`` 都必须有已接纳的来源（根地址 / 已接纳胶水 / 已完成的
  地址子查询）；
- 权威终答结束当前（子）查询；地址子查询与 CNAME 别名共享 32 跳
  预算并检测循环。

仅支持 A/AAAA/NS/CNAME 查询；不校验 DNSSEC 与否定应答——既非终答、
CNAME 也非转介的响应视为无法识别（轨迹 invalid）。

``valid`` / ``invalid`` 都是 HTTP 200 下的校验终态；只有请求格式错误
（400）与记录内容错误（422）走错误响应。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, validate_name

MAX_HOPS = 32
QTYPES = ("A", "AAAA", "NS", "CNAME")
_ADDRESS_TYPES = ("A", "AAAA")
_SUPPORTED_RECORD_TYPES = frozenset(QTYPES)
_SECTIONS = ("answer", "authority", "additional")


@dataclass(frozen=True)
class _Record:
    """轨迹中的一条资源记录（已规范化）。"""

    name: str  # 小写绝对名
    rtype: str  # 大写类型
    ttl: int
    rdata: str  # 规范化后的 RDATA（不支持的类型原样保留）
    supported: bool  # 类型是否属于 A/AAAA/NS/CNAME


class _Context:
    """一条进行中的解析线（主查询或地址子查询）。

    ``servers`` 为下一跳可用的服务器地址及其来源（根地址 / 已接纳胶水 /
    已完成的地址子查询）；``pending_ns`` 为最近一次转介的 NS 目标；
    ``visited`` 为本线已经过的查询名（CNAME 链环检测）。
    """

    __slots__ = ("kind", "for_name", "qname", "qtype", "zone", "servers",
                 "pending_ns", "visited", "answers")

    def __init__(self, kind: str, qname: str, qtype: str,
                 roots: list[str], for_name: str | None = None):
        self.kind = kind  # "main" | "address"
        self.for_name = for_name  # 地址子查询服务的待定 NS 名
        self.qname = qname
        self.qtype = qtype
        self.zone = "."
        self.servers = {addr: {"source": "root"} for addr in roots}
        self.pending_ns: dict[str, dict] = {}
        self.visited = [qname]
        self.answers: list[_Record] = []

    @property
    def question(self) -> tuple[str, str]:
        return (self.qname, self.qtype)


# ---------------------------------------------------------------------------
# 名称 / 地址 / 类型工具
# ---------------------------------------------------------------------------

def _within(name: str, zone: str) -> bool:
    """name 是否位于 zone 内（含相等；根包含一切名字）。"""
    if zone == ".":
        return True
    return name == zone or name.endswith("." + zone)


def _label_count(name: str) -> int:
    if name == ".":
        return 0
    return len(name.rstrip(".").split("."))


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


def _normalize_qtype(value, field: str) -> str:
    if not isinstance(value, str) or value.strip().upper() not in QTYPES:
        raise ReviewError(
            "invalid_request",
            f"{field} 必须是 {'/'.join(QTYPES)} 之一: {value!r}",
            400,
        )
    return value.strip().upper()


def _normalize_address(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", f"{field} 必须是 IP 地址字符串", 400
        )
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ReviewError(
            "invalid_request",
            f"{field} 不是合法 IP 地址: {value!r}",
            400,
        ) from exc


def _normalize_roots(value) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ReviewError(
            "invalid_request",
            "root_addresses 必须是非空的 IP 地址数组",
            400,
        )
    roots: list[str] = []
    for position, item in enumerate(value):
        address = _normalize_address(item, f"root_addresses[{position}]")
        if address not in roots:
            roots.append(address)
    return roots


# ---------------------------------------------------------------------------
# 记录与跳解析
# ---------------------------------------------------------------------------

def _record_error(where: str, message: str) -> ReviewError:
    return ReviewError(
        "invalid_record",
        f"{where} 内容非法: {message}",
        422,
        [{"record": where, "message": message}],
    )


def _parse_record(value, where: str) -> _Record:
    if not isinstance(value, dict):
        raise ReviewError(
            "invalid_request", f"{where} 必须是记录对象", 400
        )
    name = value.get("name")
    rtype = value.get("type")
    rdata = value.get("rdata")
    ttl = value.get("ttl", 0)
    if not isinstance(name, str) or not name.strip():
        raise ReviewError(
            "invalid_request", f"{where}.name 必须是非空字符串", 400
        )
    if not isinstance(rtype, str) or not rtype.strip():
        raise ReviewError(
            "invalid_request", f"{where}.type 必须是非空字符串", 400
        )
    if not isinstance(rdata, str):
        raise ReviewError(
            "invalid_request", f"{where}.rdata 必须是字符串", 400
        )
    if isinstance(ttl, bool) or not isinstance(ttl, int) \
            or not 0 <= ttl < 2**31:
        raise ReviewError(
            "invalid_request", f"{where}.ttl 必须是 0..2^31-1 的整数", 400
        )

    norm_name = name.strip().lower()
    if norm_name != "." and not norm_name.endswith("."):
        norm_name += "."
    try:
        validate_name(norm_name)
    except ZoneParseError as exc:
        raise _record_error(where, f"名称非法: {exc}") from exc

    rtype = rtype.strip().upper()
    supported = rtype in _SUPPORTED_RECORD_TYPES
    if not supported:
        # 不解释不支持的类型（如 SOA/RRSIG），取舍阶段逐条标注
        return _Record(norm_name, rtype, ttl, rdata, False)

    text = rdata.strip()
    try:
        if rtype == "A":
            canonical = str(ipaddress.IPv4Address(text))
        elif rtype == "AAAA":
            canonical = str(ipaddress.IPv6Address(text)).lower()
        else:  # NS / CNAME：目标为域名
            canonical = text.lower()
            if canonical != "." and not canonical.endswith("."):
                canonical += "."
            validate_name(canonical)
    except ValueError as exc:
        raise _record_error(where, f"{rtype} RDATA 非法: {exc}") from exc
    return _Record(norm_name, rtype, ttl, canonical, True)


def _parse_hops(value) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise ReviewError(
            "invalid_request", "hops 必须是非空的跳数组", 400
        )
    hops: list[dict] = []
    for index, item in enumerate(value):
        where = f"hops[{index}]"
        if not isinstance(item, dict):
            raise ReviewError(
                "invalid_request", f"{where} 必须是对象", 400
            )
        server = _normalize_address(item.get("server"), f"{where}.server")
        question = item.get("question")
        if not isinstance(question, dict):
            raise ReviewError(
                "invalid_request", f"{where}.question 必须是对象", 400
            )
        q_name = _normalize_name(question.get("name"),
                                 f"{where}.question.name")
        q_type = _normalize_qtype(question.get("type"),
                                  f"{where}.question.type")
        sections: dict[str, list[_Record]] = {}
        for section in _SECTIONS:
            raw = item.get(section, [])
            if not isinstance(raw, list):
                raise ReviewError(
                    "invalid_request",
                    f"{where}.{section} 必须是记录数组",
                    400,
                )
            sections[section] = [
                _parse_record(rec, f"{where}.{section}[{pos}]")
                for pos, rec in enumerate(raw)
            ]
        hops.append({
            "server": server,
            "question": (q_name, q_type),
            "answer": sections["answer"],
            "authority": sections["authority"],
            "additional": sections["additional"],
        })
    return hops


# ---------------------------------------------------------------------------
# 逐记录取舍
# ---------------------------------------------------------------------------

def _record_view(record: _Record) -> dict:
    return {
        "name": record.name,
        "type": record.rtype,
        "ttl": record.ttl,
        "rdata": record.rdata,
    }


def _section_views(hop: dict, section: str, reason: str) -> list[dict]:
    """非应答区的记录：不支持的类型 / 本跳用不到的区，一律丢弃。"""
    views = []
    for record in hop[section]:
        view = {"section": section, **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        else:
            view.update(verdict="discarded", reason=reason)
        views.append(view)
    return views


def _answer_views(hop: dict, ctx: _Context) -> list[dict]:
    views = []
    for record in hop["answer"]:
        view = {"section": "answer", **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        elif record.name == ctx.qname and record.rtype == ctx.qtype:
            view.update(verdict="accepted", reason="final_answer")
        elif record.name != ctx.qname:
            view.update(verdict="discarded", reason="owner_mismatch")
        else:
            view.update(verdict="discarded", reason="type_mismatch")
        views.append(view)
    views.extend(_section_views(hop, "authority", "unexpected_authority"))
    views.extend(_section_views(hop, "additional", "unexpected_additional"))
    return views


def _cname_views(hop: dict, ctx: _Context) -> list[dict]:
    views = []
    first = True
    for record in hop["answer"]:
        view = {"section": "answer", **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        elif record.name == ctx.qname and record.rtype == "CNAME":
            if first:
                view.update(verdict="accepted", reason="cname_restart")
                first = False
            else:
                view.update(verdict="discarded",
                            reason="cname_not_singleton")
        elif record.name != ctx.qname:
            view.update(verdict="discarded", reason="owner_mismatch")
        else:
            view.update(verdict="discarded", reason="type_mismatch")
        views.append(view)
    views.extend(_section_views(hop, "authority", "unexpected_authority"))
    views.extend(_section_views(hop, "additional", "unexpected_additional"))
    return views


def _referral_views(hop: dict, ctx: _Context, child: str,
                    ns_set: set[str]) -> list[dict]:
    views = []
    for record in hop["answer"]:
        view = {"section": "answer", **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        elif record.name != ctx.qname:
            view.update(verdict="discarded", reason="owner_mismatch")
        else:
            view.update(verdict="discarded", reason="type_mismatch")
        views.append(view)
    for record in hop["authority"]:
        view = {"section": "authority", **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        elif record.rtype == "NS":
            view.update(verdict="accepted", reason="referral_ns")
        else:
            view.update(verdict="discarded", reason="unexpected_authority")
        views.append(view)
    for record in hop["additional"]:
        view = {"section": "additional", **_record_view(record)}
        if not record.supported:
            view.update(verdict="discarded", reason="unsupported_type")
        elif record.rtype not in _ADDRESS_TYPES:
            view.update(verdict="discarded", reason="unexpected_additional")
        elif record.name not in ns_set:
            view.update(verdict="discarded", reason="unexpected_additional")
        elif not _within(record.name, child):
            # 区外 NS 的地址只能由独立子查询取得，additional 不接纳
            view.update(verdict="discarded", reason="out_of_bailiwick_glue")
        else:
            view.update(verdict="accepted", reason="glue")
        views.append(view)
    return views


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def trace_delegation(payload: dict) -> dict:
    """校验一条离线迭代解析轨迹，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    qname = _normalize_name(payload.get("qname"), "qname")
    qtype = _normalize_qtype(payload.get("qtype"), "qtype")
    roots = _normalize_roots(payload.get("root_addresses"))
    hops = _parse_hops(payload.get("hops"))

    # 地址来源图：每个已接纳地址记录首次接纳时的来源
    address_sources: list[dict] = []
    _seen_sources: set[str] = set()

    def note_source(address: str, source: dict) -> None:
        if address in _seen_sources:
            return
        _seen_sources.add(address)
        address_sources.append({"address": address, **source})

    for root in roots:
        note_source(root, {"source": "root"})

    main = _Context("main", qname, qtype, roots)
    stack = [main]
    active = {main.question}  # 栈上各解析线当前的问题（循环检测）
    hop_views: list[dict] = []
    final_answer: list[dict] = []
    completed = False

    def invalid(reason: str, failed_hop: int | None,
                hop: dict | None = None,
                ctx: _Context | None = None) -> dict:
        entries = list(hop_views)
        if hop is not None and ctx is not None:
            entry = {
                "hop": failed_hop,
                "server": hop["server"],
                "question": {"name": hop["question"][0],
                             "type": hop["question"][1]},
                "context": ctx.kind,
                "action": "invalid",
                "reason": reason,
            }
            if ctx.kind == "address":
                entry["for"] = ctx.for_name
            entries.append(entry)
        return {
            "qname": qname,
            "qtype": qtype,
            "status": "invalid",
            "reason": reason,
            "failed_hop": failed_hop,
            "final_answer": [],
            "hops": entries,
            "address_sources": address_sources,
            "hop_count": len(entries),
            "hop_budget": MAX_HOPS,
        }

    index = 0
    total = len(hops)
    result: dict | None = None
    while index < total:
        if index >= MAX_HOPS:
            result = invalid("hop_budget_exceeded", index, hops[index],
                             stack[-1])
            break
        hop = hops[index]
        ctx = stack[-1]
        q_name, q_type = hop["question"]

        if hop["question"] != ctx.question:
            # 与当前查询不符：仅允许对当前转介待定的 NS 发起 A/AAAA
            # 地址子查询（从根开始的独立解析）
            if q_type not in _ADDRESS_TYPES or q_name not in ctx.pending_ns:
                result = invalid("question_mismatch", index, hop, ctx)
                break
            if hop["question"] in active:
                result = invalid("address_query_loop", index, hop, ctx)
                break
            ctx = _Context("address", q_name, q_type, roots,
                           for_name=q_name)
            stack.append(ctx)
            active.add(ctx.question)

        source = ctx.servers.get(hop["server"])
        if source is None:
            result = invalid("server_no_source", index, hop, ctx)
            break

        matching = [
            r for r in hop["answer"]
            if r.supported and r.name == ctx.qname and r.rtype == ctx.qtype
        ]
        cnames = [
            r for r in hop["answer"]
            if r.supported and r.name == ctx.qname and r.rtype == "CNAME"
        ]
        ns_auth = [
            r for r in hop["authority"] if r.supported and r.rtype == "NS"
        ]

        view = {
            "hop": index,
            "server": hop["server"],
            "server_source": source,
            "question": {"name": q_name, "type": q_type},
            "context": ctx.kind,
            "zone": ctx.zone,
        }
        if ctx.kind == "address":
            view["for"] = ctx.for_name

        if matching:
            # 权威终答：结束当前（子）查询
            view["action"] = "answer"
            view["records"] = _answer_views(hop, ctx)
            ctx.answers.extend(matching)
            if ctx.kind == "main":
                final_answer = [_record_view(r) for r in ctx.answers]
                completed = True
            else:
                # 地址子查询完成：地址记入父查询的已接纳来源
                addresses = sorted({r.rdata for r in matching})
                view["resolved"] = addresses
                stack.pop()
                active.discard(ctx.question)
                parent = stack[-1]
                for address in addresses:
                    provenance = {
                        "source": "subquery",
                        "qname": ctx.for_name,
                        "qtype": ctx.qtype,
                        "hop": index,
                    }
                    parent.servers.setdefault(address, provenance)
                    note_source(address, provenance)
            hop_views.append(view)
            index += 1
            if completed:
                break
            continue

        if cnames and ctx.qtype != "CNAME":
            # CNAME：从根重启，目标不得与本链或栈上其它查询成环
            target = cnames[0].rdata
            if target in ctx.visited or (target, ctx.qtype) in active:
                result = invalid("cname_loop", index, hop, ctx)
                break
            view["action"] = "cname"
            view["target"] = target
            view["records"] = _cname_views(hop, ctx)
            active.discard(ctx.question)
            ctx.answers.append(cnames[0])
            ctx.visited.append(target)
            ctx.qname = target
            ctx.zone = "."
            ctx.servers = {addr: {"source": "root"} for addr in roots}
            ctx.pending_ns = {}
            active.add(ctx.question)
            hop_views.append(view)
            index += 1
            continue

        if ns_auth:
            owners = []
            for record in ns_auth:
                if record.name not in owners:
                    owners.append(record.name)
            if len(owners) != 1:
                result = invalid("referral_multiple_zones", index, hop, ctx)
                break
            child = owners[0]
            if not _within(child, ctx.zone):
                result = invalid("referral_out_of_bailiwick", index, hop,
                                 ctx)
                break
            if _label_count(child) <= _label_count(ctx.zone):
                result = invalid("referral_not_deeper", index, hop, ctx)
                break
            if not _within(ctx.qname, child):
                result = invalid("referral_misses_qname", index, hop, ctx)
                break
            ns_names = []
            for record in ns_auth:
                if record.rdata not in ns_names:
                    ns_names.append(record.rdata)
            ns_set = set(ns_names)
            # additional 只接纳子区内 NS 的 A/AAAA 胶水
            glue: dict[str, dict] = {}
            for record in hop["additional"]:
                if (
                    record.supported
                    and record.rtype in _ADDRESS_TYPES
                    and record.name in ns_set
                    and _within(record.name, child)
                ):
                    glue.setdefault(record.rdata, {
                        "source": "glue",
                        "hop": index,
                        "ns": record.name,
                        "zone": child,
                    })
            view["action"] = "referral"
            view["child_zone"] = child
            view["ns"] = sorted(ns_names)
            view["glue"] = sorted(glue)
            view["records"] = _referral_views(hop, ctx, child, ns_set)
            ctx.zone = child
            ctx.pending_ns = {
                ns: {"in_bailiwick": _within(ns, child)} for ns in ns_names
            }
            ctx.servers = dict(glue)
            for address, provenance in glue.items():
                note_source(address, provenance)
            hop_views.append(view)
            index += 1
            continue

        # 既非终答、CNAME 也非转介（否定应答不在支持范围）
        result = invalid("unrecognized_response", index, hop, ctx)
        break

    if result is None:
        if completed:
            if index < total:
                result = invalid("trailing_hops", index, hops[index], main)
            else:
                result = {
                    "qname": qname,
                    "qtype": qtype,
                    "status": "valid",
                    "reason": "completed",
                    "failed_hop": None,
                    "final_answer": final_answer,
                    "hops": hop_views,
                    "address_sources": address_sources,
                    "hop_count": len(hop_views),
                    "hop_budget": MAX_HOPS,
                }
        else:
            result = invalid("incomplete_trace", None)
    return result
