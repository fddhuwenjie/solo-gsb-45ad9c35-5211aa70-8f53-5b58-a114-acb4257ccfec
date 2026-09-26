"""离线 SPF（RFC 7208）求值。

不发起任何真实 DNS 查询：所有数据来自请求里给出的“本地区域文本集合”
（由 :mod:`app.zoneparse` 解析），区域解析在本地完成 TXT / MX / A / AAAA。

支持的机制：``all``、``ip4``、``ip6``、``a``、``mx``、``include``，
以及 ``redirect=`` 修饰符；限定符 ``+`` ``-`` ``~`` ``?``。
``ptr``、``exists``、任何宏（``%``）、未知机制、多条 SPF 记录、
语法非法均记为 ``permerror``。

求值规则要点：
- ``include`` 仅在子策略结果为 pass 时命中；子策略 permerror/temperror
  向上传播；none/fail/softfail/neutral 均视为未命中并继续；
- ``redirect`` 仅在本记录没有任何机制命中时执行；目标无 SPF 记录
  （none）按 permerror 处理；
- 整个递归过程共享 10 次“DNS 查询”预算，计数统一放在实际 RRset 查询
  入口：每次读取 TXT / MX / A / AAAA RRset（含顶层 SPF TXT、include 与
  redirect 目标的 TXT、``a`` 的 A 与 AAAA、``mx`` 的 MX 及每个交换主机的
  A 与 AAAA）各计一次，尝试第 11 次即 permerror；
- 求值栈上的域再次被求值即构成环，返回 permerror；
- 查询的名字落在任何已提供区域之外、或落在未提供的委派子区时，
  返回 temperror（缺失本地区域引用）。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .review import ReviewError
from .validity import find_cuts
from .zoneparse import ZoneParseError, parse_zone, txt_concat, validate_name

DNS_QUERY_LIMIT = 10

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
SUPPORTED_MECHANISMS = ("all", "ip4", "ip6", "a", "mx", "include")
# 任务范围内明确不支持的机制（出现即 permerror）
UNSUPPORTED_MECHANISMS = ("ptr", "exists")
_MODIFIER_NAME_RE = re.compile(r"^[a-z][a-z0-9.-]*$")
_DOMAIN_LABEL_SEP = "."


class SpfError(Exception):
    """求值期错误，kind 取 permerror / temperror（作为 SPF 终态返回）。"""

    def __init__(self, kind: str, reason: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class Term:
    """解析后的一个 SPF 机制。"""

    kind: str
    qualifier: str
    raw: str
    domain: str | None = None
    network: ipaddress._BaseNetwork | None = None
    ip4_cidr: int | None = None
    ip6_cidr: int | None = None


@dataclass
class ParsedRecord:
    text: str
    terms: list[Term] = field(default_factory=list)
    redirect: str | None = None


# ---------------------------------------------------------------------------
# 记录解析
# ---------------------------------------------------------------------------

def _qualify_domain(spec: str, current_domain: str) -> str:
    """SPF domain-spec：空串表示当前域；相对名补到当前域之下。"""
    name = spec.strip().lower()
    if name == "":
        absolute = current_domain
    elif name.endswith("."):
        absolute = name
    else:
        absolute = name + _DOMAIN_LABEL_SEP + current_domain
    try:
        validate_name(absolute)
    except ZoneParseError as exc:
        raise SpfError("permerror", "invalid_domain_spec",
                       f"非法域名 {spec!r}: {exc}") from exc
    return absolute


def _parse_dual_cidr(tail: str) -> tuple[int, int]:
    """解析 a/mx 的 /ipv4-cidr[/ipv6-cidr]，tail 不含域名部分。"""
    parts = tail.split("/")
    if len(parts) > 2 or any(not p.isdigit() for p in parts):
        raise SpfError("permerror", "invalid_cidr",
                       f"非法 CIDR 前缀: {tail!r}")
    ip4_cidr = int(parts[0])
    ip6_cidr = 128
    if ip4_cidr > 32:
        raise SpfError("permerror", "invalid_cidr",
                       f"IPv4 CIDR 前缀超出 32: /{ip4_cidr}")
    if len(parts) == 2:
        ip6_cidr = int(parts[1])
        if ip6_cidr > 128:
            raise SpfError("permerror", "invalid_cidr",
                           f"IPv6 CIDR 前缀超出 128: /{ip6_cidr}")
    return ip4_cidr, ip6_cidr


def _parse_a_like(
    kind: str,
    body: str,
    qualifier: str,
    raw: str,
    current_domain: str,
) -> Term:
    # a[:domain-spec][/v4[/v6]]、mx 同形
    after = body[len(kind):]
    domain = current_domain
    ip4_cidr, ip6_cidr = 32, 128
    if after == "":
        return Term(kind, qualifier, raw, domain=current_domain,
                    ip4_cidr=32, ip6_cidr=128)
    if after.startswith(":"):
        rest = after[1:]
        if "/" in rest:
            dom_part, _, cidr_part = rest.partition("/")
            ip4_cidr, ip6_cidr = _parse_dual_cidr(cidr_part)
        else:
            dom_part = rest
        domain = _qualify_domain(dom_part, current_domain)
    elif after.startswith("/"):
        ip4_cidr, ip6_cidr = _parse_dual_cidr(after[1:])
    else:
        raise SpfError("permerror", "invalid_mechanism",
                       f"无法解析的机制: {body!r}")
    return Term(kind, qualifier, raw, domain=domain,
                ip4_cidr=ip4_cidr, ip6_cidr=ip6_cidr)


def _parse_ip(kind: str, body: str, qualifier: str, raw: str) -> Term:
    expect_v4 = kind == "ip4"
    if ":" not in body:
        raise SpfError("permerror", "invalid_mechanism",
                       f"{kind} 缺少 ':': {body!r}")
    spec = body.split(":", 1)[1]
    if spec.count("/") > 1:
        raise SpfError("permerror", "invalid_cidr",
                       f"非法 {kind} 规格: {spec!r}")
    addr_part, _, cidr_part = spec.partition("/")
    max_prefix = 32 if expect_v4 else 128
    prefix = max_prefix
    if cidr_part:
        if not cidr_part.isdigit():
            raise SpfError("permerror", "invalid_cidr",
                           f"非法 {kind} CIDR: {spec!r}")
        prefix = int(cidr_part)
        if prefix > max_prefix:
            raise SpfError("permerror", "invalid_cidr",
                           f"{kind} CIDR 前缀超出 {max_prefix}: /{prefix}")
    try:
        network = ipaddress.ip_network(
            f"{addr_part}/{prefix}", strict=False
        )
    except ValueError as exc:
        raise SpfError("permerror", "invalid_mechanism",
                       f"非法 {kind} 网络 {spec!r}: {exc}") from exc
    if expect_v4 and network.version != 4:
        raise SpfError("permerror", "invalid_mechanism",
                       f"ip4 机制出现 IPv6 网络: {spec!r}")
    if not expect_v4 and network.version != 6:
        raise SpfError("permerror", "invalid_mechanism",
                       f"ip6 机制出现 IPv4 网络: {spec!r}")
    return Term(kind, qualifier, raw, network=network)


def parse_spf_record(text: str, current_domain: str) -> ParsedRecord:
    """解析一条 SPF TXT 记录；任何语法/宏/未知机制都抛 permerror。"""
    record = text.strip()
    tokens = record.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        raise SpfError("permerror", "invalid_spf_version",
                       f"不是合法 SPF 记录: {text!r}")
    # 任何宏（%{...}、%%、%_、%- 乃至孤立的 %）都不在支持范围内
    if "%" in record:
        raise SpfError("permerror", "macro_unsupported",
                       "本服务不支持 SPF 宏展开")

    parsed = ParsedRecord(text=record)
    for token in tokens[1:]:
        qualifier = "+"
        body = token
        if token[:1] in QUALIFIERS:
            qualifier = token[0]
            body = token[1:]
        if body == "":
            raise SpfError("permerror", "invalid_mechanism",
                           f"空机制: {token!r}")

        # 修饰符只在没有限定符、且形如 name=value 时出现
        if qualifier == "+" and "=" in body:
            name, _, value = body.partition("=")
            name_l = name.lower()
            if not _MODIFIER_NAME_RE.fullmatch(name_l):
                raise SpfError("permerror", "invalid_modifier",
                               f"非法修饰符名: {name!r}")
            if name_l in SUPPORTED_MECHANISMS + UNSUPPORTED_MECHANISMS:
                raise SpfError("permerror", "invalid_mechanism",
                               f"机制 {name_l} 写法非法（应为冒号语法）: {body!r}")
            if name_l == "redirect":
                if value == "":
                    raise SpfError("permerror", "invalid_modifier",
                                   "redirect= 的 domain-spec 为空")
                if parsed.redirect is not None:
                    raise SpfError("permerror", "duplicate_redirect",
                                   "出现多个 redirect= 修饰符")
                parsed.redirect = _qualify_domain(value, current_domain)
            elif name_l == "exp":
                if value == "":
                    raise SpfError("permerror", "invalid_modifier",
                                   "exp= 的 domain-spec 为空")
                # 离线不产出解释文本，但 domain-spec 仍须合法（含宏已在上面拦）
                _qualify_domain(value, current_domain)
            else:
                # RFC 7208：未知修饰符忽略
                continue
            continue

        head = re.split(r"[:/]", body, 1)[0].lower()
        if head == "all":
            if body.lower() != "all":
                raise SpfError("permerror", "invalid_mechanism",
                               f"非法 all 机制: {body!r}")
            parsed.terms.append(Term("all", qualifier, token))
        elif head in ("ip4", "ip6"):
            term = _parse_ip(head, body.lower(), qualifier, token)
            parsed.terms.append(term)
        elif head in ("a", "mx"):
            term = _parse_a_like(
                head, body.lower(), qualifier, token, current_domain
            )
            parsed.terms.append(term)
        elif head == "include":
            if not body.lower().startswith("include:"):
                raise SpfError("permerror", "invalid_mechanism",
                               f"include 缺少 ':domain-spec': {body!r}")
            target = body.split(":", 1)[1]
            if target == "":
                raise SpfError("permerror", "invalid_mechanism",
                               "include 的 domain-spec 为空")
            parsed.terms.append(
                Term("include", qualifier, token,
                     domain=_qualify_domain(target, current_domain))
            )
        elif head in UNSUPPORTED_MECHANISMS:
            raise SpfError("permerror", "unsupported_mechanism",
                           f"本服务不支持 {head} 机制（离线求值）")
        else:
            raise SpfError("permerror", "unsupported_mechanism",
                           f"未知 SPF 机制: {head!r}")
    return parsed


# ---------------------------------------------------------------------------
# 本地区域解析
# ---------------------------------------------------------------------------

class LocalResolver:
    """对已解析 Zone 集合做离线 TXT / MX / A / AAAA 解析。

    所有 RRset 读取入口（TXT / MX / A / AAAA）统一在此计数：每次读取
    消耗一次共享预算，尝试超出预算的读取立即抛 ``dns_query_limit``
    permerror（该次读取仍计入已尝试查询数）。
    """

    def __init__(self, zones: dict[str, object],
                 budget: int = DNS_QUERY_LIMIT):
        self.zones = zones
        self.budget = budget
        self.dns_queries = 0
        self._cuts = {
            apex: find_cuts(zone, apex) for apex, zone in zones.items()
        }

    def _charge(self, qname: str, rtype: str) -> None:
        """为一次 RRset 读取计费；超出预算即 permerror。"""
        self.dns_queries += 1
        if self.dns_queries > self.budget:
            raise SpfError(
                "permerror", "dns_query_limit",
                f"DNS 查询预算 {self.budget} 次已耗尽（读取 {qname} 的 "
                f"{rtype} 时第 {self.dns_queries} 次）",
            )

    def _enclosing_zone(self, qname: str):
        """返回覆盖 qname 的已提供区域；区域缺失/越过未提供委派则 temperror。"""
        qname = qname.lower()
        best: str | None = None
        for apex in self.zones:
            if qname == apex or qname.endswith(_DOMAIN_LABEL_SEP + apex):
                if best is None or len(apex) > len(best):
                    best = apex
        if best is None:
            raise SpfError(
                "temperror", "missing_local_zone",
                f"名字 {qname} 不被任何已提供的本地区域覆盖（离线无法解析）",
            )
        for cut in self._cuts[best]:
            # 切点自身由父区回答；只有严格位于切点之下才需要被委派区
            if qname != cut and qname.endswith(_DOMAIN_LABEL_SEP + cut):
                raise SpfError(
                    "temperror", "missing_local_zone",
                    f"名字 {qname} 位于委派切点 {cut} 之下，"
                    "但请求未提供该委派区域（离线无法解析）",
                )
        return self.zones[best]

    def txt_records(self, qname: str) -> list[str]:
        """返回 TXT RRset 中每条 RR 拼接后的字符串（无 RRset 时为空）。"""
        self._charge(qname, "TXT")
        zone = self._enclosing_zone(qname)
        rr = zone.get(qname.lower(), "TXT")
        if rr is None:
            return []
        return [txt_concat(element) for element in rr.rdata]

    def addresses(self, host: str) -> list[str]:
        """合并主机的 A 与 AAAA，按 (协议版本, 打包字节) 稳定排序。

        A 与 AAAA 是两次独立的 RRset 读取，各计一次查询；计费在区域
        归属判定之前，第 11 次读取直接为 dns_query_limit。
        """
        host = host.lower()
        found: list[str] = []
        for rtype in ("A", "AAAA"):
            self._charge(host, rtype)
            zone = self._enclosing_zone(host)
            rr = zone.get(host, rtype)
            if rr is not None:
                found.extend(rr.rdata)

        def key(value: str):
            addr = ipaddress.ip_address(value)
            return addr.version, addr.packed

        return sorted(found, key=key)

    def mx_exchanges(self, qname: str) -> list[tuple[int, str]]:
        """按 (优先级, 交换主机名) 稳定排序的 (preference, exchange) 列表。"""
        self._charge(qname, "MX")
        zone = self._enclosing_zone(qname)
        rr = zone.get(qname.lower(), "MX")
        if rr is None:
            return []
        entries = []
        for element in rr.rdata:
            preference, exchange = element.split(" ", 1)
            entries.append((int(preference), exchange))
        entries.sort(key=lambda item: (item[0], item[1]))
        return entries


# ---------------------------------------------------------------------------
# 求值
# ---------------------------------------------------------------------------

def _ip_in_addresses(
    client: ipaddress._BaseAddress,
    addresses: list[str],
    ip4_cidr: int,
    ip6_cidr: int,
) -> str | None:
    """client 是否落在任一地址按对应 CIDR 前缀展开的网段中；命中返回地址。"""
    prefix = ip4_cidr if client.version == 4 else ip6_cidr
    for value in addresses:
        addr = ipaddress.ip_address(value)
        if addr.version != client.version:
            continue
        network = ipaddress.ip_network(
            f"{value}/{prefix}", strict=False
        )
        if client in network:
            return value
    return None


class Evaluator:
    def __init__(self, resolver: LocalResolver,
                 client_ip: ipaddress._BaseAddress):
        self.resolver = resolver
        self.client_ip = client_ip
        self.trace: list[dict] = []
        self._stack: list[str] = []

    @property
    def dns_queries(self) -> int:
        """已尝试的 RRset 查询数（统一由解析器计数）。"""
        return self.resolver.dns_queries

    def evaluate(self, sender_domain: str, identity: str) -> str:
        try:
            status = self._check(sender_domain, 0, identity)
        except SpfError as exc:
            self.trace.append({
                "type": "result",
                "depth": 0,
                "status": exc.kind,
                "reason": exc.reason,
                "message": exc.message,
            })
            return exc.kind
        self.trace.append({"type": "result", "depth": 0, "status": status})
        return status

    # -- 递归核心 --
    def _check(self, domain: str, depth: int, relation: str) -> str:
        if domain in self._stack:
            start = self._stack.index(domain)
            chain = " -> ".join(self._stack[start:] + [domain])
            raise SpfError("permerror", "spf_loop",
                           f"SPF include/redirect 形成环: {chain}")
        self._stack.append(domain)
        event: dict = {
            "type": "policy",
            "depth": depth,
            "relation": relation,
            "domain": domain,
        }
        self.trace.append(event)
        try:
            answers = self.resolver.txt_records(domain)
            spf_records = [
                answer for answer in answers
                if answer.strip().split()[:1]
                and answer.strip().split()[0].lower() == "v=spf1"
            ]
            event["answers"] = answers
            event["record_count"] = len(spf_records)
            if not spf_records:
                # 完全没有 TXT，或有 TXT 但没有 SPF 记录，均为 none
                event["outcome"] = "none"
                return "none"
            if len(spf_records) > 1:
                raise SpfError(
                    "permerror", "multiple_spf_records",
                    f"{domain} 存在 {len(spf_records)} 条 SPF TXT 记录",
                )
            record_text = spf_records[0]
            event["record"] = record_text
            parsed = parse_spf_record(record_text, domain)

            for index, term in enumerate(parsed.terms):
                matched = self._eval_term(term, index, depth)
                if matched:
                    result = QUALIFIERS[term.qualifier]
                    event["outcome"] = result
                    return result

            if parsed.redirect is not None:
                result = self._do_redirect(parsed.redirect, depth)
                event["outcome"] = result
                return result

            event["outcome"] = "neutral"
            return "neutral"
        except SpfError as exc:
            event["outcome"] = exc.kind
            event["reason"] = exc.reason
            raise
        finally:
            self._stack.pop()

    def _eval_term(self, term: Term, index: int, depth: int) -> bool:
        event: dict = {
            "type": "term",
            "depth": depth,
            "index": index,
            "mechanism": term.kind,
            "raw": term.raw,
            "qualifier": term.qualifier,
        }
        self.trace.append(event)
        try:
            detail: dict = {}
            matched = False
            if term.kind == "all":
                matched = True
            elif term.kind in ("ip4", "ip6"):
                network = term.network
                detail["network"] = str(network)
                matched = (
                    self.client_ip.version == network.version
                    and self.client_ip in network
                )
            elif term.kind == "a":
                addresses = self.resolver.addresses(term.domain)
                detail.update({
                    "domain": term.domain,
                    "ip4_cidr": term.ip4_cidr,
                    "ip6_cidr": term.ip6_cidr,
                    "addresses": addresses,
                })
                hit = _ip_in_addresses(
                    self.client_ip, addresses,
                    term.ip4_cidr, term.ip6_cidr,
                )
                if hit is not None:
                    matched = True
                    detail["matched_address"] = hit
            elif term.kind == "mx":
                exchanges = self.resolver.mx_exchanges(term.domain)
                detail.update({
                    "domain": term.domain,
                    "ip4_cidr": term.ip4_cidr,
                    "ip6_cidr": term.ip6_cidr,
                })
                if not exchanges:
                    # 隐式 MX：无 MX RR 时按 MX 0 <域自身> 处理
                    exchanges = [(0, term.domain)]
                    detail["implicit_mx"] = True
                evaluated = []
                for preference, exchange in exchanges:
                    self_resolved = self.resolver.addresses(exchange)
                    entry = {
                        "preference": preference,
                        "exchange": exchange,
                        "addresses": self_resolved,
                    }
                    hit = _ip_in_addresses(
                        self.client_ip, self_resolved,
                        term.ip4_cidr, term.ip6_cidr,
                    )
                    if hit is not None and not matched:
                        matched = True
                        entry["matched_address"] = hit
                    evaluated.append(entry)
                detail["exchanges"] = evaluated
            elif term.kind == "include":
                detail["domain"] = term.domain
                # include 机制本身不单独计费：子策略的 TXT RRset 读取
                # 在解析器入口统一计费
                sub_status = self._check(
                    term.domain, depth + 1, "include"
                )
                detail["sub_result"] = sub_status
                # include 仅在子策略 pass 时命中；none 不命中继续求值
                matched = sub_status == "pass"
            else:  # pragma: no cover - 解析阶段已拦
                raise SpfError("permerror", "unsupported_mechanism",
                               f"未知机制 {term.kind}")
            event["matched"] = matched
            event["detail"] = detail
            event["result"] = (
                QUALIFIERS[term.qualifier] if matched else None
            )
            return matched
        except SpfError as exc:
            event["matched"] = False
            event["error"] = {
                "status": exc.kind,
                "reason": exc.reason,
                "message": exc.message,
            }
            raise

    def _do_redirect(self, target: str, depth: int) -> str:
        event: dict = {
            "type": "redirect",
            "depth": depth,
            "domain": target,
        }
        self.trace.append(event)
        try:
            # redirect 本身不单独计费：目标的 TXT RRset 读取统一计费
            status = self._check(target, depth + 1, "redirect")
        except SpfError as exc:
            event["outcome"] = exc.kind
            event["reason"] = exc.reason
            raise
        if status == "none":
            error = SpfError(
                "permerror", "redirect_no_record",
                f"redirect 目标 {target} 没有 SPF 记录",
            )
            event["outcome"] = "permerror"
            event["reason"] = error.reason
            raise error
        event["outcome"] = status
        return status


# ---------------------------------------------------------------------------
# 请求编排
# ---------------------------------------------------------------------------

def _lower_fqdn(name: str) -> str:
    normalized = name.strip().lower().rstrip(".")
    return normalized + "." if normalized else "."


def _sender_domain(mail_from: str, helo: str) -> tuple[str, str]:
    """MAIL FROM 为空时回退 HELO 域；返回 (域, 身份标签)。"""
    mail_from = (mail_from or "").strip()
    helo = (helo or "").strip()
    source: str | None = None
    identity = "mailfrom"
    if mail_from:
        candidate = mail_from
        if candidate.startswith("<") and candidate.endswith(">"):
            candidate = candidate[1:-1]
        source = candidate.rsplit("@", 1)[-1] if "@" in candidate else candidate
    if not source:
        source = helo
        identity = "helo"
    domain = source.strip() if source else ""
    # 拒绝 IP 字面量（含 [192.0.2.1] / [ipv6:::1] 之类）
    bare = domain.strip("[]").lower()
    if domain.startswith("[") or _looks_like_ip(bare):
        raise ReviewError(
            "invalid_request",
            f"发件人域不能是 IP 字面量: {domain!r}",
            400,
        )
    domain = _lower_fqdn(domain)
    if domain == ".":
        raise ReviewError(
            "invalid_request",
            "MAIL FROM 为空时必须提供非空 HELO 域",
            400,
        )
    try:
        validate_name(domain)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"非法发件人域 {domain!r}: {exc}", 400
        ) from exc
    return domain, identity


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def evaluate_spf(payload: dict) -> dict:
    """执行一次离线 SPF 求值，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones_text = payload.get("zones")
    if not isinstance(zones_text, list) or not zones_text:
        raise ReviewError(
            "invalid_request", "zones 必须是非空的区域文本字符串数组", 400
        )

    zones: dict[str, object] = {}
    parse_errors = []
    for position, text in enumerate(zones_text):
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
            "zone_parse_error",
            "本地区域文本解析失败",
            422,
            parse_errors,
        )

    client_raw = payload.get("client_ip")
    if not isinstance(client_raw, str) or not client_raw.strip():
        raise ReviewError(
            "invalid_request", "client_ip 必须是非空 IPv4/IPv6 字符串", 400
        )
    try:
        client_ip = ipaddress.ip_address(client_raw.strip())
    except ValueError as exc:
        raise ReviewError(
            "invalid_request", f"非法 client_ip {client_raw!r}: {exc}", 400
        ) from exc

    mail_from = payload.get("mail_from", "")
    helo = payload.get("helo", "")
    if not isinstance(mail_from, str) or not isinstance(helo, str):
        raise ReviewError(
            "invalid_request", "mail_from / helo 必须是字符串", 400
        )
    domain, identity = _sender_domain(mail_from, helo)

    resolver = LocalResolver(zones)
    evaluator = Evaluator(resolver, client_ip)
    result = evaluator.evaluate(domain, identity)

    return {
        "result": result,
        "identity": identity,
        "domain": domain,
        "client_ip": str(client_ip),
        "dns_queries": evaluator.dns_queries,
        "dns_query_limit": DNS_QUERY_LIMIT,
        "trace": evaluator.trace,
    }
