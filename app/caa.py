"""离线 CAA（RFC 8659）签发授权判定。

不发起任何真实 DNS 查询：所有数据来自请求里给出的“本地区域文本集合”
（由 :mod:`app.zoneparse` 解析，CAA RDATA 在区域解析阶段即完成
flags/tag 与 issue/issuewild 参数的结构化校验）。

授权规则要点（RFC 8659 §4，参数见 RFC 8657）：

- 从请求域名起沿名字树逐级向区顶查找**首个** CAA RRset；
- 某一级存在 CNAME 时沿目标**重新开始**整个查找；CNAME 链成环或
  超过 8 跳返回 ``422``；
- 查找中越过未提供的委派（NS 切点且未提供该子区）或名字不被任何
  已提供区域覆盖时，结论为 ``indeterminate``；
- 通配符证书优先使用 ``issuewild``：相关 RRset 中没有任何 issuewild
  属性时才回退到 ``issue``；非通配符请求只看 ``issue``；
- 未知属性标签设置 critical 位（flags & 128）时禁止签发，否则忽略；
- issue/issuewild 记录须同时匹配 CA 域名及参数：空签发者永不匹配
  （禁止任何 CA 签发）；记录带 ``accounturi`` 时请求账户必须相同；
  带 ``validationmethods`` 时请求的验证方式必须在其列表中；
  RRset 中至少一条记录匹配即允许签发；
- 一直查到区顶仍没有 CAA RRset，则允许签发。

终态 ``allowed`` / ``denied`` / ``indeterminate`` 都是 HTTP 200 下的
判定结论；只有请求格式错误（400）、区域解析失败（422）与
CNAME 环/超跳（422）走错误响应。
"""

from __future__ import annotations

from .review import ReviewError
from .validity import find_cuts
from .zoneparse import (
    CAA_KNOWN_TAGS,
    CaaRdata,
    ZoneParseError,
    parse_caa_rdata,
    parse_zone,
    validate_name,
)

MAX_CNAME_HOPS = 8
_DOMAIN_LABEL_SEP = "."


# ---------------------------------------------------------------------------
# 请求校验（区域文本解析与 spf/svcb 一致）
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


def _normalize_domain(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", f"{field} 必须是非空字符串", 400
        )
    name = value.strip().lower()
    if not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"{field} 非法: {exc}", 400
        ) from exc
    return name


def _normalize_optional_str(value, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", f"{field} 必须是非空字符串", 400
        )
    return value.strip()


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


def _parent_name(name: str) -> str | None:
    """父域名字；根（``.``）无父域返回 None；单标签名的父域为根。"""
    bare = name.rstrip(".")
    if not bare:
        return None
    if _DOMAIN_LABEL_SEP not in bare:
        return "."
    parent = bare.split(_DOMAIN_LABEL_SEP, 1)[1]
    return parent + "." if parent else "."


# ---------------------------------------------------------------------------
# 记录匹配
# ---------------------------------------------------------------------------

def _record_view(rr: CaaRdata) -> dict:
    return {
        "flags": rr.flags,
        "critical": rr.critical,
        "tag": rr.tag,
        "value": rr.value,
        "issuer": rr.issuer,
        "params": {name: value for name, value in rr.params},
        "accounturi": rr.accounturi,
        "validationmethods": (
            list(rr.validationmethods)
            if rr.validationmethods is not None
            else None
        ),
    }


def _matches_issuer(rr: CaaRdata, ca_domain: str,
                    account: str | None,
                    validation_method: str | None) -> tuple[bool, str]:
    """判断一条 issue/issuewild 记录是否匹配 CA 及参数。

    返回 (是否匹配, 不匹配原因码)；匹配时原因为空串。
    """
    # 空签发者禁止任何 CA 签发：对任何请求都不构成匹配
    if rr.issuer == "":
        return False, "empty_issuer"
    bare_ca = ca_domain.rstrip(".")
    bare_issuer = (rr.issuer or "").rstrip(".")
    if bare_issuer != bare_ca:
        return False, "ca_mismatch"
    if rr.accounturi is not None:
        if account is None or rr.accounturi != account:
            return False, "account_mismatch"
    if rr.validationmethods is not None:
        if validation_method is None or \
                validation_method not in rr.validationmethods:
            return False, "validation_method_mismatch"
    return True, ""


def _evaluate_rrset(rrs: list[CaaRdata], wildcard: bool, ca_domain: str,
                    account: str | None,
                    validation_method: str | None) -> dict:
    """评估命中的 CAA RRset，返回允许与否及逐记录判定。"""
    chosen = "issuewild" if wildcard else "issue"

    # 通配符请求优先 issuewild；RRset 中没有任何 issuewild 才回退 issue
    applicable_tag = chosen
    if wildcard and not any(rr.tag == "issuewild" for rr in rrs):
        applicable_tag = "issue"

    # 未知 critical 属性禁止签发（对是否通配符都适用）
    critical_unknown = [
        rr for rr in rrs
        if rr.tag not in CAA_KNOWN_TAGS and rr.critical
    ]

    records = []
    matches = []
    for rr in rrs:
        view = _record_view(rr)
        if rr.tag in ("issue", "issuewild"):
            matched, reason = _matches_issuer(
                rr, ca_domain, account, validation_method
            )
            view["matched"] = matched
            view["applicable"] = rr.tag == applicable_tag
            if not matched:
                view["reason"] = reason
            if matched and rr.tag == applicable_tag:
                matches.append(view)
        else:
            view["applicable"] = False
            if rr.tag not in CAA_KNOWN_TAGS:
                view["ignored"] = not rr.critical
        records.append(view)

    if critical_unknown:
        return {
            "allowed": False,
            "reason": "unknown_critical_property",
            "applicable_tag": applicable_tag,
            "records": records,
            "matches": [],
            "critical_unknown": [rr.tag for rr in critical_unknown],
        }
    if matches:
        return {
            "allowed": True,
            "reason": "matched",
            "applicable_tag": applicable_tag,
            "records": records,
            "matches": matches,
            "critical_unknown": [],
        }
    return {
        "allowed": False,
        "reason": "no_matching_record",
        "applicable_tag": applicable_tag,
        "records": records,
        "matches": [],
        "critical_unknown": [],
    }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def authorize_caa(payload: dict) -> dict:
    """执行一次离线 CAA 签发授权判定，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones = _parse_zones(payload.get("zones"))
    domain = _normalize_domain(payload.get("domain"), "domain")
    ca_domain = _normalize_domain(payload.get("ca_domain"), "ca_domain")
    wildcard = payload.get("wildcard", False)
    if not isinstance(wildcard, bool):
        raise ReviewError(
            "invalid_request", "wildcard 必须是布尔值", 400
        )
    account = _normalize_optional_str(payload.get("account"), "account")
    validation_method = _normalize_optional_str(
        payload.get("validation_method"), "validation_method"
    )

    cuts = {apex: find_cuts(zone, apex) for apex, zone in zones.items()}

    trace: list[dict] = []
    visited: set[str] = set()
    cname_hops = 0
    current = domain
    relevant: dict | None = None
    allowed = False
    status = ""
    reason = ""

    while True:
        level = current
        # 逐级（含 current 自身）向区顶攀爬
        while level is not None:
            if level in visited:
                chain = " -> ".join(_chain_names(trace, level))
                raise ReviewError(
                    "caa_cname_loop",
                    f"CAA 查找沿 CNAME 成环: {chain}",
                    422,
                    [{"owner": level, "hops": cname_hops,
                      "max_hops": MAX_CNAME_HOPS}],
                )
            visited.add(level)

            zone = _enclosing_zone(zones, cuts, level)
            if zone is None:
                trace.append({
                    "level": level, "action": "indeterminate",
                    "reason": "missing_local_zone",
                })
                status = "indeterminate"
                reason = "missing_local_zone"
                break

            cname = zone.get(level, "CNAME")
            if cname is not None:
                target = cname.rdata[0]
                cname_hops += 1
                if cname_hops > MAX_CNAME_HOPS:
                    raise ReviewError(
                        "caa_too_many_cname_hops",
                        f"CAA 查找的 CNAME 链超过 {MAX_CNAME_HOPS} 跳"
                        f"（第 {cname_hops} 跳指向 {target}）",
                        422,
                        [{"owner": level, "target": target,
                          "hops": cname_hops, "max_hops": MAX_CNAME_HOPS}],
                    )
                trace.append({
                    "level": level, "action": "cname", "target": target,
                    "hop": cname_hops,
                })
                # 沿 CNAME 目标重新开始整个查找
                current = target
                break

            caa = zone.get(level, "CAA")
            if caa is not None:
                rrs = [
                    parse_caa_rdata(element, ".", None)
                    for element in caa.rdata
                ]
                result = _evaluate_rrset(
                    rrs, wildcard, ca_domain, account, validation_method
                )
                trace.append({
                    "level": level, "action": "found",
                    "applicable_tag": result["applicable_tag"],
                    "records": result["records"],
                    "allowed": result["allowed"],
                    "reason": result["reason"],
                })
                relevant = {
                    "owner": level,
                    "ttl": caa.ttl,
                    "applicable_tag": result["applicable_tag"],
                    "records": result["records"],
                }
                if result["allowed"]:
                    status, allowed, reason = "allowed", True, "matched"
                else:
                    status, allowed, reason = (
                        "denied", False, result["reason"]
                    )
                    if result["critical_unknown"]:
                        relevant["critical_unknown"] = result[
                            "critical_unknown"
                        ]
                break

            trace.append({"level": level, "action": "climb"})
            parent = _parent_name(level)

            # 下一级父域将越过“已提供数据”的边界：到区顶仍无 CAA，
            # 按 RFC 8659 允许签发
            if parent is None or _enclosing_zone(
                zones, cuts, parent
            ) is None:
                trace.append({"level": level, "action": "apex_no_caa"})
                status, allowed, reason = (
                    "allowed", True, "no_caa_record"
                )
                break
            level = parent

        if status:
            trace.append({
                "action": "result", "status": status, "reason": reason,
            })
            break

    return {
        "domain": domain,
        "wildcard": wildcard,
        "ca_domain": ca_domain,
        "account": account,
        "validation_method": validation_method,
        "allowed": allowed,
        "status": status,
        "reason": reason,
        "cname_hops": cname_hops,
        "matched": _matched_views(relevant),
        "relevant": relevant,
        "trace": trace,
    }


def _matched_views(relevant: dict | None) -> list[dict]:
    """命中记录：相关 RRset 中同时匹配且适用的 issue/issuewild 记录。"""
    if relevant is None:
        return []
    return [
        view for view in relevant.get("records", [])
        if view.get("matched") and view.get("applicable")
    ]


def _chain_names(trace: list[dict], repeat: str) -> list[str]:
    """从轨迹的 CNAME 事件还原链（用于环报告），到再次出现 repeat 为止。"""
    names: list[str] = []
    started = False
    for event in trace:
        if event.get("action") != "cname":
            continue
        level, target = event["level"], event["target"]
        if not started:
            names.append(level)
            started = True
        names.append(target)
        if target == repeat:
            return names
    names.append(repeat)
    return names
