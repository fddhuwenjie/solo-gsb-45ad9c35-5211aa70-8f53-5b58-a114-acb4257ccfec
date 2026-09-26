"""离线 TLSA（DANE）记录校验（RFC 6698；仅 usage=3 DANE-EE）。

不发起任何真实 DNS 查询：TLSA 记录来自请求给出的本地区域文本集合，
叶证书来自请求给出的 PEM 文本（``cryptography`` 仅用于校验证书是否
可解析）；**不验证 DNSSEC**（验证状态由请求外部给出）、
**不验证证书链**、**不验证证书与主机名的匹配**。

selector=1 使用的 SPKI 直接从证书 DER 的 ``tbsCertificate`` 中按
ASN.1 结构截取完整的 ``SubjectPublicKeyInfo`` TLV（原始编码，
兼容可选 ``version`` 字段及短/长形式长度编码），**不**用公钥对象
重导出——部分证书（如算法标识为 id-RSASSA-PSS，见 RFC 4055）的
原始 SPKI 与重导出编码不同，重导出会把 RFC 6698 §2.3 本应匹配的
记录误判为不匹配。

校验规则要点（RFC 6698 §2.1）：

- 查询名为 ``_<端口>._<协议>.<主机名>``（协议取 tcp/udp/sctp）；
- 仅支持 usage=3（DANE-EE）：selector=0 取证书 DER、selector=1 取
  SPKI DER；matching-type=0 直接比较原始字节、1 比较 SHA-256、
  2 比较 SHA-512；其余 usage/selector/matching-type 组合的记录
  标为 ``supported=false``，不参与结论；
- 有受支持记录时，按外部 DNSSEC 状态给结论：``secure`` 下任一记录
  匹配为 ``matched``、均不匹配为 ``mismatched``；``insecure`` 为
  ``indeterminate``；``bogus`` 为 ``invalid``；
- 查询名没有 TLSA 记录为 ``none``；只有不受支持记录为
  ``unsupported``。

终态 ``matched`` / ``mismatched`` / ``indeterminate`` / ``invalid`` /
``none`` / ``unsupported`` 都是 HTTP 200 下的校验结论；只有请求格式
错误（400，含 PEM 证书解析失败）与区域解析失败（422，含 TLSA 字段/
十六进制错误）走错误响应。
"""

from __future__ import annotations

import hashlib

from .review import ReviewError
from .validity import find_cuts
from .zoneparse import ZoneParseError, parse_zone, validate_name

try:  # 证书解析依赖（镜像中经 requirements.txt 安装）
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - 镜像内始终安装
    x509 = None
    serialization = None
    _HAVE_CRYPTOGRAPHY = False

# 仅支持 usage=3（DANE-EE，域签发证书）；其余 usage 的记录不参与结论
SUPPORTED_USAGE = 3
USAGE_NAMES = {
    0: "pkix-ta",
    1: "pkix-ee",
    2: "dane-ta",
    3: "dane-ee",
}
SELECTOR_NAMES = {0: "cert", 1: "spki"}
MATCHING_NAMES = {0: "exact", 1: "sha256", 2: "sha512"}
MATCHING_HASHES = {1: "sha256", 2: "sha512"}

PROTOCOLS = ("tcp", "udp", "sctp")
DNSSEC_STATES = ("secure", "insecure", "bogus")

_DOMAIN_LABEL_SEP = "."


# ---------------------------------------------------------------------------
# 请求校验（区域文本解析与 spf/svcb/caa 一致）
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


def _normalize_hostname(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "hostname 必须是非空字符串", 400
        )
    name = value.strip().lower()
    if not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"hostname 非法: {exc}", 400
        ) from exc
    return name


def _normalize_port(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReviewError(
            "invalid_request", "port 必须是 0..65535 的整数", 400
        )
    if not 0 <= value <= 65535:
        raise ReviewError(
            "invalid_request", f"port 超出 0..65535 范围: {value}", 400
        )
    return value


def _normalize_protocol(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "protocol 必须是非空字符串", 400
        )
    protocol = value.strip().lower().lstrip("_")
    if protocol not in PROTOCOLS:
        raise ReviewError(
            "invalid_request",
            f"protocol 必须是 {'/'.join(PROTOCOLS)} 之一: {value!r}",
            400,
        )
    return protocol


def _normalize_dnssec(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "dnssec 必须是非空字符串", 400
        )
    state = value.strip().lower()
    if state not in DNSSEC_STATES:
        raise ReviewError(
            "invalid_request",
            f"dnssec 必须是 {'/'.join(DNSSEC_STATES)} 之一: {value!r}",
            400,
        )
    return state


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """读取一个 DER TLV，返回 (tag, value 起点, value 终点)。

    长度同时兼容短形式（单字节 <0x80）与长形式（0x81/0x82…）。
    """
    if offset + 2 > len(data):
        raise ValueError("DER 长度不足")
    tag = data[offset]
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or pos + count > len(data):
            raise ValueError("非法的 DER 长形式长度")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("DER TLV 长度超出数据范围")
    return tag, pos, end


def _iter_children(content: bytes):
    """依次产生 CONSTRUCTED TLV content 内每个子 TLV 的 (tag, TLV)。"""
    offset = 0
    while offset < len(content):
        tag, _, end = _read_tlv(content, offset)
        yield tag, content[offset:end]
        offset = end


def _extract_spki(cert_der: bytes) -> bytes:
    """从证书 DER 的 tbsCertificate 结构截取原始 SPKI 完整 TLV。

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
    signatureValue }；tbsCertificate 内字段固定为
    [0]version? / serialNumber / signature / issuer / validity /
    subject / subjectPublicKeyInfo / ...，故存在显式 version 时
    SPKI 是第 7 个子 TLV（索引 6），否则是第 6 个（索引 5）。
    全程按结构走，不做字节搜索，也不重导出公钥。
    """
    try:
        tag, cert_value_start, cert_end = _read_tlv(cert_der, 0)
        if tag != 0x30 or cert_end != len(cert_der):
            raise ValueError("证书不是单一 DER SEQUENCE")
        children = _iter_children(cert_der[cert_value_start:cert_end])
        tbs_tlv = next(children)[1]

        tag, tbs_value_start, tbs_end = _read_tlv(tbs_tlv, 0)
        if tag != 0x30:
            raise ValueError("tbsCertificate 不是 SEQUENCE")
        fields = list(_iter_children(tbs_tlv[tbs_value_start:tbs_end]))
        spki_index = 6 if fields and fields[0][0] == 0xA0 else 5
        spki_tag, spki_tlv = fields[spki_index]
        if spki_tag != 0x30:
            raise ValueError("subjectPublicKeyInfo 不是 SEQUENCE")
    except (ValueError, IndexError, StopIteration) as exc:
        raise ValueError(f"无法从 TBSCertificate 截取 SPKI: {exc}") from exc
    return spki_tlv


def _load_certificate(value) -> tuple[bytes, bytes]:
    """解析 PEM 叶证书，返回 (证书 DER, 证书内原始 SPKI DER)。

    ``cryptography`` 负责证书的解析校验；selector=1 所需的 SPKI 不用
    公钥对象重导出，而是从证书 DER 的 tbsCertificate 按结构截取，
    以保留证书作者写入的原始编码（如 id-RSASSA-PSS 算法标识）。
    """
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "certificate 必须是 PEM 文本字符串", 400
        )
    if not _HAVE_CRYPTOGRAPHY:  # pragma: no cover - 镜像内始终安装
        raise ReviewError(
            "tlsa_dependency_missing",
            "缺少证书解析依赖 cryptography（请按 requirements.txt 安装）",
            500,
        )
    try:
        pem = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ReviewError(
            "invalid_certificate", "certificate 不是合法的 PEM 文本", 400
        ) from exc
    try:
        cert = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise ReviewError(
            "invalid_certificate", f"PEM 叶证书解析失败: {exc}", 400
        ) from exc
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    try:
        spki_der = _extract_spki(cert_der)
    except ValueError as exc:
        raise ReviewError(
            "invalid_certificate", f"PEM 叶证书结构无效: {exc}", 400
        ) from exc
    return cert_der, spki_der


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
# 记录核对
# ---------------------------------------------------------------------------

def _evaluate_record(rdata: str, cert_der: bytes, spki_der: bytes) -> dict:
    """核对一条规范化 TLSA RDATA，返回逐条结果（RFC 6698 §2.1）。"""
    usage_s, selector_s, matching_s, expected = rdata.split(" ")
    usage, selector, matching = int(usage_s), int(selector_s), int(matching_s)
    usage_name = USAGE_NAMES.get(usage)
    selector_name = SELECTOR_NAMES.get(selector)
    matching_name = MATCHING_NAMES.get(matching)
    supported = (
        usage == SUPPORTED_USAGE
        and selector_name is not None
        and matching_name is not None
    )

    computed = None
    matched = False
    if usage != SUPPORTED_USAGE:
        reason = f"仅支持 usage=3 (DANE-EE)，记录为 usage={usage}"
    elif selector_name is None:
        reason = f"未知 selector {selector}，无法校验"
    elif matching_name is None:
        reason = f"未知 matching type {matching}，无法校验"
    else:
        source = cert_der if selector == 0 else spki_der
        hash_name = MATCHING_HASHES.get(matching)
        if hash_name is None:  # matching-type=0：直接比较原始字节
            association = source
        else:
            association = hashlib.new(hash_name, source).digest()
        computed = association.hex()
        if computed == expected:
            matched = True
            reason = "关联数据与证书匹配"
        else:
            reason = "关联数据与证书不匹配"

    return {
        "rdata": rdata,
        "usage": usage,
        "usage_name": usage_name,
        "selector": selector,
        "selector_name": selector_name,
        "matching_type": matching,
        "matching_name": matching_name,
        "supported": supported,
        "expected": expected,
        "computed": computed,
        "matched": matched,
        "reason": reason,
    }


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def verify_tlsa(payload: dict) -> dict:
    """执行一次离线 TLSA 校验，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones = _parse_zones(payload.get("zones"))
    hostname = _normalize_hostname(payload.get("hostname"))
    port = _normalize_port(payload.get("port"))
    protocol = _normalize_protocol(payload.get("protocol"))
    dnssec = _normalize_dnssec(payload.get("dnssec"))
    cert_der, spki_der = _load_certificate(payload.get("certificate"))

    qname = f"_{port}._{protocol}.{hostname}"
    cuts = {apex: find_cuts(zone, apex) for apex, zone in zones.items()}

    trace: list[dict] = [
        {
            "action": "qname",
            "qname": qname,
            "hostname": hostname,
            "port": port,
            "protocol": protocol,
        }
    ]

    rdata_list: list[str] = []
    zone = _enclosing_zone(zones, cuts, qname)
    if zone is None:
        trace.append({
            "action": "lookup",
            "qname": qname,
            "found": False,
            "reason": "missing_local_zone",
        })
    else:
        rrset = zone.get(qname, "TLSA")
        if rrset is None:
            trace.append({
                "action": "lookup",
                "zone": zone.origin,
                "qname": qname,
                "found": False,
                "reason": "no_tlsa_rrset",
            })
        else:
            rdata_list = list(rrset.rdata)
            trace.append({
                "action": "lookup",
                "zone": zone.origin,
                "qname": qname,
                "found": True,
                "ttl": rrset.ttl,
                "record_count": len(rdata_list),
            })

    records = [
        _evaluate_record(rdata, cert_der, spki_der) for rdata in rdata_list
    ]
    supported_count = sum(1 for record in records if record["supported"])
    matched_count = sum(1 for record in records if record["matched"])

    if not records:
        status = "none"
        reason = "查询名没有 TLSA 记录"
    elif supported_count == 0:
        status = "unsupported"
        reason = "所有 TLSA 记录的 usage/selector/matching type 均不受支持"
    elif dnssec == "secure":
        if matched_count:
            status = "matched"
            reason = "至少一条受支持的 TLSA 记录与证书匹配"
        else:
            status = "mismatched"
            reason = "受支持的 TLSA 记录均未与证书匹配"
    elif dnssec == "insecure":
        status = "indeterminate"
        reason = "DNSSEC 状态为 insecure，TLSA 匹配结果不可作为依据"
    else:  # bogus
        status = "invalid"
        reason = "DNSSEC 状态为 bogus，TLSA 数据无效"

    trace.append({
        "action": "result",
        "status": status,
        "dnssec": dnssec,
        "supported": supported_count,
        "matched": matched_count,
        "reason": reason,
    })

    return {
        "qname": qname,
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "dnssec": dnssec,
        "status": status,
        "reason": reason,
        "certificate": {
            "der_length": len(cert_der),
            "der_sha256": hashlib.sha256(cert_der).hexdigest(),
            "spki_sha256": hashlib.sha256(spki_der).hexdigest(),
        },
        "records": records,
        "trace": trace,
    }
