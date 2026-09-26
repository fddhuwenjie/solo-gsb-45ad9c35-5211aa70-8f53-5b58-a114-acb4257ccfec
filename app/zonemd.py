"""ZONEMD 区域摘要离线校验（RFC 8976 Simple Scheme；不校验 RRSIG）。

输入一段区域文本，解析仅位于区顶的 ZONEMD RRset，按 RFC 8976
Simple Scheme（scheme 1）重算区域摘要并逐条核对：

- 各类 RR 编为 DNSSEC 规范 wire format（RFC 4034 §6.1/6.2/6.3：
  名称小写 wire 编码、不压缩；同一 owner 的 RRset 按类型号升序；
  RRset 内 RDATA 按 wire 字节序排列；重复 RR 只取一份），排除区顶
  ZONEMD RRset 后按规范顺序拼接，对拼接结果计算摘要；
- 区域文本重排、重复 RDATA 与等价写法（相对名/``@``/时长单位等）
  不改变摘要（解析阶段已规范化、去重）；
- 支持 scheme 1（SIMPLE）与 SHA-384（算法 1）/SHA-512（算法 2）；
  未知 scheme 或摘要算法的记录标为 unsupported；
- 每条记录要求 serial 等于 SOA serial、digest 长度匹配算法，
  逐条返回 expected / computed / matched；
- 总结论：有受支持记录匹配为 ``valid``；受支持记录均不匹配为
  ``invalid``；全部不受支持（含没有 ZONEMD 记录）为 ``unsupported``。

响应附有序 RR 轨迹（按摘要输入顺序）；不校验 RRSIG。
``valid`` / ``invalid`` / ``unsupported`` 都是 HTTP 200 下的校验
终态；只有请求格式错误（400）与区域解析失败（422）走错误响应。
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct

from .models import Zone
from .review import ReviewError
from .zoneparse import (
    SvcbRdata,
    ZoneParseError,
    decode_svcb_value,
    parse_caa_rdata,
    parse_svcb_rdata,
    parse_zone,
    svcb_key_number,
    txt_strings,
)

# 本服务涉及类型的类型号（ZONEMD=63，RFC 8976 §5.1；TLSA=52，RFC 6698 §7.1）
TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "TLSA": 52,
    "ZONEMD": 63,
    "SVCB": 64,
    "HTTPS": 65,
    "CAA": 257,
}
CLASS_IN = 1

# 支持的 scheme 与摘要算法（RFC 8976 §5.2/§5.3）
SCHEMES = {1: "simple"}
HASH_ALGORITHMS = {1: "sha384", 2: "sha512"}


# ---------------------------------------------------------------------------
# DNSSEC 规范 wire format（RFC 4034 §6）
# ---------------------------------------------------------------------------

def _wire_name(name: str) -> bytes:
    """小写绝对名 -> wire format（逐标签长度前缀，根为零字节，不压缩）。"""
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name[:-1].split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _svcb_param_wire(parsed: SvcbRdata, key: str, value: str | None) -> bytes:
    """一个 SvcParam 的 wire 值（RFC 9460；已知键按结构化字段编码）。"""
    if value is None:
        return b""
    if key == "mandatory":
        return b"".join(
            struct.pack("!H", svcb_key_number(k)) for k in parsed.mandatory
        )
    if key == "alpn":
        out = bytearray()
        for item in parsed.alpn or ():
            raw = item.encode("utf-8")
            out.append(len(raw))
            out.extend(raw)
        return bytes(out)
    if key == "port":
        return struct.pack("!H", parsed.port)
    if key == "ipv4hint":
        return b"".join(
            ipaddress.IPv4Address(addr).packed for addr in parsed.ipv4hint
        )
    if key == "ipv6hint":
        return b"".join(
            ipaddress.IPv6Address(addr).packed for addr in parsed.ipv6hint
        )
    # 通用 keyNNNNN：规范文本是转义形式，解码回原始字节
    return decode_svcb_value(value).encode("utf-8")


def _svcb_wire(parsed: SvcbRdata) -> bytes:
    out = bytearray(struct.pack("!H", parsed.priority))
    out.extend(_wire_name(parsed.target))
    for key, value in parsed.params:  # 解析时已按键号升序
        param = _svcb_param_wire(parsed, key, value)
        out.extend(struct.pack("!HH", svcb_key_number(key), len(param)))
        out.extend(param)
    return bytes(out)


def _rdata_wire(rtype: str, rdata, origin: str) -> bytes:
    """把一条规范化 RDATA 编码为 DNSSEC 规范 wire format。"""
    if rtype == "A":
        return ipaddress.IPv4Address(rdata).packed
    if rtype == "AAAA":
        return ipaddress.IPv6Address(rdata).packed
    if rtype in ("NS", "CNAME"):
        return _wire_name(rdata)
    if rtype == "SOA":
        mname, rname, serial, refresh, retry, expire, minimum = rdata
        return _wire_name(mname) + _wire_name(rname) + struct.pack(
            "!IIIII",
            int(serial), int(refresh), int(retry), int(expire),
            int(minimum),
        )
    if rtype == "MX":
        preference, exchange = rdata.split(" ", 1)
        return struct.pack("!H", int(preference)) + _wire_name(exchange)
    if rtype == "TXT":
        out = bytearray()
        for text in txt_strings(rdata):
            raw = text.encode("latin-1")  # 每个字符即一个字节
            out.append(len(raw))
            out.extend(raw)
        return bytes(out)
    if rtype in ("SVCB", "HTTPS"):
        return _svcb_wire(parse_svcb_rdata(rdata, origin))
    if rtype == "CAA":
        caa = parse_caa_rdata(rdata, origin)
        tag = caa.tag.encode("ascii")
        return bytes([caa.flags, len(tag)]) + tag + caa.value.encode("utf-8")
    if rtype == "TLSA":
        usage, selector, matching_type, assoc = rdata.split(" ")
        return (
            bytes([int(usage), int(selector), int(matching_type)])
            + bytes.fromhex(assoc)
        )
    raise ReviewError("invalid_zone", f"无法编码 wire format 的类型: {rtype}",
                      422)


def _owner_key(name: str) -> tuple:
    """RFC 4034 §6.1 规范名称序的排序键（标签逆序元组）。"""
    if name == ".":
        return ()
    return tuple(reversed(name.rstrip(".").split(".")))


def _ordered_rrs(zone: Zone) -> list[dict]:
    """按 RFC 8976 Simple Scheme 的顺序展开区域 RR（排除区顶 ZONEMD RRset）。

    返回有序条目列表：owner/type/ttl/rdata（展示用）与 wire（摘要输入）。
    """
    rrsets = sorted(
        (
            rrset
            for rrset in zone.rrsets.values()
            if not (rrset.rtype == "ZONEMD" and rrset.owner == zone.origin)
        ),
        key=lambda rrset: (_owner_key(rrset.owner), TYPE_CODES[rrset.rtype]),
    )
    entries = []
    for rrset in rrsets:
        # RFC 4034 §6.3：RRset 内按 RDATA wire 字节序排列（重复已去重）
        pairs = sorted(
            (
                (_rdata_wire(rrset.rtype, rdata, zone.origin), rdata)
                for rdata in rrset.rdata
            ),
            key=lambda pair: pair[0],
        )
        for rdata_wire, rdata in pairs:
            rr_wire = (
                _wire_name(rrset.owner)
                + struct.pack(
                    "!HHIH",
                    TYPE_CODES[rrset.rtype],
                    CLASS_IN,
                    rrset.ttl,
                    len(rdata_wire),
                )
                + rdata_wire
            )
            entries.append(
                {
                    "owner": rrset.owner,
                    "type": rrset.rtype,
                    "ttl": rrset.ttl,
                    "rdata": (
                        " ".join(rdata) if rrset.rtype == "SOA" else rdata
                    ),
                    "wire": rr_wire,
                }
            )
    return entries


def _compute_digest(entries: list[dict], hash_name: str) -> str:
    """digest = hash( RR(1) | RR(2) | ... )，RFC 8976 §3.3.1.2。"""
    hasher = hashlib.new(hash_name)
    for entry in entries:
        hasher.update(entry["wire"])
    return hasher.hexdigest()


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------

def _verify_record(rdata: str, soa_serial: int, entries: list[dict],
                   computed: dict[int, str]) -> dict:
    """核对一条 ZONEMD RDATA，返回逐条结果（RFC 8976 §4 步骤 5）。"""
    serial_s, scheme_s, algorithm_s, expected = rdata.split(" ")
    serial, scheme, algorithm = int(serial_s), int(scheme_s), int(algorithm_s)
    scheme_name = SCHEMES.get(scheme)
    hash_name = HASH_ALGORITHMS.get(algorithm)
    supported = scheme_name is not None and hash_name is not None

    computed_hex = None
    matched = False
    if scheme_name is None:
        reason = f"未知 scheme {scheme}，无法校验"
    elif hash_name is None:
        reason = f"未知摘要算法 {algorithm}，无法校验"
    else:
        if algorithm not in computed:
            computed[algorithm] = _compute_digest(entries, hash_name)
        computed_hex = computed[algorithm]
        digest_size = hashlib.new(hash_name).digest_size
        digest_octets = len(expected) // 2
        if serial != soa_serial:
            reason = (
                f"serial {serial} 与 SOA serial {soa_serial} 不一致"
            )
        elif digest_octets != digest_size:
            reason = (
                f"digest 长度 {digest_octets} 字节与 {hash_name} "
                f"要求的 {digest_size} 字节不符"
            )
        elif expected != computed_hex:
            reason = "摘要与区域内容不匹配"
        else:
            matched = True
            reason = "serial 与摘要均匹配"

    return {
        "serial": serial,
        "scheme": scheme,
        "scheme_name": scheme_name,
        "hash_algorithm": algorithm,
        "hash_name": hash_name,
        "supported": supported,
        "expected": expected,
        "computed": computed_hex,
        "matched": matched,
        "reason": reason,
    }


def verify_zonemd(payload: dict) -> dict:
    """校验区域文本中区顶 ZONEMD RRset 的区域摘要。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)
    text = payload.get("zone")
    if not isinstance(text, str) or not text.strip():
        raise ReviewError(
            "invalid_request", "zone 必须是非空区域文本字符串", 400
        )
    try:
        zone = parse_zone(text)
    except ZoneParseError as exc:
        raise ReviewError(
            "zone_parse_error",
            f"区域解析失败: {exc}",
            422,
            [{"message": str(exc)}],
        ) from exc

    apex = zone.origin
    soa = zone.get(apex, "SOA")
    if soa is None:
        raise ReviewError(
            "missing_soa",
            "区域缺少区顶 SOA，无法核对 ZONEMD serial",
            422,
        )
    soa_serial = int(soa.rdata[0][2])

    entries = _ordered_rrs(zone)
    trace = [
        {
            "seq": index,
            "owner": entry["owner"],
            "type": entry["type"],
            "ttl": entry["ttl"],
            "rdata": entry["rdata"],
        }
        for index, entry in enumerate(entries, start=1)
    ]

    zonemd_rrset = zone.get(apex, "ZONEMD")
    rdata_list = list(zonemd_rrset.rdata) if zonemd_rrset is not None else []

    computed: dict[int, str] = {}
    records = [
        _verify_record(rdata, soa_serial, entries, computed)
        for rdata in rdata_list
    ]

    if any(record["matched"] for record in records):
        status = "valid"
        reason = "至少一条受支持的 ZONEMD 记录校验通过"
    elif any(record["supported"] for record in records):
        status = "invalid"
        reason = "受支持的 ZONEMD 记录均未通过校验"
    else:
        status = "unsupported"
        reason = (
            "区域中没有 ZONEMD 记录"
            if not records
            else "所有 ZONEMD 记录的 scheme/摘要算法均不受支持"
        )

    return {
        "zone_origin": apex,
        "soa_serial": soa_serial,
        "status": status,
        "reason": reason,
        "records": records,
        "trace": trace,
    }
