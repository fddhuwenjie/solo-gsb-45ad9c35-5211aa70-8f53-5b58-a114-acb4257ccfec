"""离线 AXFR（TCP 区传送）响应流检查。

不发起任何真实 DNS 查询：输入区源点 ``zone_origin`` 与 Base64 编码的
**带两字节长度前缀的 TCP DNS 响应流**（``stream`` 字段），逐帧解析
DNS 头、问题区与回答区（授权区/附加区不解析、不参与判定），支持
名称压缩（RFC 1035 §4.1.4）与本服务已有的全部记录类型，并按区传送
的结构规则给出结论。

解析错误（均为 422）：

- 长度前缀或帧体截断（``frame_truncated``）；
- 压缩指针成环（``compression_pointer_loop``）或越界
  （``compression_pointer_out_of_bounds``）；
- RDATA 长度不符（``rdata_length_mismatch``：定长类型长度不对、
  名称/字段消费的字节数与 RDLENGTH 不一致）；
- 其它 RDATA 内容非法（``invalid_rdata``）、TTL 超出 31 位
  （``invalid_record``）、不支持的 RR 类型（``unsupported_type``）、
  名称无法规范化为合法主机名（``invalid_name``）。

结构规则（违反时 ``status=invalid``）：

- 首帧问题区必须恰好是目标区的 ``IN AXFR`` 查询；后续帧问题区可为空
  或与首帧完全相同；
- 所有帧 ID 一致、QR=1、opcode=0、RCODE=0、TC=0；
- 回答必须以目标区 SOA 开始、以**完全相同**（owner/TTL/RDATA）的
  SOA 结束，中间不得再有 SOA；
- 所有回答 owner 必须位于区内；相同记录（owner/type/TTL/RDATA）
  不得重复（首尾 SOA 对除外）；同一 RRset 的 TTL 必须一致；
  回答记录的类必须为 IN；ZONEMD 只能位于区顶。

``status=incomplete``：响应流为空、没有任何回答记录、缺少闭合
SOA，或闭合 SOA 之后仍有回答记录。

``status=complete`` 时响应额外包含规范区域文本 ``zone``（与
:meth:`app.models.Zone.canonical_text` 一致，可直接作为
``/api/reviews`` 的 ``old_zone`` / ``new_zone``）。三种状态都是
HTTP 200 下的检查终态；只有请求格式错误（400）与上述解析错误
（422）走错误响应。
"""

from __future__ import annotations

import base64
import ipaddress
import struct
from dataclasses import dataclass

from .models import RRset, Zone
from .review import ReviewError
from .zonemd import TYPE_CODES
from .zoneparse import (
    SVCB_KNOWN_KEYS,
    ZoneParseError,
    escape_svcb_value,
    parse_caa_rdata,
    parse_svcb_rdata,
    quote_character_string,
    validate_name,
)

QTYPE_AXFR = 252
CLASS_IN = 1
# 与区域文本解析一致的 31 位 TTL 上限
MAX_TTL = 2**31 - 1

# 类型号 -> 类型名（含 AXFR 查询类型，供轨迹展示）
TYPE_NAMES = {code: name for name, code in TYPE_CODES.items()}
TYPE_NAMES[QTYPE_AXFR] = "AXFR"

_SVCB_NUMBER_TO_KEY = {number: key for key, number in SVCB_KNOWN_KEYS.items()}


@dataclass(frozen=True)
class AxfrRecord:
    """一条从回答区解析出的记录（rdata 为规范文本；SOA 为 7 字段元组）。"""

    owner: str
    rtype: str
    rclass: int
    ttl: int
    rdata: object

    @property
    def key(self) -> tuple:
        return (self.owner, self.rtype, self.ttl, self.rdata)

    @property
    def rdata_text(self) -> str:
        if self.rtype == "SOA":
            return " ".join(self.rdata)
        return self.rdata


@dataclass
class AxfrFrame:
    """一个解析后的 TCP DNS 报文帧（仅保留问题区与回答区）。"""

    index: int  # 1 起始的帧序号
    message_id: int
    qr: bool
    opcode: int
    tc: bool
    rcode: int
    questions: list  # (qname, qtype, qclass) 元组列表
    answers: list  # AxfrRecord 列表


# ---------------------------------------------------------------------------
# 名称解压（RFC 1035 §4.1.4）
# ---------------------------------------------------------------------------

def _read_name(frame: bytes, offset: int, where: str) -> tuple[str, int]:
    """在 ``offset`` 处读取一个（可压缩的）域名。

    返回 ``(小写绝对名, 名称结束后下一偏移)``；指针成环/越界、帧内
    截断、名称非法均抛 422。
    """
    labels: list[str] = []
    pos = offset
    end: int | None = None  # 首次跟随压缩指针后确定的“下一偏移”
    visited: set[int] = set()  # 已跳转过的指针目标（环检测）
    while True:
        if pos >= len(frame):
            raise ReviewError(
                "frame_truncated", f"{where}：名称超出报文末尾", 422
            )
        length = frame[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(frame):
                raise ReviewError(
                    "frame_truncated", f"{where}：压缩指针只有半个字节", 422
                )
            target = ((length & 0x3F) << 8) | frame[pos + 1]
            if target >= len(frame):
                raise ReviewError(
                    "compression_pointer_out_of_bounds",
                    f"{where}：压缩指针指向报文外偏移 {target}",
                    422,
                )
            if end is None:
                end = pos + 2
            if target in visited:
                raise ReviewError(
                    "compression_pointer_loop",
                    f"{where}：压缩指针在偏移 {target} 处成环",
                    422,
                )
            visited.add(target)
            pos = target
            continue
        if length & 0xC0:
            raise ReviewError(
                "invalid_name",
                f"{where}：非法标签类型字节 0x{length:02x}",
                422,
            )
        pos += 1
        if length == 0:
            break
        if pos + length > len(frame):
            raise ReviewError(
                "frame_truncated", f"{where}：标签超出报文末尾", 422
            )
        raw = frame[pos : pos + length]
        try:
            labels.append(raw.decode("ascii").lower())
        except UnicodeDecodeError as exc:
            raise ReviewError(
                "invalid_name",
                f"{where}：名称标签含非 ASCII 字节: {exc}",
                422,
            ) from exc
        pos += length
    name = (".".join(labels) + ".") if labels else "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_name", f"{where}：名称非法: {exc}", 422
        ) from exc
    return name, (end if end is not None else pos)


# ---------------------------------------------------------------------------
# RDATA 解析（wire -> 规范文本，与区域文本解析的规范形式一致）
# ---------------------------------------------------------------------------

def _length_mismatch(where: str, what: str) -> ReviewError:
    return ReviewError(
        "rdata_length_mismatch", f"{where}：{what}与 RDLENGTH 不符", 422
    )


def _svcb_param_text(key_num: int, value: bytes, where: str) -> str:
    """把一个 wire 形式的 SvcParam 还原为区域文本记号。"""
    key = _SVCB_NUMBER_TO_KEY.get(key_num)
    name = key if key is not None else f"key{key_num}"
    if key == "mandatory":
        if not value or len(value) % 2:
            raise ReviewError(
                "invalid_rdata",
                f"{where}：mandatory 参数必须是偶数长度的非空键号列表",
                422,
            )
        keys = []
        for i in range(0, len(value), 2):
            (num,) = struct.unpack("!H", value[i : i + 2])
            keys.append(_SVCB_NUMBER_TO_KEY.get(num, f"key{num}"))
        return "mandatory=" + ",".join(keys)
    if key == "alpn":
        ids = []
        i = 0
        while i < len(value):
            slen = value[i]
            i += 1
            if i + slen > len(value):
                raise ReviewError(
                    "invalid_rdata",
                    f"{where}：alpn 的协议标识长度越界",
                    422,
                )
            raw = value[i : i + slen]
            i += slen
            try:
                ids.append(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise ReviewError(
                    "invalid_rdata",
                    f"{where}：alpn 协议标识不是合法 UTF-8: {exc}",
                    422,
                ) from exc
        return "alpn=" + ",".join(escape_svcb_value(item) for item in ids)
    if key == "no-default-alpn":
        if not value:
            return "no-default-alpn"
        # 携带取值：还原为带值记号，交由 parse_svcb_rdata 拒绝
        return "no-default-alpn=" + escape_svcb_value(
            _decode_utf8_param(value, where)
        )
    if key == "port":
        if len(value) != 2:
            raise ReviewError(
                "invalid_rdata",
                f"{where}：port 参数必须是 2 字节，实际 {len(value)} 字节",
                422,
            )
        (port,) = struct.unpack("!H", value)
        return f"port={port}"
    if key in ("ipv4hint", "ipv6hint"):
        size = 4 if key == "ipv4hint" else 16
        family = ipaddress.IPv4Address if size == 4 else ipaddress.IPv6Address
        if not value or len(value) % size:
            raise ReviewError(
                "invalid_rdata",
                f"{where}：{key} 参数长度必须是 {size} 的非零倍数",
                422,
            )
        addrs = [
            str(family(value[i : i + size])).lower()
            for i in range(0, len(value), size)
        ]
        return f"{key}=" + ",".join(addrs)
    # 通用 keyNNNNN：值原样解码为文本，不做解释
    if not value:
        return name
    return f"{name}={escape_svcb_value(_decode_utf8_param(value, where))}"


def _decode_utf8_param(value: bytes, where: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewError(
            "invalid_rdata",
            f"{where}：SvcParam 值不是合法 UTF-8: {exc}",
            422,
        ) from exc


def _parse_svcb_wire(
    frame: bytes, start: int, end: int, origin: str, where: str
) -> str:
    """解析 SVCB/HTTPS 的 wire RDATA，返回与区域文本一致的规范形式。"""
    if end - start < 3:  # 2 字节优先级 + 至少 1 字节根名
        raise _length_mismatch(where, "SVCB/HTTPS RDATA 过短，")
    (priority,) = struct.unpack("!H", frame[start : start + 2])
    target, pos = _read_name(frame, start + 2, where)
    tokens: list[str] = []
    while pos < end:
        if pos + 4 > end:
            raise _length_mismatch(where, "SvcParam 头超出 RDATA 末尾，")
        key_num, vlen = struct.unpack("!HH", frame[pos : pos + 4])
        pos += 4
        if pos + vlen > end:
            raise _length_mismatch(where, "SvcParam 值超出 RDATA 末尾，")
        tokens.append(_svcb_param_text(key_num, frame[pos : pos + vlen], where))
        pos += vlen
    text = " ".join([str(priority), target] + tokens)
    try:
        return parse_svcb_rdata(text, origin).canonical
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_rdata", f"{where}：SVCB/HTTPS RDATA 非法: {exc}", 422
        ) from exc


def _parse_rdata(
    frame: bytes, rtype: str, start: int, rdlength: int, origin: str,
    where: str,
):
    """把一条 wire RDATA 解析为规范文本（SOA 为 7 字段元组）。

    名称可压缩（指针可指向 RDATA 之外的报文任意位置），但名称/字段
    在 RDATA 区间内消费的字节数必须与 RDLENGTH 完全一致。
    """
    end = start + rdlength
    if rtype == "A":
        if rdlength != 4:
            raise _length_mismatch(where, f"A RDATA 应为 4 字节（实际 {rdlength}），")
        return str(ipaddress.IPv4Address(frame[start:end]))
    if rtype == "AAAA":
        if rdlength != 16:
            raise _length_mismatch(
                where, f"AAAA RDATA 应为 16 字节（实际 {rdlength}），"
            )
        return str(ipaddress.IPv6Address(frame[start:end])).lower()
    if rtype in ("NS", "CNAME"):
        if rdlength < 1:
            raise _length_mismatch(where, f"{rtype} RDATA 为空，")
        name, pos = _read_name(frame, start, where)
        if pos != end:
            raise _length_mismatch(where, "名称未恰好占满 RDATA，")
        return name
    if rtype == "SOA":
        if rdlength < 22:  # 两个根名 + 5 个 uint32
            raise _length_mismatch(where, "SOA RDATA 过短，")
        mname, pos = _read_name(frame, start, where)
        rname, pos = _read_name(frame, pos, where)
        if pos + 20 != end:
            raise _length_mismatch(where, "名称与定时器未恰好占满 RDATA，")
        timers = struct.unpack("!IIIII", frame[pos : pos + 20])
        return (mname, rname) + tuple(str(value) for value in timers)
    if rtype == "MX":
        if rdlength < 3:  # 2 字节优先级 + 至少 1 字节根名
            raise _length_mismatch(where, "MX RDATA 过短，")
        (preference,) = struct.unpack("!H", frame[start : start + 2])
        exchange, pos = _read_name(frame, start + 2, where)
        if pos != end:
            raise _length_mismatch(where, "交换主机名未恰好占满 RDATA，")
        return f"{preference} {exchange}"
    if rtype == "TXT":
        strings = []
        pos = start
        while pos < end:
            slen = frame[pos]
            pos += 1
            if pos + slen > end:
                raise _length_mismatch(
                    where, "character-string 超出 RDATA 末尾，"
                )
            strings.append(frame[pos : pos + slen])
            pos += slen
        if not strings:
            raise ReviewError(
                "invalid_rdata", f"{where}：TXT 缺少 character-string", 422
            )
        return " ".join(quote_character_string(item) for item in strings)
    if rtype in ("SVCB", "HTTPS"):
        return _parse_svcb_wire(frame, start, end, origin, where)
    if rtype == "CAA":
        if rdlength < 2:
            raise _length_mismatch(where, "CAA RDATA 过短，")
        flags = frame[start]
        tag_len = frame[start + 1]
        if 2 + tag_len > rdlength:
            raise _length_mismatch(where, "CAA tag 超出 RDATA 末尾，")
        try:
            tag = frame[start + 2 : start + 2 + tag_len].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ReviewError(
                "invalid_rdata",
                f"{where}：CAA tag 含非 ASCII 字节: {exc}",
                422,
            ) from exc
        value = frame[start + 2 + tag_len : end]
        text = f"{flags} {tag} {quote_character_string(value)}"
        try:
            return parse_caa_rdata(text, origin).canonical
        except ZoneParseError as exc:
            raise ReviewError(
                "invalid_rdata", f"{where}：CAA RDATA 非法: {exc}", 422
            ) from exc
    if rtype == "ZONEMD":
        if rdlength < 6:
            raise _length_mismatch(where, "ZONEMD RDATA 过短，")
        serial, scheme, algorithm = struct.unpack("!IBB", frame[start : start + 6])
        digest = frame[start + 6 : end]
        if not digest:
            raise ReviewError(
                "invalid_rdata", f"{where}：ZONEMD digest 为空", 422
            )
        return f"{serial} {scheme} {algorithm} {digest.hex()}"
    if rtype == "TLSA":
        if rdlength < 3:
            raise _length_mismatch(where, "TLSA RDATA 过短，")
        usage, selector, matching_type = frame[start : start + 3]
        assoc = frame[start + 3 : end]
        if not assoc:
            raise ReviewError(
                "invalid_rdata", f"{where}：TLSA 关联数据为空", 422
            )
        return f"{usage} {selector} {matching_type} {assoc.hex()}"
    raise ReviewError(  # 不会到达：调用前已按类型号过滤
        "unsupported_type", f"{where}：不支持的 RR 类型 {rtype}", 422
    )


# ---------------------------------------------------------------------------
# 帧解析
# ---------------------------------------------------------------------------

def _split_frames(data: bytes) -> list[bytes]:
    """按两字节长度前缀切分 TCP DNS 响应流。"""
    frames = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise ReviewError(
                "frame_truncated",
                "TCP 长度前缀截断（流末尾剩余不足 2 字节）",
                422,
            )
        (length,) = struct.unpack("!H", data[pos : pos + 2])
        pos += 2
        if pos + length > len(data):
            raise ReviewError(
                "frame_truncated",
                f"帧体截断：长度前缀声明 {length} 字节，"
                f"实际剩余 {len(data) - pos} 字节",
                422,
            )
        frames.append(data[pos : pos + length])
        pos += length
    return frames


def _parse_frame(frame: bytes, index: int, origin: str) -> AxfrFrame:
    """解析一帧的 DNS 头、问题区与回答区（授权区/附加区忽略）。"""
    where = f"第 {index} 帧"
    if len(frame) < 12:
        raise ReviewError(
            "frame_truncated",
            f"{where}：DNS 头不足 12 字节（实际 {len(frame)} 字节）",
            422,
        )
    (message_id, flags, qdcount, ancount, _nscount, _arcount) = struct.unpack(
        "!HHHHHH", frame[:12]
    )
    qr = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    tc = bool(flags & 0x0200)
    rcode = flags & 0xF

    pos = 12
    questions = []
    for _ in range(qdcount):
        qname, pos = _read_name(frame, pos, f"{where} 问题区")
        if pos + 4 > len(frame):
            raise ReviewError(
                "frame_truncated", f"{where}：问题区 QTYPE/QCLASS 截断", 422
            )
        qtype, qclass = struct.unpack("!HH", frame[pos : pos + 4])
        pos += 4
        questions.append((qname, qtype, qclass))

    answers = []
    for rec_no in range(1, ancount + 1):
        owner, pos = _read_name(frame, pos, f"{where} 回答区")
        if pos + 10 > len(frame):
            raise ReviewError(
                "frame_truncated", f"{where}：第 {rec_no} 条回答的记录头截断",
                422,
            )
        rtype_code, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", frame[pos : pos + 10]
        )
        pos += 10
        rtype = TYPE_NAMES.get(rtype_code)
        if rtype is None or rtype == "AXFR":
            raise ReviewError(
                "unsupported_type",
                f"{where}：第 {rec_no} 条回答的类型号 {rtype_code} 不受支持",
                422,
            )
        rec_where = f"{where} 第 {rec_no} 条回答（{owner} {rtype}）"
        if ttl > MAX_TTL:
            raise ReviewError(
                "invalid_record",
                f"{rec_where}：TTL {ttl} 超出 31 位范围",
                422,
            )
        if pos + rdlength > len(frame):
            raise ReviewError(
                "frame_truncated", f"{rec_where}：RDATA 超出报文末尾", 422
            )
        rdata = _parse_rdata(frame, rtype, pos, rdlength, origin, rec_where)
        pos += rdlength
        answers.append(
            AxfrRecord(owner=owner, rtype=rtype, rclass=rclass, ttl=ttl,
                       rdata=rdata)
        )

    return AxfrFrame(
        index=index,
        message_id=message_id,
        qr=qr,
        opcode=opcode,
        tc=tc,
        rcode=rcode,
        questions=questions,
        answers=answers,
    )


# ---------------------------------------------------------------------------
# 结构判定
# ---------------------------------------------------------------------------

def _in_zone(name: str, origin: str) -> bool:
    if origin == ".":
        return True
    return name == origin or name.endswith("." + origin)


def _normalize_origin(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError(
            "invalid_request", "zone_origin 必须是非空字符串", 400
        )
    origin = value.strip().lower()
    if origin != "." and not origin.endswith("."):
        origin += "."
    try:
        validate_name(origin)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"zone_origin 非法: {exc}", 400
        ) from exc
    return origin


def _build_trace(frames: list[AxfrFrame]) -> list[dict]:
    """按帧及记录排列的有序轨迹（记录 seq 跨帧连续编号）。"""
    trace = []
    seq = 0
    for frame in frames:
        entries = []
        for rec in frame.answers:
            seq += 1
            entries.append(
                {
                    "seq": seq,
                    "owner": rec.owner,
                    "type": rec.rtype,
                    "ttl": rec.ttl,
                    "rdata": rec.rdata_text,
                }
            )
        trace.append(
            {
                "frame": frame.index,
                "message_id": frame.message_id,
                "questions": [
                    {
                        "qname": qname,
                        "qtype": TYPE_NAMES.get(qtype, str(qtype)),
                        "qclass": "IN" if qclass == CLASS_IN else str(qclass),
                    }
                    for qname, qtype, qclass in frame.questions
                ],
                "answers": entries,
            }
        )
    return trace


def _build_zone_text(origin: str, answers: list[AxfrRecord]) -> str:
    """把回答记录汇编为规范区域文本（可交给 /api/reviews）。"""
    collected: dict[tuple[str, str], dict] = {}
    for rec in answers:
        entry = collected.setdefault(
            (rec.owner, rec.rtype), {"ttl": rec.ttl, "rdata": set()}
        )
        entry["rdata"].add(rec.rdata)
    rrsets = {
        key: RRset(
            owner=key[0],
            rtype=key[1],
            ttl=entry["ttl"],
            rdata=tuple(sorted(entry["rdata"])),
        )
        for key, entry in collected.items()
    }
    return Zone(origin=origin, rrsets=rrsets).canonical_text()


def inspect_axfr(payload: dict) -> dict:
    """检查一段 Base64 编码的 TCP AXFR 响应流，返回可序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)
    origin = _normalize_origin(payload.get("zone_origin"))
    stream = payload.get("stream")
    if not isinstance(stream, str):
        raise ReviewError(
            "invalid_request",
            "stream 必须是 Base64 编码的 TCP DNS 响应流字符串",
            400,
        )
    try:
        data = base64.b64decode(stream, validate=True)
    except ValueError as exc:
        raise ReviewError(
            "invalid_request", f"stream 不是合法 Base64: {exc}", 400
        ) from exc

    frames = [
        _parse_frame(raw, index, origin)
        for index, raw in enumerate(_split_frames(data), start=1)
    ]
    message_count = len(frames)
    answers = [rec for frame in frames for rec in frame.answers]
    record_count = len(answers)

    def finish(status: str, reason: str, extra: dict | None = None) -> dict:
        result = {
            "zone_origin": origin,
            "status": status,
            "reason": reason,
            "message_count": message_count,
            "record_count": record_count,
            "trace": _build_trace(frames),
        }
        if extra:
            result.update(extra)
        return result

    if not frames:
        return finish("incomplete", "响应流为空：没有任何 DNS 报文")

    # ---- 帧级头检查：QR/opcode/TC/RCODE 与 ID 一致性 ----
    reference_id = frames[0].message_id
    for frame in frames:
        if not frame.qr:
            return finish(
                "invalid", f"第 {frame.index} 帧 QR=0，不是响应报文"
            )
        if frame.opcode != 0:
            return finish(
                "invalid",
                f"第 {frame.index} 帧 opcode={frame.opcode}，应为 0（QUERY）",
            )
        if frame.tc:
            return finish(
                "invalid", f"第 {frame.index} 帧 TC=1，响应被截断"
            )
        if frame.rcode != 0:
            return finish(
                "invalid",
                f"第 {frame.index} 帧 RCODE={frame.rcode}，应为 0（NOERROR）",
            )
        if frame.message_id != reference_id:
            return finish(
                "invalid",
                f"第 {frame.index} 帧 ID {frame.message_id} "
                f"与首帧 ID {reference_id} 不一致",
            )

    # ---- 问题区检查 ----
    expected_questions = [(origin, QTYPE_AXFR, CLASS_IN)]
    if frames[0].questions != expected_questions:
        return finish(
            "invalid",
            f"首帧问题区必须恰好是目标区 {origin} 的 IN AXFR 查询",
        )
    for frame in frames[1:]:
        if frame.questions not in ([], expected_questions):
            return finish(
                "invalid",
                f"第 {frame.index} 帧问题区与首帧不一致（应为空或相同）",
            )

    # ---- 回答结构检查 ----
    if not answers:
        return finish(
            "incomplete", "没有任何回答记录：缺少起始与闭合 SOA"
        )
    first = answers[0]
    if first.rtype != "SOA" or first.owner != origin:
        return finish(
            "invalid",
            f"回答必须以目标区 SOA 开始，实际首条为 {first.owner} "
            f"{first.rtype}",
        )
    soa_positions = [
        i for i, rec in enumerate(answers) if rec.rtype == "SOA"
    ]
    if len(soa_positions) == 1:
        return finish(
            "incomplete", "缺少闭合 SOA：回答未以与起始相同的 SOA 结束"
        )
    if soa_positions[-1] != record_count - 1:
        return finish(
            "incomplete",
            f"闭合 SOA（第 {soa_positions[-1] + 1} 条回答）之后仍有 "
            f"{record_count - 1 - soa_positions[-1]} 条回答记录",
        )
    if len(soa_positions) > 2:
        return finish(
            "invalid", "起始与闭合 SOA 之间不得再出现 SOA 记录"
        )
    closing = answers[-1]
    if (closing.owner, closing.ttl, closing.rdata) != (
        first.owner, first.ttl, first.rdata,
    ):
        return finish(
            "invalid",
            "闭合 SOA 与起始 SOA 不完全相同（owner/TTL/RDATA 须一致）",
        )
    for rec in answers:
        if rec.rclass != CLASS_IN:
            return finish(
                "invalid",
                f"回答记录 {rec.owner} {rec.rtype} 的类不是 IN",
            )
        if not _in_zone(rec.owner, origin):
            return finish(
                "invalid",
                f"回答记录 owner {rec.owner} 不在区 {origin} 内",
            )
        if rec.rtype == "ZONEMD" and rec.owner != origin:
            return finish(
                "invalid",
                f"ZONEMD 记录 {rec.owner} 不在区顶",
            )
    seen = set()
    for rec in answers[1:]:  # 首条 SOA 不参与：闭合 SOA 与它必然相同
        if rec.key in seen:
            return finish(
                "invalid",
                f"重复记录：{rec.owner} {rec.rtype} {rec.rdata_text}",
            )
        seen.add(rec.key)
    rrset_ttls: dict[tuple[str, str], int] = {}
    for rec in answers:
        key = (rec.owner, rec.rtype)
        known = rrset_ttls.setdefault(key, rec.ttl)
        if known != rec.ttl:
            return finish(
                "invalid",
                f"同一 RRset（{rec.owner} {rec.rtype}）出现不同 TTL："
                f"{known} 与 {rec.ttl}",
            )

    zone_text = _build_zone_text(origin, answers)
    return finish(
        "complete",
        f"区传送完整：{message_count} 个报文、{record_count} 条记录，"
        "SOA 首尾一致",
        {"zone": zone_text},
    )
