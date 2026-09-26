"""区域文本解析与规范化。

支持的指令与类型：
- 指令：``$ORIGIN``、``$TTL``
- 资源记录：``SOA``、``NS``、``A``、``AAAA``、``CNAME``、``MX``、``TXT``、
  ``SVCB``、``HTTPS``、``CAA``、``ZONEMD``、``TLSA``（类固定 IN）

规范化规则：
- 所有相对名相对当前 $ORIGIN 补全为绝对名，``@`` 表示当前源点，统一小写；
- 省略属名时继承上一条记录的属名；
- TTL 省略时使用当前 $TTL 默认值，支持 ``1h``/``2d``/``1w`` 等时长写法；
- 括号跨行合并，``;`` 之后为注释（TXT 双引号字符串内的 ``;``/括号按字面量处理）；
- A/AAAA 用 ipaddress 规范化（AAAA 压缩小写）；
- MX RDATA 规范化为 ``"<优先级> <交换主机>"``（主机补全为小写绝对名）；
- TXT 的每条 RR 由一个或多个 <character-string> 组成，RFC 1035
  引号/转义被解码后再以规范引号形式存为一个 rdata 元素，
  从而保留 RR 内字符串分组、支持重复 RDATA 去重；
- SVCB/HTTPS RDATA 按 RFC 9460 解析为 ``"<优先级> <目标> [参数...]"``，
  参数按键号排序、值重新转义为规范形式（详见 :func:`parse_svcb_rdata`）；
- CAA RDATA 按 RFC 8659 解析为 ``"<flags> <tag> <value>"``：flags 为
  0..255 的无符号整数，tag 为非空字母数字串（1..255），value 是单个
  <character-string>（按 UTF-8 解码）；``issue``/``issuewild`` 的 value
  进一步解析出签发者与 ``accounturi``/``validationmethods`` 参数，
  参数按名排序后重新转义（详见 :func:`parse_caa_rdata`）；
- ZONEMD RDATA 按 RFC 8976 解析为 ``"<serial> <scheme> <hash-algorithm>
  <digest>"``：serial 为 32 位无符号整数，scheme 与 hash-algorithm 为
  0..255，digest 是非空的偶数长度十六进制串（可跨多个记号书写，
  规范化为小写拼接）；ZONEMD 仅允许位于区顶（当前源点）；
- TLSA RDATA 按 RFC 6698 解析为 ``"<usage> <selector> <matching-type>
  <association-data>"``：前三个字段为 0..255 的整数，关联数据是非空的
  偶数长度十六进制串（可跨多个记号书写，规范化为小写拼接）；
- 同一 RRset 的重复 RDATA 去重（不影响摘要），TTL 不一致视为解析错误。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .models import RRset, SUPPORTED_TYPES, Zone


class ZoneParseError(ValueError):
    """区域文本解析失败。"""

    def __init__(self, message: str, line_no: int | None = None):
        if line_no is not None:
            message = f"第 {line_no} 行: {message}"
        super().__init__(message)
        self.line_no = line_no


_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_TOKEN_RE = re.compile(r"\S+")


def _scan_line(line: str) -> tuple[str, int, int]:
    """扫描一行，返回 (注释剥离后的文本, 开括号数, 闭括号数)。

    TXT 双引号字符串内的 ``;`` 不是注释、``(``/``)`` 不参与续行；
    引号内 ``\\`` 转义紧跟的一个字符（含引号本身）。
    """
    out: list[str] = []
    opened = closed = 0
    quoted = False
    escaped = False
    for ch in line:
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == ";":
            break
        if ch == '"':
            quoted = True
            out.append(ch)
        elif ch == "(":
            opened += 1
        elif ch == ")":
            closed += 1
        else:
            out.append(ch)
    return "".join(out), opened, closed


def _blank_parens_outside_quotes(text: str) -> str:
    """把引号外的续行括号替换为空格，引号内内容原样保留。"""
    out: list[str] = []
    quoted = False
    escaped = False
    for ch in text:
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
            out.append(ch)
        elif ch in "()":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _normalize_whitespace_outside_quotes(text: str) -> str:
    """折叠引号外的连续空白为单个空格；引号串内空白原样保留。"""
    out: list[str] = []
    quoted = False
    escaped = False
    prev_space = False
    for ch in text:
        if quoted:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                quoted = False
            continue
        if ch == '"':
            quoted = True
            out.append(ch)
            prev_space = False
        elif ch.isspace():
            if not prev_space:
                out.append(" ")
            prev_space = True
        else:
            out.append(ch)
            prev_space = False
    return "".join(out)


def _logical_lines(text: str):
    """把物理行展开为逻辑行（处理括号续行与注释），产出 (行号, 文本)。

    保留原始前导空白，以便识别“省略属名”的记录行。
    """
    parts: list[str] = []
    start_line = 0
    depth = 0
    for idx, raw in enumerate(text.splitlines(), start=1):
        # ; 在引号外注释到行尾；TXT 引号内的 ; 与括号按字面处理
        line, opened, closed = _scan_line(raw)
        if depth == 0:
            if opened:
                start_line = idx
            parts = [line]
        else:
            parts.append(line.lstrip())
        depth += opened - closed
        if depth < 0:
            raise ZoneParseError("括号不匹配（多余的 ')'）", idx)
        if depth == 0:
            # 去掉引号外的续行括号记号本身（RFC 主文件中括号仅作续行/分组）
            head_text = _blank_parens_outside_quotes(parts[0])
            tail_text = _blank_parens_outside_quotes(" ".join(parts[1:]))
            joined = head_text + " " + tail_text
            joined = _normalize_whitespace_outside_quotes(joined).rstrip()
            if joined.strip():
                yield start_line or idx, joined
            parts = []
            start_line = 0
    if depth != 0:
        raise ZoneParseError("括号未闭合（缺少 ')'）", start_line or None)


def _parse_duration(token: str, line_no: int) -> int:
    token = token.strip()
    if token.isdigit():
        value = int(token)
    else:
        match = re.fullmatch(r"(\d+)\s*([smhdwSMHDW])", token)
        if not match:
            raise ZoneParseError(f"无法识别的时长/TTL: {token!r}", line_no)
        value = int(match.group(1)) * _DURATION_UNITS[match.group(2).lower()]
    if not 0 <= value <= 2**31 - 1:
        raise ZoneParseError(f"TTL/时长超出 31 位范围: {token}", line_no)
    return value


def normalize_name(token: str, origin: str) -> str:
    """把名称记号规范化为小写绝对 FQDN。"""
    name = token.lower().strip()
    if name == "@":
        return origin
    if name == ".":
        return "."
    if name.endswith("."):
        absolute = name
    else:
        absolute = f"{name}.{origin}"
    validate_name(absolute)
    return absolute


def validate_name(name: str) -> None:
    if not name.endswith("."):
        raise ZoneParseError(f"内部错误，名称非绝对名: {name!r}")
    if name == ".":
        return
    bare = name[:-1]
    if len(bare) > 253:
        raise ZoneParseError(f"名称超过 253 字节: {name!r}")
    for label in bare.split("."):
        if not _LABEL_RE.fullmatch(label):
            raise ZoneParseError(f"非法名称标签: {label!r}（来自 {name!r}）")


def _normalize_addr(token: str, rtype: str, line_no: int) -> str:
    try:
        if rtype == "A":
            return str(ipaddress.IPv4Address(token))
        return str(ipaddress.IPv6Address(token)).lower()
    except ValueError as exc:
        raise ZoneParseError(f"非法 {rtype} 地址 {token!r}", line_no) from exc


def _parse_txt_rdata(remainder: str, line_no: int) -> str:
    """解析一条 TXT RR 的 RDATA 尾部，返回规范引号形式的单个字符串。

    支持 RFC 1035 的 <character-string>：引号串（``\\DDD`` 三位十进制、
    ``\\x`` 转义）与无引号原子（到空白为止）。一条 RR 可由多个
    character-string 组成，规范化时逐串解码后重新加引号并以空格连接。
    """
    pieces: list[str] = []
    i = 0
    n = len(remainder)
    while i < n:
        while i < n and remainder[i].isspace():
            i += 1
        if i >= n:
            break
        chars: list[int] = []
        quoted = remainder[i] == '"'
        if quoted:
            i += 1
        while i < n:
            ch = remainder[i]
            if quoted:
                if ch == '"':
                    i += 1
                    break
                if ch == "\\":
                    i += 1
                    if i >= n:
                        raise ZoneParseError("TXT 转义不完整", line_no)
                    esc = remainder[i]
                    if esc.isdigit():
                        digits = esc
                        for _ in range(2):
                            i += 1
                            if i >= n or not remainder[i].isdigit():
                                raise ZoneParseError(
                                    "TXT \\DDD 转义需要三位十进制数字", line_no
                                )
                            digits += remainder[i]
                        value = int(digits)
                        if value > 255:
                            raise ZoneParseError(
                                f"TXT \\{digits} 超出字节范围", line_no
                            )
                        chars.append(value)
                    else:
                        chars.append(ord(esc) & 0xFF)
                else:
                    chars.extend(ch.encode("utf-8"))
                i += 1
            else:
                # 无引号原子：到空白为止；引号/分号/反斜杠不得出现在原子中
                if ch.isspace():
                    break
                if ch in '";\\':
                    raise ZoneParseError(
                        f"TXT 无引号字符段中出现非法字符 {ch!r}", line_no
                    )
                chars.extend(ch.encode("utf-8"))
                i += 1
        else:
            if quoted:
                raise ZoneParseError("TXT 引号未闭合", line_no)
        data = bytes(chars)
        if len(data) > 255:
            raise ZoneParseError(
                "TXT 单个 character-string 超过 255 字节", line_no
            )
        pieces.append(_quote_character_string(data))
    if not pieces:
        raise ZoneParseError("TXT 缺少 character-string 字段", line_no)
    return " ".join(pieces)


def _quote_character_string(data: bytes) -> str:
    """把一个已解码的 TXT character-string 字节串重新规范化为引号形式。"""
    out = ['"']
    for byte in data:
        ch = chr(byte)
        if ch == '"' or ch == "\\":
            out.append("\\" + ch)
        elif 32 <= byte <= 126:
            out.append(ch)
        else:
            out.append("\\%03d" % byte)
    out.append('"')
    return "".join(out)


def quote_character_string(data: bytes) -> str:
    """把一个已解码的 <character-string> 字节串编码为规范引号形式。

    供 AXFR wire→文本还原等需要重建 TXT/CAA 文本的场景复用。
    """
    return _quote_character_string(data)


def txt_strings(element: str) -> list[str]:
    """把规范化 rdata 元素还原为该 RR 内各 character-string 的解码文本。"""
    result: list[str] = []
    i = 0
    n = len(element)
    while i < n:
        while i < n and element[i].isspace():
            i += 1
        if i >= n:
            break
        if element[i] != '"':
            raise ValueError(
                f"TXT 规范化文本应以引号串开始: {element!r}（位置 {i}）"
            )
        chars: list[str] = []
        i += 1  # 跳过开引号
        while i < n:
            ch = element[i]
            if ch == '"':
                i += 1
                break
            if ch == "\\":
                i += 1
                if i >= n:
                    raise ValueError("TXT 规范化文本含不完整转义")
                esc = element[i]
                if esc.isdigit():
                    digits = element[i : i + 3]
                    if len(digits) != 3 or not digits.isdigit():
                        raise ValueError("TXT 规范化文本含非法 \\DDD 转义")
                    chars.append(chr(int(digits)))
                    i += 3
                else:
                    chars.append(esc)
                    i += 1
            else:
                chars.append(ch)
                i += 1
        else:
            raise ValueError("TXT 规范化文本引号未闭合")
        result.append("".join(chars))
    return result


def txt_concat(element: str) -> str:
    """拼接一条 TXT RR 的所有 character-string（SPF 按 RFC 7208 这样取值）。"""
    return "".join(txt_strings(element))


def _parse_soa(tokens: list[str], line_no: int, origin: str) -> tuple[str, tuple[str, ...]]:
    # SOA: mname rname serial refresh retry expire minimum（常带括号续行）
    if len(tokens) != 7:
        raise ZoneParseError(
            f"SOA RDATA 应为 7 个字段 (mname rname serial refresh retry expire minimum)，"
            f"实际 {len(tokens)} 个",
            line_no,
        )
    mname = normalize_name(tokens[0], origin)
    rname = normalize_name(tokens[1], origin)
    serial_token, refresh, retry, expire, minimum = tokens[2:]
    serial = int(serial_token) if serial_token.isdigit() else None
    if serial is None or not 0 <= serial < 2**32:
        raise ZoneParseError(f"SOA 序列号非法: {serial_token!r}", line_no)
    fields = [
        mname,
        rname,
        str(serial),
        str(_parse_duration(refresh, line_no)),
        str(_parse_duration(retry, line_no)),
        str(_parse_duration(expire, line_no)),
        str(_parse_duration(minimum, line_no)),
    ]
    return str(serial), (tuple(fields),)


# ---------------------------------------------------------------------------
# SVCB / HTTPS（RFC 9460）
# ---------------------------------------------------------------------------

# 本服务结构化支持的 SvcParamKey（名称 -> 键号）
SVCB_KNOWN_KEYS = {
    "mandatory": 0,
    "alpn": 1,
    "no-default-alpn": 2,
    "port": 3,
    "ipv4hint": 4,
    "ipv6hint": 6,
}
_SVCB_NUMBER_TO_KEY = {number: key for key, number in SVCB_KNOWN_KEYS.items()}


@dataclass(frozen=True)
class SvcbRdata:
    """一条规范化 SVCB/HTTPS RDATA。

    ``params`` 为按键号排序的 ``(规范键名, 规范值)`` 元组；无值键
    （如 ``no-default-alpn``）的规范值为 ``None``。
    """

    priority: int
    target: str  # 小写绝对名；"." 原样保留（别名不可用 / ServiceMode 回落 owner）
    params: tuple[tuple[str, str | None], ...]
    mandatory: tuple[str, ...]
    alpn: tuple[str, ...] | None
    no_default_alpn: bool
    port: int | None
    ipv4hint: tuple[str, ...]
    ipv6hint: tuple[str, ...]
    canonical: str


def svcb_key_number(key: str) -> int:
    """规范键名对应的 SvcParamKey 键号（通用 ``keyN`` 取其 N）。"""
    if key in SVCB_KNOWN_KEYS:
        return SVCB_KNOWN_KEYS[key]
    return int(key[3:])


def normalize_svcb_key(name: str, line_no: int | None = None) -> str:
    """校验并规范化一个 SvcParamKey 名称。

    已知键返回小写名；未知键只接受 RFC 9460 的通用 ``keyNNNNN`` 形式，
    且键号落在已知键上时归一到对应名称。
    """
    low = name.strip().lower()
    if low in SVCB_KNOWN_KEYS:
        return low
    if low.startswith("key") and low[3:].isdigit():
        number = int(low[3:])
        if number >= 65535:
            raise ZoneParseError(
                f"SVCB 参数键号非法或保留: {name!r}", line_no
            )
        mapped = _SVCB_NUMBER_TO_KEY.get(number)
        return mapped if mapped is not None else f"key{number}"
    raise ZoneParseError(
        f"未知 SVCB 参数键: {name!r}（未知键须使用 keyNNNNN 通用形式）",
        line_no,
    )


def _tokenize_svcb(remainder: str, line_no: int | None) -> list[str]:
    """按空白切分 SVCB RDATA；双引号内的空白与转义保留在记号内。"""
    tokens: list[str] = []
    i, n = 0, len(remainder)
    while i < n:
        while i < n and remainder[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        quoted = False
        escaped = False
        while i < n:
            ch = remainder[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif quoted:
                if ch == '"':
                    quoted = False
            elif ch == '"':
                quoted = True
            elif ch.isspace():
                break
            i += 1
        if quoted:
            raise ZoneParseError("SVCB 参数引号未闭合", line_no)
        tokens.append(remainder[start:i])
    return tokens


def _decode_svcb_value(raw: str, line_no: int | None) -> str:
    """解码 SvcParamValue：去除引号、处理 ``\\DDD`` 与 ``\\X`` 转义。

    解码结果必须是合法 UTF-8（保证后续可以安全地放进 JSON 响应）。
    """
    data = bytearray()
    i, n = 0, len(raw)
    quoted = False
    while i < n:
        ch = raw[i]
        if ch == "\\":
            i += 1
            if i >= n:
                raise ZoneParseError("SVCB 参数值转义不完整", line_no)
            esc = raw[i]
            if esc.isdigit():
                digits = raw[i : i + 3]
                if len(digits) != 3 or not digits.isdigit():
                    raise ZoneParseError(
                        "SVCB \\DDD 转义需要三位十进制数字", line_no
                    )
                value = int(digits)
                if value > 255:
                    raise ZoneParseError(
                        f"SVCB \\{digits} 超出字节范围", line_no
                    )
                data.append(value)
                i += 3
                continue
            data.extend(esc.encode("utf-8"))
            i += 1
            continue
        if ch == '"':
            quoted = not quoted
            i += 1
            continue
        data.extend(ch.encode("utf-8"))
        i += 1
    if quoted:
        raise ZoneParseError("SVCB 参数值引号未闭合", line_no)
    try:
        return bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZoneParseError(
            f"SVCB 参数值不是合法 UTF-8: {exc}", line_no
        ) from exc


def decode_svcb_value(raw: str) -> str:
    """解码一个 SvcParamValue 文本形式（引号/``\\DDD``/``\\X`` 转义）。

    供 ZONEMD wire 编码等需要还原参数原始字节的场景复用。
    """
    return _decode_svcb_value(raw, None)


def _split_svcb_list(raw: str, line_no: int | None) -> list[str]:
    """按未转义的逗号切开列表值，逐项解码转义。

    引号仅是 <character-string> 的定界符、不属于值内容，因此引号内的
    逗号仍然是列表分隔符；只有 ``\\,`` 能把逗号留在某一项里。
    """
    segments: list[str] = []
    buf: list[str] = []
    escaped = False
    for ch in raw:
        if escaped:
            buf.append("\\" + ch)  # 保留转义记号，交由解码阶段处理
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            continue  # 引号只是定界符
        if ch == ",":
            segments.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if escaped:
        raise ZoneParseError("SVCB 参数值转义不完整", line_no)
    segments.append("".join(buf))
    return [_decode_svcb_value(segment, line_no) for segment in segments]


def _escape_svcb_value(value: str) -> str:
    """把解码值重新编码为规范形式：单记号、不依赖引号。"""
    out: list[str] = []
    for byte in value.encode("utf-8"):
        ch = chr(byte)
        if ch in ('"', "\\", ","):
            out.append("\\" + ch)
        elif 33 <= byte <= 126:
            out.append(ch)
        else:
            out.append("\\%03d" % byte)
    return "".join(out)


def escape_svcb_value(value: str) -> str:
    """把解码后的 SvcParamValue 重新编码为规范文本形式。

    供 AXFR wire→文本还原等需要重建参数文本的场景复用。
    """
    return _escape_svcb_value(value)


def parse_svcb_rdata(
    remainder: str, origin: str, line_no: int | None = None
) -> SvcbRdata:
    """解析一条 SVCB/HTTPS RDATA（``<优先级> <目标> [参数...]``）。

    校验（违反抛 :class:`ZoneParseError`）：
    - 优先级为 0..65535 的整数；目标为合法域名（``.`` 原样保留）；
    - 参数键唯一；未知键只接受 ``keyNNNNN`` 通用形式；
    - ``mandatory`` 不得引用自身、不得引用记录中缺失的参数键；
    - ``no-default-alpn`` 必须与 ``alpn`` 同时出现；
    - AliasMode（优先级 0）记录不得携带任何参数。
    """
    tokens = _tokenize_svcb(remainder, line_no)
    if len(tokens) < 2:
        raise ZoneParseError(
            "SVCB/HTTPS RDATA 应为 '<优先级> <目标> [参数...]'，"
            f"实际只有 {len(tokens)} 个字段",
            line_no,
        )
    priority_token, target_token = tokens[0], tokens[1]
    if not priority_token.isdigit():
        raise ZoneParseError(
            f"SVCB 优先级必须是 0..65535 的整数: {priority_token!r}", line_no
        )
    priority = int(priority_token)
    if priority > 65535:
        raise ZoneParseError(
            f"SVCB 优先级超出 0..65535: {priority}", line_no
        )
    target = normalize_name(target_token, origin)

    raw_params: dict[str, str | None] = {}
    for token in tokens[2:]:
        key_token, sep, value_token = token.partition("=")
        key = normalize_svcb_key(key_token, line_no)
        if key in raw_params:
            raise ZoneParseError(f"SVCB 参数键重复: {key}", line_no)
        raw_params[key] = value_token if sep else None

    mandatory: tuple[str, ...] = ()
    alpn: tuple[str, ...] | None = None
    no_default_alpn = False
    port: int | None = None
    ipv4hint: tuple[str, ...] = ()
    ipv6hint: tuple[str, ...] = ()
    # key -> (键号, 规范值/None)
    parsed: dict[str, tuple[int, str | None]] = {}

    for key, raw_value in raw_params.items():
        number = svcb_key_number(key)
        canonical_value: str | None
        if key == "mandatory":
            if not raw_value:
                raise ZoneParseError(
                    "mandatory 需要非空的参数键列表", line_no
                )
            items = []
            for item in _split_svcb_list(raw_value, line_no):
                listed = normalize_svcb_key(item, line_no)
                if listed == "mandatory":
                    raise ZoneParseError(
                        "mandatory 列表不得包含 mandatory 自身", line_no
                    )
                items.append(listed)
            keys = sorted(set(items), key=svcb_key_number)
            mandatory = tuple(keys)
            canonical_value = ",".join(keys)
        elif key == "alpn":
            if raw_value is None:
                raise ZoneParseError("alpn 需要取值", line_no)
            items = _split_svcb_list(raw_value, line_no)
            if any(item == "" for item in items):
                raise ZoneParseError("alpn 列表含空的协议标识", line_no)
            alpn = tuple(items)
            canonical_value = ",".join(
                _escape_svcb_value(item) for item in items
            )
        elif key == "no-default-alpn":
            if raw_value not in (None, ""):
                raise ZoneParseError(
                    "no-default-alpn 不允许携带取值", line_no
                )
            no_default_alpn = True
            canonical_value = None
        elif key == "port":
            if raw_value is None:
                raise ZoneParseError("port 需要取值", line_no)
            value = _decode_svcb_value(raw_value, line_no)
            if not value.isdigit() or int(value) > 65535:
                raise ZoneParseError(
                    f"port 必须是 0..65535 的整数: {value!r}", line_no
                )
            port = int(value)
            canonical_value = str(port)
        elif key in ("ipv4hint", "ipv6hint"):
            if not raw_value:
                raise ZoneParseError(f"{key} 需要非空的地址列表", line_no)
            expect_v4 = key == "ipv4hint"
            addresses = []
            for item in _split_svcb_list(raw_value, line_no):
                try:
                    addr = (
                        ipaddress.IPv4Address(item)
                        if expect_v4
                        else ipaddress.IPv6Address(item)
                    )
                except ValueError as exc:
                    raise ZoneParseError(
                        f"{key} 含非法地址 {item!r}", line_no
                    ) from exc
                addresses.append(str(addr).lower())
            if expect_v4:
                ipv4hint = tuple(addresses)
            else:
                ipv6hint = tuple(addresses)
            canonical_value = ",".join(addresses)
        else:  # 通用 keyNNNNN：值原样解码保存，不做解释
            if raw_value is None:
                canonical_value = None
            else:
                decoded = _decode_svcb_value(raw_value, line_no)
                canonical_value = (
                    _escape_svcb_value(decoded) if decoded != "" else None
                )
        parsed[key] = (number, canonical_value)

    for key in mandatory:
        if key not in raw_params:
            raise ZoneParseError(
                f"mandatory 引用了记录中缺失的参数键: {key}", line_no
            )
    if no_default_alpn and alpn is None:
        raise ZoneParseError(
            "no-default-alpn 需要与 alpn 同时出现", line_no
        )
    if priority == 0 and raw_params:
        raise ZoneParseError(
            "AliasMode（优先级 0）记录不得携带 SvcParams", line_no
        )

    ordered = sorted(parsed.items(), key=lambda kv: kv[1][0])
    params = tuple((key, value[1]) for key, value in ordered)
    tokens_out = [
        key if value is None else f"{key}={value}" for key, value in params
    ]
    canonical = " ".join([str(priority), target] + tokens_out)
    return SvcbRdata(
        priority=priority,
        target=target,
        params=params,
        mandatory=mandatory,
        alpn=alpn,
        no_default_alpn=no_default_alpn,
        port=port,
        ipv4hint=ipv4hint,
        ipv6hint=ipv6hint,
        canonical=canonical,
    )


# ---------------------------------------------------------------------------
# CAA（RFC 8659，参数 RFC 8657）
# ---------------------------------------------------------------------------

# 本服务理解的 CAA 属性标签：其余标签即“未知 property”
CAA_KNOWN_TAGS = frozenset({"issue", "issuewild", "iodef"})
_CAA_TAG_RE = re.compile(r"^[A-Za-z0-9]{1,255}$")
_CAA_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9]+$")
CRITICAL_BIT = 0x80


@dataclass(frozen=True)
class CaaRdata:
    """一条规范化 CAA RDATA。

    ``params`` 仅对 ``issue`` / ``issuewild`` 有意义，为按参数名排序的
    ``(小写参数名, 原始值)`` 元组；``accounturi`` / ``validationmethods``
    分别结构化到对应字段（后者为按值排序的方法列表）。
    """

    flags: int
    tag: str
    value: str
    issuer: str | None
    params: tuple[tuple[str, str], ...]
    accounturi: str | None
    validationmethods: tuple[str, ...] | None
    canonical: str

    @property
    def critical(self) -> bool:
        return bool(self.flags & CRITICAL_BIT)


def _parse_caa_issue_value(
    value: str, line_no: int | None
) -> tuple[str, tuple[tuple[str, str], ...], str | None, tuple[str, ...] | None]:
    """解析 issue/issuewild 的 value：``<签发者>(;name=value)*``。

    返回 (小写签发者, 按名排序的参数, accounturi, 排序后的验证方式)。
    签发者为空串表示“空签发者”（禁止任何 CA 签发）。
    """
    segments = value.split(";")
    issuer = segments[0].strip().lower()
    if issuer != "":
        try:
            validate_name(
                issuer if issuer.endswith(".") else issuer + "."
            )
        except ZoneParseError as exc:
            raise ZoneParseError(
                f"CAA issue/issuewild 签发者域名非法: {issuer!r}: {exc}",
                line_no,
            ) from exc
    params: dict[str, str] = {}
    for segment in segments[1:]:
        piece = segment.strip()
        if piece == "":
            # 宽容结尾的 ';' / 纯空白参数段
            continue
        name, sep, param_value = piece.partition("=")
        name = name.strip().lower()
        if not sep or not _CAA_PARAM_NAME_RE.fullmatch(name):
            raise ZoneParseError(
                f"CAA issue/issuewild 参数应为 name=value: {segment!r}",
                line_no,
            )
        if name in params:
            raise ZoneParseError(
                f"CAA issue/issuewild 参数重复: {name}", line_no
            )
        params[name] = param_value.strip()

    accounturi = params.get("accounturi")

    methods = params.get("validationmethods")
    validationmethods: tuple[str, ...] | None = None
    if methods is not None:
        items = [item.strip() for item in methods.split(",") if item.strip()]
        if not items:
            raise ZoneParseError(
                "CAA validationmethods 不能为空", line_no
            )
        validationmethods = tuple(sorted(set(items)))

    ordered = tuple(sorted(params.items()))
    return issuer, ordered, accounturi, validationmethods


def parse_caa_rdata(
    remainder: str, origin: str, line_no: int | None = None
) -> CaaRdata:
    """解析一条 CAA RR 的 RDATA（``<flags> <tag> <value>``，RFC 8659）。

    校验（违反抛 :class:`ZoneParseError`）：
    - flags 为 0..255 的无符号整数；
    - tag 为 1..255 字节的字母数字串；
    - value 必须恰好由一个 <character-string> 组成，解码后为合法 UTF-8；
    - issue/issuewild 的 value 须符合 ``<签发者>(;name=value)*``，
      签发者须为空或合法域名，参数名须为字母数字串且不重复，
      ``validationmethods`` 须为非空的逗号分隔列表。
    """
    tokens = _tokenize_svcb(remainder, line_no)
    if len(tokens) < 3:
        raise ZoneParseError(
            "CAA RDATA 应为 '<flags> <tag> <value>' 三个字段，"
            f"实际只有 {len(tokens)} 个",
            line_no,
        )
    if len(tokens) > 3:
        raise ZoneParseError(
            "CAA value 必须是单个 <character-string>"
            "（多段文本请整体加引号）",
            line_no,
        )
    flags_token, tag_token, value_token = tokens
    if not flags_token.isdigit() or not 0 <= int(flags_token) <= 255:
        raise ZoneParseError(
            f"CAA flags 必须是 0..255 的整数: {flags_token!r}", line_no
        )
    flags = int(flags_token)
    tag = tag_token.lower()
    if not _CAA_TAG_RE.fullmatch(tag):
        raise ZoneParseError(
            f"CAA tag 必须是 1..255 字节的非空字母数字串: {tag_token!r}",
            line_no,
        )
    value = _decode_svcb_value(value_token, line_no)
    if len(value.encode("utf-8")) > 512:
        raise ZoneParseError(
            "CAA value 超过 512 字节", line_no
        )

    issuer: str | None = None
    params: tuple[tuple[str, str], ...] = ()
    accounturi: str | None = None
    validationmethods: tuple[str, ...] | None = None
    canonical_value = value
    if tag in ("issue", "issuewild"):
        issuer, params, accounturi, validationmethods = (
            _parse_caa_issue_value(value, line_no)
        )
        # 参数按名排序、validationmethods 按值排序后重组，使书写顺序
        # 不改变规范文本（同一逻辑 RDATA 可去重）
        canon_params = dict(params)
        if validationmethods is not None:
            canon_params["validationmethods"] = ",".join(validationmethods)
        canonical_value = issuer + "".join(
            f";{name}={value}" for name, value in sorted(canon_params.items())
        )

    canonical = f"{flags} {tag} {_quote_character_string(canonical_value.encode('utf-8'))}"
    return CaaRdata(
        flags=flags,
        tag=tag,
        value=value,
        issuer=issuer,
        params=params,
        accounturi=accounturi,
        validationmethods=validationmethods,
        canonical=canonical,
    )


# ---------------------------------------------------------------------------
# ZONEMD（RFC 8976）
# ---------------------------------------------------------------------------

_ZONEMD_DIGEST_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def _parse_zonemd(tokens: list[str], line_no: int) -> str:
    """解析一条 ZONEMD RDATA，返回规范文本形式。

    RDATA 为 ``<serial> <scheme> <hash-algorithm> <digest>``：serial 为
    32 位无符号整数，scheme 与 hash-algorithm 为 0..255 的整数，digest
    是非空的偶数长度十六进制串（可跨多个记号书写，规范化为小写拼接）。
    scheme/算法是否受支持、digest 长度是否匹配算法等语义判定由
    :mod:`app.zonemd` 在校验环节逐条进行。
    """
    if len(tokens) < 4:
        raise ZoneParseError(
            "ZONEMD RDATA 应为 '<serial> <scheme> <hash-algorithm> "
            f"<digest>'，实际只有 {len(tokens)} 个字段",
            line_no,
        )
    serial_token, scheme_token, algorithm_token = tokens[0], tokens[1], tokens[2]
    digest_token = "".join(tokens[3:])
    if not serial_token.isdigit() or not 0 <= int(serial_token) < 2**32:
        raise ZoneParseError(f"ZONEMD serial 非法: {serial_token!r}", line_no)
    if not scheme_token.isdigit() or not 0 <= int(scheme_token) <= 255:
        raise ZoneParseError(f"ZONEMD scheme 非法: {scheme_token!r}", line_no)
    if not algorithm_token.isdigit() or not 0 <= int(algorithm_token) <= 255:
        raise ZoneParseError(
            f"ZONEMD hash algorithm 非法: {algorithm_token!r}", line_no
        )
    if not _ZONEMD_DIGEST_RE.fullmatch(digest_token):
        raise ZoneParseError(
            "ZONEMD digest 必须是非空的偶数长度十六进制串", line_no
        )
    return (
        f"{int(serial_token)} {int(scheme_token)} {int(algorithm_token)} "
        f"{digest_token.lower()}"
    )


# ---------------------------------------------------------------------------
# TLSA（RFC 6698）
# ---------------------------------------------------------------------------

_TLSA_ASSOC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def _parse_tlsa(tokens: list[str], line_no: int) -> str:
    """解析一条 TLSA RDATA，返回规范文本形式。

    RDATA 为 ``<usage> <selector> <matching-type> <association-data>``：
    前三个字段为 0..255 的整数，关联数据是非空的偶数长度十六进制串
    （可跨多个记号书写，规范化为小写拼接）。usage/selector/matching-type
    组合是否受支持、关联数据与证书是否匹配等语义判定由
    :mod:`app.tlsa` 在校验环节逐条进行。
    """
    if len(tokens) < 4:
        raise ZoneParseError(
            "TLSA RDATA 应为 '<usage> <selector> <matching-type> "
            f"<association-data>'，实际只有 {len(tokens)} 个字段",
            line_no,
        )
    fields = []
    for token, name in zip(tokens[:3], ("usage", "selector", "matching type")):
        if not token.isdigit() or not 0 <= int(token) <= 255:
            raise ZoneParseError(f"TLSA {name} 非法: {token!r}", line_no)
        fields.append(str(int(token)))
    assoc_token = "".join(tokens[3:])
    if not _TLSA_ASSOC_RE.fullmatch(assoc_token):
        raise ZoneParseError(
            "TLSA 关联数据必须是非空的偶数长度十六进制串", line_no
        )
    return " ".join(fields) + " " + assoc_token.lower()


def parse_zone(
    text: str,
    default_origin: str | None = None,
    default_ttl: int | None = None,
) -> Zone:
    """解析区域文本，返回规范化 Zone。

    源点取值：优先使用第一个 $ORIGIN 指令，否则使用 default_origin；
    二者皆无则报错。
    """
    origin: str | None = default_origin.lower().rstrip(".") + "." if default_origin else None
    apex: str | None = None
    current_ttl = default_ttl
    last_owner: str | None = None

    # key -> [ttl, set(rdata)]，随后固化为 RRset
    collected: dict[tuple[str, str], list] = {}
    soa_serial: str | None = None

    for line_no, line in _logical_lines(text):
        tokens = line.split()
        head = tokens[0].lower()

        if head == "$origin":
            if len(tokens) != 2:
                raise ZoneParseError("$ORIGIN 需要恰好一个参数", line_no)
            value = tokens[1].lower()
            if not value.endswith("."):
                if origin is None:
                    raise ZoneParseError(
                        "相对的 $ORIGIN 需要已存在的源点上下文", line_no
                    )
                value = f"{value}.{origin}"
            validate_name(value)
            if origin is None:
                apex = value
            origin = value
            continue

        if head == "$ttl":
            if len(tokens) != 2:
                raise ZoneParseError("$TTL 需要恰好一个参数", line_no)
            current_ttl = _parse_duration(tokens[1], line_no)
            continue

        if head.startswith("$"):
            raise ZoneParseError(f"不支持的指令: {tokens[0]}", line_no)

        if origin is None:
            raise ZoneParseError(
                "缺少 $ORIGIN 指令（且未提供默认源点），无法解析相对名", line_no
            )

        owner: str
        # 属名省略：以空白开头的行继承上一条属名
        if line[:1].isspace():
            if last_owner is None:
                raise ZoneParseError("首条记录不能省略属名", line_no)
            owner = last_owner
            body = line.lstrip()
        else:
            gap = re.search(r"\s", line)
            if gap is None:
                raise ZoneParseError("记录缺少 TTL/类型/RDATA 字段", line_no)
            owner_token = line[: gap.start()]
            body = line[gap.end() :].lstrip()
            owner = normalize_name(owner_token, origin)
            last_owner = owner

        ttl: int | None = None
        rtype: str | None = None
        rdata_start = None
        pos = 0
        while True:
            while pos < len(body) and body[pos].isspace():
                pos += 1
            match = _TOKEN_RE.match(body, pos)
            if match is None:
                break
            tok = match.group(0)
            low = tok.lower()
            if (ttl is None and re.fullmatch(r"\d+[smhdwSMHDW]", tok)) or (
                ttl is None and low.isdigit()
            ):
                ttl = _parse_duration(tok, line_no)
            elif low == "in":
                pass  # 类固定 IN，允许出现在 TTL 前后
            elif low.upper() in SUPPORTED_TYPES:
                rtype = low.upper()
                rdata_start = match.end()
                break
            else:
                raise ZoneParseError(
                    f"无法解析的记录前缀字段: {tok!r}", line_no
                )
            pos = match.end()

        if rtype is None:
            raise ZoneParseError("记录缺少受支持的 RR 类型", line_no)
        if ttl is None:
            if current_ttl is None:
                raise ZoneParseError(
                    f"记录省略了 TTL 且此前没有 $TTL 指令", line_no
                )
            ttl = current_ttl

        # TXT 必须保留引号与空白的原始位置，按 character-string 解析；
        # 其余类型仍按空白记号处理
        rdata_remainder = body[rdata_start:]
        rdata_tokens = rdata_remainder.split()

        key = (owner, rtype)
        if rtype == "SOA":
            serial_value, rdata = _parse_soa(rdata_tokens, line_no, origin)
            if owner != origin:
                raise ZoneParseError("SOA 必须位于区顶（当前源点）", line_no)
            if soa_serial is not None:
                raise ZoneParseError("区顶只允许一个 SOA RRset", line_no)
            soa_serial = serial_value
        elif rtype == "ZONEMD":
            if owner != origin:
                raise ZoneParseError(
                    "ZONEMD 必须位于区顶（当前源点）", line_no
                )
            rdata = (_parse_zonemd(rdata_tokens, line_no),)
        elif rtype == "TLSA":
            rdata = (_parse_tlsa(rdata_tokens, line_no),)
        elif rtype in ("NS", "CNAME"):
            if len(rdata_tokens) != 1:
                raise ZoneParseError(f"{rtype} 只能有一个目标字段", line_no)
            rdata = (normalize_name(rdata_tokens[0], origin),)
        elif rtype == "MX":
            if len(rdata_tokens) != 2:
                raise ZoneParseError(
                    "MX RDATA 应为 '<优先级> <交换主机>' 两个字段", line_no
                )
            preference = rdata_tokens[0]
            if not preference.isdigit() or not 0 <= int(preference) <= 65535:
                raise ZoneParseError(
                    f"MX 优先级非法: {preference!r}", line_no
                )
            exchange = normalize_name(rdata_tokens[1], origin)
            rdata = (f"{int(preference)} {exchange}",)
        elif rtype == "TXT":
            rdata = (_parse_txt_rdata(rdata_remainder, line_no),)
        elif rtype in ("SVCB", "HTTPS"):
            rdata = (parse_svcb_rdata(rdata_remainder, origin, line_no).canonical,)
        elif rtype == "CAA":
            rdata = (parse_caa_rdata(rdata_remainder, origin, line_no).canonical,)
        else:  # A / AAAA
            if not rdata_tokens:
                raise ZoneParseError(f"{rtype} 缺少地址字段", line_no)
            rdata = tuple(
                _normalize_addr(tok, rtype, line_no) for tok in rdata_tokens
            )

        entry = collected.get(key)
        if entry is None:
            collected[key] = [ttl, set(rdata)]
        else:
            if entry[0] != ttl:
                raise ZoneParseError(
                    f"{owner} {rtype} 的同一 RRset 出现不同 TTL: {entry[0]} 与 {ttl}",
                    line_no,
                )
            entry[1].update(rdata)

    if apex is None:
        if origin is None:
            raise ZoneParseError("区域中缺少 $ORIGIN，无法确定区顶")
        apex = origin

    rrsets: dict[tuple[str, str], RRset] = {}
    for (owner, rtype), (rr_ttl, values) in collected.items():
        rrsets[(owner, rtype)] = RRset(
            owner=owner,
            rtype=rtype,
            ttl=rr_ttl,
            rdata=tuple(sorted(values)),
        )

    return Zone(origin=apex, rrsets=rrsets)
