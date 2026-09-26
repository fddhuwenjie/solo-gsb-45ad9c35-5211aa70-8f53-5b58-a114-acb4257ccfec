"""RFC 1982 序列号算术（32 位序列号空间，序列号长度 SERIAL_BITS=32）。

DNS SOA serial 使用环绕的无符号 32 位整数。判断两个序列号的先后，
不能直接用整数大小，而要按 RFC 1982 §3.2 的规则：两值之差落在
(0, 2^(N-1)) 时前者才“小于”后者；差恰为 2^(N-1) 时结果未定义。
"""

from __future__ import annotations

SERIAL_BITS = 32
MOD = 1 << SERIAL_BITS
HALF = 1 << (SERIAL_BITS - 1)


class SerialError(ValueError):
    """序列号非法或不可比较。"""


def parse_serial(token: str) -> int:
    token = token.strip()
    try:
        value = int(token)
    except ValueError as exc:
        raise SerialError(f"序列号不是整数: {token!r}") from exc
    if not 0 <= value < MOD:
        raise SerialError(f"序列号超出 32 位无符号范围: {value}")
    return value


def compare(i1: int, i2: int) -> int:
    """比较两个 32 位序列号。

    返回 -1 / 0 / 1 表示 i1 早于 / 等于 / 晚于 i2；
    差值恰好为 2^31 时结果未定义，抛出 SerialError。
    """
    if i1 == i2:
        return 0
    diff = (i2 - i1) % MOD
    if 0 < diff < HALF:
        return -1  # i1 < i2
    if HALF < diff < MOD:
        return 1  # i1 > i2
    raise SerialError(
        f"序列号 {i1} 与 {i2} 相差恰好 2^31，按 RFC 1982 结果未定义"
    )


def add(serial: int, n: int = 1) -> int:
    """序列号加法（RFC 1982 §3.1），n 不得超过 2^(SERIAL_BITS-1)-1。"""
    if not 0 <= n < HALF:
        raise SerialError(f"序列号加法增量越界: {n}")
    return (serial + n) % MOD


def check_zone_serial(old_serial: int, new_serial: int) -> str:
    """审查新旧 SOA 序列号，返回状态码。

    - ``ok``：新序列号严格更新；
    - ``unchanged``：两者相等；
    - ``regressed``：新序列号回退；
    - ``undefined``：差值为 2^31，RFC 1982 未定义。
    """
    cmp_result = compare(old_serial, new_serial)
    if cmp_result < 0:
        return "ok"
    if cmp_result == 0:
        return "unchanged"
    return "regressed"
