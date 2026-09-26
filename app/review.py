"""审查编排：把解析、不变量校验、RFC 1982 序列号与安全规划串起来。"""

from __future__ import annotations

from .digest import diff_digest, review_digest, sha256_hex
from .planner import plan_changes
from .serial import SerialError, check_zone_serial
from .validity import validate_zone
from .zoneparse import ZoneParseError, parse_zone


class ReviewError(Exception):
    """审查请求级错误，携带 HTTP 状态码与错误码。"""

    def __init__(self, code: str, message: str, status: int = 400,
                 details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details or []

    def to_body(self) -> dict:
        body = {"error": {"code": self.code, "message": self.message}}
        if self.details:
            body["error"]["details"] = self.details
        return body


def _parse_side(text: str, label: str, default_ttl: int | None):
    if not isinstance(text, str) or not text.strip():
        raise ReviewError(
            "invalid_request", f"{label} 区域文本必须是非空字符串", 400
        )
    try:
        return parse_zone(text, default_ttl=default_ttl)
    except ZoneParseError as exc:
        raise ReviewError(
            "zone_parse_error",
            f"{label} 区域解析失败: {exc}",
            422,
            [{"side": label, "message": str(exc)}],
        ) from exc


def perform_review(payload: dict) -> dict:
    """执行一次审查，返回可直接序列化给客户端的结果字典。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    old_text = payload.get("old_zone")
    new_text = payload.get("new_zone")
    default_ttl = payload.get("default_ttl")
    if default_ttl is not None:
        if not isinstance(default_ttl, int) or not 0 <= default_ttl < 2**31:
            raise ReviewError(
                "invalid_request", "default_ttl 必须是 0..2^31-1 的整数", 400
            )

    old = _parse_side(old_text, "old", default_ttl)
    new = _parse_side(new_text, "new", default_ttl)

    if old.origin != new.origin:
        raise ReviewError(
            "origin_mismatch",
            f"两侧区域源点不一致: {old.origin} != {new.origin}",
            422,
            [{"old_origin": old.origin, "new_origin": new.origin}],
        )
    apex = old.origin

    # 两端点必须各自合法；若新区域自身就不合法，审查直接失败
    old_conflicts = validate_zone(old, apex)
    new_conflicts = validate_zone(new, apex)
    if old_conflicts:
        raise ReviewError(
            "invalid_old_zone",
            "旧区域不满足发布不变量，无法作为变更基线",
            422,
            old_conflicts,
        )
    if new_conflicts:
        raise ReviewError(
            "invalid_new_zone",
            "新区域不满足发布不变量，不存在能到达该目标的安全顺序",
            422,
            new_conflicts,
        )

    old_soa = old.get(apex, "SOA")
    new_soa = new.get(apex, "SOA")
    old_serial = int(old_soa.rdata[0][2])
    new_serial = int(new_soa.rdata[0][2])
    serial_block = None
    try:
        serial_status = check_zone_serial(old_serial, new_serial)
    except SerialError as exc:
        serial_status = "undefined"
        serial_block = str(exc)

    if serial_status != "ok":
        if serial_status == "unchanged":
            message = "新旧 SOA 序列号相同，未按 RFC 1982 严格递增"
        elif serial_status == "undefined":
            message = serial_block or "序列号差值为 2^31，RFC 1982 未定义"
        else:
            message = (
                f"SOA 序列号回退: {new_serial} 早于 {old_serial} "
                "（RFC 1982 32 位序列号空间）"
            )
        raise ReviewError(
            f"serial_{serial_status}",
            message,
            422,
            [{
                "old_serial": old_serial,
                "new_serial": new_serial,
                "rfc": "RFC 1982",
            }],
        )

    plan_result = plan_changes(old, new)

    canonical_old = old.canonical_text()
    canonical_new = new.canonical_text()
    fingerprint_payload = {
        "origin": apex,
        "old_text": canonical_old,
        "new_text": canonical_new,
        "old_serial": old_serial,
        "new_serial": new_serial,
        "serial_status": serial_status,
        "diff": plan_result["diff"],
        "safe": plan_result["safe"],
        "conflicts": plan_result["conflicts"],
        "plan": plan_result["plan"],
    }

    return {
        "origin": apex,
        "serial": {
            "old": old_serial,
            "new": new_serial,
            "status": serial_status,
            "detail": serial_block,
        },
        "canonical": {
            "old": canonical_old,
            "new": canonical_new,
            "old_sha256": sha256_hex(canonical_old),
            "new_sha256": sha256_hex(canonical_new),
        },
        "diff": plan_result["diff"],
        "diff_sha256": diff_digest(plan_result["diff"]),
        "safe": plan_result["safe"],
        "conflicts": plan_result["conflicts"],
        "plan": plan_result["plan"],
        "digest": review_digest(fingerprint_payload),
    }
