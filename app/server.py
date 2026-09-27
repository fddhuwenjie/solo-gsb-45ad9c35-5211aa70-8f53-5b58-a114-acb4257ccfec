"""基于标准库 ThreadingHTTPServer 的 DNS 区域变更审查与离线 SPF 求值 HTTP API。

路由：
- ``POST /api/reviews``            执行审查（不落库，返回审查指纹）
- ``POST /api/reviews/confirm``    审查并保存规范差异与复演请求
- ``POST /api/spf/evaluate``       基于本地区域文本离线求值 SPF
- ``POST /api/dnssec/nsec-proof``  校验 NSEC 链并判定 NODATA/NXDOMAIN 否认证明
- ``POST /api/svcb/resolve``       离线解析 SVCB/HTTPS（AliasMode/ServiceMode）
- ``POST /api/caa/authorize``      离线 CAA（RFC 8659）签发授权判定
- ``POST /api/zonemd/verify``      校验区顶 ZONEMD 区域摘要（RFC 8976 Simple）
- ``POST /api/tlsa/verify``        离线 TLSA（DANE）记录校验（RFC 6698，仅 usage=3）
- ``POST /api/axfr/inspect``       离线检查 Base64 编码的 TCP AXFR 响应流
- ``POST /api/dns/delegation-trace`` 离线校验迭代解析轨迹（转介/胶水/地址子查询）
- ``POST /api/dns/cache/replay``   离线复演带 TTL 衰减的解析缓存（正/负缓存、CNAME 链）
- ``GET  /api/reviews``            已确认审查列表
- ``GET  /api/reviews/<id>``       读取已确认审查（含复演请求）
- ``GET  /healthz``                健康检查
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .nsec import verify_nsec_proof
from .axfr import inspect_axfr
from .delegation import trace_delegation
from .dnscache import replay_cache
from .review import ReviewError, perform_review
from .spf import evaluate_spf
from .storage import Store
from .svcb import resolve_svcb
from .caa import authorize_caa
from .tlsa import verify_tlsa
from .zonemd import verify_zonemd

MAX_BODY_BYTES = 2 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "DnsZoneReview/1.0"

    # ---- 基础收发 ----
    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ReviewError("invalid_request", "缺少 JSON 请求体", 400)
        if length > MAX_BODY_BYTES:
            raise ReviewError(
                "request_too_large",
                f"请求体超过 {MAX_BODY_BYTES} 字节上限",
                413,
            )
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReviewError("invalid_json", f"请求体不是合法 JSON: {exc}",
                              400) from exc
        if not isinstance(payload, dict):
            raise ReviewError("invalid_request", "请求体必须是 JSON 对象",
                              400)
        return payload

    def _error(self, exc: ReviewError) -> None:
        self._send_json(exc.status, exc.to_body())

    # ---- 路由 ----
    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        path = urlsplit(self.path).path
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/reviews":
            self._send_json(200, {"reviews": self.server.store.list_reviews()})
            return
        if path.startswith("/api/reviews/"):
            review_id = path.rsplit("/", 1)[-1]
            row = self.server.store.get_review(review_id)
            if row is None:
                self._error(ReviewError("not_found", "审查记录不存在", 404))
                return
            self._send_json(200, row)
            return
        self._error(ReviewError("not_found", "未知路径", 404))

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/api/reviews":
            self._handle_review(confirm=False)
        elif path == "/api/reviews/confirm":
            self._handle_review(confirm=True)
        elif path == "/api/spf/evaluate":
            self._handle_spf_evaluate()
        elif path == "/api/dnssec/nsec-proof":
            self._handle_nsec_proof()
        elif path == "/api/svcb/resolve":
            self._handle_svcb_resolve()
        elif path == "/api/caa/authorize":
            self._handle_caa_authorize()
        elif path == "/api/zonemd/verify":
            self._handle_zonemd_verify()
        elif path == "/api/tlsa/verify":
            self._handle_tlsa_verify()
        elif path == "/api/axfr/inspect":
            self._handle_axfr_inspect()
        elif path == "/api/dns/delegation-trace":
            self._handle_delegation_trace()
        elif path == "/api/dns/cache/replay":
            self._handle_cache_replay()
        else:
            self._error(ReviewError("not_found", "未知路径", 404))

    def _handle_review(self, confirm: bool) -> None:
        try:
            payload = self._read_json()
            result = perform_review(payload)
        except ReviewError as exc:
            self._error(exc)
            return

        if not confirm:
            self._send_json(200, {"confirmed": False, "review": result})
            return

        if not result["safe"]:
            self._error(
                ReviewError(
                    "unsafe_change",
                    "不存在安全发布顺序：不确认、不保存、不给出发布计划",
                    409,
                    result["conflicts"],
                )
            )
            return

        review_id = self.server.store.save_review(payload, result)
        self._send_json(
            201,
            {"confirmed": True, "id": review_id, "review": result},
        )

    def _handle_spf_evaluate(self) -> None:
        try:
            payload = self._read_json()
            result = evaluate_spf(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # SPF 的 permerror/temperror/none 等都是 200 下的求值终态，
        # 只有请求格式与区域解析问题才走 _error
        self._send_json(200, {"spf": result})

    def _handle_nsec_proof(self) -> None:
        try:
            payload = self._read_json()
            result = verify_nsec_proof(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # valid=true/false 都是 200 下的证明结论；
        # 只有请求格式（400）与 NSEC 链错误（422）走 _error
        self._send_json(200, {"nsec_proof": result})

    def _handle_svcb_resolve(self) -> None:
        try:
            payload = self._read_json()
            result = resolve_svcb(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # ok/unavailable/nodata/filtered/unresolvable 都是 200 下的解析
        # 终态；只有请求格式（400）与记录/别名链错误（422）走 _error
        self._send_json(200, {"svcb": result})

    def _handle_caa_authorize(self) -> None:
        try:
            payload = self._read_json()
            result = authorize_caa(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # allowed/denied/indeterminate 都是 200 下的判定终态；
        # 只有请求格式（400）、区域解析（422）与 CNAME 环/超跳（422）走 _error
        self._send_json(200, {"caa": result})

    def _handle_zonemd_verify(self) -> None:
        try:
            payload = self._read_json()
            result = verify_zonemd(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # valid/invalid/unsupported 都是 200 下的校验终态；
        # 只有请求格式（400）与区域解析（422）走 _error
        self._send_json(200, {"zonemd": result})

    def _handle_tlsa_verify(self) -> None:
        try:
            payload = self._read_json()
            result = verify_tlsa(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # matched/mismatched/indeterminate/invalid/none/unsupported
        # 都是 200 下的校验终态；只有请求格式（400，含 PEM 证书解析
        # 失败）与区域解析（422，含 TLSA 字段/十六进制错误）走 _error
        self._send_json(200, {"tlsa": result})

    def _handle_axfr_inspect(self) -> None:
        try:
            payload = self._read_json()
            result = inspect_axfr(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # complete/incomplete/invalid 都是 200 下的检查终态；
        # 只有请求格式（400）与流解析错误（422，含指针成环/越界、
        # 帧截断、RDATA 长度不符）走 _error
        self._send_json(200, {"axfr": result})

    def _handle_delegation_trace(self) -> None:
        try:
            payload = self._read_json()
            result = trace_delegation(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # valid/invalid 都是 200 下的校验终态；
        # 只有请求格式（400）与记录内容错误（422）走 _error
        self._send_json(200, {"delegation_trace": result})

    def _handle_cache_replay(self) -> None:
        try:
            payload = self._read_json()
            result = replay_cache(payload)
        except ReviewError as exc:
            self._error(exc)
            return
        # hit/miss 都是 200 下的复演终态；
        # 只有请求格式（400）与离线响应内容错误（422）走 _error
        self._send_json(200, {"cache_replay": result})

    def log_message(self, fmt: str, *args) -> None:
        # ThreadingHTTPServer 下把日志写到 stderr 即可
        import sys
        sys.stderr.write(
            "[%s] %s\n" % (self.log_date_time_string(), fmt % args)
        )


def build_server(host: str, port: int, db_path: str) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.store = Store(db_path)
    return server


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    db_path = os.environ.get("DATABASE", "/data/reviews.db")
    server = build_server(host, port, db_path)
    print(f"DNS 区域变更审查 API 监听 http://{host}:{port}  数据库={db_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
