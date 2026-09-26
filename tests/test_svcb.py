"""离线 SVCB/HTTPS 解析（app.svcb）单元测试与 HTTP 端到端测试。"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.review import ReviewError
from app.server import build_server
from app.svcb import MAX_ALIAS_HOPS, resolve_svcb
from app.zoneparse import parse_zone

SOA_NS = "@ IN SOA ns host 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\n"


def make_zone(apex: str, records: str = "") -> str:
    lines = [f"$ORIGIN {apex}", "$TTL 300", SOA_NS.rstrip("\n")]
    if records:
        lines.append(records.rstrip("\n"))
    return "\n".join(lines) + "\n"


def resolve(zones, qname, qtype="HTTPS", **extra):
    payload = {"zones": zones, "qname": qname, "qtype": qtype}
    payload.update(extra)
    return resolve_svcb(payload)


def error_of(zones, qname="www.example.com.", qtype="HTTPS", **extra):
    try:
        resolve(zones, qname, qtype, **extra)
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


class SvcbParseTests(unittest.TestCase):
    """RDATA 解析与校验（解析失败 -> 422 zone_parse_error）。"""

    def parse(self, rdata: str):
        zone = parse_zone(make_zone("example.com.", f"www IN HTTPS {rdata}\n"))
        return zone.get("www.example.com.", "HTTPS").rdata[0]

    def test_service_mode_canonical(self):
        canonical = self.parse(
            '1 . alpn="h2,h3" port=8443 ipv4hint=192.0.2.80 '
            "ipv6hint=2001:DB8::80 no-default-alpn"
        )
        self.assertEqual(
            canonical,
            "1 . alpn=h2,h3 no-default-alpn port=8443 "
            "ipv4hint=192.0.2.80 ipv6hint=2001:db8::80",
        )

    def test_alias_mode_canonical(self):
        self.assertEqual(self.parse("0 Svc"), "0 svc.example.com.")

    def test_generic_key_and_number_alias(self):
        # key3 == port、key1 == alpn；未知键 key65400 原样保留
        canonical = self.parse("1 svc key3=8443 key1=h2 key65400=abc")
        self.assertEqual(canonical, "1 svc.example.com. alpn=h2 port=8443 "
                                    "key65400=abc")

    def test_duplicate_param_key_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse("1 svc alpn=h2 alpn=h3")
        self.assertIn("参数键重复", str(ctx.exception))
        # key1 与 alpn 归一后同样冲突
        with self.assertRaises(Exception):
            self.parse("1 svc alpn=h2 key1=h3")

    def test_mandatory_missing_param_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse("1 svc mandatory=port alpn=h2")
        self.assertIn("mandatory", str(ctx.exception))

    def test_mandatory_self_reference_rejected(self):
        with self.assertRaises(Exception):
            self.parse("1 svc mandatory=mandatory alpn=h2")

    def test_no_default_alpn_without_alpn_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse("1 svc no-default-alpn")
        self.assertIn("no-default-alpn", str(ctx.exception))

    def test_bad_priority_rejected(self):
        for bad in ("abc", "-1", "65536", "1.5"):
            with self.subTest(bad=bad):
                with self.assertRaises(Exception):
                    self.parse(f"{bad} svc")

    def test_bad_port_rejected(self):
        for bad in ("65536", "-1", "http"):
            with self.subTest(bad=bad):
                with self.assertRaises(Exception):
                    self.parse(f"1 svc port={bad}")

    def test_unknown_named_key_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse("1 svc foo=bar")
        self.assertIn("未知 SVCB 参数键", str(ctx.exception))

    def test_alias_mode_with_params_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse("0 svc alpn=h2")
        self.assertIn("AliasMode", str(ctx.exception))

    def test_escaped_comma_single_alpn_id(self):
        # \, 转义的逗号不是列表分隔符
        self.assertEqual(self.parse(r"1 svc alpn=h2\,h3"),
                         "1 svc.example.com. alpn=h2\\,h3")

    def test_empty_alpn_item_rejected(self):
        with self.assertRaises(Exception):
            self.parse("1 svc alpn=h2,")

    def test_reserved_key65535_rejected(self):
        with self.assertRaises(Exception):
            self.parse("1 svc key65535=abc")


class ServiceModeTests(unittest.TestCase):
    ZONE = make_zone(
        "example.com.",
        "www IN HTTPS 1 . alpn=h2,h3 port=8443 "
        "ipv4hint=192.0.2.80 ipv6hint=2001:db8::80\n"
        "multi IN HTTPS 2 b-target alpn=h2\n"
        "multi IN HTTPS 1 z-target alpn=h2\n"
        "multi IN HTTPS 1 a-target alpn=h2\n",
    )

    def test_target_dot_falls_back_to_owner(self):
        result = resolve([self.ZONE], "www.example.com.")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["alias_hops"], 0)
        (endpoint,) = result["endpoints"]
        self.assertEqual(endpoint["target"], "www.example.com.")
        self.assertEqual(endpoint["alpn"], ["h2", "h3"])
        self.assertEqual(endpoint["port"], 8443)
        self.assertEqual(endpoint["ipv4hint"], ["192.0.2.80"])
        self.assertEqual(endpoint["ipv6hint"], ["2001:db8::80"])

    def test_endpoints_sorted_by_priority_then_target(self):
        result = resolve([self.ZONE], "multi.example.com.")
        self.assertEqual(result["status"], "ok")
        ordered = [(ep["priority"], ep["target"]) for ep in result["endpoints"]]
        self.assertEqual(
            ordered,
            [(1, "a-target.example.com."), (1, "z-target.example.com."),
             (2, "b-target.example.com.")],
        )

    def test_service_trace_records(self):
        result = resolve([self.ZONE], "www.example.com.")
        (hop,) = result["trace"]
        self.assertEqual(hop["action"], "service")
        self.assertEqual(hop["owner"], "www.example.com.")
        self.assertTrue(hop["records"][0]["usable"])
        self.assertEqual(hop["records"][0]["effective_target"],
                         "www.example.com.")


class FilteringTests(unittest.TestCase):
    ZONE = make_zone(
        "example.com.",
        "www IN HTTPS 1 . alpn=h2 mandatory=key65400 key65400=xyz\n"
        "www IN HTTPS 2 . alpn=h3\n"
        "www IN HTTPS 3 . port=8443\n",
    )

    def test_mandatory_unknown_key_filtered(self):
        # 客户端不支持 key65400 -> 含该 mandatory 的记录被过滤
        result = resolve(
            [self.ZONE], "www.example.com.",
            client_keys=["mandatory", "alpn", "port"],
        )
        self.assertEqual(result["status"], "ok")
        priorities = [ep["priority"] for ep in result["endpoints"]]
        self.assertEqual(priorities, [2, 3])
        record1 = result["trace"][0]["records"][0]
        self.assertFalse(record1["usable"])
        self.assertEqual(record1["reason"], "mandatory_unknown_key")
        self.assertEqual(record1["detail"], "key65400")

    def test_mandatory_known_key_kept(self):
        result = resolve(
            [self.ZONE], "www.example.com.",
            client_keys=["mandatory", "alpn", "port", "key65400"],
        )
        priorities = [ep["priority"] for ep in result["endpoints"]]
        self.assertEqual(priorities, [1, 2, 3])

    def test_alpn_no_overlap_filtered(self):
        # 客户端只讲 h2：h3 记录被过滤；无 alpn 的记录（默认 ALPN）保留
        result = resolve([self.ZONE], "www.example.com.",
                         client_keys=["mandatory", "alpn", "port",
                                      "key65400"],
                         client_alpn=["h2"])
        priorities = [ep["priority"] for ep in result["endpoints"]]
        self.assertEqual(priorities, [1, 3])
        record2 = result["trace"][0]["records"][1]
        self.assertEqual(record2["reason"], "alpn_no_overlap")

    def test_all_filtered_status(self):
        zone = make_zone(
            "example.com.",
            "www IN HTTPS 1 . alpn=h2\n"
            "www IN HTTPS 2 . alpn=h3\n",
        )
        result = resolve([zone], "www.example.com.", client_alpn=["h9"])
        self.assertEqual(result["status"], "filtered")
        self.assertEqual(result["endpoints"], [])

    def test_no_client_alpn_means_no_alpn_filter(self):
        result = resolve([self.ZONE], "www.example.com.",
                         client_keys=["mandatory", "alpn", "port",
                                      "key65400"])
        self.assertEqual(len(result["endpoints"]), 3)


class AliasModeTests(unittest.TestCase):
    def test_alias_chain_same_qtype(self):
        zone = make_zone(
            "example.com.",
            "www IN HTTPS 0 svc\n"
            "svc IN HTTPS 1 . alpn=h2\n"
            "svc IN SVCB 1 other port=9443\n",
        )
        result = resolve([zone], "www.example.com.", "HTTPS")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["alias_hops"], 1)
        actions = [event["action"] for event in result["trace"]]
        self.assertEqual(actions, ["alias", "service"])
        self.assertEqual(result["trace"][0]["target"], "svc.example.com.")
        # HTTPS 别名链不受 SVCB 记录影响
        self.assertEqual(result["endpoints"][0]["target"],
                         "svc.example.com.")
        self.assertEqual(result["endpoints"][0]["port"], None)

        # 同名的 SVCB 查询走 SVCB 自己的记录（www 无 SVCB -> nodata）
        result = resolve([zone], "www.example.com.", "SVCB")
        self.assertEqual(result["status"], "nodata")
        result = resolve([zone], "svc.example.com.", "SVCB")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["endpoints"][0]["port"], 9443)

    def test_cross_zone_alias(self):
        zone1 = make_zone("example.com.", "www IN HTTPS 0 svc.example.net.")
        zone2 = make_zone("example.net.",
                          "svc IN HTTPS 1 . alpn=h2")
        result = resolve([zone1, zone2], "www.example.com.")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["endpoints"][0]["target"],
                         "svc.example.net.")

    def test_alias_target_dot_unavailable(self):
        zone = make_zone("example.com.", "dead IN HTTPS 0 .")
        result = resolve([zone], "dead.example.com.")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["endpoints"], [])
        self.assertEqual(result["trace"][-1]["action"], "unavailable")

    def test_multiple_aliases_rejected(self):
        zone = make_zone(
            "example.com.",
            "www IN HTTPS 0 a\nwww IN HTTPS 0 b\n",
        )
        exc = error_of([zone])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "multiple_aliases")

    def test_alias_mixed_with_service_rejected(self):
        zone = make_zone(
            "example.com.",
            "www IN HTTPS 0 a\nwww IN HTTPS 1 b alpn=h2\n",
        )
        exc = error_of([zone])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "multiple_aliases")

    def test_alias_loop_rejected(self):
        zone = make_zone(
            "example.com.",
            "a IN HTTPS 0 b\nb IN HTTPS 0 a\n",
        )
        exc = error_of([zone], qname="a.example.com.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "alias_loop")

    def test_alias_self_loop_rejected(self):
        zone = make_zone("example.com.", "a IN HTTPS 0 a\n")
        exc = error_of([zone], qname="a.example.com.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "alias_loop")

    def _chain_zone(self, links: int) -> str:
        records = []
        for i in range(links):
            records.append(f"h{i} IN HTTPS 0 h{i + 1}")
        records.append(f"h{links} IN HTTPS 1 . alpn=h2")
        return make_zone("example.com.", "\n".join(records))

    def test_alias_hops_limit(self):
        # 恰好 8 跳可以解析
        zone = self._chain_zone(MAX_ALIAS_HOPS)
        result = resolve([zone], "h0.example.com.")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["alias_hops"], MAX_ALIAS_HOPS)

        # 第 9 跳超出上限
        zone = self._chain_zone(MAX_ALIAS_HOPS + 1)
        exc = error_of([zone], qname="h0.example.com.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "alias_too_many_hops")


class TerminalStatusTests(unittest.TestCase):
    ZONE = make_zone("example.com.", "www IN A 192.0.2.80\n")

    def test_nodata(self):
        result = resolve([self.ZONE], "www.example.com.")
        self.assertEqual(result["status"], "nodata")
        self.assertEqual(result["endpoints"], [])

    def test_unresolvable_outside_zones(self):
        result = resolve([self.ZONE], "www.elsewhere.test.")
        self.assertEqual(result["status"], "unresolvable")
        self.assertEqual(result["trace"][0]["reason"], "missing_local_zone")

    def test_unresolvable_under_undelegated_cut(self):
        zone = make_zone(
            "example.com.",
            "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n",
        )
        result = resolve([zone], "www.sub.example.com.")
        self.assertEqual(result["status"], "unresolvable")


class RequestValidationTests(unittest.TestCase):
    ZONE = make_zone("example.com.", "www IN HTTPS 1 . alpn=h2\n")

    def test_bad_qtype(self):
        exc = error_of([self.ZONE], qtype="A")
        self.assertEqual(exc.status, 400)

    def test_bad_qname(self):
        exc = error_of([self.ZONE], qname="")
        self.assertEqual(exc.status, 400)
        exc = error_of([self.ZONE], qname="bad..name.")
        self.assertEqual(exc.status, 400)

    def test_bad_zones(self):
        exc = error_of([], qname="www.example.com.")
        self.assertEqual(exc.status, 400)
        exc = error_of([""], qname="www.example.com.")
        self.assertEqual(exc.status, 400)

    def test_zone_parse_error_is_422(self):
        exc = error_of(["$ORIGIN broken.\nwww IN HTTPS 1 svc foo=bar\n"],
                       qname="www.broken.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "zone_parse_error")

    def test_bad_client_keys(self):
        exc = error_of([self.ZONE], client_keys=["not a key!"])
        self.assertEqual(exc.status, 400)
        exc = error_of([self.ZONE], client_keys="alpn")
        self.assertEqual(exc.status, 400)

    def test_bad_client_alpn(self):
        exc = error_of([self.ZONE], client_alpn=["h2", ""])
        self.assertEqual(exc.status, 400)

    def test_default_client_keys_accept_known_mandatory(self):
        zone = make_zone(
            "example.com.",
            "www IN HTTPS 1 . alpn=h2 mandatory=alpn,port port=443\n",
        )
        result = resolve([zone], "www.example.com.")
        self.assertEqual(result["status"], "ok")

    def test_qname_case_and_trailing_dot_normalized(self):
        r1 = resolve([self.ZONE], "WWW.Example.COM")
        r2 = resolve([self.ZONE], "www.example.com.")
        self.assertEqual(r1["qname"], "www.example.com.")
        self.assertEqual(
            json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True)
        )

    def test_same_input_stable_output(self):
        r1 = resolve([self.ZONE], "www.example.com.")
        r2 = resolve([self.ZONE], "www.example.com.")
        self.assertEqual(
            json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True)
        )


def _request(url: str, payload: dict | None = None, method: str = "POST"):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class SvcbApiTests(unittest.TestCase):
    ZONE = make_zone(
        "example.com.",
        "www IN HTTPS 0 svc\n"
        "svc IN HTTPS 1 . alpn=h2,h3 port=8443 "
        "ipv4hint=192.0.2.80 ipv6hint=2001:db8::80\n"
        "svc IN HTTPS 2 backup alpn=h2\n",
    )

    @classmethod
    def setUpClass(cls):
        cls.server = build_server("127.0.0.1", 0, ":memory:")
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _resolve(self, **overrides):
        payload = {
            "zones": [self.ZONE],
            "qname": "www.example.com.",
            "qtype": "HTTPS",
            "client_keys": ["mandatory", "alpn", "no-default-alpn",
                            "port", "ipv4hint", "ipv6hint"],
            "client_alpn": ["h2"],
        }
        payload.update(overrides)
        return _request(self.base + "/api/svcb/resolve", payload)

    def test_resolve_over_http(self):
        status, body = self._resolve()
        self.assertEqual(status, 200, body)
        svcb = body["svcb"]
        self.assertEqual(svcb["status"], "ok")
        self.assertEqual(svcb["alias_hops"], 1)
        self.assertEqual(len(svcb["endpoints"]), 2)
        self.assertEqual(svcb["endpoints"][0]["target"],
                         "svc.example.com.")
        self.assertEqual([e["action"] for e in svcb["trace"]],
                         ["alias", "service"])

    def test_terminal_statuses_are_200(self):
        status, body = self._resolve(qname="absent.example.com.")
        self.assertEqual(status, 200)
        self.assertEqual(body["svcb"]["status"], "nodata")

    def test_record_error_is_422(self):
        bad_zone = make_zone("example.com.",
                             "www IN HTTPS 1 svc mandatory=port alpn=h2\n")
        status, body = self._resolve(zones=[bad_zone])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "zone_parse_error")

    def test_alias_loop_is_422(self):
        loop_zone = make_zone("example.com.",
                              "a IN HTTPS 0 b\nb IN HTTPS 0 a\n")
        status, body = self._resolve(zones=[loop_zone],
                                     qname="a.example.com.")
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "alias_loop")

    def test_request_format_error_is_400(self):
        status, body = self._resolve(qtype="TXT")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
