"""ZONEMD 区域摘要校验（app.zonemd）单元测试与 HTTP 端到端测试。

已知答案向量来自 RFC 8976 Appendix A（A.1 Simple EXAMPLE Zone、
A.3 EXAMPLE Zone with Multiple Digests）。
"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.review import ReviewError, perform_review
from app.server import build_server
from app.zonemd import verify_zonemd
from app.zoneparse import parse_zone

# RFC 8976 Appendix A.1：SOA + NS + 胶水 + ZONEMD（SHA-384）
A1_DIGEST = (
    "c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3"
    "a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c"
)
A1_ZONE = f"""$ORIGIN example.
$TTL 86400
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ IN NS ns1
@ IN NS ns2
@ IN ZONEMD 2018031900 1 1 {A1_DIGEST}
ns1 3600 IN A 203.0.113.63
ns2 3600 IN AAAA 2001:db8::63
"""

# RFC 8976 Appendix A.3：SHA-384 + SHA-512 + 私有范围 scheme/算法
A3_SHA384 = (
    "62e6cf51b02e54b9b5f967d547ce43136792901f9f88e637"
    "493daaf401c92c279dd10f0edb1c56f8080211f8480ee306"
)
A3_SHA512 = (
    "08cfa1115c7b948c4163a901270395ea226a930cd2cbcf2f"
    "a9a5e6eb85f37c8a4e114d884e66f176eab121cb02db7d65"
    "2e0cc4827e7a3204f166b47e5613fd27"
)
A3_ZONE = f"""$ORIGIN example.
$TTL 86400
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ IN NS ns1.example.
@ IN NS ns2.example.
@ IN ZONEMD 2018031900 1 1 {A3_SHA384}
@ IN ZONEMD 2018031900 1 2 {A3_SHA512}
@ IN ZONEMD 2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee
@ IN ZONEMD 2018031900 241 1 e1846540e33a9e4189792d18d5d131f605fc283e
ns1 3600 IN A 203.0.113.63
ns2 86400 IN TXT "This example has multiple digests"
NS2.EXAMPLE. 3600 IN AAAA 2001:db8::63
"""


def error_of(payload):
    try:
        verify_zonemd(payload)
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


def records_by_key(result):
    return {
        (rec["scheme"], rec["hash_algorithm"]): rec
        for rec in result["records"]
    }


class RfcVectorTests(unittest.TestCase):
    """RFC 8976 Appendix A 官方向量。"""

    def test_a1_simple_zone_sha384(self):
        result = verify_zonemd({"zone": A1_ZONE})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["zone_origin"], "example.")
        self.assertEqual(result["soa_serial"], 2018031900)
        self.assertEqual(len(result["records"]), 1)
        rec = result["records"][0]
        self.assertTrue(rec["supported"])
        self.assertTrue(rec["matched"])
        self.assertEqual(rec["scheme_name"], "simple")
        self.assertEqual(rec["hash_name"], "sha384")
        self.assertEqual(rec["expected"], A1_DIGEST)
        self.assertEqual(rec["computed"], A1_DIGEST)

    def test_a3_multiple_digests(self):
        result = verify_zonemd({"zone": A3_ZONE})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(len(result["records"]), 4)
        by_key = records_by_key(result)
        sha384 = by_key[(1, 1)]
        sha512 = by_key[(1, 2)]
        self.assertTrue(sha384["matched"])
        self.assertEqual(sha384["computed"], A3_SHA384)
        self.assertTrue(sha512["matched"])
        self.assertEqual(sha512["hash_name"], "sha512")
        self.assertEqual(sha512["computed"], A3_SHA512)
        # 私有范围算法/ scheme：标为 unsupported，不参与结论
        private_alg = by_key[(1, 240)]
        private_scheme = by_key[(241, 1)]
        self.assertFalse(private_alg["supported"])
        self.assertFalse(private_alg["matched"])
        self.assertIsNone(private_alg["computed"])
        self.assertFalse(private_scheme["supported"])
        self.assertIsNone(private_scheme["computed"])


class CanonicalizationTests(unittest.TestCase):
    """重排、重复与等价文本不得改变摘要。"""

    def test_reorder_duplicate_equivalent_text_same_digest(self):
        # 记录乱序 + 重复 RDATA + 相对名/@ + 时长单位 + digest 跨记号括号续行
        variant = f"""$TTL 24h
$ORIGIN example.
ns2 1h IN AAAA 2001:0db8:0000:0000:0000:0000:0000:0063
ns1 3600 IN A 203.0.113.63
ns1 3600 IN A 203.0.113.63
@ IN ZONEMD 2018031900 1 1 (
    c68090d90a7aed716bc459f9340e3d7c
    1370d4d24b7e2fc3a1ddc0b9a87153b9
    a9713b3c9ae5cc27777f98b8e730044c )
@ IN NS ns2
@ IN NS ns1
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
"""
        result = verify_zonemd({"zone": variant})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["records"][0]["computed"], A1_DIGEST)
        self.assertTrue(result["records"][0]["matched"])

    def test_same_input_stable(self):
        r1 = verify_zonemd({"zone": A3_ZONE})
        r2 = verify_zonemd({"zone": A3_ZONE})
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(r2, sort_keys=True))

    def test_trace_ordered_and_excludes_zonemd(self):
        result = verify_zonemd({"zone": A1_ZONE})
        trace = result["trace"]
        self.assertEqual([entry["seq"] for entry in trace],
                         list(range(1, len(trace) + 1)))
        self.assertNotIn("ZONEMD", {entry["type"] for entry in trace})
        # 规范序：区顶 NS（RDATA 按 wire 序）-> 区顶 SOA -> ns1 A -> ns2 AAAA
        self.assertEqual(
            [(entry["owner"], entry["type"]) for entry in trace],
            [
                ("example.", "NS"),
                ("example.", "NS"),
                ("example.", "SOA"),
                ("ns1.example.", "A"),
                ("ns2.example.", "AAAA"),
            ],
        )
        self.assertEqual(trace[0]["rdata"], "ns1.example.")
        self.assertEqual(trace[1]["rdata"], "ns2.example.")
        self.assertEqual(trace[0]["ttl"], 86400)
        self.assertEqual(trace[3]["ttl"], 3600)
        self.assertEqual(
            trace[2]["rdata"],
            "ns1.example. admin.example. 2018031900 1800 900 604800 86400",
        )


class VerdictTests(unittest.TestCase):
    """serial / digest 长度 / 摘要匹配与 valid/invalid/unsupported 结论。"""

    def test_serial_mismatch_invalid(self):
        zone = A1_ZONE.replace(
            f"@ IN ZONEMD 2018031900 1 1 {A1_DIGEST}",
            f"@ IN ZONEMD 2018031901 1 1 {A1_DIGEST}",
        )
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "invalid")
        rec = result["records"][0]
        self.assertTrue(rec["supported"])
        self.assertFalse(rec["matched"])
        self.assertIn("serial", rec["reason"])
        # computed 仍然给出（供排查）
        self.assertEqual(rec["computed"], A1_DIGEST)

    def test_digest_mismatch_invalid(self):
        zone = A1_ZONE.replace(A1_DIGEST, "0" * 96)
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "invalid")
        rec = result["records"][0]
        self.assertFalse(rec["matched"])
        self.assertEqual(rec["expected"], "0" * 96)
        self.assertEqual(rec["computed"], A1_DIGEST)

    def test_digest_length_mismatch_invalid(self):
        # SHA-384 要求 48 字节；给 64 字节（SHA-512 长度）不匹配
        zone = A1_ZONE.replace(A1_DIGEST, "ab" * 64)
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "invalid")
        self.assertIn("长度", result["records"][0]["reason"])
        # 过短（< 12 字节）同样不匹配
        zone = A1_ZONE.replace(A1_DIGEST, "ab" * 8)
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "invalid")
        self.assertIn("长度", result["records"][0]["reason"])

    def test_sha512_single_record_valid(self):
        # 只保留 A.3 的 SHA-512 记录
        zone = f"""$ORIGIN example.
$TTL 86400
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ IN NS ns1.example.
@ IN NS ns2.example.
@ IN ZONEMD 2018031900 1 2 {A3_SHA512}
ns1 3600 IN A 203.0.113.63
ns2 86400 IN TXT "This example has multiple digests"
NS2.EXAMPLE. 3600 IN AAAA 2001:db8::63
"""
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["records"][0]["hash_name"], "sha512")

    def test_one_supported_match_is_enough(self):
        # 一条不匹配（serial 错）+ 一条匹配 -> valid
        zone = A1_ZONE.replace(
            f"@ IN ZONEMD 2018031900 1 1 {A1_DIGEST}",
            f"@ IN ZONEMD 2018031901 1 1 {A1_DIGEST}\n"
            f"@ IN ZONEMD 2018031900 1 1 {A1_DIGEST}",
        )
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "valid")
        self.assertEqual(len(result["records"]), 2)

    def test_all_unsupported(self):
        zone = """$ORIGIN example.
$TTL 86400
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ IN NS ns1
@ IN ZONEMD 2018031900 1 240 e2d523f654b9422a96c5a8f44607bbee
@ IN ZONEMD 2018031900 241 1 e1846540e33a9e4189792d18d5d131f605fc283e
ns1 3600 IN A 203.0.113.63
"""
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(len(result["records"]), 2)
        for rec in result["records"]:
            self.assertFalse(rec["supported"])
            self.assertFalse(rec["matched"])
            self.assertIsNone(rec["computed"])
        reasons = {rec["reason"] for rec in result["records"]}
        self.assertTrue(any("scheme" in r for r in reasons))
        self.assertTrue(any("算法" in r for r in reasons))

    def test_no_zonemd_unsupported(self):
        zone = """$ORIGIN example.
$TTL 86400
@ IN SOA ns1 admin 2018031900 1800 900 604800 86400
@ IN NS ns1
ns1 3600 IN A 203.0.113.63
"""
        result = verify_zonemd({"zone": zone})
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["records"], [])
        self.assertGreaterEqual(len(result["trace"]), 3)


class RichZoneTests(unittest.TestCase):
    """MX/TXT/CNAME/SVCB/HTTPS/CAA 等类型进入摘要的往返一致性。"""

    RICH_PREFIX = """$ORIGIN example.com.
$TTL 300
@ IN SOA ns1 admin 2024010100 600 300 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.10
@ IN MX 10 mail
mail IN A 192.0.2.50
alias IN CNAME www
www IN A 192.0.2.80
www IN TXT "hello world"
@ IN CAA 0 issue "letsencrypt.org"
_svc IN SVCB 1 www alpn=h2,h3 port=8443 ipv4hint=192.0.2.80
@ IN HTTPS 0 .
"""

    def _zone_with_digest(self, digest: str) -> str:
        return (
            self.RICH_PREFIX
            + f'@ IN ZONEMD 2024010100 1 1 {digest}\n'
        )

    def test_roundtrip_all_supported_types(self):
        placeholder = self._zone_with_digest("00" * 48)
        computed = verify_zonemd({"zone": placeholder})["records"][0][
            "computed"
        ]
        self.assertIsNotNone(computed)
        result = verify_zonemd({"zone": self._zone_with_digest(computed)})
        self.assertEqual(result["status"], "valid")
        self.assertTrue(result["records"][0]["matched"])
        types_in_trace = {entry["type"] for entry in result["trace"]}
        self.assertEqual(
            types_in_trace,
            {"SOA", "NS", "A", "MX", "CNAME", "TXT", "CAA", "SVCB",
             "HTTPS"},
        )

    def test_equivalent_svcb_caa_text_same_digest(self):
        placeholder = self._zone_with_digest("00" * 48)
        computed = verify_zonemd({"zone": placeholder})["records"][0][
            "computed"
        ]
        # 等价写法：SVCB 参数乱序/key3≡port、CAA 参数乱序、TTL 单位、大写名
        variant = """$ORIGIN example.com.
$TTL 5m
@ IN SOA ns1 admin 2024010100 600 300 86400 300
@ IN NS ns1
NS1 IN A 192.0.2.10
@ IN MX 10 MAIL
mail IN A 192.0.2.50
alias IN CNAME www
www IN A 192.0.2.80
www IN TXT "hello world"
@ IN CAA 0 ISSUE "letsencrypt.org"
_svc IN SVCB 1 www key3=8443 ipv4hint=192.0.2.80 alpn=h2,h3
@ IN HTTPS 0 .
"""
        result = verify_zonemd(
            {"zone": variant + f'@ IN ZONEMD 2024010100 1 1 {"00" * 48}\n'}
        )
        self.assertEqual(result["records"][0]["computed"], computed)


class RequestValidationTests(unittest.TestCase):
    def test_missing_or_empty_zone_400(self):
        exc = error_of({})
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_request")
        exc = error_of({"zone": 42})
        self.assertEqual(exc.status, 400)
        exc = error_of({"zone": "   "})
        self.assertEqual(exc.status, 400)

    def test_zone_parse_error_422(self):
        exc = error_of({"zone": "$ORIGIN broken.\n@ IN TXT unclosed\""})
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "zone_parse_error")

    def test_missing_soa_422(self):
        exc = error_of({"zone": "$ORIGIN example.\n$TTL 300\n@ IN NS ns1\n"})
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "missing_soa")

    def test_zonemd_not_at_apex_422(self):
        exc = error_of({
            "zone": "$ORIGIN example.\n$TTL 300\n"
                    "@ IN SOA ns1 a 1 1h 1h 1w 1h\n"
                    "@ IN NS ns1\nsub IN ZONEMD 1 1 1 " + "ab" * 48 + "\n"
        })
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "zone_parse_error")
        self.assertIn("区顶", str(exc))

    def test_bad_digest_hex_422(self):
        for bad in ("xyz", "abc", "", "gg" * 48):
            exc = error_of({
                "zone": "$ORIGIN example.\n$TTL 300\n"
                        "@ IN SOA ns1 a 1 1h 1h 1w 1h\n"
                        "@ IN NS ns1\n@ IN ZONEMD 1 1 1 " + bad + "\n"
            })
            self.assertEqual(exc.status, 422, bad)
            self.assertEqual(exc.code, "zone_parse_error")

    def test_field_range_422(self):
        base = ("$ORIGIN example.\n$TTL 300\n"
                "@ IN SOA ns1 a 1 1h 1h 1w 1h\n@ IN NS ns1\n")
        for rdata in ("4294967296 1 1 aabb", "1 256 1 aabb",
                      "1 1 256 aabb", "1 1 1"):
            exc = error_of({"zone": base + f"@ IN ZONEMD {rdata}\n"})
            self.assertEqual(exc.status, 422, rdata)


class ParserIntegrationTests(unittest.TestCase):
    """ZONEMD 进入共享解析器后的行为。"""

    def test_zonemd_canonical_and_dedup(self):
        zone = parse_zone(
            "$ORIGIN example.\n$TTL 300\n"
            "@ IN SOA ns1 a 1 1h 1h 1w 1h\n@ IN NS ns1\n"
            "@ IN ZONEMD 1 1 1 AABB\n"
            "@ IN ZONEMD 1 1 1 aabb\n"
            "@ IN ZONEMD 1 1 2 ccdd\n"
        )
        rrset = zone.get("example.", "ZONEMD")
        self.assertIsNotNone(rrset)
        # 大小写等价重复去重；digest 统一小写
        self.assertEqual(
            rrset.rdata,
            ("1 1 1 aabb", "1 1 2 ccdd"),
        )

    def test_review_endpoint_accepts_zonemd(self):
        old = ("$ORIGIN lab.test.\n$TTL 300\n"
               "@ IN SOA ns1 admin 1 600 300 86400 300\n@ IN NS ns1\n"
               "ns1 IN A 192.0.2.10\n")
        new = ("$ORIGIN lab.test.\n$TTL 300\n"
               "@ IN SOA ns1 admin 2 600 300 86400 300\n@ IN NS ns1\n"
               "ns1 IN A 192.0.2.10\n"
               "@ IN ZONEMD 2 1 1 " + "ab" * 48 + "\n")
        result = perform_review({"old_zone": old, "new_zone": new})
        self.assertTrue(result["safe"])
        added = {
            (entry["new"]["owner"], entry["new"]["type"])
            for entry in result["diff"]
            if entry["action"] == "add"
        }
        self.assertIn(("lab.test.", "ZONEMD"), added)


class ZonemdApiTests(unittest.TestCase):
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

    def _post(self, path, payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_valid_over_http(self):
        status, body = self._post("/api/zonemd/verify", {"zone": A1_ZONE})
        self.assertEqual(status, 200, body)
        zonemd = body["zonemd"]
        self.assertEqual(zonemd["status"], "valid")
        self.assertTrue(zonemd["records"][0]["matched"])
        self.assertEqual(zonemd["records"][0]["computed"], A1_DIGEST)
        self.assertTrue(zonemd["trace"])

    def test_invalid_and_unsupported_are_200(self):
        status, body = self._post(
            "/api/zonemd/verify",
            {"zone": A1_ZONE.replace(A1_DIGEST, "0" * 96)},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["zonemd"]["status"], "invalid")

        status, body = self._post(
            "/api/zonemd/verify",
            {"zone": "$ORIGIN example.\n$TTL 300\n"
                     "@ IN SOA ns1 a 1 1h 1h 1w 1h\n@ IN NS ns1\n"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["zonemd"]["status"], "unsupported")

    def test_errors_over_http(self):
        status, body = self._post("/api/zonemd/verify", {"zone": ""})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

        status, body = self._post(
            "/api/zonemd/verify",
            {"zone": "$ORIGIN broken.\n@ IN TXT unclosed\""},
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "zone_parse_error")


if __name__ == "__main__":
    unittest.main()
