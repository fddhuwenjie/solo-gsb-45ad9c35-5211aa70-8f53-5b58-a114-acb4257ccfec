"""HTTP API 端到端测试（线程内起真实服务器）。"""

import json
import threading
import unittest
import urllib.request
import urllib.error

from app.server import build_server

OLD = """$ORIGIN lab.test.
$TTL 300
@ IN SOA ns1 admin 2024010100 600 300 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.10
old IN A 192.0.2.20
"""

NEW = """$ORIGIN lab.test.
$TTL 300
@ IN SOA ns1 admin 2024010101 600 300 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.10
new IN A 192.0.2.30
"""


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


class ApiTests(unittest.TestCase):
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

    def test_health(self):
        status, body = _request(self.base + "/healthz", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_review_then_confirm_persists_replay(self):
        payload = {"old_zone": OLD, "new_zone": NEW}
        status, body = _request(self.base + "/api/reviews", payload)
        self.assertEqual(status, 200)
        review = body["review"]
        self.assertTrue(review["safe"])
        self.assertEqual(review["serial"]["status"], "ok")
        digest = review["digest"]

        status, body = _request(self.base + "/api/reviews/confirm", payload)
        self.assertEqual(status, 201, body)
        self.assertTrue(body["confirmed"])
        rid = body["id"]

        status, body = _request(self.base + f"/api/reviews/{rid}",
                                method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body["review"]["digest"], digest)
        self.assertEqual(body["replay_request"], payload)

        status, body = _request(self.base + "/api/reviews", method="GET")
        self.assertEqual(status, 200)
        self.assertTrue(any(r["id"] == rid for r in body["reviews"]))

    def test_repeated_submission_same_digest(self):
        p1 = {"old_zone": OLD, "new_zone": NEW}
        # 乱序 + 重复 RDATA 的等价写法
        new_shuffled = NEW.replace(
            "new IN A 192.0.2.30",
            "new IN A 192.0.2.30\nnew IN A 192.0.2.30",
        )
        # 重复 RDATA 与记录乱序不改变规范摘要
        new_shuffled = """$TTL 300
$ORIGIN lab.test.
new IN A 192.0.2.30
new IN A 192.0.2.30
ns1 IN A 192.0.2.10
@ IN NS ns1
@ IN SOA ns1 admin 2024010101 600 300 86400 300
"""
        p2 = {"old_zone": OLD, "new_zone": new_shuffled}
        _, b1 = _request(self.base + "/api/reviews", p1)
        _, b2 = _request(self.base + "/api/reviews", p2)
        self.assertEqual(b1["review"]["diff_sha256"],
                         b2["review"]["diff_sha256"])
        self.assertEqual(b1["review"]["digest"], b2["review"]["digest"])

    def test_unsafe_confirm_refused(self):
        new_bad = """$ORIGIN lab.test.
$TTL 300
@ IN SOA ns1 admin 2024010101 600 300 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.10
new IN A 192.0.2.30
sub IN NS ns.sub
"""
        payload = {"old_zone": OLD, "new_zone": new_bad}
        status, body = _request(self.base + "/api/reviews", payload)
        self.assertEqual(status, 422)
        self.assertIn("missing_glue", json.dumps(body))

        status, body = _request(self.base + "/api/reviews/confirm", payload)
        self.assertEqual(status, 422)

    def test_origin_mismatch(self):
        other = NEW.replace("lab.test.", "other.test.")
        status, body = _request(
            self.base + "/api/reviews",
            {"old_zone": OLD, "new_zone": other},
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "origin_mismatch")


class SpfApiTests(unittest.TestCase):
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

    ZONE = """$ORIGIN example.com.
$TTL 300
@ IN SOA ns1 admin 2024010100 600 300 86400 300
@ IN NS ns1
ns1 IN A 192.0.2.10
@ IN MX 10 mail
mail IN A 192.0.2.50
@ IN TXT "v=spf1 ip4:192.0.2.0/24 mx -all"
"""

    def _evaluate(self, **overrides):
        payload = {
            "zones": [self.ZONE],
            "client_ip": "192.0.2.77",
            "mail_from": "alice@example.com",
            "helo": "mx.sender.example",
        }
        payload.update(overrides)
        return _request(self.base + "/api/spf/evaluate", payload)

    def test_pass_with_trace(self):
        status, body = self._evaluate()
        self.assertEqual(status, 200, body)
        spf = body["spf"]
        self.assertEqual(spf["result"], "pass")
        self.assertEqual(spf["domain"], "example.com.")
        self.assertEqual(spf["dns_query_limit"], 10)
        types_ = [e["type"] for e in spf["trace"]]
        self.assertEqual(types_[0], "policy")
        self.assertEqual(types_[-1], "result")

    def test_mx_match_and_fail(self):
        status, body = self._evaluate(client_ip="192.0.2.50")
        self.assertEqual(status, 200)
        self.assertEqual(body["spf"]["result"], "pass")

        status, body = self._evaluate(client_ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertEqual(body["spf"]["result"], "fail")

    def test_helo_fallback_identity(self):
        status, body = self._evaluate(mail_from="",
                                      helo="example.com")
        self.assertEqual(status, 200)
        self.assertEqual(body["spf"]["identity"], "helo")

    def test_permerror_and_temperror_are_200_terminal_states(self):
        # 多条 SPF -> permerror（仍 200，SPF 终态在 body 内）
        zone_two = self.ZONE + '@ IN TXT "v=spf1 ?all"\n'
        status, body = self._evaluate(zones=[zone_two])
        self.assertEqual(status, 200)
        self.assertEqual(body["spf"]["result"], "permerror")

        # 查询的域不在任何本地区域内 -> temperror
        status, body = self._evaluate(mail_from="alice@elsewhere.test")
        self.assertEqual(status, 200)
        self.assertEqual(body["spf"]["result"], "temperror")

    def test_request_validation_errors(self):
        status, body = self._evaluate(zones=[])
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

        status, body = self._evaluate(client_ip="not-an-ip")
        self.assertEqual(status, 400)

    def test_zone_parse_error_is_422(self):
        status, body = self._evaluate(
            zones=["$ORIGIN broken.\n@ IN TXT unclosed\""])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "zone_parse_error")

    def test_same_input_stable(self):
        _, b1 = self._evaluate(client_ip="8.8.8.8")
        _, b2 = self._evaluate(client_ip="8.8.8.8")
        self.assertEqual(json.dumps(b1, sort_keys=True),
                         json.dumps(b2, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
