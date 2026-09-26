"""NSEC 否认证明校验：单元测试 + HTTP 端到端。"""

import copy
import json
import threading
import unittest
import urllib.error
import urllib.request

from app.nsec import verify_nsec_proof
from app.review import ReviewError
from app.server import build_server

# 规范名称序：example.com. < a < alias < mail < mail 之后的 www
NSEC = [
    {"owner": "example.com.", "next": "a.example.com.",
     "types": ["SOA", "NS", "A", "NSEC"]},
    {"owner": "a.example.com.", "next": "alias.example.com.",
     "types": ["A", "NSEC"]},
    {"owner": "alias.example.com.", "next": "mail.example.com.",
     "types": ["CNAME", "NSEC"]},
    {"owner": "mail.example.com.", "next": "www.example.com.",
     "types": ["A", "MX", "NSEC"]},
    {"owner": "www.example.com.", "next": "example.com.",
     "types": ["A", "NSEC"]},
]


def make_payload(query, nsec=None, origin="example.com."):
    return {
        "zone_origin": origin,
        "nsec": copy.deepcopy(NSEC if nsec is None else nsec),
        "query": query,
    }


def proof_owners(result):
    return [record["owner"] for record in result["proof"]]


class NodataTests(unittest.TestCase):
    def test_nodata_valid(self):
        result = verify_nsec_proof(make_payload(
            {"name": "mail.example.com.", "type": "TXT",
             "expected": "nodata"}))
        self.assertTrue(result["valid"])
        self.assertEqual(result["reason"], "NODATA 证明成立")
        self.assertEqual(proof_owners(result), ["mail.example.com."])
        self.assertEqual(
            result["proof"][0]["types"], ["A", "MX", "NSEC"])
        self.assertEqual(len(result["checks"]), 1)
        self.assertEqual(result["checks"][0]["check"], "nodata")
        self.assertTrue(result["checks"][0]["valid"])

    def test_nodata_relative_query_name(self):
        result = verify_nsec_proof(make_payload(
            {"name": "mail", "type": "txt", "expected": "NODATA"}))
        self.assertTrue(result["valid"])
        self.assertEqual(result["query"]["name"], "mail.example.com.")
        self.assertEqual(result["query"]["type"], "TXT")
        self.assertEqual(result["query"]["expected"], "nodata")

    def test_nodata_type_present(self):
        result = verify_nsec_proof(make_payload(
            {"name": "mail.example.com.", "type": "MX",
             "expected": "nodata"}))
        self.assertFalse(result["valid"])
        self.assertEqual(result["proof"], [])
        self.assertIn("MX", result["reason"])

    def test_nodata_cname_present(self):
        result = verify_nsec_proof(make_payload(
            {"name": "alias.example.com.", "type": "A",
             "expected": "nodata"}))
        self.assertFalse(result["valid"])
        self.assertIn("CNAME", result["reason"])

    def test_nodata_name_not_present(self):
        result = verify_nsec_proof(make_payload(
            {"name": "ghost.example.com.", "type": "A",
             "expected": "nodata"}))
        self.assertFalse(result["valid"])
        self.assertEqual(result["checks"][0]["records"], [])


class NxdomainTests(unittest.TestCase):
    def test_nxdomain_valid(self):
        result = verify_nsec_proof(make_payload(
            {"name": "ghost.example.com.", "type": "A",
             "expected": "nxdomain"}))
        self.assertTrue(result["valid"])
        self.assertEqual(result["reason"], "NXDOMAIN 证明成立")
        # 覆盖 ghost 的是 alias->mail；覆盖 *.example.com. 的是区顶记录
        self.assertEqual(proof_owners(result),
                         ["example.com.", "alias.example.com."])
        checks = {c["check"]: c for c in result["checks"]}
        self.assertTrue(checks["qname_cover"]["valid"])
        self.assertTrue(checks["wildcard_cover"]["valid"])
        self.assertIn("*.example.com.",
                      checks["wildcard_cover"]["reason"])

    def test_nxdomain_wrap_interval(self):
        # x 排在最大 owner www 之后，落在绕回区间 (www, example.com.)
        result = verify_nsec_proof(make_payload(
            {"name": "x.example.com.", "type": "A",
             "expected": "nxdomain"}))
        self.assertTrue(result["valid"])
        self.assertEqual(proof_owners(result),
                         ["example.com.", "www.example.com."])

    def test_nxdomain_closest_encloser_deeper(self):
        # y.a.example.com. 的最近封闭名是 a.example.com.；
        # 查询名与 *.a.example.com. 由同一条 NSEC 覆盖 -> 最小证明为一条
        result = verify_nsec_proof(make_payload(
            {"name": "y.a.example.com.", "type": "A",
             "expected": "nxdomain"}))
        self.assertTrue(result["valid"])
        self.assertEqual(proof_owners(result), ["a.example.com."])
        checks = {c["check"]: c for c in result["checks"]}
        self.assertIn("*.a.example.com.",
                      checks["wildcard_cover"]["reason"])

    def test_nxdomain_name_exists(self):
        result = verify_nsec_proof(make_payload(
            {"name": "mail.example.com.", "type": "A",
             "expected": "nxdomain"}))
        self.assertFalse(result["valid"])
        self.assertEqual(result["proof"], [])
        checks = {c["check"]: c for c in result["checks"]}
        self.assertFalse(checks["qname_cover"]["valid"])

    def test_query_name_out_of_zone(self):
        result = verify_nsec_proof(make_payload(
            {"name": "other.org.", "type": "A", "expected": "nxdomain"}))
        self.assertFalse(result["valid"])
        self.assertEqual(result["proof"], [])
        self.assertEqual(result["checks"], [])
        self.assertIn("不在区", result["reason"])

    def test_single_record_chain(self):
        nsec = [{"owner": "example.com.", "next": "example.com.",
                 "types": ["SOA", "NSEC"]}]
        result = verify_nsec_proof(make_payload(
            {"name": "www.example.com.", "type": "A",
             "expected": "nxdomain"}, nsec=nsec))
        self.assertTrue(result["valid"])
        self.assertEqual(proof_owners(result), ["example.com."])

        result = verify_nsec_proof(make_payload(
            {"name": "example.com.", "type": "MX",
             "expected": "nodata"}, nsec=nsec))
        self.assertTrue(result["valid"])


class ChainValidationTests(unittest.TestCase):
    def _assert_error(self, payload, status, code):
        with self.assertRaises(ReviewError) as ctx:
            verify_nsec_proof(payload)
        self.assertEqual(ctx.exception.status, status)
        self.assertEqual(ctx.exception.code, code)

    def test_broken_next(self):
        nsec = copy.deepcopy(NSEC)
        nsec[1]["next"] = "mail.example.com."  # 跳过 alias
        self._assert_error(
            make_payload({"name": "ghost.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "nsec_chain_error")

    def test_broken_wraparound(self):
        nsec = copy.deepcopy(NSEC)
        nsec[4]["next"] = "a.example.com."  # 最大 owner 未绕回最小 owner
        self._assert_error(
            make_payload({"name": "ghost.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "nsec_chain_error")

    def test_single_record_must_point_to_itself(self):
        nsec = [{"owner": "example.com.", "next": "www.example.com.",
                 "types": ["SOA", "NSEC"]}]
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "nsec_chain_error")

    def test_empty_chain(self):
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=[]),
            422, "nsec_chain_error")

    def test_duplicate_owner(self):
        nsec = NSEC + [{"owner": "a.example.com.",
                        "next": "alias.example.com.",
                        "types": ["A", "NSEC"]}]
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "duplicate_owner")

    def test_owner_out_of_zone(self):
        nsec = copy.deepcopy(NSEC)
        nsec[1]["owner"] = "a.other.org."
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "name_out_of_zone")

    def test_next_out_of_zone(self):
        nsec = copy.deepcopy(NSEC)
        nsec[1]["next"] = "alias.other.org."
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "name_out_of_zone")

    def test_missing_nsec_type(self):
        nsec = copy.deepcopy(NSEC)
        nsec[3]["types"] = ["A", "MX"]
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec),
            422, "missing_nsec_type")

    def test_malformed_record(self):
        self._assert_error(
            make_payload({"name": "x.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=["oops"]),
            422, "invalid_nsec_record")


class DeterminismTests(unittest.TestCase):
    def test_reorder_does_not_change_result(self):
        query = {"name": "ghost.example.com.", "type": "A",
                 "expected": "nxdomain"}
        shuffled = [NSEC[2], NSEC[4], NSEC[0], NSEC[3], NSEC[1]]
        shuffled = [dict(rec, types=list(reversed(rec["types"])))
                    for rec in shuffled]
        r1 = verify_nsec_proof(make_payload(query))
        r2 = verify_nsec_proof(make_payload(query, nsec=shuffled))
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(r2, sort_keys=True))

    def test_duplicate_types_are_deduped(self):
        nsec = copy.deepcopy(NSEC)
        nsec[3]["types"] = ["MX", "A", "NSEC", "A", "MX", "NSEC"]
        r1 = verify_nsec_proof(make_payload(
            {"name": "mail.example.com.", "type": "TXT",
             "expected": "nodata"}))
        r2 = verify_nsec_proof(make_payload(
            {"name": "mail.example.com.", "type": "TXT",
             "expected": "nodata"}, nsec=nsec))
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(r2, sort_keys=True))


class RequestValidationTests(unittest.TestCase):
    def _assert_400(self, payload):
        with self.assertRaises(ReviewError) as ctx:
            verify_nsec_proof(payload)
        self.assertEqual(ctx.exception.status, 400)
        self.assertEqual(ctx.exception.code, "invalid_request")

    def test_bad_request_shapes(self):
        self._assert_400({})
        self._assert_400(make_payload(
            {"name": "x.example.com.", "type": "A",
             "expected": "nxdomain"}, origin=""))
        self._assert_400({"zone_origin": "example.com.", "nsec": NSEC})
        self._assert_400(make_payload(
            {"name": "x.example.com.", "type": "A", "expected": "bogus"}))
        self._assert_400(make_payload(
            {"name": "x.example.com.", "type": "", "expected": "nodata"}))
        self._assert_400(make_payload(
            {"name": "bad..name", "type": "A", "expected": "nodata"}))
        payload = make_payload({"name": "x.example.com.", "type": "A",
                                "expected": "nodata"})
        payload["nsec"] = "not-a-list"
        self._assert_400(payload)


def _request(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class NsecApiTests(unittest.TestCase):
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

    def test_nxdomain_ok_over_http(self):
        status, body = _request(
            self.base + "/api/dnssec/nsec-proof",
            make_payload({"name": "ghost.example.com.", "type": "A",
                          "expected": "nxdomain"}))
        self.assertEqual(status, 200, body)
        proof = body["nsec_proof"]
        self.assertTrue(proof["valid"])
        self.assertEqual([r["owner"] for r in proof["proof"]],
                         ["example.com.", "alias.example.com."])

    def test_chain_error_is_422_over_http(self):
        nsec = copy.deepcopy(NSEC)
        nsec[0]["next"] = "www.example.com."
        status, body = _request(
            self.base + "/api/dnssec/nsec-proof",
            make_payload({"name": "ghost.example.com.", "type": "A",
                          "expected": "nxdomain"}, nsec=nsec))
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "nsec_chain_error")

    def test_invalid_request_is_400_over_http(self):
        status, body = _request(self.base + "/api/dnssec/nsec-proof", {})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
