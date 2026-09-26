"""离线迭代解析轨迹校验（app.delegation）单元测试与 HTTP 端到端测试。"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.delegation import MAX_HOPS, trace_delegation
from app.review import ReviewError
from app.server import build_server


def rec(name, rtype, rdata, ttl=300):
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": rdata}


def hop(server, qname, qtype="A", answer=None, authority=None,
        additional=None):
    return {
        "server": server,
        "question": {"name": qname, "type": qtype},
        "answer": answer or [],
        "authority": authority or [],
        "additional": additional or [],
    }


def trace(hops, qname="www.example.com.", qtype="A", roots=("192.0.2.1",)):
    return {
        "qname": qname,
        "qtype": qtype,
        "root_addresses": list(roots),
        "hops": hops,
    }


def referral(server, qname, child, ns, glue=None, qtype="A"):
    """构造一跳转介：authority 给 NS，additional 给 (ns, 地址) 胶水。"""
    additional = [rec(ns_name, "A", addr)
                  for ns_name, addr in (glue or {}).items()]
    return hop(server, qname, qtype,
               authority=[rec(child, "NS", target) for target in ns],
               additional=additional)


def error_of(payload):
    try:
        trace_delegation(payload)
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


class ValidTraceTests(unittest.TestCase):
    """合法轨迹：简单转介链、区外 NS 子查询、CNAME 重启、NS 查询。"""

    def test_simple_referral_chain(self):
        hops = [
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            referral("192.0.2.2", "www.example.com.", "example.com.",
                     ["ns1.example.com."],
                     {"ns1.example.com.": "192.0.2.3"}),
            hop("192.0.2.3", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ]
        result = trace_delegation(trace(hops))
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["reason"], "completed")
        self.assertIsNone(result["failed_hop"])
        self.assertEqual(
            [h["action"] for h in result["hops"]],
            ["referral", "referral", "answer"],
        )
        self.assertEqual(result["hop_count"], 3)
        self.assertEqual(result["hop_budget"], MAX_HOPS)
        self.assertEqual(
            [a["rdata"] for a in result["final_answer"]], ["192.0.2.80"]
        )
        # 地址来源图：根 + 两跳胶水
        sources = {s["address"]: s for s in result["address_sources"]}
        self.assertEqual(sources["192.0.2.1"]["source"], "root")
        self.assertEqual(sources["192.0.2.2"]["source"], "glue")
        self.assertEqual(sources["192.0.2.2"]["hop"], 0)
        self.assertEqual(sources["192.0.2.3"]["ns"], "ns1.example.com.")
        # 第二跳的 server 来源指向第一跳的胶水
        self.assertEqual(
            result["hops"][1]["server_source"],
            {"source": "glue", "hop": 0, "ns": "ns1.com.", "zone": "com."},
        )

    def test_out_of_bailiwick_ns_via_subquery(self):
        hops = [
            # 根 -> com.：区外 NS，additional 里的地址不接纳
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["a.gtld-servers.net."],
                     {"a.gtld-servers.net.": "192.0.2.53"}),
            # 地址子查询 a.gtld-servers.net. A（从根独立解析）
            referral("192.0.2.1", "a.gtld-servers.net.", "net.",
                     ["ns1.net."], {"ns1.net.": "192.0.2.77"}),
            referral("192.0.2.77", "a.gtld-servers.net.",
                     "gtld-servers.net.", ["a.gtld-servers.net."],
                     {"a.gtld-servers.net.": "192.0.2.53"}),
            hop("192.0.2.53", "a.gtld-servers.net.",
                answer=[rec("a.gtld-servers.net.", "A", "192.0.2.53")]),
            # 主查询继续：server 来源是已完成的地址子查询
            referral("192.0.2.53", "www.example.com.", "example.com.",
                     ["ns1.example.com."],
                     {"ns1.example.com.": "192.0.2.10"}),
            hop("192.0.2.10", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ]
        result = trace_delegation(trace(hops))
        self.assertEqual(result["status"], "valid", result)
        hops_view = result["hops"]
        # 首跳 additional 的区外胶水被丢弃
        self.assertEqual(hops_view[0]["records"][1]["verdict"], "discarded")
        self.assertEqual(hops_view[0]["records"][1]["reason"],
                         "out_of_bailiwick_glue")
        self.assertEqual(hops_view[0]["glue"], [])
        # 子查询跳标注 context/for
        self.assertEqual(hops_view[1]["context"], "address")
        self.assertEqual(hops_view[1]["for"], "a.gtld-servers.net.")
        self.assertEqual(hops_view[1]["server_source"],
                         {"source": "root"})
        # 子查询完成跳给出解析出的地址
        self.assertEqual(hops_view[3]["action"], "answer")
        self.assertEqual(hops_view[3]["resolved"], ["192.0.2.53"])
        # 主查询恢复跳的 server 来源是子查询
        self.assertEqual(hops_view[4]["server_source"]["source"], "subquery")
        self.assertEqual(hops_view[4]["server_source"]["qname"],
                         "a.gtld-servers.net.")
        self.assertEqual(hops_view[4]["server_source"]["hop"], 3)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(
            [a["rdata"] for a in result["final_answer"]], ["192.0.2.80"]
        )

    def test_cname_restarts_from_root(self):
        hops = [
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                answer=[rec("www.example.com.", "CNAME",
                            "web.example.net.")]),
            # 从根重启：首跳必须再次是根地址
            referral("192.0.2.1", "web.example.net.", "net.",
                     ["ns1.net."], {"ns1.net.": "192.0.2.4"}),
            hop("192.0.2.4", "web.example.net.",
                answer=[rec("web.example.net.", "A", "192.0.2.90")]),
        ]
        result = trace_delegation(trace(hops))
        self.assertEqual(result["status"], "valid", result)
        self.assertEqual(result["hops"][1]["action"], "cname")
        self.assertEqual(result["hops"][1]["target"], "web.example.net.")
        # 重启后 zone 回到根、server 来源为根
        self.assertEqual(result["hops"][2]["zone"], ".")
        self.assertEqual(result["hops"][2]["server_source"],
                         {"source": "root"})
        # final_answer 含 CNAME 链与最终地址
        self.assertEqual([a["type"] for a in result["final_answer"]],
                         ["CNAME", "A"])
        self.assertEqual(result["final_answer"][1]["rdata"], "192.0.2.90")

    def test_ns_query_and_ipv6_glue(self):
        hops = [
            referral("2001:db8::1", "example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"},
                     qtype="NS"),
            hop("192.0.2.2", "example.com.", "NS",
                answer=[rec("example.com.", "NS", "ns1.example.com."),
                        rec("example.com.", "NS", "ns2.example.com.")]),
        ]
        result = trace_delegation(
            trace(hops, qname="example.com.", qtype="NS",
                  roots=("2001:db8::1",)))
        self.assertEqual(result["status"], "valid", result)
        self.assertEqual(len(result["final_answer"]), 2)
        self.assertEqual(result["hops"][0]["server"], "2001:db8::1")

    def test_cname_query_type_is_final(self):
        # qtype=CNAME 时 CNAME 记录即终答，不触发重启
        hops = [
            hop("192.0.2.1", "www.example.com.", "CNAME",
                answer=[rec("www.example.com.", "CNAME",
                            "web.example.net.")]),
        ]
        result = trace_delegation(
            trace(hops, qname="www.example.com.", qtype="CNAME"))
        self.assertEqual(result["status"], "valid", result)
        self.assertEqual(result["hops"][0]["action"], "answer")
        self.assertEqual(result["final_answer"][0]["type"], "CNAME")

    def test_record_dispositions(self):
        hops = [
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("example.com.", "NS", "ns1.example.com."),
                           rec("example.com.", "NS", "ns2.other.net.")],
                additional=[
                    rec("ns1.example.com.", "A", "192.0.2.9"),
                    rec("ns2.other.net.", "A", "192.0.2.10"),
                    rec("random.example.com.", "A", "192.0.2.11"),
                    rec("example.com.", "SOA",
                        "ns1.example.com. h.example.com. 1 2 3 4 5"),
                ]),
            hop("192.0.2.9", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ]
        result = trace_delegation(trace(hops))
        self.assertEqual(result["status"], "valid", result)
        records = result["hops"][0]["records"]
        by_name = {r["name"]: r for r in records if r["section"] != "answer"}
        self.assertEqual(by_name["ns1.example.com."]["verdict"], "accepted")
        self.assertEqual(by_name["ns1.example.com."]["reason"], "glue")
        self.assertEqual(by_name["ns2.other.net."]["reason"],
                         "out_of_bailiwick_glue")
        self.assertEqual(by_name["random.example.com."]["reason"],
                         "unexpected_additional")
        self.assertEqual(by_name["example.com."]["reason"],
                         "unsupported_type")

    def test_nested_address_subqueries(self):
        # 子查询里再开子查询：ns2.other.org. 先解析，再回到 ns1.example.net.
        hops = [
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("example.com.", "NS", "ns1.example.net.")]),
            hop("192.0.2.1", "ns1.example.net.",
                authority=[rec("example.net.", "NS", "ns2.other.org.")]),
            referral("192.0.2.1", "ns2.other.org.", "other.org.",
                     ["ns1.other.org."], {"ns1.other.org.": "192.0.2.7"}),
            hop("192.0.2.7", "ns2.other.org.",
                answer=[rec("ns2.other.org.", "A", "192.0.2.8")]),
            hop("192.0.2.8", "ns1.example.net.",
                answer=[rec("ns1.example.net.", "A", "192.0.2.9")]),
            hop("192.0.2.9", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ]
        result = trace_delegation(trace(hops))
        self.assertEqual(result["status"], "valid", result)
        # 内层子查询完成后，外层子查询的 server 来源是内层子查询
        self.assertEqual(result["hops"][4]["server_source"]["source"],
                         "subquery")
        self.assertEqual(result["hops"][4]["server_source"]["qname"],
                         "ns2.other.org.")
        # 主查询的 server 来源是外层子查询
        self.assertEqual(result["hops"][5]["server_source"]["qname"],
                         "ns1.example.net.")

    def test_deterministic_output(self):
        hops = [
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ]
        r1 = trace_delegation(trace(hops))
        r2 = trace_delegation(trace(hops))
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(r2, sort_keys=True))


class InvalidTraceTests(unittest.TestCase):
    """invalid 终态：问题错配、越权转介、server 无来源、超预算、循环等。"""

    def check(self, hops, reason, failed_hop, **kwargs):
        result = trace_delegation(trace(hops, **kwargs))
        self.assertEqual(result["status"], "invalid", result)
        self.assertEqual(result["reason"], reason, result)
        self.assertEqual(result["failed_hop"], failed_hop, result)
        self.assertEqual(result["final_answer"], [])
        if failed_hop is not None:
            last = result["hops"][-1]
            self.assertEqual(last["hop"], failed_hop)
            self.assertEqual(last["action"], "invalid")
            self.assertEqual(last["reason"], reason)
        return result

    def test_first_hop_must_use_root(self):
        self.check([hop("192.0.2.99", "www.example.com.")],
                   "server_no_source", 0)

    def test_first_hop_question_must_match_query(self):
        self.check([hop("192.0.2.1", "other.example.com.")],
                   "question_mismatch", 0)

    def test_question_mismatch_mid_trace(self):
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "unrelated.org."),
        ], "question_mismatch", 1)

    def test_referral_out_of_bailiwick(self):
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                authority=[rec("example.net.", "NS", "ns1.example.net.")]),
        ], "referral_out_of_bailiwick", 1)

    def test_referral_not_deeper(self):
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                authority=[rec("com.", "NS", "ns2.com.")]),
        ], "referral_not_deeper", 1)

    def test_referral_misses_qname(self):
        self.check([
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("org.", "NS", "ns1.org.")]),
        ], "referral_misses_qname", 0)

    def test_referral_multiple_zones(self):
        self.check([
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("com.", "NS", "ns1.com."),
                           rec("net.", "NS", "ns1.net.")]),
        ], "referral_multiple_zones", 0)

    def test_server_without_source(self):
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.9", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ], "server_no_source", 1)

    def test_subquery_first_hop_must_use_root(self):
        # 子查询是独立解析，首跳也必须从根开始
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            referral("192.0.2.2", "www.example.com.", "example.com.",
                     ["ns1.example.net."]),
            hop("192.0.2.2", "ns1.example.net."),
        ], "server_no_source", 2)

    def test_cname_loop(self):
        self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                answer=[rec("www.example.com.", "CNAME",
                            "www.example.com.")]),
        ], "cname_loop", 1)

    def test_cname_loop_across_restarts(self):
        self.check([
            hop("192.0.2.1", "a.example.com.",
                answer=[rec("a.example.com.", "CNAME", "b.example.com.")]),
            hop("192.0.2.1", "b.example.com.",
                answer=[rec("b.example.com.", "CNAME", "a.example.com.")]),
        ], "cname_loop", 1, qname="a.example.com.")

    def test_address_query_loop(self):
        self.check([
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("example.com.", "NS", "ns1.example.net.")]),
            hop("192.0.2.1", "ns1.example.net.",
                authority=[rec("example.net.", "NS", "ns2.other.org.")]),
            hop("192.0.2.1", "ns2.other.org.",
                authority=[rec("other.org.", "NS", "ns1.example.net.")]),
            hop("192.0.2.1", "ns1.example.net."),
        ], "address_query_loop", 3)

    def test_cname_loop_into_active_subquery(self):
        # 子查询的 CNAME 指回主查询正在解析的名字 -> 跨解析线循环
        self.check([
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("example.com.", "NS", "ns1.example.net.")]),
            hop("192.0.2.1", "ns1.example.net.",
                answer=[rec("ns1.example.net.", "CNAME",
                            "www.example.com.")]),
        ], "cname_loop", 1)

    def test_unrecognized_response(self):
        # 既非终答、CNAME 也非转介（否定应答不在支持范围）
        self.check([hop("192.0.2.1", "www.example.com.")],
                   "unrecognized_response", 0)

    def test_incomplete_trace(self):
        result = self.check([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
        ], "incomplete_trace", None)
        self.assertEqual(result["hop_count"], 1)

    def test_trailing_hops(self):
        self.check([
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ], "trailing_hops", 1)

    def test_hop_budget_exceeded(self):
        labels = ["x"] + [f"l{i:02d}" for i in range(44)]
        qname = ".".join(labels) + "."
        hops = []
        for k in range(MAX_HOPS + 8):
            child = ".".join(labels[-(k + 1):]) + "."
            hops.append(referral(f"192.0.2.{k + 1}", qname, child,
                                 [f"ns.{child}"],
                                 {f"ns.{child}": f"192.0.2.{k + 2}"}))
        result = self.check(hops, "hop_budget_exceeded", MAX_HOPS,
                            qname=qname)
        self.assertEqual(result["hop_budget"], MAX_HOPS)
        # 前 32 跳全部成功处理
        self.assertEqual(len(result["hops"]), MAX_HOPS + 1)

    def test_exact_budget_is_valid(self):
        # 恰好 32 跳（31 次转介 + 终答）不超预算
        labels = ["x"] + [f"l{i:02d}" for i in range(30)]
        qname = ".".join(labels) + "."
        hops = []
        for k in range(MAX_HOPS - 1):
            child = ".".join(labels[-(k + 1):]) + "."
            hops.append(referral(f"192.0.2.{k + 1}", qname, child,
                                 [f"ns.{child}"],
                                 {f"ns.{child}": f"192.0.2.{k + 2}"}))
        hops.append(hop(f"192.0.2.{MAX_HOPS}", qname,
                        answer=[rec(qname, "A", "192.0.2.80")]))
        result = trace_delegation(trace(hops, qname=qname))
        self.assertEqual(result["status"], "valid", result)
        self.assertEqual(result["hop_count"], MAX_HOPS)


class RequestValidationTests(unittest.TestCase):
    """请求格式（400）与记录内容（422）。"""

    def test_bad_qtype(self):
        exc = error_of(trace([hop("192.0.2.1", "www.example.com.")],
                             qtype="MX"))
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_request")

    def test_empty_roots(self):
        exc = error_of(trace([hop("192.0.2.1", "www.example.com.")],
                             roots=()))
        self.assertEqual(exc.status, 400)

    def test_bad_root_address(self):
        exc = error_of(trace([hop("192.0.2.1", "www.example.com.")],
                             roots=("not-an-ip",)))
        self.assertEqual(exc.status, 400)

    def test_empty_hops(self):
        exc = error_of(trace([]))
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_request")

    def test_bad_server(self):
        exc = error_of(trace([hop("999.1.1.1", "www.example.com.")]))
        self.assertEqual(exc.status, 400)

    def test_missing_question(self):
        exc = error_of(trace([{"server": "192.0.2.1"}]))
        self.assertEqual(exc.status, 400)

    def test_bad_question_type(self):
        exc = error_of(trace([hop("192.0.2.1", "www.example.com.",
                                 "TXT")]))
        self.assertEqual(exc.status, 400)

    def test_bad_ttl(self):
        exc = error_of(trace([
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80",
                            ttl=-1)]),
        ]))
        self.assertEqual(exc.status, 400)

    def test_bad_record_rdata_is_422(self):
        exc = error_of(trace([
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.999")]),
        ]))
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "invalid_record")
        self.assertEqual(exc.details[0]["record"],
                         "hops[0].answer[0]")

    def test_bad_record_name_is_422(self):
        exc = error_of(trace([
            hop("192.0.2.1", "www.example.com.",
                authority=[rec("bad..name.", "NS", "ns1.com.")]),
        ]))
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "invalid_record")

    def test_bad_cname_target_is_422(self):
        exc = error_of(trace([
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "CNAME", "not a name")]),
        ]))
        self.assertEqual(exc.status, 422)


class DelegationApiTests(unittest.TestCase):
    """HTTP 端到端：valid/invalid 都是 200，格式错误走 400/422。"""

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

    def _post(self, payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + "/api/dns/delegation-trace", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_valid_trace(self):
        payload = trace([
            referral("192.0.2.1", "www.example.com.", "com.",
                     ["ns1.com."], {"ns1.com.": "192.0.2.2"}),
            hop("192.0.2.2", "www.example.com.",
                answer=[rec("www.example.com.", "A", "192.0.2.80")]),
        ])
        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        result = body["delegation_trace"]
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["final_answer"][0]["rdata"], "192.0.2.80")

    def test_invalid_trace_is_200(self):
        payload = trace([hop("192.0.2.99", "www.example.com.")])
        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        result = body["delegation_trace"]
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["reason"], "server_no_source")
        self.assertEqual(result["failed_hop"], 0)

    def test_request_error_is_400(self):
        status, body = self._post(trace([], qtype="MX"))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_record_error_is_422(self):
        payload = trace([
            hop("192.0.2.1", "www.example.com.",
                answer=[rec("www.example.com.", "A", "not-an-address")]),
        ])
        status, body = self._post(payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "invalid_record")

    def test_old_endpoints_still_work(self):
        req = urllib.request.Request(self.base + "/healthz", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)


if __name__ == "__main__":
    unittest.main()
