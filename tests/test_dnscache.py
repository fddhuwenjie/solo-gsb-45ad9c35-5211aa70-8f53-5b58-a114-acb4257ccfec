"""离线 DNS 缓存复演（/api/dns/cache/replay）单元测试。"""

import unittest

from app.dnscache import replay_cache
from app.review import ReviewError


def _soa(owner="example.com.", ttl=3600, minimum=None,
         rdata=None):
    minimum = ttl if minimum is None else minimum
    rdata = rdata or (
        f"ns1.{owner} admin.{owner} 1 3600 3600 604800 {minimum}")
    return {"name": owner, "type": "SOA", "ttl": ttl, "rdata": rdata}


def _rr(name, rtype, rdata, ttl):
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": rdata}


def _ev(seq_results, idx):
    return seq_results[idx]


def _run(events):
    return replay_cache({"events": events})["events"]


class PositiveCacheTests(unittest.TestCase):
    def test_learn_then_hit_with_ttl_decay(self):
        events = [
            {"time": 10, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": "NOERROR",
                          "answer": [_rr("www.example.com.", "A",
                                         "192.0.2.1", 100)],
                          "authority": []}},
            {"time": 40, "name": "www.example.com.", "type": "A"},
            {"time": 110, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[0]["hit"])
        self.assertEqual(results[0]["reason"], "learned_positive")
        self.assertEqual(results[0]["ttl_remaining"], 100)
        added = results[0]["changes"]["added"]
        self.assertEqual([a["reason"] for a in added], ["learned"])

        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["reason"], "hit_positive")
        self.assertEqual(results[1]["ttl_remaining"], 70)
        self.assertEqual(results[1]["answer"]["records"][0]["rdata"],
                         ["192.0.2.1"])
        self.assertEqual(results[1]["changes"]["deleted"], [])

        # 恰在到期时刻（110 = 10+100）算 miss，删除原因 expired
        self.assertFalse(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "miss_no_data")
        deleted = results[2]["changes"]["deleted"]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["reason"], "expired")
        self.assertEqual(deleted[0]["name"], "www.example.com.")

    def test_ttl_zero_visible_to_later_same_time_event(self):
        events = [
            {"time": 5, "name": "a.example.com.", "type": "A",
             "response": {"answer": [_rr("a.example.com.", "A",
                                         "192.0.2.2", 0)]}},
            # 同一时刻按输入顺序：第二项在其后，TTL=0 尚未到期
            {"time": 5, "name": "a.example.com.", "type": "A"},
            # 下一时刻 t=6：expire_at=5 <= 6，miss
            {"time": 6, "name": "a.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertEqual(results[0]["reason"], "learned_positive")
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["ttl_remaining"], 0)
        self.assertFalse(results[2]["hit"])
        self.assertEqual(results[2]["changes"]["deleted"][0]["reason"],
                         "expired")

    def test_refresh_replaces_with_new_ttl(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [_rr("www.example.com.", "A",
                                         "192.0.2.1", 100)]}},
            # 恰在到期时刻（100）算 miss，可附新权威响应整体刷新
            {"time": 100, "name": "www.example.com.", "type": "A",
             "response": {"answer": [_rr("www.example.com.", "A",
                                         "192.0.2.9", 200)]}},
            {"time": 299, "name": "www.example.com.", "type": "A"},
            {"time": 300, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[1]["hit"])
        self.assertEqual(results[1]["answer"]["records"][0]["rdata"],
                         ["192.0.2.9"])
        self.assertEqual(results[1]["ttl_remaining"], 200)
        reasons = {d["reason"] for d in results[1]["changes"]["deleted"]}
        self.assertIn("expired", reasons)
        added = results[1]["changes"]["added"]
        self.assertEqual([a["reason"] for a in added], ["learned"])
        # 新 TTL 到期点 300：t=299 仍存活（剩余 1）
        self.assertTrue(results[2]["hit"])
        self.assertEqual(results[2]["ttl_remaining"], 1)
        # t=300 恰到期 -> miss
        self.assertFalse(results[3]["hit"])


class CnameChainTests(unittest.TestCase):
    def test_cname_chain_hit_independent_ttls(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "CNAME", "cdn.example.net.", 100),
                 _rr("cdn.example.net.", "CNAME", "edge.cdn.net.", 200),
                 _rr("edge.cdn.net.", "A", "203.0.113.7", 50),
             ]}},
            {"time": 30, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        learned = results[0]
        self.assertEqual(learned["reason"], "learned_positive")
        # 三个 RRset 分别学习，各自 TTL
        added = {(a["name"], a["type"]): a for a
                 in learned["changes"]["added"]}
        self.assertEqual(added[("www.example.com.", "CNAME")]["ttl"], 100)
        self.assertEqual(added[("cdn.example.net.", "CNAME")]["ttl"], 200)
        self.assertEqual(added[("edge.cdn.net.", "A")]["ttl"], 50)

        hit = results[1]
        self.assertTrue(hit["hit"])
        chain = hit["answer"]["cname_chain"]
        self.assertEqual([c["name"] for c in chain],
                         ["www.example.com.", "cdn.example.net."])
        self.assertEqual(chain[0]["ttl_remaining"], 70)
        self.assertEqual(chain[1]["ttl_remaining"], 170)
        # 终 RRset TTL=50 为链上最小值，故整体剩余 20
        self.assertEqual(hit["ttl_remaining"], 20)

    def test_chain_section_expiry_breaks_chain(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "CNAME", "cdn.example.net.", 100),
                 _rr("cdn.example.net.", "A", "203.0.113.7", 40),
             ]}},
            # t=40：终 A 恰到期，链节缺失 -> miss
            {"time": 40, "name": "www.example.com.", "type": "A"},
            # t=41 重新提供终 A（TTL 30）
            {"time": 41, "name": "cdn.example.net.", "type": "A",
             "response": {"answer": [_rr("cdn.example.net.", "A",
                                         "203.0.113.8", 30)]}},
            # 链又完整：t=41 沿 CNAME（剩 59）取 A（剩 30）
            {"time": 41, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[1]["hit"])
        self.assertEqual(results[1]["reason"], "miss_cname_broken_chain")
        self.assertEqual(results[1]["detail"]["missing_at"],
                         "cdn.example.net.")
        self.assertTrue(results[3]["hit"])
        self.assertEqual(
            results[3]["answer"]["records"][0]["rdata"],
            ["203.0.113.8"])

    def test_cname_loop_in_cache_is_miss(self):
        # 两个 CNAME 都随正向响应学习（各带不相关终数据，避免被当 NODATA）
        events = [
            {"time": 0, "name": "a.example.com.", "type": "CNAME",
             "response": {"answer": [
                 _rr("a.example.com.", "CNAME", "b.example.com.", 100)]}},
            {"time": 0, "name": "b.example.com.", "type": "CNAME",
             "response": {"answer": [
                 _rr("b.example.com.", "CNAME", "a.example.com.", 100)]}},
            {"time": 1, "name": "a.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "miss_cname_loop")
        self.assertEqual(results[2]["detail"]["loop_at"], "a.example.com.")

    def test_cname_loop_in_response_is_422(self):
        payload = {"events": [
            {"time": 0, "name": "a.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("a.example.com.", "CNAME", "b.example.com.", 100),
                 _rr("b.example.com.", "CNAME", "a.example.com.", 100)]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "cname_loop")
        self.assertEqual(ctx.exception.status, 422)

    def test_cname_qtype_returns_cname_directly(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "CNAME",
             "response": {"answer": [
                 _rr("www.example.com.", "CNAME", "cdn.example.net.", 60)]}},
            {"time": 10, "name": "www.example.com.", "type": "CNAME"},
        ]
        results = _run(events)
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["answer"]["cname_chain"], [])
        self.assertEqual(results[1]["answer"]["records"][0]["rdata"],
                         ["cdn.example.net."])

    def test_multi_rdata_rrset_dedup_and_sorted(self):
        events = [
            {"time": 0, "name": "mx.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("mx.example.com.", "A", "192.0.2.9", 60),
                 _rr("mx.example.com.", "A", "192.0.2.1", 60),
                 _rr("mx.example.com.", "A", "192.0.2.9", 60)]}},
            {"time": 1, "name": "mx.example.com.", "type": "A"},
        ]
        results = _run(events)
        rdata = results[1]["answer"]["records"][0]["rdata"]
        self.assertEqual(rdata, ["192.0.2.1", "192.0.2.9"])

    def test_direct_data_takes_precedence_over_cname(self):
        # 同响应中终名同时有 CNAME 与 A：按“直接数据优先”命中 A
        events = [
            {"time": 0, "name": "both.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("both.example.com.", "CNAME",
                     "other.example.net.", 60),
                 _rr("both.example.com.", "A", "192.0.2.7", 60)]}},
            {"time": 1, "name": "both.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["answer"]["records"][0]["rdata"],
                         ["192.0.2.7"])
        self.assertEqual(results[1]["answer"]["cname_chain"], [])

    def test_unreachable_answer_is_422(self):
        payload = {"events": [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "A", "192.0.2.1", 60),
                 _rr("stray.example.org.", "A", "198.51.100.9", 60)]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "answer_unreachable")


class NegativeCacheTests(unittest.TestCase):
    def test_nxdomain_applies_all_types_and_removes_positive(self):
        events = [
            {"time": 0, "name": "ghost.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("ghost.example.com.", "A", "192.0.2.5", 100),
                 _rr("ghost.example.com.", "CNAME",
                     "elsewhere.example.net.", 100)]}},
            # t=10 权威 NXDOMAIN：AA=1，SOA 覆盖查询名
            {"time": 10, "name": "ghost.example.com.", "type": "AAAA",
             "response": {"aa": True, "rcode": 3, "answer": [],
                          "authority": [
                              _soa("example.com.", ttl=300, minimum=60)]}},
            # NXDOMAIN 覆盖同名全部类型：A、AAAA、NS、CNAME 皆为负命中
            {"time": 20, "name": "ghost.example.com.", "type": "A"},
            {"time": 20, "name": "ghost.example.com.", "type": "NS"},
        ]
        results = _run(events)
        learn = results[1]
        self.assertFalse(learn["hit"])
        self.assertEqual(learn["reason"], "learned_nxdomain")
        # 负 TTL = min(SOA TTL 300, MINIMUM 60) = 60
        self.assertEqual(learn["ttl_remaining"], 60)
        # 写入 NXDOMAIN 删除同名正向 A 与 CNAME
        deleted = {(d["name"], d["type"]): d["reason"]
                   for d in learn["changes"]["deleted"]}
        self.assertEqual(deleted[("ghost.example.com.", "A")],
                         "nxdomain_removes_positive")
        self.assertEqual(deleted[("ghost.example.com.", "CNAME")],
                         "nxdomain_removes_positive")

        self.assertTrue(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "hit_nxdomain")
        self.assertEqual(results[2]["answer"]["negative"], "nxdomain")
        self.assertIsNone(results[2]["answer"]["type"])
        self.assertTrue(results[3]["hit"])
        self.assertEqual(results[3]["reason"], "hit_nxdomain")

    def test_nxdomain_expires_at_boundary(self):
        # 负 TTL = min(30, 60) = 30
        events = [
            {"time": 0, "name": "x.example.com.", "type": "A",
             "response": {"aa": True, "rcode": "NXDOMAIN",
                          "authority": [_soa(ttl=30, minimum=60)]}},
            {"time": 30, "name": "x.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[1]["hit"])
        self.assertEqual(results[1]["changes"]["deleted"][0]["reason"],
                         "expired")

    def test_nodata_type_specific(self):
        events = [
            {"time": 0, "name": "host.example.com.", "type": "AAAA",
             "response": {"aa": True, "rcode": 0, "answer": [],
                          "authority": [_soa(ttl=3600, minimum=300)]}},
            {"time": 10, "name": "host.example.com.", "type": "AAAA"},
            # NODATA 只适用于该类型：A 查询仍是 miss
            {"time": 10, "name": "host.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertEqual(results[0]["reason"], "learned_nodata")
        self.assertEqual(results[0]["ttl_remaining"], 300)
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["reason"], "hit_nodata")
        self.assertEqual(results[1]["answer"]["type"], "AAAA")
        self.assertFalse(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "miss_no_data")

    def test_nodata_with_cname_chain_prefix(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "AAAA",
             "response": {"aa": True, "rcode": 0, "answer": [
                 _rr("www.example.com.", "CNAME", "v6.example.net.", 100)],
                          "authority": [
                              _soa("example.net.", ttl=1000, minimum=50)]}},
            {"time": 20, "name": "www.example.com.", "type": "AAAA"},
        ]
        results = _run(events)
        self.assertEqual(results[0]["reason"], "learned_nodata")
        answer = results[0]["answer"]
        self.assertEqual(answer["name"], "v6.example.net.")
        self.assertEqual(len(answer["cname_chain"]), 1)
        self.assertEqual(answer["ttl_remaining"], 50)
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["reason"], "hit_nodata")

    def test_negative_requires_aa(self):
        payload = {"events": [
            {"time": 0, "name": "x.example.com.", "type": "A",
             "response": {"aa": False, "rcode": 3,
                          "authority": [_soa()]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "negative_not_authoritative")

        payload["events"][0]["response"] = {
            "aa": False, "rcode": 0, "answer": [], "authority": [_soa()]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "negative_not_authoritative")

    def test_negative_requires_covering_soa(self):
        payload = {"events": [
            {"time": 0, "name": "www.example.com.", "type": "A",
             # 授权 SOA 属于 other.net.，不覆盖查询名
             "response": {"aa": True, "rcode": 3,
                          "authority": [_soa("other.net.")]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "negative_missing_soa")

    def test_nxdomain_with_answers_is_422(self):
        # NXDOMAIN 只允许随附 CNAME 链；终名上的正向 A 不合法
        payload = {"events": [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 3, "answer": [
                 _rr("www.example.com.", "CNAME",
                     "ghost.example.net.", 60),
                 _rr("ghost.example.net.", "A", "203.0.113.9", 60)],
                          "authority": [_soa("example.net.")]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code, "nxdomain_with_answers")

    def test_nxdomain_with_cname_chain(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 3, "answer": [
                 _rr("www.example.com.", "CNAME",
                     "gone.example.net.", 500)],
                          "authority": [_soa("example.net.",
                                             ttl=500, minimum=100)]}},
            # 沿链负命中（负缓存在终名 gone）
            {"time": 10, "name": "www.example.com.", "type": "A"},
            # 直接查终名的任意类型同样被 NXDOMAIN 覆盖
            {"time": 10, "name": "gone.example.net.", "type": "NS"},
        ]
        results = _run(events)
        learn = results[0]
        self.assertEqual(learn["reason"], "learned_nxdomain")
        answer = learn["answer"]
        self.assertEqual(answer["name"], "gone.example.net.")
        self.assertEqual(len(answer["cname_chain"]), 1)
        self.assertEqual(answer["ttl_remaining"], 100)
        added = {(a["name"], a.get("type")) for a
                 in learn["changes"]["added"]}
        self.assertIn(("www.example.com.", "CNAME"), added)
        self.assertIn(("gone.example.net.", None), added)

        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["reason"], "hit_nxdomain")
        self.assertEqual(results[1]["answer"]["name"],
                         "gone.example.net.")
        self.assertTrue(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "hit_nxdomain")

    def test_invalid_nodata_chain_writes_nothing(self):
        # 先学到一个正常条目；随后带 CNAME 链前缀的 NODATA AA=0 -> 422：
        # 整个请求失败，不返回任何结果（调用方不会拿到半成品快照）。
        payload = {"events": [
            {"time": 0, "name": "keep.example.com.", "type": "A",
             "response": {"answer": [_rr("keep.example.com.", "A",
                                         "192.0.2.1", 100)]}},
            {"time": 1, "name": "www.example.com.", "type": "AAAA",
             "response": {"aa": False, "rcode": 0, "answer": [
                 _rr("www.example.com.", "CNAME", "v6.example.net.", 100)],
                          "authority": [_soa("example.net.")]}},
        ]}
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.code,
                         "negative_not_authoritative")

    def test_covering_soa_most_specific(self):
        events = [
            {"time": 0, "name": "host.sub.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 3, "authority": [
                 _soa("example.com.", ttl=3600, minimum=600),
                 _soa("sub.example.com.", ttl=3600, minimum=30),
             ]}},
        ]
        results = _run(events)
        # 取最具体（最长）SOA：负 TTL = min(3600,30) = 30
        self.assertEqual(results[0]["ttl_remaining"], 30)
        self.assertEqual(results[0]["answer"]["soa"],
                         "sub.example.com.")


class InteractionTests(unittest.TestCase):
    def test_positive_write_removes_conflicting_negatives(self):
        # 写入正向结果（链补齐场景）须删除终名存活的 NODATA 负项：
        # t=0 学习 www CNAME(短 TTL) -> cdn 与 cdn NODATA(A)（长 TTL）；
        # 待 www CNAME 到期而 NODATA 仍存活时，整条链的正向响应补齐，
        # 学习 cdn A 必须删除存活的 NODATA(cdn,A)。
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 0, "answer": [
                 _rr("www.example.com.", "CNAME",
                     "cdn.example.net.", 10)],
                          "authority": [
                              _soa("example.net.", minimum=1000,
                                   ttl=1000)]}},
            {"time": 1, "name": "www.example.com.", "type": "A"},
            # t=11：www CNAME 已到期 -> 链节缺失 miss；cdn NODATA 仍存活
            {"time": 11, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 0, "answer": [
                 _rr("www.example.com.", "CNAME",
                     "cdn.example.net.", 500),
                 _rr("cdn.example.net.", "A", "203.0.113.9", 500)]}},
            {"time": 12, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertEqual(results[1]["reason"], "hit_nodata")
        deleted = [d["reason"] for d in results[2]["changes"]["deleted"]]
        self.assertIn("positive_removes_negative", deleted)
        self.assertTrue(results[3]["hit"])
        self.assertEqual(results[3]["answer"]["records"][0]["rdata"],
                         ["203.0.113.9"])

        # 场景：正向学习删除同 (name,type) NODATA 后，NODATA 只否认该
        # 类型——另一类型（AAAA）仍 miss
        events2 = [
            {"time": 0, "name": "host2.example.net.", "type": "A",
             "response": {"aa": True, "rcode": 0, "answer": [],
                          "authority": [_soa("example.net.",
                                             minimum=1000, ttl=1000)]}},
            {"time": 1, "name": "mail.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("mail.example.com.", "CNAME",
                     "host2.example.net.", 500),
                 _rr("host2.example.net.", "A", "203.0.113.20", 500)]}},
            {"time": 2, "name": "mail.example.com.", "type": "A"},
            {"time": 2, "name": "host2.example.net.", "type": "AAAA"},
        ]
        r2 = _run(events2)
        deleted = {(d["name"], d.get("type")): d["reason"]
                   for d in r2[1]["changes"]["deleted"]}
        self.assertEqual(deleted[("host2.example.net.", "A")],
                         "positive_removes_negative")
        self.assertTrue(r2[2]["hit"])
        self.assertEqual(r2[2]["reason"], "hit_positive")
        self.assertFalse(r2[3]["hit"])

    def test_nodata_after_positive_expiry(self):
        # 正向 A TTL=1；恰在到期（t=1）权威 NODATA 成为新的权威结论
        events = [
            {"time": 0, "name": "h.example.com.", "type": "A",
             "response": {"answer": [_rr("h.example.com.", "A",
                                         "192.0.2.1", 1)]}},
            {"time": 1, "name": "h.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 0, "answer": [],
                          "authority": [_soa(minimum=60, ttl=120)]}},
            {"time": 2, "name": "h.example.com.", "type": "A"},
        ]
        results = _run(events)
        deleted = [d["reason"] for d in results[1]["changes"]["deleted"]]
        self.assertIn("expired", deleted)
        self.assertTrue(results[2]["hit"])
        self.assertEqual(results[2]["reason"], "hit_nodata")

        # 同一时刻先 NXDOMAIN（born_at=0）：其后同刻的 A 查询仍是
        # NXDOMAIN 命中（NXDOMAIN 适用于全部类型），响应被忽略
        events2 = [
            {"time": 0, "name": "h2.example.com.", "type": "AAAA",
             "response": {"aa": True, "rcode": 3,
                          "authority": [_soa(minimum=100, ttl=100)]}},
            {"time": 0, "name": "h2.example.com.", "type": "A"},
        ]
        r2 = _run(events2)
        self.assertTrue(r2[1]["hit"])
        self.assertEqual(r2[1]["reason"], "hit_nxdomain")

    def test_nxdomain_shadows_same_name_nodata(self):
        # 先写长 TTL NODATA(A)（t=0）；NODATA 存活期内再学到短 TTL 的
        # 同名 NXDOMAIN（t=1）——该事件查 NS 以避开 A 的 NODATA 命中。
        # NXDOMAIN 存活期遮蔽 NODATA；到期后未到期的 NODATA 重新生效。
        events = [
            {"time": 0, "name": "h.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 0, "answer": [],
                          "authority": [_soa(minimum=1000, ttl=1000)]}},
            {"time": 1, "name": "h.example.com.", "type": "NS",
             "response": {"aa": True, "rcode": 3,
                          "authority": [_soa(minimum=50, ttl=50)]}},
            {"time": 2, "name": "h.example.com.", "type": "A"},
            {"time": 52, "name": "h.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertEqual(results[2]["reason"], "hit_nxdomain")
        self.assertTrue(results[3]["hit"])
        self.assertEqual(results[3]["reason"], "hit_nodata")

    def test_negative_hit_along_cname_chain(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "CNAME", "gone.example.net.", 500),
                 _rr("gone.example.net.", "A", "203.0.113.5", 10)]}},
            # t=1：gone A 恰到期，链节缺失 -> miss
            {"time": 10, "name": "www.example.com.", "type": "A"},
            # t=11：gone 权威 NXDOMAIN（直接子查询）
            {"time": 11, "name": "gone.example.net.", "type": "A",
             "response": {"aa": True, "rcode": "NXDOMAIN",
                          "authority": [_soa("example.net.",
                                             ttl=500, minimum=100)]}},
            {"time": 12, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertEqual(results[1]["reason"], "miss_cname_broken_chain")
        answer = results[3]["answer"]
        self.assertEqual(answer["negative"], "nxdomain")
        self.assertEqual(answer["name"], "gone.example.net.")
        self.assertEqual(len(answer["cname_chain"]), 1)
        # min(NXDOMAIN 99, CNAME 488) = 99
        self.assertEqual(answer["ttl_remaining"], 99)

    def test_uncacheable_rcode_miss_no_write(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"aa": True, "rcode": "SERVFAIL"}},
            {"time": 1, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        self.assertFalse(results[0]["hit"])
        self.assertEqual(results[0]["reason"], "miss_uncacheable_rcode")
        self.assertIsNone(results[0]["answer"])
        self.assertEqual(results[0]["changes"]["added"], [])
        self.assertFalse(results[1]["hit"])


class ResponseNoticesTests(unittest.TestCase):
    def test_non_aa_positive_accepted_with_notice(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"aa": False, "rcode": 0,
                          "answer": [_rr("www.example.com.", "A",
                                         "192.0.2.1", 60)]}},
        ]
        results = _run(events)
        self.assertEqual(results[0]["reason"], "learned_positive")
        codes = [n["code"] for n in results[0]["notices"]]
        self.assertIn("non_authoritative_positive_accepted", codes)

    def test_rrset_ttl_mismatch_uses_min(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "A", "192.0.2.1", 100),
                 _rr("www.example.com.", "A", "192.0.2.2", 40)]}},
            {"time": 40, "name": "www.example.com.", "type": "A"},
        ]
        results = _run(events)
        codes = [n["code"] for n in results[0]["notices"]]
        self.assertIn("rrset_ttl_mismatch_min_used", codes)
        # 较小 TTL 40：t=40 恰到期
        self.assertFalse(results[1]["hit"])

    def test_authority_non_soa_ignored(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [_rr("www.example.com.", "A",
                                         "192.0.2.1", 60)],
                          "authority": [
                              {"name": "example.com.", "type": "NS",
                               "ttl": 3600, "rdata": "ns1.example.com."},
                              _soa()]}},
        ]
        results = _run(events)
        codes = [n["code"] for n in results[0]["notices"]]
        self.assertIn("authority_non_soa_ignored", codes)

    def test_response_ignored_on_hit(self):
        events = [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [_rr("www.example.com.", "A",
                                         "192.0.2.1", 60)]}},
            {"time": 1, "name": "www.example.com.", "type": "A",
             "response": {"answer": [_rr("www.example.com.", "A",
                                         "192.0.2.9", 600)]}},
        ]
        results = _run(events)
        self.assertTrue(results[1]["hit"])
        self.assertEqual(results[1]["answer"]["records"][0]["rdata"],
                         ["192.0.2.1"])
        codes = [n["code"] for n in results[1]["notices"]]
        self.assertIn("response_ignored_on_hit", codes)


class RequestValidationTests(unittest.TestCase):
    def _expect(self, payload, code=400):
        with self.assertRaises(ReviewError) as ctx:
            replay_cache(payload)
        self.assertEqual(ctx.exception.status, code)
        return ctx.exception

    def test_events_required_nonempty(self):
        self._expect({})
        self._expect({"events": []})

    def test_time_non_decreasing(self):
        exc = self._expect({"events": [
            {"time": 10, "name": "a.example.com.", "type": "A"},
            {"time": 9, "name": "a.example.com.", "type": "A"},
        ]})
        self.assertEqual(exc.code, "invalid_request")

    def test_bad_name_type_time(self):
        self._expect({"events": [{"time": -1, "name": "a.com.",
                                  "type": "A"}]})
        self._expect({"events": [{"time": 0, "name": "", "type": "A"}]})
        self._expect({"events": [{"time": 0, "name": "a.com.",
                                  "type": "MX"}]})
        self._expect({"events": [{"time": 1.5, "name": "a.com.",
                                  "type": "A"}]})

    def test_bad_record_is_422(self):
        exc = self._expect({"events": [
            {"time": 0, "name": "a.example.com.", "type": "A",
             "response": {"answer": [_rr("a.example.com.", "A",
                                         "not-an-ip", 60)]}}]}, 422)
        self.assertEqual(exc.code, "invalid_record")

    def test_bad_soa_fields_is_422(self):
        exc = self._expect({"events": [
            {"time": 0, "name": "a.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 3,
                          "authority": [{"name": "example.com.",
                                         "type": "SOA", "ttl": 60,
                                         "rdata": "ns admin 1 1h"}]}}]}, 422)
        self.assertEqual(exc.code, "invalid_record")


class SnapshotTests(unittest.TestCase):
    def test_final_snapshot_contents_and_order(self):
        out = replay_cache({"events": [
            {"time": 0, "name": "www.example.com.", "type": "A",
             "response": {"answer": [
                 _rr("www.example.com.", "CNAME", "cdn.example.net.", 100),
                 _rr("cdn.example.net.", "A", "203.0.113.1", 80)]}},
            {"time": 0, "name": "bad.example.com.", "type": "A",
             "response": {"aa": True, "rcode": 3,
                          "authority": [_soa(minimum=600, ttl=600)]}},
            {"time": 10, "name": "host.example.com.", "type": "AAAA",
             "response": {"aa": True, "rcode": 0, "answer": [],
                          "authority": [_soa(minimum=300, ttl=3600)]}},
            {"time": 90, "name": "www.example.com.", "type": "A"},
        ]})
        snap = out["snapshot"]
        # 快照时间为最后事件时间；此时 cdn A（80s）已到期并被清除
        self.assertEqual(snap["time"], 90)
        positives = {(p["name"], p["type"]): p for p in snap["positive"]}
        self.assertNotIn(("cdn.example.net.", "A"), positives)
        # www CNAME 仍存活（100s），剩 10
        self.assertEqual(
            positives[("www.example.com.", "CNAME")]["ttl_remaining"], 10)
        negatives = {(n["name"], n["type"]): n for n in snap["negative"]}
        self.assertIn(("bad.example.com.", None), negatives)
        self.assertEqual(negatives[("bad.example.com.", None)]["negative"],
                         "nxdomain")
        self.assertIn(("host.example.com.", "AAAA"), negatives)
        # 排序：规范名称序
        names = [p["name"] for p in snap["positive"]]
        self.assertEqual(names, sorted(names, key=lambda n: tuple(
            reversed(n.rstrip(".").split(".")))))


if __name__ == "__main__":
    unittest.main()
