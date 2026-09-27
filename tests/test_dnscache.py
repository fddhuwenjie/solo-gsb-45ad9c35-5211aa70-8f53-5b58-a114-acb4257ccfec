"""离线 DNS 缓存复演（app.dnscache）单元测试与 HTTP 端到端测试。"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.dnscache import replay_cache
from app.review import ReviewError
from app.server import build_server

SOA = "ns1.example.com. admin.example.com. 1 7200 3600 86400 60"


def rr(name, rtype, rdata, ttl=300):
    return {"name": name, "type": rtype, "ttl": ttl, "rdata": rdata}


def soa_rr(owner="example.com.", ttl=300, minimum=60):
    return rr(owner, "SOA",
              f"ns1.example.com. admin.example.com. 1 7200 3600 86400 "
              f"{minimum}",
              ttl=ttl)


def event(time, name, qtype, response=None):
    item = {"time": time, "name": name, "type": qtype}
    if response is not None:
        item["response"] = response
    return item


def resp(rcode="NOERROR", aa=True, answer=None, authority=None):
    return {
        "aa": aa,
        "rcode": rcode,
        "answer": answer or [],
        "authority": authority or [],
    }


def replay(events):
    return replay_cache({"events": events})


def error_of(events):
    try:
        replay_cache({"events": events})
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


class PositiveCacheTests(unittest.TestCase):
    def test_miss_then_learn_then_hit_with_ttl_decay(self):
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.1"),
                rr("www.example.com.", "A", "192.0.2.2"),
            ])),
            event(100, "www.example.com.", "A"),
        ])
        e0, e1 = out["events"]
        self.assertEqual(e0["status"], "miss")
        self.assertEqual(e0["reason"], "not_cached")
        self.assertEqual(e0["response"]["decision"], "positive")
        store = [c for c in e0["changes"] if c["action"] == "store"]
        self.assertEqual(store[0]["reason"], "answer_learned")
        self.assertEqual(store[0]["entry"]["ttl"], 300)
        self.assertEqual(e1["status"], "hit")
        self.assertEqual(e1["hit"], "positive")
        self.assertEqual(e1["reason"], "positive_hit")
        self.assertEqual(e1["answer"][0]["ttl_remaining"], 200)
        self.assertEqual(e1["answer"][0]["rdata"],
                         ["192.0.2.1", "192.0.2.2"])
        self.assertEqual(e1["changes"], [])

    def test_expires_exactly_at_ttl_is_a_miss(self):
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.1", ttl=300)])),
            event(300, "www.example.com.", "A"),
        ])
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "miss")
        removed = [c for c in e1["changes"] if c["action"] == "remove"]
        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["reason"], "ttl_expired")
        self.assertEqual(removed[0]["entry"]["ttl_remaining"], 0)

    def test_zero_ttl_learned_is_gone_for_next_event_same_time(self):
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.1", ttl=0)])),
            event(0, "www.example.com.", "A"),
        ])
        self.assertEqual(out["events"][0]["status"], "miss")
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "miss")
        self.assertTrue(
            any(c["reason"] == "ttl_expired" for c in e1["changes"])
        )

    def test_rrset_and_cname_decay_by_their_own_ttl(self):
        # CNAME 节 TTL=100，末端 A TTL=300：100 秒后链节到期即 miss，
        # 但末端 A 仍在缓存（snapshot 可见）
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=100),
                rr("b.example.com.", "A", "192.0.2.9", ttl=300),
            ])),
            event(100, "a.example.com.", "A"),
        ])
        self.assertEqual(out["events"][1]["status"], "miss")
        names = sorted(
            (c["entry"]["name"], c["entry"]["type"])
            for c in out["events"][1]["changes"]
        )
        self.assertIn(("a.example.com.", "CNAME"), names)
        self.assertNotIn(("b.example.com.", "A"), names)
        snap = out["snapshot"]["positive"]
        self.assertEqual([(e["name"], e["type"]) for e in snap],
                         [("b.example.com.", "A")])


class CnameChainTests(unittest.TestCase):
    def _learn_chain(self):
        return replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=100),
                rr("b.example.com.", "CNAME", "c.example.com.", ttl=200),
                rr("c.example.com.", "A", "192.0.2.3", ttl=300),
            ])),
        ])

    def test_hit_follows_cached_chain_with_independent_ttls(self):
        out = self._learn_chain()
        e1 = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=100),
                rr("b.example.com.", "CNAME", "c.example.com.", ttl=200),
                rr("c.example.com.", "A", "192.0.2.3", ttl=300),
            ])),
            event(50, "a.example.com.", "A"),
        ])["events"][1]
        self.assertEqual(e1["status"], "hit")
        self.assertEqual(e1["reason"], "cname_chain_hit")
        self.assertEqual(
            [(a["name"], a["type"], a["ttl_remaining"]) for a in
             e1["answer"]],
            [("a.example.com.", "CNAME", 50),
             ("b.example.com.", "CNAME", 150),
             ("c.example.com.", "A", 250)],
        )

    def test_missing_chain_link_is_miss(self):
        # 只缓存 a->b，没有 b 的 CNAME 也没有 b 的 A
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.")])),
            event(10, "a.example.com.", "A"),
        ])
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "miss")
        self.assertEqual(e1["reason"],
                         "cname_chain_missing:b.example.com.")

    def test_cycle_in_cached_chain_is_miss(self):
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=500),
                rr("b.example.com.", "CNAME", "a.example.com.", ttl=500),
            ])),
            event(10, "a.example.com.", "A"),
        ])
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "miss")
        self.assertEqual(e1["reason"],
                         "cname_chain_cycle:b.example.com.")

    def test_self_cname_is_miss(self):
        out = replay([
            event(0, "x.example.com.", "A", resp(answer=[
                rr("x.example.com.", "CNAME", "x.example.com.")])),
            event(10, "x.example.com.", "A"),
        ])
        self.assertEqual(out["events"][1]["status"], "miss")
        self.assertEqual(out["events"][1]["reason"],
                         "cname_chain_cycle:x.example.com.")

    def test_cname_query_does_not_follow_chain(self):
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=500),
                rr("b.example.com.", "A", "192.0.2.4", ttl=500),
            ])),
            event(10, "a.example.com.", "CNAME"),
        ])
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "hit")
        self.assertEqual(len(e1["answer"]), 1)
        self.assertEqual(e1["answer"][0]["type"], "CNAME")


class NegativeCacheTests(unittest.TestCase):
    def test_nxdomain_covers_all_types_nodata_single_type(self):
        out = replay([
            event(0, "ghost.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr()])),
            event(0, "empty.example.com.", "AAAA",
                  resp("NOERROR", authority=[soa_rr()])),
            event(10, "ghost.example.com.", "AAAA"),
            event(10, "empty.example.com.", "AAAA"),
            event(10, "empty.example.com.", "A"),
        ])
        self.assertEqual(out["events"][2]["status"], "hit")
        self.assertEqual(out["events"][2]["hit"], "negative")
        self.assertEqual(out["events"][2]["reason"], "nxdomain_hit")
        self.assertEqual(out["events"][2]["negative"]["kind"], "nxdomain")
        self.assertIsNone(out["events"][2]["negative"]["qtype"])
        self.assertEqual(out["events"][3]["reason"], "nodata_hit")
        self.assertEqual(out["events"][3]["negative"]["qtype"], "AAAA")
        # NODATA 只适用于该类型：A 仍为 miss
        self.assertEqual(out["events"][4]["status"], "miss")
        self.assertEqual(out["events"][4]["reason"], "not_cached")

    def test_negative_ttl_is_min_of_soa_ttl_and_minimum(self):
        out = replay([
            event(0, "ghost.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr(ttl=300, minimum=60)])),
        ])
        neg = out["events"][0]["response"]["negative"]
        self.assertEqual(neg["ttl"], 60)
        self.assertEqual(out["snapshot"]["negative"][0]["ttl_remaining"], 60)

        out2 = replay([
            event(0, "ghost.example.com.", "A",
                   resp("NXDOMAIN", authority=[soa_rr(ttl=30, minimum=600)])),
        ])
        self.assertEqual(out2["events"][0]["response"]["negative"]["ttl"],
                         30)

    def test_nxdomain_requires_aa(self):
        out = replay([
            event(0, "ghost.example.com.", "A",
                  resp("NXDOMAIN", aa=False, authority=[soa_rr()])),
            event(10, "ghost.example.com.", "A"),
        ])
        decision = out["events"][0]["response"]
        self.assertEqual(decision["decision"], "ignored")
        self.assertEqual(decision["reason"], "aa_not_set")
        self.assertFalse(decision["learned"])
        self.assertEqual(out["events"][1]["status"], "miss")

    def test_requires_soa_covering_qname(self):
        out = replay([
            event(0, "ghost.other.net.", "A",
                  resp("NXDOMAIN", authority=[soa_rr("example.com.")])),
            event(10, "ghost.other.net.", "A"),
        ])
        decision = out["events"][0]["response"]
        self.assertEqual(decision["decision"], "ignored")
        self.assertEqual(decision["reason"], "soa_not_covering")
        self.assertEqual(out["events"][1]["status"], "miss")

    def test_longest_matching_soa_is_used(self):
        out = replay([
            event(0, "www.sub.example.com.", "A", resp(authority=[
                soa_rr("example.com.", ttl=300, minimum=60),
                soa_rr("sub.example.com.", ttl=300, minimum=30),
            ])),
        ])
        neg = out["events"][0]["response"]["negative"]
        self.assertEqual(neg["kind"], "nodata")
        self.assertEqual(neg["ttl"], 30)
        self.assertEqual(neg["soa"]["name"], "sub.example.com.")

    def test_root_soa_covers_every_name(self):
        out = replay([
            event(0, "g.other.net.", "A",
                  resp("NXDOMAIN", authority=[
                      rr(".", "SOA",
                         "a.root. admin. 1 7200 3600 86400 50", ttl=100)])),
        ])
        neg = out["events"][0]["response"]["negative"]
        self.assertEqual(neg["kind"], "nxdomain")
        self.assertEqual(neg["ttl"], 50)

    def test_negative_entry_expires(self):
        out = replay([
            event(0, "ghost.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr(ttl=60, minimum=60)])),
            event(60, "ghost.example.com.", "A"),
        ])
        self.assertEqual(out["events"][1]["status"], "miss")

    def test_negative_hit_through_cname_chain_returns_chain(self):
        out = replay([
            # 先学 a -> b
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=500)])),
            # b 的 A 为 NODATA（响应仍带 a->b 链）
            event(10, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=500)],
                authority=[soa_rr()])),
            event(20, "a.example.com.", "A"),
        ])
        e2 = out["events"][2]
        self.assertEqual(e2["status"], "hit")
        self.assertEqual(e2["hit"], "negative")
        self.assertEqual(e2["reason"], "nodata_hit")
        self.assertEqual(len(e2["answer"]), 1)
        self.assertEqual(e2["answer"][0]["name"], "a.example.com.")
        self.assertEqual(e2["negative"]["name"], "b.example.com.")
        self.assertEqual(e2["negative"]["qtype"], "A")

    def test_nodata_via_cname_chain_in_response_is_at_terminal(self):
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=500),
                rr("b.example.com.", "CNAME", "c.example.com.", ttl=500),
            ], authority=[soa_rr()])),
            event(10, "a.example.com.", "A"),
        ])
        e1 = out["events"][1]
        self.assertEqual(e1["status"], "hit")
        self.assertEqual(e1["negative"]["name"], "c.example.com.")


class CoherenceTests(unittest.TestCase):
    def test_positive_write_removes_conflicting_nxdomain(self):
        # 缓存里先有 ghost 的 NXDOMAIN（覆盖全部类型）；随后另一条 miss 的
        # 正向响应顺带携带 ghost 的 A —— 写入该正向项须删除冲突 NXDOMAIN。
        out = replay([
            event(0, "ghost.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr()])),
            event(10, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.5"),
                rr("ghost.example.com.", "A", "192.0.2.6"),
            ])),
            event(20, "ghost.example.com.", "AAAA"),
        ])
        changes = out["events"][1]["changes"]
        self.assertTrue(any(
            c["action"] == "remove"
            and c["entry"].get("kind") == "nxdomain"
            and c["reason"] == "positive_overrides_nxdomain"
            for c in changes
        ))
        # NXDOMAIN 消失：ghost 的 AAAA 不再被否定
        self.assertEqual(out["events"][2]["status"], "miss")
        self.assertEqual(out["events"][2]["reason"], "not_cached")

    def test_positive_write_removes_conflicting_nodata_only(self):
        # www 的 AAAA 为 NODATA；一条正向响应顺带写入 www 的 A，
        # AAAA-NODATA 不与 A 冲突，须保留。
        out = replay([
            event(0, "www.example.com.", "AAAA",
                  resp(authority=[soa_rr()])),
            event(10, "other.example.com.", "A", resp(answer=[
                rr("other.example.com.", "A", "192.0.2.5"),
                rr("www.example.com.", "A", "192.0.2.5"),
            ])),
            event(20, "www.example.com.", "AAAA"),
        ])
        self.assertEqual(out["events"][2]["status"], "hit")
        self.assertEqual(out["events"][2]["reason"], "nodata_hit")

    def test_cname_write_removes_all_nodata_at_name(self):
        # www 先有 A 与 AAAA 两个 NODATA；正向响应顺带写入 www CNAME，
        # 须删除同名全部类型 NODATA（CNAME 排他）。
        out = replay([
            event(0, "www.example.com.", "A", resp(authority=[soa_rr()])),
            event(0, "www.example.com.", "AAAA",
                  resp(authority=[soa_rr()])),
            event(10, "other.example.com.", "A", resp(answer=[
                rr("other.example.com.", "A", "192.0.2.5"),
                rr("www.example.com.", "CNAME", "cdn.example.net."),
            ])),
        ])
        reasons = [c["reason"] for c in out["events"][2]["changes"]]
        self.assertEqual(reasons.count("positive_overrides_nodata"), 2)

    def test_nxdomain_write_removes_positive_and_cname(self):
        # www 先缓存 A 与 AAAA；随后 www 的一个未缓存类型（TXT）收到
        # NXDOMAIN —— 写入否定项须删除同名全部正向项（含 CNAME）。
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.5"),
                rr("www.example.com.", "AAAA", "2001:db8::5"),
            ])),
            event(10, "www.example.com.", "TXT",
                  resp("NXDOMAIN", authority=[soa_rr()])),
        ])
        changes = out["events"][1]["changes"]
        removed = [c for c in changes if c["action"] == "remove"]
        self.assertEqual(
            sorted(c["reason"] for c in removed),
            ["nxdomain_overrides_positive", "nxdomain_overrides_positive"],
        )
        self.assertEqual(out["snapshot"]["positive"], [])
        self.assertEqual(len(out["snapshot"]["negative"]), 1)

    def test_nxdomain_write_removes_cname_tagged_separately(self):
        # www CNAME 已缓存；查 www 的 TXT 沿链在 x 处缺失而 miss，
        # 该查询给出针对 www 的 NXDOMAIN -> 删除同名 CNAME
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "CNAME", "x.example.com.")])),
            event(10, "www.example.com.", "TXT",
                  resp("NXDOMAIN", authority=[soa_rr()])),
        ])
        reasons = [c["reason"] for c in out["events"][1]["changes"]
                   if c["action"] == "remove"]
        self.assertEqual(reasons, ["nxdomain_overrides_cname"])

    def test_refresh_same_key(self):
        # 同一 RRset 经另一条 miss 响应的附带记录再次学习 -> 刷新
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.5", ttl=100)])),
            event(50, "other.example.com.", "A", resp(answer=[
                rr("other.example.com.", "A", "192.0.2.1", ttl=100),
                rr("www.example.com.", "A", "192.0.2.6", ttl=100),
            ])),
        ])
        stores = [c for c in out["events"][1]["changes"]
                  if c["action"] == "store"
                  and c["entry"]["name"] == "www.example.com."]
        self.assertEqual(stores[0]["reason"], "answer_refreshed")
        self.assertEqual(stores[0]["entry"]["expire_at"], 150)


class ResponseHandlingTests(unittest.TestCase):
    def test_response_on_hit_is_ignored(self):
        out = replay([
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.5")])),
            event(10, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.9")])),
        ])
        self.assertEqual(out["events"][1]["response"], None)
        self.assertEqual(out["events"][1]["answer"][0]["rdata"],
                         ["192.0.2.5"])

    def test_unsupported_rcode_is_not_learned(self):
        out = replay([
            event(0, "www.example.com.", "A",
                  resp("SERVFAIL") if False else {
                      "aa": False, "rcode": 2, "answer": [],
                      "authority": []}),
            event(10, "www.example.com.", "A"),
        ])
        decision = out["events"][0]["response"]
        self.assertEqual(decision["decision"], "ignored")
        self.assertEqual(decision["reason"], "unsupported_rcode")
        self.assertEqual(out["events"][1]["status"], "miss")

    def test_non_aa_nodata_answer_rrs_still_learned(self):
        out = replay([
            event(0, "a.example.com.", "A",
                  resp("NOERROR", aa=False, answer=[
                      rr("a.example.com.", "CNAME", "b.example.com.",
                         ttl=500)], authority=[soa_rr()])),
            event(10, "a.example.com.", "CNAME"),
        ])
        # 否定项不接纳，但 answer 中的 CNAME 已学习
        self.assertEqual(out["events"][1]["status"], "hit")
        self.assertEqual(out["events"][1]["answer"][0]["type"], "CNAME")

    def test_cname_chain_in_response_learned_independently(self):
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com.", ttl=100),
                rr("b.example.com.", "CNAME", "c.example.com.", ttl=200),
                rr("c.example.com.", "A", "192.0.2.3", ttl=300),
            ])),
        ])
        snap = {(e["name"], e["type"]): e
                for e in out["snapshot"]["positive"]}
        self.assertEqual(snap[("a.example.com.", "CNAME")]["ttl"], 100)
        self.assertEqual(snap[("b.example.com.", "CNAME")]["ttl"], 200)
        self.assertEqual(snap[("c.example.com.", "A")]["ttl"], 300)

    def test_answer_cname_cycle_is_cached_and_lookup_misses(self):
        out = replay([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com."),
                rr("b.example.com.", "CNAME", "a.example.com."),
            ])),
            event(10, "a.example.com.", "A"),
        ])
        # 响应被视为 NODATA（无 AA/SOA 故否定项不接纳），两个 CNAME
        # RRset 照常学习；随后沿缓存链成环 -> miss
        self.assertEqual(out["events"][0]["response"]["decision"],
                         "ignored")
        self.assertEqual(out["events"][1]["status"], "miss")
        self.assertEqual(out["events"][1]["reason"],
                         "cname_chain_cycle:b.example.com.")


class ValidationTests(unittest.TestCase):
    def test_non_decreasing_time_enforced(self):
        exc = error_of([
            event(10, "a.example.com.", "A"),
            event(5, "a.example.com.", "A"),
        ])
        self.assertEqual(exc.status, 400)

    def test_events_must_be_list(self):
        exc = None
        try:
            replay_cache({"events": {}})
        except ReviewError as e:
            exc = e
        self.assertEqual(exc.status, 400)

    def test_bad_address_is_422(self):
        exc = error_of([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "A", "not-an-ip")])),
        ])
        self.assertEqual(exc.status, 422)

    def test_rrset_ttl_mismatch_is_422(self):
        exc = error_of([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "A", "192.0.2.1", ttl=100),
                rr("a.example.com.", "A", "192.0.2.2", ttl=200),
            ])),
        ])
        self.assertEqual(exc.status, 422)

    def test_cname_singleton_is_422(self):
        exc = error_of([
            event(0, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "CNAME", "b.example.com."),
                rr("a.example.com.", "CNAME", "c.example.com."),
            ])),
        ])
        self.assertEqual(exc.status, 422)

    def test_bad_soa_fields_is_422(self):
        exc = error_of([
            event(0, "ghost.example.com.", "A", resp("NXDOMAIN",
                  authority=[rr("example.com.", "SOA",
                                "ns host 1 2 3 4 nope")])),
        ])
        self.assertEqual(exc.status, 422)

    def test_relative_names_completed(self):
        out = replay([
            event(0, "www", "A", resp(answer=[
                {"name": "www", "type": "A", "ttl": 300,
                 "rdata": "192.0.2.1"}])),
        ])
        self.assertEqual(
            out["snapshot"]["positive"][0]["name"], "www."
        )


class SameTimeOrderingTests(unittest.TestCase):
    def test_same_timestamp_processed_in_input_order(self):
        out = replay([
            event(100, "a.example.com.", "A", resp(answer=[
                rr("a.example.com.", "A", "192.0.2.1", ttl=100)])),
            event(100, "b.example.com.", "A"),
            event(100, "a.example.com.", "A"),
        ])
        # 第一条在 t=100 学到（expire_at=200）；同刻第三条仍命中
        self.assertEqual(out["events"][0]["status"], "miss")
        self.assertEqual(out["events"][1]["status"], "miss")
        self.assertEqual(out["events"][2]["status"], "hit")


class SnapshotTests(unittest.TestCase):
    def test_snapshot_sorted_and_shows_remaining_ttl(self):
        out = replay([
            event(0, "z.example.com.", "A", resp(answer=[
                rr("z.example.com.", "A", "192.0.2.9", ttl=300)])),
            event(0, "a.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr(ttl=60, minimum=45)])),
            event(0, "q.example.com.", "A",
                  resp("NXDOMAIN", authority=[soa_rr(ttl=600, minimum=600)])),
            event(100, "q.example.com.", "A"),
        ])
        snap = out["snapshot"]
        self.assertEqual(snap["time"], 100)
        self.assertEqual(
            [p["name"] for p in snap["positive"]],
            ["z.example.com."],
        )
        self.assertEqual(snap["positive"][0]["ttl_remaining"], 200)
        # a 的负项 TTL=45 已在 t=100 到期；q 的负项剩余 500
        self.assertEqual(
            [n["name"] for n in snap["negative"]],
            ["q.example.com."],
        )
        self.assertEqual(snap["negative"][0]["ttl_remaining"], 500)
        self.assertEqual(snap["negative"][0]["kind"], "nxdomain")

    def test_empty_events(self):
        out = replay([])
        self.assertEqual(out["events"], [])
        self.assertEqual(out["snapshot"],
                         {"time": None, "positive": [], "negative": []})


# ---------------------------------------------------------------------------
# HTTP 端到端
# ---------------------------------------------------------------------------

class CacheReplayApiTests(unittest.TestCase):
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

    def test_endpoint_roundtrip(self):
        payload = {"events": [
            event(0, "www.example.com.", "A", resp(answer=[
                rr("www.example.com.", "A", "192.0.2.1")])),
            event(10, "www.example.com.", "A"),
        ]}
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + "/api/dns/cache/replay", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.status, 200)
            body = json.loads(response.read())
        events = body["cache_replay"]["events"]
        self.assertEqual(events[0]["status"], "miss")
        self.assertEqual(events[1]["status"], "hit")

    def test_bad_request_returns_400(self):
        data = json.dumps({"events": "nope"}).encode()
        req = urllib.request.Request(
            self.base + "/api/dns/cache/replay", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_old_endpoints_still_routed(self):
        req = urllib.request.Request(self.base + "/healthz")
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(response.status, 200)


if __name__ == "__main__":
    unittest.main()
