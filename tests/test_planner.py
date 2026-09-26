"""规划器与不变量测试：安全排序、委派宏、冲突见证。"""

import unittest

from app.models import RRset, Zone
from app.planner import plan_changes
from app.review import ReviewError, perform_review
from app.validity import validate_zone


def rr(owner: str, rtype: str, ttl: int, *rdata: str) -> RRset:
    # SOA 的 7 个字段以一条嵌套 RDATA 存放
    if rtype == "SOA":
        return RRset(owner, rtype, ttl, (tuple(rdata[0].split()),))
    return RRset(owner, rtype, ttl, tuple(sorted(rdata)))


def make_zone(origin: str, records: list[RRset]) -> Zone:
    return Zone(origin, {(r.owner, r.rtype): r for r in records})


def base_zone(serial: int = 100, extra: list[RRset] | None = None) -> Zone:
    records = [
        rr("z.test.", "SOA", 60,
           f"ns1.z.test. admin.z.test. {serial} 60 60 60 60"),
        rr("z.test.", "NS", 60, "ns1.z.test."),
        rr("ns1.z.test.", "A", 60, "192.0.2.1"),
    ]
    records.extend(extra or [])
    return make_zone("z.test.", records)


def replay(plan: list, old: Zone, new: Zone) -> dict:
    """按发布计划逐步复演，校验每一步后区域仍合法。"""
    from app.validity import validate_zone

    state = dict(old.rrsets)
    for step in plan:
        members = step.get("members") or [step]
        for m in members:
            act = m["action"]
            target = m["new"] if act != "delete" else m["old"]
            key = (target["owner"], target["type"])
            if act == "delete":
                state.pop(key)
            else:
                data = tuple(target["rdata"])
                if key[1] == "SOA":
                    data = (tuple(target["rdata"][0]),)
                state[key] = RRset(key[0], key[1], target["ttl"], data)
        conflicts = validate_zone(Zone(old.origin, state), old.origin)
        if conflicts:
            return {"valid": False, "conflict": conflicts[0], "state": state}
    return {"valid": state == new.rrsets, "state": state}


class SafePlanTests(unittest.TestCase):
    def test_simple_add_and_ttl_change(self):
        old = base_zone()
        new = base_zone(101, [rr("www.z.test.", "A", 300, "203.0.113.9")])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        actions = [(d["action"], d["new"]["owner"], d["new"]["type"])
                   for d in result["diff"]]
        self.assertIn(("add", "www.z.test.", "A"), actions)
        self.assertIn(("replace", "z.test.", "SOA"), actions)
        self.assertTrue(replay(result["plan"], old, new)["valid"])
        # SOA 最后一步
        last = result["plan"][-1]
        self.assertEqual(last["new"]["type"], "SOA")

    def test_a_to_cname_removes_first(self):
        old = base_zone(100, [rr("www.z.test.", "A", 60, "203.0.113.1")])
        new = base_zone(101, [
            rr("www.z.test.", "CNAME", 60, "target.z.test."),
            rr("target.z.test.", "A", 60, "203.0.113.2"),
        ])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        sim = replay(result["plan"], old, new)
        self.assertTrue(sim["valid"], sim.get("conflict"))
        types_at_www = [
            (s["action"], s["new"]["type"] if s["action"] != "delete"
             else s["old"]["type"])
            for s in result["plan"]
            if (s.get("new") or s.get("old"))["owner"] == "www.z.test."
        ]
        # 删除 A 必须早于 CNAME 生效
        del_idx = next(i for i, (a, t) in enumerate(types_at_www)
                       if a == "delete")
        add_idx = next(i for i, (a, t) in enumerate(types_at_www)
                       if a == "add")
        self.assertLess(del_idx, add_idx)

    def test_cname_to_a(self):
        old = base_zone(100, [
            rr("www.z.test.", "CNAME", 60, "t.z.test."),
            rr("t.z.test.", "A", 60, "203.0.113.2"),
        ])
        new = base_zone(101, [rr("www.z.test.", "A", 60, "203.0.113.5")])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])

    def test_new_delegation_is_atomic_with_glue(self):
        old = base_zone(100, [rr("child.z.test.", "A", 60, "198.51.100.7")])
        new = base_zone(101, [
            rr("child.z.test.", "NS", 60, "ns.child.z.test."),
            rr("ns.child.z.test.", "A", 60, "198.51.100.9"),
        ])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        # 必须存在一个含 NS+胶水的原子委派步骤
        macro = [s for s in result["plan"] if s["action"] == "delegation"]
        self.assertEqual(len(macro), 1)
        members = {(m["new"] or m["old"])["type"] for m in macro[0]["members"]}
        self.assertEqual(members, {"NS", "A"})
        self.assertTrue(macro[0]["atomic"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])

    def test_remove_delegation_order(self):
        old = base_zone(100, [
            rr("child.z.test.", "NS", 60, "ns.child.z.test."),
            rr("ns.child.z.test.", "A", 60, "198.51.100.9"),
        ])
        new = base_zone(101, [rr("child.z.test.", "A", 60, "198.51.100.10")])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])
        # NS 删除早于旧胶水删除
        flat = []
        for step in result["plan"]:
            for m in step.get("members") or [step]:
                flat.append((m["action"], (m["new"] or m["old"])["owner"],
                             (m["new"] or m["old"])["type"]))
        ns_del = next(i for i, x in enumerate(flat)
                      if x == ("delete", "child.z.test.", "NS"))
        glue_del = next(i for i, x in enumerate(flat)
                        if x == ("delete", "ns.child.z.test.", "A"))
        self.assertLess(ns_del, glue_del)

    def test_delegation_ns_target_change_with_glue(self):
        old = base_zone(100, [
            rr("d.z.test.", "NS", 60, "a.d.z.test."),
            rr("a.d.z.test.", "A", 60, "198.51.100.1"),
        ])
        new = base_zone(101, [
            rr("d.z.test.", "NS", 60, "b.d.z.test."),
            rr("b.d.z.test.", "A", 60, "198.51.100.2"),
        ])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])

    def test_cname_chain_added_target_first(self):
        old = base_zone(100)
        new = base_zone(101, [
            rr("a.z.test.", "A", 60, "203.0.113.1"),
            rr("b.z.test.", "CNAME", 60, "a.z.test."),
            rr("c.z.test.", "CNAME", 60, "b.z.test."),
        ])
        result = plan_changes(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])

    def test_apex_soa_always_present_uses_replace(self):
        old = base_zone(100)
        new = base_zone(101)
        result = plan_changes(old, new)
        soa_steps = [d for d in result["diff"]
                     if d["new"] and d["new"]["type"] == "SOA"]
        self.assertEqual(soa_steps[0]["action"], "replace")
        self.assertTrue(result["safe"])


class UnsafePlanTests(unittest.TestCase):
    def _review(self, old: Zone, new: Zone) -> dict:
        def text(zone: Zone) -> str:
            return zone.canonical_text()
        return perform_review(
            {"old_zone": text(old), "new_zone": text(new)}
        )

    def test_target_zone_missing_glue_is_rejected(self):
        old = base_zone(100)
        # NS 指向域内名字但完全没有胶水 —— 新区域自身非法
        bad = base_zone(101, [
            rr("child.z.test.", "NS", 60, "ns.child.z.test."),
        ])
        with self.assertRaises(ReviewError) as ctx:
            self._review(old, bad)
        self.assertEqual(ctx.exception.code, "invalid_new_zone")
        codes = {d["code"] for d in ctx.exception.details}
        self.assertIn("missing_glue", codes)

    def test_cname_redirect_swap_is_solvable_by_reordering(self):
        # 合法无环终态下，CNAME 重指总存在安全顺序（按新图叶→根换边）；
        # 朴素地按提交顺序会成环，规划器必须靠回溯找到安全顺序。
        old = base_zone(100, [
            rr("a.z.test.", "CNAME", 60, "b.z.test."),
            rr("b.z.test.", "CNAME", 60, "x.z.test."),
            rr("x.z.test.", "A", 60, "203.0.113.1"),
        ])
        new = base_zone(101, [
            rr("a.z.test.", "CNAME", 60, "x.z.test."),
            rr("b.z.test.", "CNAME", 60, "a.z.test."),
            rr("x.z.test.", "A", 60, "203.0.113.1"),
        ])
        from app.validity import validate_zone
        self.assertEqual(validate_zone(new, "z.test."), [])

        result = self._review(old, new)
        self.assertTrue(result["safe"], result["conflicts"])
        self.assertTrue(replay(result["plan"], old, new)["valid"])


class ConflictWitnessTests(unittest.TestCase):
    def test_minimum_cycle_witness(self):
        from app.planner import _find_min_cycle
        # 3 环之外挂若干节点，见证必须是最小的 3 环
        edges = {(1, 2), (2, 3), (3, 1), (1, 4), (4, 5)}
        cycle = _find_min_cycle({1, 2, 3, 4, 5}, edges)
        self.assertEqual(set(cycle), {1, 2, 3})

    def test_no_cycle_returns_empty(self):
        from app.planner import _find_min_cycle
        self.assertEqual(_find_min_cycle({1, 2}, {(1, 2)}), [])

    def test_self_loop_witness(self):
        from app.planner import _find_min_cycle
        self.assertEqual(_find_min_cycle({1}, {(1, 1)}), [1])


class ValidityTests(unittest.TestCase):
    def test_missing_apex_ns(self):
        zone = make_zone("z.test.", [
            rr("z.test.", "SOA", 60, "n.z.test. a.z.test. 1 60 60 60 60"),
            rr("n.z.test.", "A", 60, "10.0.0.1"),
        ])
        codes = {c["code"] for c in validate_zone(zone, "z.test.")}
        self.assertIn("apex_ns_missing", codes)

    def test_glue_outside_bailiwick_not_required(self):
        zone = base_zone(1, [
            rr("child.z.test.", "NS", 60, "ns1.other.example."),
        ])
        codes = {c["code"] for c in validate_zone(zone, "z.test.")}
        self.assertNotIn("missing_glue", codes)

    def test_stray_data_under_cut(self):
        zone = base_zone(1, [
            rr("child.z.test.", "NS", 60, "ns.child.z.test."),
            rr("ns.child.z.test.", "A", 60, "10.0.0.2"),
            rr("host.child.z.test.", "A", 60, "10.0.0.3"),
        ])
        codes = {c["code"] for c in validate_zone(zone, "z.test.")}
        self.assertIn("stray_data_under_cut", codes)


if __name__ == "__main__":
    unittest.main()
