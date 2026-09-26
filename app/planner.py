"""RRset 差异与安全发布顺序规划。

输入两个已规范化且各自通过不变量校验的区域，产出：

1. ``diff``：RRset 级差异（add / delete / replace），按规范序排列；
2. ``plan``：一组原子发布步骤。多数步骤只动一个 RRset；
   委派切点的 NS 与胶水变更可能融合成一个原子“委派步骤”——
   先加 NS 会缺胶水、先加胶水又成无主数据，两个单步顺序都违反不变量；
3. 若不存在安全顺序，``safe=False`` 且 ``plan`` 为 null（绝不给出发布计划），
   ``conflicts`` 给出最小冲突 RRset 见证（一个环 / 一组互斥 RRset）。

规划方法：先在操作之间建立必须遵守的先后边（CNAME 排他、切点生命周期），
再在拓扑可行的候选中带回溯搜索；每提交一组都在状态副本上模拟并完整重放
不变量校验（含 CNAME 环）。状态完全由“已完成集合”决定，据此剪枝。
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import RRset, Zone
from .validity import (
    cname_graph,
    is_subdomain,
    validate_zone,
)


@dataclass
class Op:
    """单个 RRset 的原子变更。"""

    op_id: int
    action: str  # add | delete | replace
    owner: str
    rtype: str
    old: RRset | None
    new: RRset | None

    @property
    def key(self) -> tuple[str, str]:
        return self.owner, self.rtype


@dataclass
class Group:
    """原子发布步骤：一个或多个同时生效的 Op（委派宏）。"""

    group_id: int
    ops: list[Op]

    @property
    def keys(self) -> set[tuple[str, str]]:
        return {op.key for op in self.ops}


# ---------------------------------------------------------------------------
# 差异
# ---------------------------------------------------------------------------

def _key_order(key: tuple[str, str]):
    return tuple(reversed(key[0].rstrip(".").split("."))), key[1]


def build_diff(old: Zone, new: Zone) -> list[Op]:
    ops: list[Op] = []
    op_id = 0
    for key in sorted(set(old.rrsets) | set(new.rrsets), key=_key_order):
        old_rr = old.rrsets.get(key)
        new_rr = new.rrsets.get(key)
        if old_rr is None:
            action = "add"
        elif new_rr is None:
            action = "delete"
        else:
            if (old_rr.ttl, old_rr.rdata) == (new_rr.ttl, new_rr.rdata):
                continue
            action = "replace"
        ops.append(Op(op_id, action, key[0], key[1], old_rr, new_rr))
        op_id += 1
    return ops


# ---------------------------------------------------------------------------
# 委派宏分组
# ---------------------------------------------------------------------------

def _glue_names(ns_rr: RRset | None, cut: str) -> set[str]:
    """切点 NS 中域内（in-bailiwick）目标集合。"""
    if ns_rr is None:
        return set()
    return {t for t in ns_rr.rdata if is_subdomain(t, cut)}


def build_groups(ops: list[Op], old: Zone, new: Zone) -> list[Group]:
    """NS 的 add/replace 与其新出现的域内目标地址变更融合为原子步骤。

    非区顶委派：切点 NS 与 in-bailiwick 胶水必须同时生效（否则先 NS 则
    缺胶水，先胶水则成切点下无主数据）。区顶新增 NS 主机同理，虽然它不
    构成委派切点，但 NS 指向“尚不存在”的区内侧地址也不应作为一个
    可发布中间态。
    """
    consumed: set[int] = set()
    groups: list[Group] = []
    gid = 0

    ns_like = [
        op for op in ops
        if op.rtype == "NS" and op.action in ("add", "replace")
    ]
    for op in ns_like:
        cut = op.owner
        old_targets = set(old.get(cut, "NS").rdata) if old.get(cut, "NS") else set()
        new_targets = set(new.get(cut, "NS").rdata) if new.get(cut, "NS") else set()
        targets = (old_targets | new_targets) if cut != old.origin else new_targets
        members = [op]
        for other in ops:
            if other is op or other.op_id in consumed:
                continue
            if other.rtype in ("A", "AAAA") and other.owner in targets:
                members.append(other)
        for m in members:
            consumed.add(m.op_id)
        groups.append(Group(gid, members))
        gid += 1

    for op in ops:
        if op.op_id not in consumed:
            consumed.add(op.op_id)
            groups.append(Group(gid, [op]))
            gid += 1

    return groups


# ---------------------------------------------------------------------------
# 先后约束
# ---------------------------------------------------------------------------

def build_edges(
    groups: list[Group], ops: list[Op], old: Zone, new: Zone
) -> set[tuple[int, int]]:
    """返回组间先后边 (before_group, after_group)。"""
    group_of: dict[int, int] = {}
    for g in groups:
        for op in g.ops:
            group_of[op.op_id] = g.group_id
    edges: set[tuple[int, int]] = set()

    def edge(a: Op, b: Op) -> None:
        ga, gb = group_of[a.op_id], group_of[b.op_id]
        if ga != gb:
            edges.add((ga, gb))

    ops_by_owner: dict[str, list[Op]] = {}
    for op in ops:
        ops_by_owner.setdefault(op.owner, []).append(op)

    # 1) CNAME 排他
    for owner, owner_ops in ops_by_owner.items():
        cname_ops = [o for o in owner_ops if o.rtype == "CNAME"]
        other_ops = [o for o in owner_ops if o.rtype != "CNAME"]
        for co in cname_ops:
            for oo in other_ops:
                if co.action == "add":
                    if oo.action == "delete":
                        edge(oo, co)   # 旧数据先撤，CNAME 再生效
                    else:
                        edge(co, oo)   # 理论上端点校验已拦（终态共存）
                elif co.action == "delete":
                    edge(co, oo)       # CNAME 先撤，新数据再生效
                # replace：合法端点下同属主不会有其它类型的变更

    # 2) CNAME 目标就绪：新 CNAME 指向的名字若在本区内发生变更，
    #    目标记录（A/AAAA/CNAME）应先于 CNAME 生效（更安全的中间态）。
    for co in ops:
        if co.rtype != "CNAME" or co.action == "delete" or co.new is None:
            continue
        target = co.new.rdata[0]
        for to in ops:
            if to is co or to.owner != target:
                continue
            if to.action == "delete":
                continue
            # 目标的增改先于引用它的 CNAME
            edge(to, co)

    # 3) 委派切点生命周期
    cut_names = {
        op.owner for op in ops if op.rtype == "NS" and op.owner != old.origin
    }
    for cut in cut_names:
        ns_op = next(o for o in ops if o.owner == cut and o.rtype == "NS")
        macro = {m.op_id for g in groups if g.group_id == group_of[ns_op.op_id]
                 for m in g.ops}

        for sub in ops:
            if sub.op_id in macro or not is_subdomain(sub.owner, cut):
                continue
            if sub.owner == cut:
                # 切点自身剩余的地址记录（未进入胶水宏）= 夹带数据
                if sub.rtype in ("A", "AAAA"):
                    if sub.action == "delete":
                        edge(sub, ns_op)
                    elif ns_op.action == "delete":
                        edge(ns_op, sub)
                    else:
                        edge(sub, ns_op)
                continue
            if sub.rtype in ("A", "AAAA") and sub.action == "delete" \
                    and ns_op.action == "delete":
                # 切点移除后，旧胶水才能删除（否则删除期间缺胶水）
                edge(ns_op, sub)
                continue
            if sub.action == "delete":
                edge(sub, ns_op)       # 切点生效前清空夹带数据
            elif ns_op.action == "delete":
                edge(ns_op, sub)       # 切点移除后再放回新数据
            else:
                edge(sub, ns_op)

    return edges


# ---------------------------------------------------------------------------
# 状态模拟
# ---------------------------------------------------------------------------

def _apply(state: dict[tuple[str, str], RRset], op: Op) -> None:
    if op.action == "add":
        state[op.key] = op.new
    elif op.action == "delete":
        state.pop(op.key, None)
    else:
        state[op.key] = op.new


def _group_conflicts(
    state: dict[tuple[str, str], RRset], group: Group, apex: str
) -> list[dict]:
    candidate = dict(state)
    for op in group.ops:
        _apply(candidate, op)
    return validate_zone(Zone(apex, candidate), apex)


def _cname_depth(graph: dict[str, str]) -> dict[str, int]:
    """最终 CNAME DAG 上到链尾的距离（端点已校验无环）。"""
    depth: dict[str, int] = {}

    def walk(node: str) -> int:
        if node in depth:
            return depth[node]
        depth[node] = 0
        target = graph.get(node)
        depth[node] = 0 if target is None else 1 + walk(target)
        return depth[node]

    for n in graph:
        walk(n)
    return depth


def _group_priority(group: Group, depth: dict[str, int], apex: str) -> tuple:
    """候选提交次序的启发式分层（仅影响搜索尝试顺序，正确性由模拟保证）。"""
    actions = {op.action for op in group.ops}
    has_ns = any(op.rtype == "NS" for op in group.ops)
    apex_soa = any(op.rtype == "SOA" for op in group.ops)
    cname_ops = [op for op in group.ops if op.rtype == "CNAME"]

    if all(a == "delete" for a in actions) and not has_ns:
        category = 1  # 先清理（含 CNAME 撤销，最有利于破除旧边）
    elif has_ns and "delete" in actions:
        category = 2  # 委派移除
    elif apex_soa:
        category = 8  # SOA 序列号最后推进
    elif all(a == "replace" for a in actions) and not cname_ops and not has_ns:
        category = 4
    elif has_ns and not any(op.owner == apex for op in group.ops):
        category = 5  # 非区顶委派新建/更换（宏）
    elif cname_ops:
        category = 6  # CNAME 新增/更换，按链深从浅到深尝试
    else:
        category = 7  # 普通新增（含区顶 NS 增改）

    # 距链尾越浅（depth 小）越早尝试，使新边出现时其目标已稳定
    cname_rank = min((depth.get(op.owner, 0) for op in cname_ops), default=0)
    names = tuple(sorted((op.owner, op.rtype) for op in group.ops))
    return (category, cname_rank, names)


# ---------------------------------------------------------------------------
# 最小环（Tarjan SCC + SCC 内 BFS 最短环）
# ---------------------------------------------------------------------------

def _find_min_cycle(nodes: set[int], edges: set[tuple[int, int]]) -> list[int]:
    adj: dict[int, set[int]] = {n: set() for n in nodes}
    for a, b in edges:
        if a in nodes and b in nodes:
            adj[a].add(b)

    index = 0
    stack: list[int] = []
    on: set[int] = set()
    idx: dict[int, int] = {}
    low: dict[int, int] = {}
    sccs: list[list[int]] = []

    def strong(v: int) -> None:
        nonlocal index
        idx[v] = low[v] = index
        index += 1
        stack.append(v)
        on.add(v)
        for w in adj[v]:
            if w not in idx:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = stack.pop()
                on.discard(w)
                comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for n in sorted(nodes):
        if n not in idx:
            strong(n)

    cyclic = [c for c in sccs if len(c) > 1 or (c and c[0] in adj[c[0]])]
    if not cyclic:
        return []
    comp = min(cyclic, key=len)
    comp_set = set(comp)
    best = comp
    for start in comp:
        prev: dict[int, int] = {start: start}
        queue = [start]
        while queue:
            v = queue.pop(0)
            for w in sorted(adj[v]):
                if w not in comp_set:
                    continue
                if w == start and prev[v] != start:
                    cyc = []
                    cur = v
                    while cur != start:
                        cyc.append(cur)
                        cur = prev[cur]
                    cyc.append(start)
                    cyc.reverse()
                    if len(cyc) < len(best):
                        best = cyc
                    queue = []
                    break
                if w not in prev:
                    prev[w] = v
                    queue.append(w)
    return best


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------

def plan_changes(old: Zone, new: Zone) -> dict:
    apex = old.origin
    ops = build_diff(old, new)
    diff_entries = [_op_entry(op) for op in ops]

    if not ops:
        return {"diff": diff_entries, "plan": [], "safe": True, "conflicts": []}

    groups = build_groups(ops, old, new)
    edges = build_edges(groups, ops, old, new)
    by_id = {g.group_id: g for g in groups}
    depth = _cname_depth(cname_graph(new))

    preds: dict[int, set[int]] = {g.group_id: set() for g in groups}
    succs: dict[int, set[int]] = {g.group_id: set() for g in groups}
    for a, b in edges:
        succs[a].add(b)
        preds[b].add(a)

    seen: set[frozenset] = set()

    def search(
        done: frozenset,
        state: dict[tuple[str, str], RRset],
        prefix: list[int],
    ) -> list[int] | None:
        if len(done) == len(groups):
            return prefix
        if done in seen:
            return None
        seen.add(done)

        ready = [
            gid for gid in by_id
            if gid not in done and preds[gid] <= done
        ]
        candidates = []
        invalid: list[tuple[int, list[dict]]] = []
        for gid in ready:
            problems = _group_conflicts(state, by_id[gid], apex)
            if problems:
                invalid.append((gid, problems))
            else:
                candidates.append(gid)
        candidates.sort(
            key=lambda gid: _group_priority(by_id[gid], depth, apex)
        )

        if not candidates:
            search.blocked = (ready, invalid, done)
            return None

        for gid in candidates:
            nxt_state = dict(state)
            for op in by_id[gid].ops:
                _apply(nxt_state, op)
            result = search(done | {gid}, nxt_state, prefix + [gid])
            if result is not None:
                return result
        return None

    search.blocked = None
    order = search(frozenset(), dict(old.rrsets), [])

    if order is None:
        conflicts = _diagnose(
            groups, edges, by_id, preds, succs, old, search.blocked
        )
        return _unsafe_result(diff_entries, conflicts)

    # 复演终态，确认与目标一致
    state = dict(old.rrsets)
    steps = []
    for gid in order:
        g = by_id[gid]
        for op in g.ops:
            _apply(state, op)
        steps.append(_step(g))

    if state != new.rrsets or validate_zone(Zone(apex, state), apex):
        return _unsafe_result(
            diff_entries,
            [{
                "code": "no_safe_order",
                "rrsets": [],
                "message": "规划结束但终态未通过校验",
            }],
        )

    return {
        "diff": diff_entries,
        "plan": steps,
        "safe": True,
        "conflicts": [],
    }


def _diagnose(groups, edges, by_id, preds, succs, old, blocked):
    apex = old.origin
    if blocked is not None:
        _ready, invalid, done = blocked
        undone = set(by_id) - done
        # 1) 剩余图存在循环约束
        cycle = _find_min_cycle(undone, edges)
        if cycle:
            return [
                {
                    "code": "no_safe_order",
                    "rrsets": sorted(
                        {key for gid in cycle for key in by_id[gid].keys}
                    ),
                    "message": "变更之间存在循环先后约束，无法排序发布",
                }
            ]
        # 2) 瞬态 CNAME 环见证（模拟某候选时必然成环）
        witness = _transient_cname_witness(invalid)
        if witness is not None:
            return [witness]
        # 3) 退化为首个不变量冲突原因
        gid, problems = invalid[0]
        p = problems[0]
        return [{
            "code": p.get("code", "no_safe_order"),
            "rrsets": p.get("rrsets") or sorted(by_id[gid].keys),
            "message": "不存在保持全部不变量的安全发布顺序: "
            + p.get("message", "某一步在任何可选顺序下都违反不变量"),
        }]
    cycle = _find_min_cycle(set(by_id), edges)
    if cycle:
        return [
            {
                "code": "no_safe_order",
                "rrsets": sorted(
                    {key for gid in cycle for key in by_id[gid].keys}
                ),
                "message": "变更之间存在循环先后约束，无法排序发布",
            }
        ]
    return [{
        "code": "no_safe_order",
        "rrsets": [],
        "message": "不存在安全发布顺序",
    }]


def _transient_cname_witness(invalid) -> dict | None:
    """从候选模拟产生的冲突中取 CNAME 环见证。"""
    for _gid, problems in invalid:
        for p in problems:
            if p.get("code") == "cname_loop":
                return {
                    "code": "cname_loop_transient",
                    "rrsets": p["rrsets"],
                    "message": "任何排序都会在过程中产生 CNAME 环: "
                    + p.get("message", ""),
                }
    return None


def _unsafe_result(diff_entries: list[dict], conflicts: list[dict]) -> dict:
    """合并冲突为去重后的最小 RRset 见证列表。"""
    merged: dict[tuple[str, str], tuple[str, str]] = {}
    for c in conflicts:
        for key in c["rrsets"]:
            merged.setdefault(key, (c["code"], c["message"]))
    ordered = [
        {
            "code": merged[k][0],
            "rrset": {"owner": k[0], "type": k[1]},
            "message": merged[k][1],
        }
        for k in sorted(merged, key=_key_order)
    ]
    return {
        "diff": diff_entries,
        "plan": None,
        "safe": False,
        "conflicts": ordered,
    }


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------

def rrset_summary(rr: RRset) -> dict:
    return {
        "owner": rr.owner,
        "ttl": rr.ttl,
        "type": rr.rtype,
        # SOA 的嵌套 7 字段在 JSON 中展平为单条字段数组
        "rdata": [list(rr.rdata[0])] if rr.rtype == "SOA"
        else list(rr.rdata),
    }


def _op_entry(op: Op) -> dict:
    return {
        "action": op.action,
        "old": rrset_summary(op.old) if op.old else None,
        "new": rrset_summary(op.new) if op.new else None,
    }


def _step(group: Group) -> dict:
    def member(op: Op) -> dict:
        return {
            "action": op.action,
            "old": rrset_summary(op.old) if op.old else None,
            "new": rrset_summary(op.new) if op.new else None,
        }

    if len(group.ops) == 1:
        item = member(group.ops[0])
        item["atomic"] = True
        return item

    return {
        "action": "delegation",
        "atomic": True,
        "members": [member(op) for op in group.ops],
    }
