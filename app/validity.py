"""区域不变量校验。

任意“可发布”的中间状态与最终状态都必须满足：

1. 区顶有且仅有一个 SOA，至少一个 NS；区顶不得出现 CNAME；
2. CNAME 排他：带 CNAME 的 owner 不能有任何其它类型；CNAME 目标链不得成环；
3. 委派（非区顶 NS）构成区域切割点：
   - 切割子树内只能有切点的 NS 与域内胶水（A/AAAA），不得夹带其它数据；
   - 域内（in-bailiwick，即位于切点子树内）的 NS 目标必须能在本区内
     找到 A 或 AAAA 胶水；
4. SOA 只能存在于区顶。
"""

from __future__ import annotations

from .models import Zone


def is_subdomain(name: str, apex: str) -> bool:
    """name 是否为 apex 本身或其子域（均为小写绝对名）。"""
    return name == apex or name.endswith("." + apex)


def find_cuts(zone: Zone, apex: str) -> list[str]:
    """非区顶 NS 的 owner 即委派切点，按规范名序返回。"""
    cuts = [
        owner
        for (owner, rtype) in zone.rrsets
        if rtype == "NS" and owner != apex
    ]
    cuts.sort(key=lambda n: tuple(reversed(n.rstrip(".").split("."))))
    return cuts


def cname_graph(zone: Zone) -> dict[str, str]:
    return {
        owner: next(iter(rr.rdata))
        for (owner, rtype), rr in zone.rrsets.items()
        if rtype == "CNAME"
    }


def find_cname_cycle(graph: dict[str, str]) -> list[str] | None:
    """在 CNAME 图中找一个环，返回环上 owner 列表；无环返回 None。"""
    state: dict[str, int] = {}  # 0=在栈上 1=已完成
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        mark = state.get(node)
        if mark == 0:
            # 找到环：从栈中该节点开始
            return stack[stack.index(node):]
        if mark == 1:
            return None
        state[node] = 0
        stack.append(node)
        target = graph.get(node)
        if target is not None:
            found = visit(target)
            if found is not None:
                return found
        stack.pop()
        state[node] = 1
        return None

    for start in graph:
        if start not in state:
            found = visit(start)
            if found is not None:
                return found
    return None


def _conflict(code: str, rrsets: list[tuple[str, str]], message: str) -> dict:
    return {"code": code, "rrsets": sorted(rrsets), "message": message}


def validate_zone(zone: Zone, apex: str) -> list[dict]:
    """返回冲突列表；空列表代表区域满足全部发布不变量。"""
    conflicts: list[dict] = []
    by_owner: dict[str, list[str]] = {}
    for owner, rtype in zone.rrsets:
        by_owner.setdefault(owner, []).append(rtype)

    # ---- 区顶 SOA / NS / CNAME ----
    apex_types = by_owner.get(apex, [])
    if "SOA" not in apex_types:
        conflicts.append(
            _conflict("apex_soa_missing", [(apex, "SOA")],
                      f"区顶 {apex} 缺少 SOA RRset")
        )
    else:
        soa = zone.get(apex, "SOA")
        if len(soa.rdata) != 1:
            conflicts.append(
                _conflict("apex_soa_multiple", [(apex, "SOA")],
                          "区顶 SOA 必须恰好包含一条 RDATA")
            )
    if "NS" not in apex_types:
        conflicts.append(
            _conflict("apex_ns_missing", [(apex, "NS")],
                      f"区顶 {apex} 缺少 NS RRset")
        )
    if "CNAME" in apex_types:
        conflicts.append(
            _conflict("apex_cname", [(apex, "CNAME")],
                      "区顶不得存在 CNAME")
        )

    # ---- 非区顶 SOA ----
    for owner, rtype in zone.rrsets:
        if rtype == "SOA" and owner != apex:
            conflicts.append(
                _conflict("non_apex_soa", [(owner, "SOA")],
                          f"SOA 只能位于区顶，而 {owner} 位于切点之下")
            )

    # ---- CNAME 排他 ----
    for owner, types in by_owner.items():
        if "CNAME" in types and len(types) > 1:
            members = [(owner, t) for t in types]
            conflicts.append(
                _conflict("cname_coexistence", members,
                          f"{owner} 同时拥有 CNAME 与其它 RR 类型，违反 CNAME 排他性")
            )
    for owner in by_owner:
        cname = zone.get(owner, "CNAME")
        if cname is not None and len(cname.rdata) != 1:
            conflicts.append(
                _conflict("cname_multiple", [(owner, "CNAME")],
                          f"{owner} 的 CNAME 必须恰好指向一个目标")
            )

    # ---- CNAME 环 ----
    graph = cname_graph(zone)
    cycle = find_cname_cycle(graph)
    if cycle is not None:
        conflicts.append(
            _conflict("cname_loop",
                      [(owner, "CNAME") for owner in cycle],
                      "CNAME 目标链成环: " + " -> ".join(cycle + [cycle[0]]))
        )

    # ---- 委派切点与胶水 ----
    # 区顶 NS 的域内目标是区内普通主机记录，不需要（也不是）胶水；
    # 只有非区顶 NS 形成的切点才需要 in-bailiwick 胶水。
    cuts = find_cuts(zone, apex)
    for cut in cuts:
        subtree = {
            (o, t): rr
            for (o, t), rr in zone.rrsets.items()
            if is_subdomain(o, cut)
        }
        # 切点 NS
        cut_types = [t for (o, t) in subtree if o == cut]
        for t in cut_types:
            if t not in ("NS", "A", "AAAA"):
                conflicts.append(
                    _conflict("delegation_non_glue_data", [(cut, t)],
                              f"委派切点 {cut} 处只允许 NS 与胶水，发现 {t}")
                )
        # 子树内（切点之下更深层）只允许胶水地址
        for (o, t) in subtree:
            if o != cut and t not in ("A", "AAAA"):
                conflicts.append(
                    _conflict("delegation_subtree_data", [(o, t)],
                              f"委派切点 {cut} 的子树内不得存在 {o} {t}")
                )
        # 域内（in-bailiwick）NS 目标必须在切点处提供 A/AAAA 胶水
        ns_rr = subtree.get((cut, "NS"))
        referenced: set[str] = set()
        if ns_rr is not None:
            for target in ns_rr.rdata:
                if is_subdomain(target, cut):
                    referenced.add(target)
                    if (target, "A") not in subtree and (
                        target, "AAAA"
                    ) not in subtree:
                        conflicts.append(
                            _conflict(
                                "missing_glue",
                                [(cut, "NS"), (target, "A"),
                                 (target, "AAAA")],
                                f"域内 NS 目标 {target}（委派 {cut}）"
                                "缺少 A/AAAA 胶水",
                            )
                        )
        # 多余/无主的地址记录
        for (o, t) in subtree:
            if t in ("A", "AAAA") and o not in referenced and o != cut:
                # o == cut 自身的地址若非任何 NS 目标引用，下面也会报
                conflicts.append(
                    _conflict(
                        "stray_data_under_cut",
                        [(o, t)],
                        f"{o} {t} 位于委派 {cut} 子树内但不被任何 NS 目标引用",
                    )
                )
        cut_addr = zone.get(cut, "A") or zone.get(cut, "AAAA")
        if cut_addr is not None and cut not in referenced:
            conflicts.append(
                _conflict(
                    "stray_data_under_cut",
                    [(cut, t) for t in cut_types if t in ("A", "AAAA")],
                    f"切点 {cut} 自身的地址不被任何 NS 目标引用",
                )
            )

    return conflicts
