"""离线 SPF 求值（app.spf）单元测试。"""

import json
import unittest

from app.review import ReviewError
from app.spf import DNS_QUERY_LIMIT, SpfError, evaluate_spf, parse_spf_record

SOA_NS = "@ IN SOA ns host 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\n"


def make_zone(apex: str, spf=None, records: str = "", extra_txt=None):
    """构造带 SOA/NS 的区域文本；spf 可为字符串或字符串列表。"""
    lines = [f"$ORIGIN {apex}", "$TTL 300", SOA_NS.rstrip("\n")]
    if spf is not None:
        values = spf if isinstance(spf, list) else [spf]
        for value in values:
            lines.append('@ IN TXT "' + value + '"')
    if extra_txt:
        for value in extra_txt:
            lines.append('@ IN TXT "' + value + '"')
    if records:
        lines.append(records.rstrip("\n"))
    return "\n".join(lines) + "\n"


def evaluate(zones, ip, mail_from="user@example.com", helo="helo.example"):
    return evaluate_spf(
        {
            "zones": zones,
            "client_ip": ip,
            "mail_from": mail_from,
            "helo": helo,
        }
    )


class QualifierTests(unittest.TestCase):
    def test_all_qualifiers(self):
        expected = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
        for qualifier, status in expected.items():
            with self.subTest(qualifier=qualifier):
                result = evaluate(
                    [make_zone("example.com.", f"v=spf1 {qualifier}all")],
                    "203.0.113.7",
                )
                self.assertEqual(result["result"], status)

    def test_default_qualifier_is_pass(self):
        result = evaluate(
            [make_zone("example.com.", "v=spf1 all")],
            "203.0.113.7",
        )
        self.assertEqual(result["result"], "pass")


class NoneAndPermerrorTests(unittest.TestCase):
    def test_no_txt_returns_none(self):
        result = evaluate(
            [make_zone("example.com.")], "203.0.113.7"
        )
        self.assertEqual(result["result"], "none")

    def test_txt_without_spf_returns_none(self):
        result = evaluate(
            [make_zone("example.com.", extra_txt=["not-an-spf-record",
                                                  "v=something else"])],
            "203.0.113.7",
        )
        self.assertEqual(result["result"], "none")

    def test_multiple_spf_records_permerror(self):
        result = evaluate(
            [make_zone("example.com.", ["v=spf1 -all", "v=spf1 ?all"])],
            "203.0.113.7",
        )
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "multiple_spf_records")

    def test_macro_anywhere_is_permerror(self):
        for record in (
            "v=spf1 ip4:10.0.0.0/8 -all exp=txt.%{d}",
            "v=spf1 include:%{i}._spf.example.com. -all",
            "v=spf1 a:mail-%{c}.example.com. -all",
            "v=spf1 %% -all",
        ):
            with self.subTest(record=record):
                result = evaluate(
                    [make_zone("example.com.", record)], "203.0.113.7"
                )
                self.assertEqual(result["result"], "permerror")
                self.assertEqual(result["trace"][-1]["reason"],
                                 "macro_unsupported")

    def test_unsupported_mechanisms_permerror(self):
        for record in ("v=spf1 ptr -all", "v=spf1 exists:%{i}.spf. -all",
                       "v=spf1 bogus:x -all"):
            with self.subTest(record=record):
                # exists 带宏时 macro 检查先触发；不带宏的情况单独覆盖
                if "%{" in record:
                    continue
                result = evaluate(
                    [make_zone("example.com.", record)], "203.0.113.7"
                )
                self.assertEqual(result["result"], "permerror")

    def test_exists_without_macro_is_permerror(self):
        result = evaluate(
            [make_zone("example.com.",
                       "v=spf1 exists:example.com. -all")],
            "203.0.113.7",
        )
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"],
                         "unsupported_mechanism")

    def test_invalid_syntax_permerror(self):
        for record in (
            "v=spf1 ip4:not-an-ip -all",
            "v=spf1 ip4:10.0.0.0/40 -all",
            "v=spf1 ip6:10.0.0.0/8 -all",
            "v=spf1 a//24 -all",
            "v=spf1 a/40 -all",
            "v=spf1 include: -all",
            "v=spf1 redirect= -all",
            "v=spf1 ip4=1.2.3.4 -all",
            "v=spf1 redirect=a.test. redirect=b.test. -all",
        ):
            with self.subTest(record=record):
                result = evaluate(
                    [make_zone("example.com.", record)], "203.0.113.7"
                )
                self.assertEqual(result["result"], "permerror", record)

    def test_unknown_modifier_ignored(self):
        result = evaluate(
            [make_zone("example.com.",
                       "v=spf1 -all foo=bar unknownmod=ignored")],
            "203.0.113.7",
        )
        self.assertEqual(result["result"], "fail")

    def test_empty_record_neutral(self):
        result = evaluate(
            [make_zone("example.com.", "v=spf1")], "203.0.113.7"
        )
        self.assertEqual(result["result"], "neutral")


class IpMechanismTests(unittest.TestCase):
    def test_ip4_match_and_miss(self):
        zones = [make_zone("example.com.",
                           "v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.5 -all")]
        self.assertEqual(evaluate(zones, "192.0.2.77")["result"], "pass")
        self.assertEqual(evaluate(zones, "198.51.100.5")["result"], "pass")
        self.assertEqual(evaluate(zones, "198.51.100.6")["result"], "fail")

    def test_ip6_match(self):
        zones = [make_zone("example.com.", "v=spf1 ip6:2001:db8::/32 -all")]
        self.assertEqual(
            evaluate(zones, "2001:db8:1::4")["result"], "pass")
        self.assertEqual(
            evaluate(zones, "2001:db9::1")["result"], "fail")

    def test_ip4_term_does_not_match_v6_client(self):
        zones = [make_zone("example.com.", "v=spf1 ip4:192.0.2.0/24 -all")]
        self.assertEqual(
            evaluate(zones, "2001:db8::1")["result"], "fail")

    def test_evaluation_short_circuits_on_first_match(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 ip4:203.0.113.0/24 ip4:203.0.113.7 -all",
        )]
        result = evaluate(zones, "203.0.113.7")
        # 只求值了第一条 ip4 就返回，第二条不应出现在轨迹里
        term_indices = [t["index"] for t in result["trace"]
                        if t["type"] == "term"]
        self.assertEqual(term_indices, [0])


class AMxMechanismTests(unittest.TestCase):
    def test_a_matches_apex_and_cidr(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 a/27 a:backup.example.com. -all",
            records=(
                "@ IN A 192.0.2.50\n"
                "backup IN A 198.51.100.10\n"
            ),
        )]
        # 区顶地址 192.0.2.50 按 /27 展开为 192.0.2.32/27
        self.assertEqual(evaluate(zones, "192.0.2.50")["result"], "pass")
        self.assertEqual(evaluate(zones, "192.0.2.60")["result"], "pass")
        self.assertEqual(evaluate(zones, "192.0.2.70")["result"], "fail")
        # backup 主机无 CIDR 限定，按 /32 精确匹配
        self.assertEqual(evaluate(zones, "198.51.100.10")["result"], "pass")
        self.assertEqual(evaluate(zones, "198.51.100.11")["result"], "fail")
        self.assertEqual(evaluate(zones, "10.0.0.1")["result"], "fail")

    def test_mx_resolves_exchanges(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 mx -all",
            records=(
                "@ IN MX 10 m1\n"
                "@ IN MX 20 m2\n"
                "m1 IN A 192.0.2.11\n"
                "m2 IN AAAA 2001:db8::11\n"
            ),
        )]
        self.assertEqual(evaluate(zones, "192.0.2.11")["result"], "pass")
        self.assertEqual(evaluate(zones, "2001:db8::11")["result"], "pass")
        self.assertEqual(evaluate(zones, "203.0.113.9")["result"], "fail")

    def test_implicit_mx_self(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 mx -all",
            records="@ IN A 192.0.2.30\n",
        )]
        self.assertEqual(evaluate(zones, "192.0.2.30")["result"], "pass")

    def test_mx_counts_mx_plus_exchange_a_and_aaaa(self):
        # 一个交换主机（仅有 A）：策略 TXT + MX + 交换主机 A + AAAA = 4
        zones = [make_zone(
            "example.com.",
            "v=spf1 mx -all",
            records=(
                "@ IN MX 10 m1\n"
                "m1 IN A 192.0.2.11\n"
            ),
        )]
        result = evaluate(zones, "10.0.0.1")
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["dns_queries"], 4)

        # 两个交换主机（第二个有 AAAA）：1 + 1 + 2*2 = 6
        zones = [make_zone(
            "example.com.",
            "v=spf1 mx -all",
            records=(
                "@ IN MX 10 m1\n"
                "@ IN MX 20 m2\n"
                "m1 IN A 192.0.2.11\n"
                "m2 IN AAAA 2001:db8::11\n"
            ),
        )]
        result = evaluate(zones, "10.0.0.1")
        self.assertEqual(result["dns_queries"], 6)

    def test_implicit_mx_self_counts_self_address_lookups(self):
        # 隐式 MX 同样要读域自身的 A/AAAA
        zones = [make_zone(
            "example.com.",
            "v=spf1 mx -all",
            records="@ IN A 192.0.2.30\n",
        )]
        result = evaluate(zones, "10.0.0.1")
        self.assertEqual(result["dns_queries"], 4)

    def test_mx_exhausts_budget_resolving_exchanges(self):
        # 5 个交换主机：TXT(1) + MX(1) + 每个交换主机 A/AAAA 各一次，
        # 第 5 个交换主机的 A 是第 11 次查询 -> permerror（而不是漏掉计费）
        records = "\n".join(
            f"@ IN MX {i} m{i}\nm{i} IN A 10.0.0.{i}\n"
            for i in range(1, 6)
        )
        zones = [make_zone("example.com.", "v=spf1 mx -all",
                           records=records)]
        result = evaluate(zones, "8.8.8.8")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)
        # 超预算发生在 mx 机制内部（解析第 5 个交换主机的 A 时）
        term = next(e for e in result["trace"] if e["type"] == "term")
        self.assertEqual(term["mechanism"], "mx")
        self.assertEqual(term["error"]["reason"], "dns_query_limit")

    def test_a_term_reads_a_and_aaaa_rrsets(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 a -all",
            records="@ IN A 192.0.2.1\n",
        )]
        result = evaluate(zones, "10.0.0.1")
        # 策略 TXT 一次 + a 的 A、AAAA 各一次
        self.assertEqual(result["dns_queries"], 3)

    def test_relative_domain_spec_under_current_domain(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 a:mail -all",
            records="mail IN A 172.16.0.1\n",
        )]
        self.assertEqual(
            evaluate(zones, "172.16.0.1")["result"], "pass")


class IncludeTests(unittest.TestCase):
    def _zones(self, sub_record="v=spf1 ip4:10.0.0.0/8 -all",
               top_record="v=spf1 include:sub.example.com. -all"):
        return [
            make_zone("example.com.", top_record),
            make_zone("sub.example.com.", sub_record),
        ]

    def test_include_pass_only(self):
        zones = self._zones()
        self.assertEqual(evaluate(zones, "10.1.2.3")["result"], "pass")

    def test_include_non_pass_continues(self):
        for sub, expected_continue in (
            ("v=spf1 -all", "fail"),
            ("v=spf1 ~all", "fail"),
            ("v=spf1 ?all", "fail"),
        ):
            with self.subTest(sub=sub):
                zones = self._zones(sub)
                self.assertEqual(
                    evaluate(zones, "203.0.113.1")["result"],
                    expected_continue,
                )

    def test_include_none_continues(self):
        zones = self._zones(None)  # 子域没有任何 SPF
        result = evaluate(zones, "203.0.113.1")
        self.assertEqual(result["result"], "fail")

    def test_include_permerror_propagates(self):
        zones = self._zones("v=spf1 ptr -all")
        result = evaluate(zones, "203.0.113.1")
        self.assertEqual(result["result"], "permerror")

    def test_include_qualifier_applies_on_pass(self):
        zones = self._zones(
            top_record="v=spf1 -include:sub.example.com. ?all",
        )
        result = evaluate(zones, "10.1.2.3")
        self.assertEqual(result["result"], "fail")
        result = evaluate(zones, "8.8.8.8")
        self.assertEqual(result["result"], "neutral")


class RedirectTests(unittest.TestCase):
    def _zones(self, target="v=spf1 ip4:10.0.0.0/8 -all",
               top="v=spf1 redirect=dest.example.com."):
        return [
            make_zone("example.com.", top),
            make_zone("dest.example.com.", target),
        ]

    def test_redirect_when_no_mechanism_match(self):
        zones = self._zones()
        self.assertEqual(evaluate(zones, "10.1.2.3")["result"], "pass")
        self.assertEqual(evaluate(zones, "8.8.8.8")["result"], "fail")

    def test_redirect_ignored_when_mechanism_matches(self):
        zones = self._zones(
            top="v=spf1 -ip4:9.9.9.9 redirect=dest.example.com."
        )
        # ip4 命中（限定符 -），redirect 不得执行
        result = evaluate(zones, "9.9.9.9")
        self.assertEqual(result["result"], "fail")
        self.assertEqual(
            [e for e in result["trace"] if e["type"] == "redirect"], []
        )

    def test_redirect_runs_when_mechanisms_do_not_match(self):
        zones = self._zones(
            target="v=spf1 +all",
            top="v=spf1 ip4:9.9.9.9 redirect=dest.example.com.",
        )
        result = evaluate(zones, "8.8.8.8")
        self.assertEqual(result["result"], "pass")

    def test_redirect_target_none_is_permerror(self):
        zones = self._zones(target=None)
        result = evaluate(zones, "8.8.8.8")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"],
                         "redirect_no_record")


class LoopAndBudgetTests(unittest.TestCase):
    def test_direct_include_loop(self):
        zones = [
            make_zone("a.test.", "v=spf1 include:b.test. -all"),
            make_zone("b.test.", "v=spf1 include:a.test. -all"),
        ]
        result = evaluate(
            zones, "1.1.1.1",
            mail_from="user@a.test",
        )
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "spf_loop")

    def test_redirect_loop(self):
        zones = [
            make_zone("a.test.", "v=spf1 redirect=b.test."),
            make_zone("b.test.", "v=spf1 redirect=a.test."),
        ]
        result = evaluate(
            zones, "1.1.1.1", mail_from="user@a.test")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "spf_loop")

    def test_diamond_is_not_a_loop(self):
        zones = [
            make_zone("a.test.", "v=spf1 include:b.test. include:c.test. -all"),
            make_zone("b.test.", "v=spf1 include:d.test. -all"),
            make_zone("c.test.", "v=spf1 include:d.test. -all"),
            make_zone("d.test.", "v=spf1 -all"),
        ]
        result = evaluate(zones, "1.1.1.1", mail_from="user@a.test")
        self.assertEqual(result["result"], "fail")
        # a/b/c/d 四条策略 TXT（菱形共享 d）共 5 次 RRset 查询
        self.assertEqual(result["dns_queries"], 5)

    def test_shared_dns_query_budget(self):
        # 统一在 TXT 入口计费：初始 TXT 也占预算。
        # d0 -> ... -> d11：d0..d10 的 TXT 共 11 次读取（含 10 次 include
        # 目标 TXT），第 11 次（读取 d10 的 TXT）即超预算，d11 的策略
        # 根本不会被读到。
        chain = []
        for i in range(DNS_QUERY_LIMIT + 1):
            chain.append(make_zone(
                f"d{i}.test.",
                f"v=spf1 include:d{i+1}.test. -all",
            ))
        chain.append(make_zone(
            f"d{DNS_QUERY_LIMIT + 1}.test.", "v=spf1 -all"))
        result = evaluate(
            chain, "1.1.1.1", mail_from="user@d0.test")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)
        # 第 11 条策略（d10）的 TXT 读取即被截断：轨迹里有它的 policy
        # 事件，但记录内容从未读取，且该深度下没有任何 term 事件
        policies = [e for e in result["trace"] if e["type"] == "policy"]
        self.assertEqual(policies[-1]["domain"], "d10.test.")
        self.assertNotIn("record", policies[-1])
        self.assertEqual(len(policies), DNS_QUERY_LIMIT + 1)
        depth_terms = [e for e in result["trace"]
                       if e["type"] == "term"
                       and e["depth"] == DNS_QUERY_LIMIT]
        self.assertEqual(depth_terms, [])

    def test_exactly_at_budget_is_ok(self):
        # 10 次 RRset 读取恰好落在预算边界内：
        # d0 -> d1 -> ... -> d9，共 10 条记录、9 次 include，
        # TXT 读取 10 次，第 10 次（d9）允许执行并返回 fail。
        chain = []
        for i in range(DNS_QUERY_LIMIT - 1):
            chain.append(make_zone(
                f"d{i}.test.",
                f"v=spf1 include:d{i+1}.test. -all",
            ))
        chain.append(make_zone(f"d{DNS_QUERY_LIMIT - 1}.test.", "v=spf1 -all"))
        result = evaluate(
            chain, "1.1.1.1", mail_from="user@d0.test")
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT)

    def test_a_and_mx_consume_shared_budget(self):
        # 每个 a 读 A + AAAA 两次；初始 TXT 已占 1 次：
        # a#1=查询2,3；a#2=4,5；a#3=6,7；a#4=8,9；a#5 的 A 是第 10 次、
        # AAAA 是第 11 次 -> 第 5 个 a 处超预算
        terms = " ".join(["a"] * (DNS_QUERY_LIMIT + 1))
        zones = [make_zone(
            "x.test.", f"v=spf1 {terms} -all",
            records="@ IN A 10.0.0.1\n",
        )]
        result = evaluate_spf({
            "zones": zones, "client_ip": "8.8.8.8",
            "mail_from": "user@x.test", "helo": "h",
        })
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)
        term_events = [e for e in result["trace"] if e["type"] == "term"]
        self.assertEqual([e["index"] for e in term_events], [0, 1, 2, 3, 4])

    def test_initial_txt_consumes_budget_before_any_mechanism(self):
        # 9 次 include：d0..d9 共 10 条策略 TXT 恰好用满预算，
        # d9 的 a 机制第一次读 A 就是第 11 次 -> permerror
        chain = []
        for i in range(DNS_QUERY_LIMIT - 1):
            chain.append(make_zone(
                f"d{i}.test.",
                f"v=spf1 include:d{i+1}.test. -all",
            ))
        chain.append(make_zone(
            f"d{DNS_QUERY_LIMIT - 1}.test.",
            "v=spf1 a -all",
            records="@ IN A 10.0.0.1\n",
        ))
        result = evaluate(
            chain, "8.8.8.8", mail_from="user@d0.test")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)
        # 最后一个 term 是 a，其 A 读取即超预算
        last_term = [e for e in result["trace"]
                     if e["type"] == "term"][-1]
        self.assertEqual(last_term["mechanism"], "a")
        self.assertEqual(last_term["error"]["reason"], "dns_query_limit")

    def test_eleventh_query_outside_zone_is_still_permerror(self):
        # 第 11 次读取即使目标不被任何区域覆盖，也优先是预算 permerror，
        # 而不是 missing_local_zone temperror。
        # 预算构造：初始 TXT(1) + 4 个 a 的 A/AAAA(8) = 9，
        # 区域外 a 的 A 是第 10 次（在预算内）-> temperror
        zones = [make_zone(
            "x.test.",
            "v=spf1 a a a a a:elsewhere.test. -all",
            records="@ IN A 10.0.0.1\n",
        )]
        result = evaluate_spf({
            "zones": zones, "client_ip": "8.8.8.8",
            "mail_from": "user@x.test", "helo": "h",
        })
        self.assertEqual(result["result"], "temperror")
        self.assertEqual(result["trace"][-1]["reason"], "missing_local_zone")
        self.assertEqual(result["dns_queries"], 10)

        # 把第 10 次查询用掉（隐式 mx 读 MX+A+AAAA 共 3 次），
        # 使区域外 a 的 A 成为第 11 次读取 -> permerror 优先于 temperror
        zones = [make_zone(
            "x.test.",
            "v=spf1 a a a mx a:elsewhere.test. -all",
            records="@ IN A 10.0.0.1\n",
        )]
        result = evaluate_spf({
            "zones": zones, "client_ip": "8.8.8.8",
            "mail_from": "user@x.test", "helo": "h",
        })
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)

    def test_redirect_target_txt_consumes_budget(self):
        # 初始 TXT(1) + redirect 目标 TXT(1) = 2；redirect 本身不另计费
        zones = [
            make_zone("example.com.", "v=spf1 redirect=dest.test."),
            make_zone("dest.test.", "v=spf1 -all"),
        ]
        result = evaluate(zones, "1.1.1.1")
        self.assertEqual(result["result"], "fail")
        self.assertEqual(result["dns_queries"], 2)

    def test_redirect_exhausts_budget_at_eleventh_txt(self):
        # 9 次 include（TXT 共 10 次：d0..d9）后 d9 执行 redirect 到 r：
        # r 的 TXT 是第 11 次读取 -> permerror，redirect 不另计费
        chain = []
        for i in range(DNS_QUERY_LIMIT - 1):
            chain.append(make_zone(
                f"d{i}.test.",
                f"v=spf1 include:d{i+1}.test. -all",
            ))
        chain.append(make_zone(
            f"d{DNS_QUERY_LIMIT - 1}.test.",
            "v=spf1 redirect=r.test.",
        ))
        chain.append(make_zone("r.test.", "v=spf1 -all"))
        result = evaluate(
            chain, "1.1.1.1", mail_from="user@d0.test")
        self.assertEqual(result["result"], "permerror")
        self.assertEqual(result["trace"][-1]["reason"], "dns_query_limit")
        self.assertEqual(result["dns_queries"], DNS_QUERY_LIMIT + 1)


class LocalZoneReferenceTests(unittest.TestCase):
    DELEGATED_PARENT = (
        "$ORIGIN parent.test.\n"
        "$TTL 300\n"
        "@ IN SOA ns host 1 1h 1h 1w 1h\n"
        "@ IN NS ns\n"
        "ns IN A 192.0.2.1\n"
        "sub IN NS ns.sub.parent.test.\n"
        "ns.sub.parent.test. IN A 192.0.2.9\n"
        '@ IN TXT "v=spf1 include:target.sub.parent.test. -all"\n'
    )

    def test_query_outside_any_zone_is_temperror(self):
        zones = [make_zone("example.com.", "v=spf1 redirect=elsewhere.test.")]
        result = evaluate(zones, "1.1.1.1")
        self.assertEqual(result["result"], "temperror")
        self.assertEqual(result["trace"][-1]["reason"],
                         "missing_local_zone")

    def test_query_under_unprovided_delegation_is_temperror(self):
        result = evaluate(
            [self.DELEGATED_PARENT], "1.1.1.1",
            mail_from="user@deep.sub.parent.test",
        )
        self.assertEqual(result["result"], "temperror")
        self.assertEqual(result["trace"][-1]["reason"],
                         "missing_local_zone")

    def test_query_at_cut_name_uses_parent_zone(self):
        # 切点自身由父区回答；无 TXT 即 none（不是 temperror）
        parent = self.DELEGATED_PARENT.split('@ IN TXT')[0]
        result = evaluate(
            [parent], "1.1.1.1",
            mail_from="user@sub.parent.test",
        )
        self.assertEqual(result["result"], "none")

    def test_provided_delegated_child_zone_resolves(self):
        child = (
            "$ORIGIN sub.parent.test.\n"
            "$TTL 300\n"
            "@ IN SOA ns host 1 1h 1h 1w 1h\n"
            "@ IN NS ns.sub.parent.test.\n"
            'ns IN A 192.0.2.9\n'
            'target IN TXT "v=spf1 -all"\n'
        )
        result = evaluate(
            [self.DELEGATED_PARENT, child], "1.1.1.1",
            mail_from="user@parent.test",
        )
        self.assertEqual(result["result"], "fail")

    def test_a_target_in_missing_zone_is_temperror(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 a:mail.elsewhere.test. -all",
        )]
        result = evaluate(zones, "1.1.1.1")
        self.assertEqual(result["result"], "temperror")


class IdentityAndValidationTests(unittest.TestCase):
    def test_empty_mail_from_uses_helo_domain(self):
        zones = [make_zone("helo.example.", "v=spf1 -all")]
        result = evaluate_spf({
            "zones": zones, "client_ip": "1.1.1.1",
            "mail_from": "", "helo": "helo.example",
        })
        self.assertEqual(result["identity"], "helo")
        self.assertEqual(result["domain"], "helo.example.")
        self.assertEqual(result["result"], "fail")

    def test_null_sender_angle_brackets_uses_helo(self):
        zones = [make_zone("helo.example.", "v=spf1 -all")]
        result = evaluate_spf({
            "zones": zones, "client_ip": "1.1.1.1",
            "mail_from": "<>", "helo": "helo.example",
        })
        self.assertEqual(result["identity"], "helo")

    def test_missing_helo_and_empty_mail_from_is_400(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_spf({
                "zones": [make_zone("example.com.", "v=spf1 -all")],
                "client_ip": "1.1.1.1",
                "mail_from": "", "helo": "",
            })
        self.assertEqual(ctx.exception.status, 400)

    def test_ip_literal_identity_rejected(self):
        with self.assertRaises(ReviewError):
            evaluate_spf({
                "zones": [make_zone("example.com.", "v=spf1 -all")],
                "client_ip": "1.1.1.1",
                "mail_from": "user@[1.2.3.4]", "helo": "h",
            })

    def test_invalid_client_ip_rejected(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_spf({
                "zones": [make_zone("example.com.", "v=spf1 -all")],
                "client_ip": "999.1.1.1",
                "mail_from": "a@example.com", "helo": "h",
            })
        self.assertEqual(ctx.exception.status, 400)

    def test_duplicate_zone_origin_rejected(self):
        zone = make_zone("example.com.", "v=spf1 -all")
        with self.assertRaises(ReviewError) as ctx:
            evaluate_spf({
                "zones": [zone, zone], "client_ip": "1.1.1.1",
                "mail_from": "a@example.com", "helo": "h",
            })
        self.assertEqual(ctx.exception.status, 400)

    def test_zone_parse_error_is_422(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_spf({
                "zones": ["$ORIGIN broken.\n@ IN TXT unbalanced\""],
                "client_ip": "1.1.1.1",
                "mail_from": "a@broken", "helo": "h",
            })
        self.assertEqual(ctx.exception.status, 422)


class TraceAndDeterminismTests(unittest.TestCase):
    def _payload(self):
        zones = [
            make_zone(
                "example.com.",
                "v=spf1 mx include:sub.example.com. ~all",
                records="@ IN MX 10 m1\nm1 IN A 192.0.2.11\n",
            ),
            make_zone("sub.example.com.", "v=spf1 ip4:10.0.0.0/8 -all"),
        ]
        return {
            "zones": zones, "client_ip": "203.0.113.1",
            "mail_from": "user@example.com", "helo": "h",
        }

    def test_trace_is_ordered_and_structured(self):
        result = evaluate_spf(self._payload())
        types_ = [e["type"] for e in result["trace"]]
        # policy -> term(mx) -> term(include) -> policy(sub) -> term(ip4)
        #        -> term(all) -> result
        self.assertEqual(types_[0], "policy")
        self.assertEqual(types_[-1], "result")
        self.assertIn("redirect", types_) if False else None
        term_events = [e for e in result["trace"] if e["type"] == "term"]
        self.assertTrue(all("mechanism" in e for e in term_events))
        self.assertTrue(all("matched" in e for e in term_events))
        self.assertTrue(all("result" in e for e in term_events))
        policy_events = [e for e in result["trace"] if e["type"] == "policy"]
        self.assertEqual([p["depth"] for p in policy_events], [0, 1])
        self.assertEqual(policy_events[1]["relation"], "include")

    def test_same_input_stable_output(self):
        r1 = evaluate_spf(self._payload())
        r2 = evaluate_spf(self._payload())
        self.assertEqual(
            json.dumps(r1, ensure_ascii=False, sort_keys=True),
            json.dumps(r2, ensure_ascii=False, sort_keys=True),
        )

    def test_trace_records_match_detail(self):
        zones = [make_zone(
            "example.com.",
            "v=spf1 ip4:192.0.2.0/24 -all",
        )]
        result = evaluate(zones, "192.0.2.9")
        term = next(e for e in result["trace"] if e["type"] == "term")
        self.assertTrue(term["matched"])
        self.assertEqual(term["result"], "pass")
        self.assertEqual(term["detail"]["network"], "192.0.2.0/24")


class ParserUnitTests(unittest.TestCase):
    def test_parse_helpers(self):
        parsed = parse_spf_record(
            "v=spf1 ip4:10.0.0.0/8 a:mail.example.com./24 mx ~all",
            "example.com.",
        )
        self.assertEqual([t.kind for t in parsed.terms],
                         ["ip4", "a", "mx", "all"])
        self.assertIsNone(parsed.redirect)

    def test_parse_redirect(self):
        parsed = parse_spf_record(
            "v=spf1 -all redirect=target.example.com.", "example.com.")
        self.assertEqual(parsed.redirect, "target.example.com.")

    def test_parse_relative_redirect_qualified(self):
        parsed = parse_spf_record(
            "v=spf1 -all redirect=mail", "example.com.")
        self.assertEqual(parsed.redirect, "mail.example.com.")

    def test_parse_bad_record_raises_permerror(self):
        with self.assertRaises(SpfError) as ctx:
            parse_spf_record("not-spf", "example.com.")
        self.assertEqual(ctx.exception.kind, "permerror")


if __name__ == "__main__":
    unittest.main()
