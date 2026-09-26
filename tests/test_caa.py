"""离线 CAA 签发授权（app.caa）单元测试与 HTTP 端到端测试。"""

import json
import threading
import unittest
import urllib.error
import urllib.request

from app.caa import MAX_CNAME_HOPS, authorize_caa
from app.review import ReviewError
from app.server import build_server
from app.zoneparse import parse_zone

SOA_NS = "@ IN SOA ns host 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\n"

CA = "letsencrypt.org"


def make_zone(apex: str, records: str = "") -> str:
    lines = [f"$ORIGIN {apex}", "$TTL 300", SOA_NS.rstrip("\n")]
    if records:
        lines.append(records.rstrip("\n"))
    return "\n".join(lines) + "\n"


def authorize(zones, domain="www.example.com.", *, ca_domain=CA,
              wildcard=False, account=None, validation_method=None):
    payload = {
        "zones": zones,
        "domain": domain,
        "wildcard": wildcard,
        "ca_domain": ca_domain,
    }
    if account is not None:
        payload["account"] = account
    if validation_method is not None:
        payload["validation_method"] = validation_method
    return authorize_caa(payload)


def error_of(zones, domain="www.example.com.", **extra):
    try:
        authorize(zones, domain, **extra)
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


class CaaParseTests(unittest.TestCase):
    """RDATA 解析与校验（解析失败 -> 422 zone_parse_error）。"""

    def parse(self, rdata: str):
        zone = parse_zone(make_zone("example.com.", f"www IN CAA {rdata}\n"))
        return zone.get("www.example.com.", "CAA").rdata[0]

    def test_basic_canonical(self):
        self.assertEqual(self.parse('0 issue "letsencrypt.org"'),
                         '0 issue "letsencrypt.org"')

    def test_flags_and_tag_lowercased(self):
        self.assertEqual(self.parse('128 ISSUEWILD "ca.test"'),
                         '128 issuewild "ca.test"')

    def test_critical_bit_parsed(self):
        from app.zoneparse import parse_caa_rdata
        rr = parse_caa_rdata('128 issue "ca"', "example.com.")
        self.assertTrue(rr.critical)
        self.assertEqual(rr.flags, 128)
        rr0 = parse_caa_rdata('0 issue "ca"', "example.com.")
        self.assertFalse(rr0.critical)

    def test_issue_params_structured(self):
        from app.zoneparse import parse_caa_rdata
        rr = parse_caa_rdata(
            '0 issue "letsencrypt.org; validationmethods=http-01,dns-01; '
            'accounturi=https://acct"',
            "example.com.",
        )
        self.assertEqual(rr.issuer, "letsencrypt.org")
        self.assertEqual(rr.accounturi, "https://acct")
        self.assertEqual(rr.validationmethods, ("dns-01", "http-01"))

    def test_param_order_canonical_and_dedup(self):
        # 参数书写顺序不同、validationmethods 顺序不同 -> 同一规范 RDATA
        z1 = self.parse(
            '0 issue "ca; validationmethods=http-01,dns-01; accounturi=a"'
        )
        z2 = self.parse(
            '0 issue "ca; accounturi=a; validationmethods=dns-01,http-01"'
        )
        self.assertEqual(z1, z2)
        zone = parse_zone(make_zone(
            "example.com.",
            'www IN CAA 0 issue "ca; validationmethods=http-01,dns-01"\n'
            'www IN CAA 0 issue "ca; validationmethods=dns-01,http-01"\n',
        ))
        self.assertEqual(len(zone.get("www.example.com.", "CAA").rdata), 1)

    def test_unquoted_single_token_value(self):
        self.assertEqual(self.parse("0 iodef mailto:abuse@example.com"),
                         '0 iodef "mailto:abuse@example.com"')

    def test_empty_issuer(self):
        from app.zoneparse import parse_caa_rdata
        rr = parse_caa_rdata('0 issue ";"', "example.com.")
        self.assertEqual(rr.issuer, "")
        self.assertEqual(rr.value, ";")

    def test_bad_flags(self):
        for bad in ("256", "-1", "x", "1.5"):
            with self.subTest(bad=bad):
                with self.assertRaises(Exception):
                    self.parse(f'{bad} issue "ca"')

    def test_bad_tag(self):
        for bad in ("is_sue", "tag-1", "is.sue", "a" * 256):
            with self.subTest(bad=bad[:10]):
                with self.assertRaises(Exception):
                    self.parse(f'0 {bad} "ca"')

    def test_multiple_char_strings_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self.parse('0 issue "letsencrypt.org" "extra"')
        self.assertIn("单个 <character-string>", str(ctx.exception))

    def test_bad_issuer_domain(self):
        with self.assertRaises(Exception):
            self.parse('0 issue "bad..name"')

    def test_bad_param_syntax(self):
        with self.assertRaises(Exception):
            self.parse('0 issue "ca; noparam"')
        with self.assertRaises(Exception):
            self.parse('0 issue "ca; bad-name=x"')

    def test_duplicate_param_rejected(self):
        with self.assertRaises(Exception):
            self.parse('0 issue "ca; accounturi=a; accounturi=b"')

    def test_empty_validationmethods_rejected(self):
        with self.assertRaises(Exception):
            self.parse('0 issue "ca; validationmethods="')
        with self.assertRaises(Exception):
            self.parse('0 issue "ca; validationmethods=,"')


class BasicAuthorizeTests(unittest.TestCase):
    def test_no_caa_allows_to_apex(self):
        zone = make_zone("example.com.")
        result = authorize([zone], "deep.www.example.com.")
        self.assertEqual(result["status"], "allowed")
        self.assertTrue(result["allowed"])
        self.assertEqual(result["reason"], "no_caa_record")
        self.assertIsNone(result["relevant"])
        self.assertEqual(result["matched"], [])
        actions = [e["action"] for e in result["trace"]]
        self.assertEqual(actions.count("climb"), 3)
        self.assertIn("apex_no_caa", actions)
        self.assertEqual(actions[-1], "result")

    def test_single_label_apex_no_parent_crash(self):
        # 单标签区顶（如 com.）的父域是根：到区顶无 CAA 即允许，不应崩溃
        zone = make_zone("com.")
        result = authorize([zone], "com.")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["reason"], "no_caa_record")

    def test_issue_match_allows(self):
        zone = make_zone("example.com.",
                         'www IN CAA 0 issue "letsencrypt.org"\n')
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["owner"], "www.example.com.")
        (hit,) = result["matched"]
        self.assertEqual(hit["tag"], "issue")
        self.assertEqual(hit["issuer"], "letsencrypt.org")

    def test_ca_mismatch_denies(self):
        zone = make_zone("example.com.",
                         'www IN CAA 0 issue "other-ca.test"\n')
        result = authorize([zone])
        self.assertEqual(result["status"], "denied")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "no_matching_record")
        rec = result["relevant"]["records"][0]
        self.assertFalse(rec["matched"])
        self.assertEqual(rec["reason"], "ca_mismatch")

    def test_empty_issuer_denies_everyone(self):
        zone = make_zone("example.com.", 'www IN CAA 0 issue ";"\n')
        result = authorize([zone])
        self.assertEqual(result["status"], "denied")
        self.assertEqual(
            result["relevant"]["records"][0]["reason"], "empty_issuer"
        )

    def test_climb_finds_first_rrset_at_ancestor(self):
        # www 本身无 CAA，example.com. 区顶的 CAA 是首个相关 RRset
        zone = make_zone("example.com.",
                         '@ IN CAA 0 issue "letsencrypt.org"\n')
        result = authorize([zone], "www.example.com.")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["owner"], "example.com.")
        actions = [e["action"] for e in result["trace"]]
        self.assertEqual(actions, ["climb", "found", "result"])

    def test_second_issuer_in_rrset_matches(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 0 issue "a-ca.test"\n'
            'www IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")
        (hit,) = result["matched"]
        self.assertEqual(hit["issuer"], "letsencrypt.org")


class WildcardTests(unittest.TestCase):
    def test_issuewild_preferred(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 0 issue "letsencrypt.org"\n'
            'www IN CAA 0 issuewild "other-ca.test"\n',
        )
        result = authorize([zone], wildcard=True)
        # issuewild 存在时绝不回退 issue：即使 issue 匹配也拒绝
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["relevant"]["applicable_tag"], "issuewild")

    def test_issuewild_match(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 0 issue "other-ca.test"\n'
            'www IN CAA 0 issuewild "letsencrypt.org"\n',
        )
        result = authorize([zone], wildcard=True)
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["matched"][0]["tag"], "issuewild")

    def test_issuewild_absent_falls_back_to_issue(self):
        zone = make_zone("example.com.",
                         'www IN CAA 0 issue "letsencrypt.org"\n')
        result = authorize([zone], wildcard=True)
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["applicable_tag"], "issue")

    def test_non_wildcard_ignores_issuewild(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 0 issue "letsencrypt.org"\n'
            'www IN CAA 0 issuewild "other-ca.test"\n',
        )
        result = authorize([zone], wildcard=False)
        self.assertEqual(result["status"], "allowed")


class UnknownPropertyTests(unittest.TestCase):
    def test_unknown_critical_denies(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 128 foo "bar"\n'
            'www IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "denied")
        self.assertEqual(result["reason"], "unknown_critical_property")
        self.assertEqual(result["relevant"]["critical_unknown"], ["foo"])

    def test_unknown_non_critical_ignored(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 1 foo "bar"\n'
            'www IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")
        self.assertNotIn("critical_unknown", result["relevant"])
        foo = next(r for r in result["relevant"]["records"] if r["tag"] == "foo")
        self.assertTrue(foo["ignored"])

    def test_iodef_never_critical_unknown(self):
        zone = make_zone(
            "example.com.",
            'www IN CAA 128 iodef "mailto:a@example.com"\n'
            'www IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")


class ParameterTests(unittest.TestCase):
    ZONE_TMPL = 'www IN CAA 0 issue "letsencrypt.org{extra}"\n'

    def zone(self, extra):
        return make_zone("example.com.", self.ZONE_TMPL.format(extra=extra))

    def test_account_match(self):
        zone = self.zone("; accounturi=https://acct")
        result = authorize([zone], account="https://acct")
        self.assertEqual(result["status"], "allowed")

    def test_account_mismatch(self):
        zone = self.zone("; accounturi=https://acct")
        result = authorize([zone], account="https://other")
        self.assertEqual(result["status"], "denied")
        self.assertEqual(
            result["relevant"]["records"][0]["reason"], "account_mismatch"
        )

    def test_record_requires_account_but_request_omits(self):
        zone = self.zone("; accounturi=https://acct")
        result = authorize([zone])
        self.assertEqual(result["status"], "denied")

    def test_account_without_record_constraint_allowed(self):
        zone = make_zone("example.com.",
                         'www IN CAA 0 issue "letsencrypt.org"\n')
        result = authorize([zone], account="https://anything")
        self.assertEqual(result["status"], "allowed")

    def test_validation_method_in_list(self):
        zone = self.zone("; validationmethods=dns-01,http-01")
        self.assertEqual(
            authorize([zone], validation_method="http-01")["status"],
            "allowed",
        )

    def test_validation_method_not_in_list(self):
        zone = self.zone("; validationmethods=dns-01")
        result = authorize([zone], validation_method="http-01")
        self.assertEqual(result["status"], "denied")
        self.assertEqual(
            result["relevant"]["records"][0]["reason"],
            "validation_method_mismatch",
        )

    def test_record_requires_method_but_request_omits(self):
        zone = self.zone("; validationmethods=http-01")
        self.assertEqual(authorize([zone])["status"], "denied")


class CnameRestartTests(unittest.TestCase):
    def test_restart_at_target(self):
        zone = make_zone(
            "example.com.",
            "www IN CNAME host\n"
            'host IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["cname_hops"], 1)
        actions = [e["action"] for e in result["trace"]]
        self.assertEqual(actions[0], "cname")
        self.assertEqual(result["trace"][0]["target"], "host.example.com.")
        self.assertEqual(result["relevant"]["owner"], "host.example.com.")

    def test_restart_then_climb_targets_tree(self):
        # CNAME 到 host；host 无 CAA，向 example.com 区顶攀爬命中
        zone = make_zone(
            "example.com.",
            "www IN CNAME host\n"
            'host IN A 192.0.2.5\n'
            '@ IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["owner"], "example.com.")

    def test_self_loop(self):
        zone = make_zone("example.com.", "www IN CNAME www\n")
        exc = error_of([zone])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "caa_cname_loop")

    def test_two_node_loop(self):
        zone = make_zone("example.com.",
                         "a IN CNAME b\nb IN CNAME a\n")
        exc = error_of([zone], domain="a.example.com.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "caa_cname_loop")

    def _chain_zone(self, links: int) -> str:
        records = "".join(
            f"h{i} IN CNAME h{i + 1}\n" for i in range(links)
        )
        records += 'h{} IN CAA 0 issue "letsencrypt.org"\n'.format(links)
        return make_zone("example.com.", records)

    def test_hops_limit(self):
        result = authorize([self._chain_zone(MAX_CNAME_HOPS)],
                           domain="h0.example.com.")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["cname_hops"], MAX_CNAME_HOPS)

        exc = error_of([self._chain_zone(MAX_CNAME_HOPS + 1)],
                       domain="h0.example.com.")
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "caa_too_many_cname_hops")


class DelegationTests(unittest.TestCase):
    PARENT = make_zone(
        "example.com.",
        "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n",
    )

    def test_undelegated_cut_is_indeterminate(self):
        result = authorize([self.PARENT], "www.sub.example.com.")
        self.assertEqual(result["status"], "indeterminate")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "missing_local_zone")
        self.assertIsNone(result["relevant"])

    def test_outside_any_zone_is_indeterminate(self):
        result = authorize([self.PARENT], "www.elsewhere.test.")
        self.assertEqual(result["status"], "indeterminate")

    def test_cut_itself_served_by_parent(self):
        zone = make_zone(
            "example.com.",
            "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n"
            'sub IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([zone], "sub.example.com.")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["owner"], "sub.example.com.")

    def test_provided_child_zone_resolves(self):
        child = make_zone(
            "sub.example.com.",
            'www IN CAA 0 issue "letsencrypt.org"\n',
        )
        result = authorize([self.PARENT, child], "www.sub.example.com.")
        self.assertEqual(result["status"], "allowed")
        self.assertEqual(result["relevant"]["owner"], "www.sub.example.com.")

    def test_cname_into_undelegated_cut_indeterminate(self):
        zone = make_zone(
            "example.com.",
            "www IN CNAME host.sub\n"
            "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n",
        )
        result = authorize([zone])
        self.assertEqual(result["status"], "indeterminate")
        self.assertEqual(result["cname_hops"], 1)


class RequestValidationTests(unittest.TestCase):
    ZONE = make_zone("example.com.",
                     'www IN CAA 0 issue "letsencrypt.org"\n')

    def test_bad_domain(self):
        self.assertEqual(error_of([self.ZONE], "").status, 400)
        self.assertEqual(error_of([self.ZONE], "bad..name.").status, 400)

    def test_bad_ca_domain(self):
        exc = error_of([self.ZONE], ca_domain="not a name")
        self.assertEqual(exc.status, 400)

    def test_bad_wildcard(self):
        payload = {
            "zones": [self.ZONE], "domain": "www.example.com.",
            "wildcard": "yes", "ca_domain": CA,
        }
        with self.assertRaises(ReviewError) as ctx:
            authorize_caa(payload)
        self.assertEqual(ctx.exception.status, 400)

    def test_bad_zones(self):
        self.assertEqual(error_of([]).status, 400)
        self.assertEqual(error_of([""]).status, 400)

    def test_zone_parse_error_is_422(self):
        zone = "$ORIGIN example.com.\nwww IN CAA 999 issue ca\n"
        exc = error_of([zone])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "zone_parse_error")

    def test_name_normalized(self):
        r1 = authorize([self.ZONE], "WWW.Example.COM")
        r2 = authorize([self.ZONE], "www.example.com.")
        self.assertEqual(r1["domain"], "www.example.com.")
        self.assertEqual(
            json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True)
        )

    def test_same_input_stable_output(self):
        r1 = authorize([self.ZONE])
        r2 = authorize([self.ZONE])
        self.assertEqual(
            json.dumps(r1, sort_keys=True), json.dumps(r2, sort_keys=True)
        )


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


class CaaApiTests(unittest.TestCase):
    ZONE = make_zone(
        "example.com.",
        'www IN CAA 0 issue "letsencrypt.org; accounturi=https://acct"\n',
    )

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

    def _authorize(self, **overrides):
        payload = {
            "zones": [self.ZONE],
            "domain": "www.example.com.",
            "wildcard": False,
            "ca_domain": "letsencrypt.org",
            "account": "https://acct",
        }
        payload.update(overrides)
        return _request(self.base + "/api/caa/authorize", payload)

    def test_authorize_over_http(self):
        status, body = self._authorize()
        self.assertEqual(status, 200, body)
        caa = body["caa"]
        self.assertEqual(caa["status"], "allowed")
        self.assertTrue(caa["allowed"])
        self.assertEqual(caa["matched"][0]["accounturi"], "https://acct")

    def test_denied_is_200(self):
        status, body = self._authorize(account="https://wrong")
        self.assertEqual(status, 200)
        self.assertEqual(body["caa"]["status"], "denied")

    def test_indeterminate_is_200(self):
        zone = make_zone(
            "example.com.",
            "sub IN NS ns.sub\nns.sub IN A 192.0.2.9\n",
        )
        status, body = self._authorize(
            zones=[zone], domain="www.sub.example.com."
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["caa"]["status"], "indeterminate")

    def test_cname_loop_is_422(self):
        zone = make_zone("example.com.",
                         "a IN CNAME b\nb IN CNAME a\n")
        status, body = self._authorize(zones=[zone],
                                       domain="a.example.com.")
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "caa_cname_loop")

    def test_zone_parse_error_is_422(self):
        bad = "$ORIGIN example.com.\n$TTL 300\n" + SOA_NS + \
              'www IN CAA 999 issue "ca"\n'
        status, body = self._authorize(zones=[bad])
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "zone_parse_error")

    def test_request_format_error_is_400(self):
        status, body = self._authorize(domain="")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
