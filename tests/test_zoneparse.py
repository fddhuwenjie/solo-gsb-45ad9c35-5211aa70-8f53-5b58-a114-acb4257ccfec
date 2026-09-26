"""解析与规范化测试。"""

import unittest

from app.zoneparse import parse_zone

BASE = """$ORIGIN example.org.
$TTL 3600
@   IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 3600
@   IN NS  ns1.example.org.
@   IN NS  ns2
ns1 IN A   192.0.2.1
www IN AAAA 2001:db8::1
"""


class ParseTests(unittest.TestCase):
    def test_relative_names_normalized(self):
        zone = parse_zone(BASE)
        self.assertEqual(zone.origin, "example.org.")
        # ns2（相对名）补全为绝对名
        self.assertEqual(
            zone.get("example.org.", "NS").rdata,
            ("ns1.example.org.", "ns2.example.org."),
        )
        # AAAA 压缩规范化
        self.assertEqual(
            zone.get("www.example.org.", "AAAA").rdata, ("2001:db8::1",)
        )

    def test_at_owner_and_omitted_owner_and_ttl_units(self):
        text = """$ORIGIN example.com.
$TTL 1h
@ IN SOA ns host 1 1h 1h 1w 1h
@ IN NS ns
ns IN A 192.0.2.2
www 300 IN A 192.0.2.3
    300 IN A 192.0.2.4
"""
        zone = parse_zone(text)
        self.assertEqual(zone.get("example.com.", "SOA").ttl, 3600)
        soa = zone.get("example.com.", "SOA").rdata[0]
        self.assertEqual(soa[3], "3600")
        self.assertEqual(soa[5], "604800")
        www = zone.get("www.example.com.", "A")
        self.assertEqual(www.ttl, 300)
        self.assertEqual(www.rdata, ("192.0.2.3", "192.0.2.4"))

    def test_parenthesized_soa_multiline(self):
        text = """$ORIGIN x.test.
$TTL 60
@ IN SOA ns admin ( 10 60 60 60 60 )
@ IN NS ns
ns IN A 10.0.0.1
"""
        zone = parse_zone(text)
        self.assertIsNotNone(zone.get("x.test.", "SOA"))

    def test_duplicate_rdata_deduplicated(self):
        text = """$ORIGIN d.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
www IN A 10.1.1.1
www IN A 10.1.1.1
www IN A 10.1.1.2
"""
        zone = parse_zone(text)
        self.assertEqual(
            zone.get("www.d.test.", "A").rdata, ("10.1.1.1", "10.1.1.2")
        )

    def test_shuffled_orders_produce_same_canonical(self):
        z1 = parse_zone(BASE)
        shuffled = """$ORIGIN example.org.
$TTL 3600
www IN AAAA 2001:DB8::1
@   IN NS  ns2
ns1 IN A   192.0.2.1
@   IN NS  ns1.example.org.
@   IN SOA ns1 hostmaster 2024010101 7200 3600 1209600 3600
"""
        z2 = parse_zone(shuffled)
        self.assertEqual(z1.canonical_text(), z2.canonical_text())

    def test_mixed_ttl_same_rrset_is_error(self):
        text = """$ORIGIN t.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
www 60 IN A 1.1.1.1
www 90 IN A 2.2.2.2
"""
        with self.assertRaises(ValueError):
            parse_zone(text)

    def test_missing_origin_is_error(self):
        with self.assertRaises(ValueError):
            parse_zone("@ IN SOA n h 1 60 60 60 60\n")


class MxTxtParseTests(unittest.TestCase):
    BASE = """$ORIGIN mx.test.
$TTL 300
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN MX 10 mail
@ IN MX 20 backup.example.net.
@ IN TXT "v=spf1 -all"
@ IN TXT "two" "strings"
"""

    def test_mx_normalized(self):
        zone = parse_zone(self.BASE)
        self.assertEqual(
            zone.get("mx.test.", "MX").rdata,
            ("10 mail.mx.test.", "20 backup.example.net."),
        )

    def test_txt_keeps_rr_grouping_and_decodes_escapes(self):
        zone = parse_zone(self.BASE)
        rdata = zone.get("mx.test.", "TXT").rdata
        # 两条 RR 各为一个元素；多 character-string 保留分组
        self.assertEqual(rdata, ('"two" "strings"', '"v=spf1 -all"'))

    def test_txt_semicolon_and_paren_inside_quotes(self):
        text = """$ORIGIN t.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN TXT "a;b (c)" ; trailing comment
"""
        zone = parse_zone(text)
        self.assertEqual(zone.get("t.test.", "TXT").rdata, ('"a;b (c)"',))

    def test_txt_decimal_and_quote_escape(self):
        from app.zoneparse import txt_concat
        text = """$ORIGIN t.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN TXT "say \\"hi\\" end \\065x"
"""
        zone = parse_zone(text)
        element = zone.get("t.test.", "TXT").rdata[0]
        self.assertEqual(txt_concat(element), 'say "hi" end Ax')

    def test_txt_multiline_parenthesized(self):
        from app.zoneparse import txt_concat
        text = """$ORIGIN t.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN TXT ( "part1" "part2" )
"""
        zone = parse_zone(text)
        self.assertEqual(
            [txt_concat(x) for x in zone.get("t.test.", "TXT").rdata],
            ["part1part2"],
        )

    def test_txt_duplicate_rr_deduplicated(self):
        text = """$ORIGIN d.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN TXT "same"
@ IN TXT "same"
"""
        zone = parse_zone(text)
        self.assertEqual(zone.get("d.test.", "TXT").rdata, ('"same"',))

    def test_mx_bad_preference_is_error(self):
        text = """$ORIGIN d.test.
$TTL 60
@ IN SOA n h 1 60 60 60 60
@ IN NS n
n IN A 10.0.0.1
@ IN MX 70000 mail
"""
        with self.assertRaises(ValueError):
            parse_zone(text)


if __name__ == "__main__":
    unittest.main()
