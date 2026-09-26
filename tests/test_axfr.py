"""AXFR 响应流检查（app.axfr）单元测试与 HTTP 端到端测试。

测试里的报文用小型 wire 编码器现场构造，覆盖名称压缩（含跨记录指针）、
各类结构违例与全部解析错误分支。
"""

import base64
import json
import struct
import threading
import unittest
import urllib.error
import urllib.request

from app.axfr import inspect_axfr
from app.review import ReviewError, perform_review
from app.server import build_server
from app.zoneparse import parse_zone

ORIGIN = "example.com."
SERIAL = 2024010100

# 类型号（与 app.zonemd.TYPE_CODES 一致）
T_A, T_NS, T_CNAME, T_SOA, T_MX, T_TXT = 1, 2, 5, 6, 15, 16
T_AAAA, T_TLSA, T_ZONEMD, T_SVCB, T_HTTPS, T_CAA = 28, 52, 63, 64, 65, 257


# ---------------------------------------------------------------------------
# wire 编码辅助
# ---------------------------------------------------------------------------

def name_wire(name: str) -> bytes:
    """不压缩的完整 wire 名称。"""
    if name == ".":
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def ptr(offset: int) -> bytes:
    """指向报文内 offset 的压缩指针。"""
    return struct.pack("!H", 0xC000 | offset)


def header(mid, qd, an, flags=0x8000):
    return struct.pack("!HHHHHH", mid, flags, qd, an, 0, 0)


def question(name=ORIGIN, qtype=252, qclass=1):
    return name_wire(name) + struct.pack("!HH", qtype, qclass)


def record(owner_wire, rtype, ttl, rdata, rclass=1):
    return (
        owner_wire
        + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata))
        + rdata
    )


def soa_rdata(mname_wire, rname_wire, serial=SERIAL,
              refresh=600, retry=300, expire=86400, minimum=300):
    return mname_wire + rname_wire + struct.pack(
        "!IIIII", serial, refresh, retry, expire, minimum
    )


def stream_b64(*frames: bytes) -> str:
    data = b"".join(struct.pack("!H", len(f)) + f for f in frames)
    return base64.b64encode(data).decode("ascii")


MID = 0x1234


def good_frames():
    """两帧完整 AXFR：帧 1 带问题区与 SOA/NS×2，帧 2 问题区为空。

    帧 1 的 owner 与 RDATA 名称均压缩指向问题区（偏移 12）；
    帧 2 内 ``example.com.`` 出现在偏移 16、``ns1.example.com.``
    出现在偏移 12，后续记录用帧内指针引用。
    """
    apex = ptr(12)
    soa = record(apex, T_SOA, 300,
                 soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
    ns1 = record(apex, T_NS, 300, b"\x03ns1" + ptr(12))
    ns2 = record(apex, T_NS, 300, b"\x03ns2" + ptr(12))
    frame1 = header(MID, 1, 3) + question() + soa + ns1 + ns2

    a1 = record(name_wire("ns1.example.com."), T_A, 300,
                bytes([192, 0, 2, 10]))
    a2 = record(b"\x03ns2" + ptr(16), T_A, 300, bytes([192, 0, 2, 11]))
    a3 = record(b"\x03www" + ptr(16), T_A, 300, bytes([192, 0, 2, 80]))
    soa_end = record(ptr(16), T_SOA, 300,
                     soa_rdata(ptr(12), b"\x05admin" + ptr(16)))
    frame2 = header(MID, 0, 4) + a1 + a2 + a3 + soa_end
    return [frame1, frame2]


EXPECTED_ZONE = (
    "$ORIGIN example.com.\n"
    "example.com. 300 IN NS ns1.example.com.\n"
    "example.com. 300 IN NS ns2.example.com.\n"
    "example.com. 300 IN SOA ns1.example.com. admin.example.com. "
    "2024010100 600 300 86400 300\n"
    "ns1.example.com. 300 IN A 192.0.2.10\n"
    "ns2.example.com. 300 IN A 192.0.2.11\n"
    "www.example.com. 300 IN A 192.0.2.80\n"
)


def inspect(frames, origin=ORIGIN):
    return inspect_axfr({"zone_origin": origin, "stream": stream_b64(*frames)})


def error_of(frames, origin=ORIGIN):
    try:
        inspect(frames, origin)
    except ReviewError as exc:
        return exc
    raise AssertionError("应当抛出 ReviewError")


# ---------------------------------------------------------------------------
# 完整传输
# ---------------------------------------------------------------------------

class CompleteTransferTests(unittest.TestCase):
    def test_complete_two_frames_with_compression(self):
        result = inspect(good_frames())
        self.assertEqual(result["status"], "complete", result)
        self.assertEqual(result["zone_origin"], ORIGIN)
        self.assertEqual(result["message_count"], 2)
        self.assertEqual(result["record_count"], 7)
        self.assertEqual(result["zone"], EXPECTED_ZONE)

    def test_trace_arranged_by_frame_and_record(self):
        result = inspect(good_frames())
        trace = result["trace"]
        self.assertEqual([t["frame"] for t in trace], [1, 2])
        self.assertEqual(trace[0]["message_id"], MID)
        self.assertEqual(
            trace[0]["questions"],
            [{"qname": ORIGIN, "qtype": "AXFR", "qclass": "IN"}],
        )
        self.assertEqual(trace[1]["questions"], [])
        seqs = [a["seq"] for t in trace for a in t["answers"]]
        self.assertEqual(seqs, list(range(1, 8)))
        first = trace[0]["answers"][0]
        self.assertEqual(
            first,
            {
                "seq": 1,
                "owner": ORIGIN,
                "type": "SOA",
                "ttl": 300,
                "rdata": "ns1.example.com. admin.example.com. "
                         "2024010100 600 300 86400 300",
            },
        )

    def test_zone_text_roundtrips_and_feeds_review(self):
        result = inspect(good_frames())
        # 规范区域文本可被区域解析器原样回读（再规范化结果不变）
        self.assertEqual(parse_zone(result["zone"]).canonical_text(),
                         result["zone"])
        # 可直接交给现有审查接口
        new_zone = (
            result["zone"].replace("2024010100", "2024010101")
            + "new.example.com. 300 IN A 192.0.2.30\n"
        )
        review = perform_review(
            {"old_zone": result["zone"], "new_zone": new_zone}
        )
        self.assertTrue(review["safe"])

    def test_subsequent_frames_may_repeat_question(self):
        # 后续帧问题区与首帧相同也合法（帧内偏移随之变化，全部用全名）
        frame1, _ = good_frames()
        recs = [
            record(name_wire("ns1.example.com."), T_A, 300,
                   bytes([192, 0, 2, 10])),
            record(name_wire("ns2.example.com."), T_A, 300,
                   bytes([192, 0, 2, 11])),
            record(name_wire("www.example.com."), T_A, 300,
                   bytes([192, 0, 2, 80])),
            record(name_wire("example.com."), T_SOA, 300,
                   soa_rdata(name_wire("ns1.example.com."),
                             name_wire("admin.example.com."))),
        ]
        frame2 = header(MID, 1, len(recs)) + question() + b"".join(recs)
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "complete", result)
        self.assertEqual(result["zone"], EXPECTED_ZONE)

    def test_all_supported_types_round_trip(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        ns = record(apex, T_NS, 300, b"\x03ns1" + ptr(12))
        frame1 = header(MID, 1, 2) + question() + soa + ns
        txt = bytes([5]) + b"v=spf" + bytes([3]) + b"1 a"
        caa = bytes([0, 5]) + b"issue" + b"letsencrypt.org"
        https = (
            struct.pack("!H", 1) + b"\x00"
            + struct.pack("!HH", 1, 3) + bytes([2]) + b"h2"
            + struct.pack("!HH", 3, 2) + struct.pack("!H", 443)
        )
        recs = [
            record(name_wire("ns1.example.com."), T_A, 300,
                   bytes([192, 0, 2, 10])),
            record(name_wire("ns1.example.com."), T_AAAA, 300,
                   bytes.fromhex("20010db8" + "00" * 11 + "10")),
            record(name_wire("alias.example.com."), T_CNAME, 300,
                   name_wire("www.example.com.")),
            record(name_wire("example.com."), T_MX, 300,
                   struct.pack("!H", 10) + name_wire("mail.example.com.")),
            record(name_wire("example.com."), T_TXT, 300, txt),
            record(name_wire("example.com."), T_CAA, 300, caa),
            record(name_wire("_443._tcp.www.example.com."), T_TLSA, 300,
                   bytes([3, 1, 1]) + bytes.fromhex("ab" * 32)),
            record(name_wire("example.com."), T_ZONEMD, 300,
                   struct.pack("!IBB", SERIAL, 1, 1)
                   + bytes.fromhex("cd" * 48)),
            record(name_wire("svc.example.com."), T_HTTPS, 300, https),
            record(name_wire("example.com."), T_SOA, 300,
                   soa_rdata(name_wire("ns1.example.com."),
                             name_wire("admin.example.com."))),
        ]
        frame2 = header(MID, 0, len(recs)) + b"".join(recs)
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "complete", result)
        zone = parse_zone(result["zone"])
        self.assertEqual(zone.get(ORIGIN, "TXT").rdata, ('"v=spf" "1 a"',))
        self.assertEqual(zone.get(ORIGIN, "CAA").rdata,
                         ('0 issue "letsencrypt.org"',))
        self.assertEqual(zone.get("svc.example.com.", "HTTPS").rdata,
                         ("1 . alpn=h2 port=443",))
        self.assertEqual(zone.get(ORIGIN, "ZONEMD").rdata,
                         (f"{SERIAL} 1 1 " + "cd" * 48,))
        self.assertEqual(
            zone.get("_443._tcp.www.example.com.", "TLSA").rdata,
            ("3 1 1 " + "ab" * 32,),
        )
        self.assertEqual(zone.get("alias.example.com.", "CNAME").rdata,
                         ("www.example.com.",))
        self.assertEqual(zone.get(ORIGIN, "MX").rdata,
                         ("10 mail.example.com.",))
        self.assertEqual(zone.get("ns1.example.com.", "AAAA").rdata,
                         ("2001:db8::10",))


# ---------------------------------------------------------------------------
# incomplete
# ---------------------------------------------------------------------------

class IncompleteTests(unittest.TestCase):
    def test_empty_stream(self):
        result = inspect_axfr({"zone_origin": ORIGIN, "stream": ""})
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["message_count"], 0)
        self.assertEqual(result["record_count"], 0)
        self.assertNotIn("zone", result)

    def test_no_answers_at_all(self):
        frame = header(MID, 1, 0) + question()
        result = inspect([frame])
        self.assertEqual(result["status"], "incomplete")

    def test_missing_closing_soa(self):
        frame1, _ = good_frames()  # 只有起始 SOA
        result = inspect([frame1])
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("闭合 SOA", result["reason"])

    def test_answers_after_closing_soa(self):
        frame1, _ = good_frames()
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        extra = record(name_wire("www.example.com."), T_A, 300,
                       bytes([192, 0, 2, 80]))
        frame2 = header(MID, 0, 3) + a1 + closing + extra
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("之后仍有", result["reason"])


# ---------------------------------------------------------------------------
# invalid
# ---------------------------------------------------------------------------

class InvalidTests(unittest.TestCase):
    def test_first_question_must_be_in_axfr(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        # qtype 不是 AXFR
        frame = header(MID, 1, 1) + question(qtype=T_A) + soa
        self.assertEqual(inspect([frame])["status"], "invalid")
        # qname 不是目标区
        frame = header(MID, 1, 1) + question("other.com.") + soa
        self.assertEqual(inspect([frame])["status"], "invalid")
        # 首帧没有问题区（无问题区可指，记录用全名构造）
        soa_full = record(
            name_wire("example.com."), T_SOA, 300,
            soa_rdata(name_wire("ns1.example.com."),
                      name_wire("admin.example.com.")),
        )
        frame = header(MID, 0, 1) + soa_full
        self.assertEqual(inspect([frame])["status"], "invalid")

    def test_header_flag_violations(self):
        frame1, frame2 = good_frames()
        good_q = question()
        cases = {
            "qr0": 0x0000,
            "tc1": 0x8000 | 0x0200,
            "rcode3": 0x8000 | 0x0003,
            "opcode1": 0x8000 | (1 << 11),
        }
        for name, flags in cases.items():
            with self.subTest(case=name):
                bad = header(MID, 1, 0, flags=flags) + good_q
                self.assertEqual(inspect([bad, frame2])["status"], "invalid")

    def test_id_mismatch(self):
        frame1, frame2 = good_frames()
        # 重新生成 ID 不同的第二帧
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2_bad = header(0x9999, 0, 2) + a1 + closing
        result = inspect([frame1, frame2_bad])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("ID", result["reason"])

    def test_subsequent_question_differs(self):
        frame1, _ = good_frames()
        frame2 = header(MID, 1, 0) + question("other.com.")
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")

    def test_first_answer_not_apex_soa(self):
        ns = record(ptr(12), T_NS, 300, b"\x03ns1" + ptr(12))
        frame = header(MID, 1, 1) + question() + ns
        self.assertEqual(inspect([frame])["status"], "invalid")
        # SOA 但 owner 不是区顶
        soa = record(name_wire("sub.example.com."), T_SOA, 300,
                     soa_rdata(name_wire("ns1.example.com."),
                               name_wire("admin.example.com.")))
        frame = header(MID, 1, 1) + question() + soa
        self.assertEqual(inspect([frame])["status"], "invalid")

    def test_middle_soa_invalid(self):
        frame1, _ = good_frames()
        dup_soa = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2 = header(MID, 0, 3) + dup_soa + a1 + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("不得再出现 SOA", result["reason"])

    def test_closing_soa_differs(self):
        frame1, _ = good_frames()
        closing = record(
            name_wire("example.com."), T_SOA, 300,
            soa_rdata(name_wire("ns1.example.com."),
                      name_wire("admin.example.com."), serial=SERIAL + 1),
        )
        frame2 = header(MID, 0, 1) + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("不完全相同", result["reason"])

    def test_owner_out_of_zone(self):
        frame1, _ = good_frames()
        bad = record(name_wire("www.other.com."), T_A, 300,
                     bytes([192, 0, 2, 80]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2 = header(MID, 0, 2) + bad + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("不在区", result["reason"])

    def test_duplicate_record(self):
        frame1, _ = good_frames()
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2 = header(MID, 0, 3) + a1 + a1 + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("重复记录", result["reason"])

    def test_rrset_ttl_mismatch(self):
        frame1, _ = good_frames()
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]))
        a2 = record(name_wire("ns1.example.com."), T_A, 600,
                    bytes([192, 0, 2, 11]))
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2 = header(MID, 0, 3) + a1 + a2 + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("TTL", result["reason"])

    def test_non_in_class(self):
        frame1, _ = good_frames()
        a1 = record(name_wire("ns1.example.com."), T_A, 300,
                    bytes([192, 0, 2, 10]), rclass=3)
        closing = record(name_wire("example.com."), T_SOA, 300,
                         soa_rdata(name_wire("ns1.example.com."),
                                   name_wire("admin.example.com.")))
        frame2 = header(MID, 0, 2) + a1 + closing
        result = inspect([frame1, frame2])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("类不是 IN", result["reason"])


# ---------------------------------------------------------------------------
# 422 解析错误
# ---------------------------------------------------------------------------

class ParseErrorTests(unittest.TestCase):
    def test_compression_pointer_loop(self):
        # 问题名就是一个指向自身（偏移 12）的指针
        frame = header(MID, 1, 0) + ptr(12) + struct.pack("!HH", 252, 1)
        exc = error_of([frame])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "compression_pointer_loop")

    def test_compression_pointer_chain_loop(self):
        # 偏移 12 的指针指向 14，14 又指回 12
        frame = (
            header(MID, 1, 0)
            + ptr(14) + ptr(12)
            + struct.pack("!HH", 252, 1)
        )
        exc = error_of([frame])
        self.assertEqual(exc.code, "compression_pointer_loop")

    def test_compression_pointer_out_of_bounds(self):
        frame = header(MID, 1, 0) + ptr(0x3FFF) + struct.pack("!HH", 252, 1)
        exc = error_of([frame])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "compression_pointer_out_of_bounds")

    def test_frame_body_truncated(self):
        frame1, _ = good_frames()
        data = struct.pack("!H", len(frame1)) + frame1
        data += struct.pack("!H", 100) + b"\x00" * 10  # 声明 100 只剩 10
        stream = base64.b64encode(data).decode()
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": ORIGIN, "stream": stream})
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, "frame_truncated")

    def test_length_prefix_truncated(self):
        stream = base64.b64encode(b"\x00").decode()
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": ORIGIN, "stream": stream})
        self.assertEqual(ctx.exception.code, "frame_truncated")

    def test_header_truncated(self):
        exc = error_of([b"\x12\x34\x80"])
        self.assertEqual(exc.code, "frame_truncated")

    def test_name_truncated(self):
        # 问题名标签声明 7 字节但报文到此结束
        frame = header(MID, 1, 0) + b"\x07exa"
        exc = error_of([frame])
        self.assertEqual(exc.code, "frame_truncated")

    def test_rdata_length_mismatch_fixed_size(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        bad_a = record(name_wire("ns1.example.com."), T_A, 300,
                       b"\x01\x02\x03\x04\x05")  # A 应为 4 字节
        frame = header(MID, 1, 2) + question() + soa + bad_a
        exc = error_of([frame])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "rdata_length_mismatch")

    def test_rdata_length_mismatch_name(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        # NS 名称后多出一个字节，RDLENGTH 与名称消费不符
        bad_ns = record(apex, T_NS, 300, b"\x03ns1" + ptr(12) + b"\x00")
        frame = header(MID, 1, 2) + question() + soa + bad_ns
        exc = error_of([frame])
        self.assertEqual(exc.code, "rdata_length_mismatch")

    def test_txt_empty_rdata(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        bad_txt = record(apex, T_TXT, 300, b"")
        frame = header(MID, 1, 2) + question() + soa + bad_txt
        exc = error_of([frame])
        self.assertEqual(exc.code, "invalid_rdata")

    def test_unsupported_type(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        unknown = record(apex, 99, 300, b"\x01\x02")
        frame = header(MID, 1, 2) + question() + soa + unknown
        exc = error_of([frame])
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "unsupported_type")

    def test_ttl_out_of_range(self):
        apex = ptr(12)
        soa = record(apex, T_SOA, 300,
                     soa_rdata(b"\x03ns1" + ptr(12), b"\x05admin" + ptr(12)))
        big_ttl = record(apex, T_NS, 2**31, b"\x03ns1" + ptr(12))
        frame = header(MID, 1, 2) + question() + soa + big_ttl
        exc = error_of([frame])
        self.assertEqual(exc.code, "invalid_record")


# ---------------------------------------------------------------------------
# 请求格式（400）
# ---------------------------------------------------------------------------

class RequestValidationTests(unittest.TestCase):
    def test_missing_fields(self):
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"stream": "AA=="})
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": ORIGIN})
        self.assertEqual(ctx.exception.status, 400)

    def test_bad_origin(self):
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": "bad..name", "stream": ""})
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": 42, "stream": ""})
        self.assertEqual(ctx.exception.status, 400)

    def test_bad_base64(self):
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": ORIGIN, "stream": "!!!not-b64!!!"})
        self.assertEqual(ctx.exception.status, 400)
        with self.assertRaises(ReviewError) as ctx:
            inspect_axfr({"zone_origin": ORIGIN, "stream": 123})
        self.assertEqual(ctx.exception.status, 400)

    def test_origin_normalization(self):
        # 大小写与结尾根点不影响目标区判定
        result = inspect(good_frames(), origin="Example.COM")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["zone_origin"], ORIGIN)


# ---------------------------------------------------------------------------
# HTTP 端到端
# ---------------------------------------------------------------------------

def _request(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


class AxfrApiTests(unittest.TestCase):
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

    def test_complete_over_http(self):
        payload = {"zone_origin": ORIGIN, "stream": stream_b64(*good_frames())}
        status, body = _request(self.base + "/api/axfr/inspect", payload)
        self.assertEqual(status, 200, body)
        axfr = body["axfr"]
        self.assertEqual(axfr["status"], "complete")
        self.assertEqual(axfr["message_count"], 2)
        self.assertEqual(axfr["record_count"], 7)
        self.assertEqual(axfr["zone"], EXPECTED_ZONE)

    def test_incomplete_over_http(self):
        frame1, _ = good_frames()
        payload = {"zone_origin": ORIGIN, "stream": stream_b64(frame1)}
        status, body = _request(self.base + "/api/axfr/inspect", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["axfr"]["status"], "incomplete")
        self.assertNotIn("zone", body["axfr"])

    def test_parse_error_is_422(self):
        frame = header(MID, 1, 0) + ptr(12) + struct.pack("!HH", 252, 1)
        payload = {"zone_origin": ORIGIN, "stream": stream_b64(frame)}
        status, body = _request(self.base + "/api/axfr/inspect", payload)
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "compression_pointer_loop")

    def test_bad_base64_is_400(self):
        payload = {"zone_origin": ORIGIN, "stream": "%%%"}
        status, body = _request(self.base + "/api/axfr/inspect", payload)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

    def test_same_input_stable(self):
        payload = {"zone_origin": ORIGIN, "stream": stream_b64(*good_frames())}
        _, b1 = _request(self.base + "/api/axfr/inspect", payload)
        _, b2 = _request(self.base + "/api/axfr/inspect", payload)
        self.assertEqual(json.dumps(b1, sort_keys=True),
                         json.dumps(b2, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
