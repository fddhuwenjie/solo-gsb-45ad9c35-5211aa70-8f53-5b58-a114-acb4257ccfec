"""TLSA（DANE）记录离线校验（app.tlsa）单元测试与 HTTP 端到端测试。

证书由 cryptography 现场生成（EC P-256 自签名叶证书）；缺少
cryptography 依赖时整组测试跳过。
"""

import datetime
import hashlib
import json
import threading
import unittest
import urllib.error
import urllib.request

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

from app.review import ReviewError, perform_review
from app.server import build_server
from app.tlsa import (
    _extract_spki,
    _read_tlv as _app_read_tlv,
    verify_tlsa,
)
from app.zonemd import verify_zonemd
from app.zoneparse import ZoneParseError, parse_zone


def make_certificate(common_name="www.example.com"):
    """生成一张自签名叶证书，返回 (PEM 文本, 证书 DER, SPKI DER)。"""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, der, spki


# ---------------------------------------------------------------------------
# DER TLV 小工具：构造 SPKI 算法标识为 id-rsassaPss 的叶证书
# （cryptography 的 builder 只会在 SPKI 中写 rsaEncryption）
# ---------------------------------------------------------------------------

_OID_RSASSA_PSS = bytes.fromhex("06092a864886f70d01010a")
_OID_SHA256 = bytes.fromhex("0609608648016503040201")
_OID_MGF1 = bytes.fromhex("06092a864886f70d010108")
_NULL = bytes.fromhex("0500")


def _der_length(length):
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_tlv(tag, content):
    return bytes([tag]) + _der_length(len(content)) + content


def _read_tlv(data, offset):
    tag = data[offset]
    first = data[offset + 1]
    value_start = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[value_start:value_start + count], "big")
        value_start += count
    return tag, value_start, value_start + length


def _der_children(content):
    """返回 [(tag, 完整 TLV, V 部分), ...]。"""
    children = []
    offset = 0
    while offset < len(content):
        tag, value_start, end = _read_tlv(content, offset)
        children.append((tag, content[offset:end], content[value_start:end]))
        offset = end
    return children


def _split_certificate(cert_der):
    """返回 (tbsCertificate TLV, signatureAlgorithm TLV, signature TLV)。"""
    _, start, end = _read_tlv(cert_der, 0)
    children = _der_children(cert_der[start:end])
    return children[0][1], children[1][1], children[2][1]


def _tbs_fields(tbs_der):
    _, start, end = _read_tlv(tbs_der, 0)
    return _der_children(tbs_der[start:end])


def _pss_algorithm_identifier():
    """id-rsassaPss + 显式 SHA-256/MGF1-SHA256/salt=32 参数（RFC 4055）。

    RFC 4055 的 RSASSA-PSS-params 使用显式（constructed）上下文标签
    [0]/[1]/[2] 包装内部类型，例如 saltLength 编码为 A2 03 02 01 20。
    """
    sha256_alg = _der_tlv(0x30, _OID_SHA256 + _NULL)
    mgf1_alg = _der_tlv(
        0x30, _OID_MGF1 + _der_tlv(0x30, _OID_SHA256 + _NULL)
    )
    params = (
        _der_tlv(0xA0, sha256_alg)
        + _der_tlv(0xA1, mgf1_alg)
        + _der_tlv(0xA2, _der_tlv(0x02, bytes([32])))
    )
    return _der_tlv(0x30, _OID_RSASSA_PSS + _der_tlv(0x30, params))


def make_pss_spki_certificate(common_name="www.example.com"):
    """构造 SPKI 算法标识为 id-rsassaPss 的 RSA 叶证书。

    先用 builder 构造普通 RSA（sha256WithRSAEncryption）证书，再按 TLV
    结构把 tbsCertificate 中 SPKI 的 AlgorithmIdentifier 替换为
    id-rsassaPss（重包后签名不再有效，但 DANE-EE selector=1 只按字节
    核对 SPKI，cryptography 加载证书时也不验签）。返回
    (PEM, 证书 DER, 证书内原始 SPKI DER, 公钥重导出 SPKI DER)。
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)

    tbs, sig_alg, sig_value = _split_certificate(der)
    fields = _tbs_fields(tbs)
    spki_index = 6 if fields[0][0] == 0xA0 else 5
    spki = fields[spki_index][1]
    _, spki_start, spki_end = _read_tlv(spki, 0)
    spki_children = _der_children(spki[spki_start:spki_end])
    new_spki = _der_tlv(
        0x30, _pss_algorithm_identifier() + spki_children[1][1]
    )
    new_tbs_body = b"".join(
        new_spki if i == spki_index else field[1]
        for i, field in enumerate(fields)
    )
    new_tbs = _der_tlv(0x30, new_tbs_body)
    new_der = _der_tlv(0x30, new_tbs + sig_alg + sig_value)

    # cryptography 可正常加载；重导出的公钥 SPKI 退回 rsaEncryption
    loaded = x509.load_der_x509_certificate(new_der)
    reexport = loaded.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    original = _extract_spki(new_der)
    assert original != reexport  # 本用例的前置条件：两种编码必须不同
    pem = loaded.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return pem, new_der, original, reexport


def make_rsa_certificate(common_name="www.example.com"):
    """普通 sha256WithRSAEncryption 叶证书（长形式长度 0x82）。"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem, der, spki


def strip_version_field(cert_der):
    """删除 tbsCertificate 的可选 [0] version 字段，模拟 v1 证书。"""
    tbs, sig_alg, sig_value = _split_certificate(cert_der)
    fields = _tbs_fields(tbs)
    assert fields[0][0] == 0xA0
    new_tbs = _der_tlv(0x30, b"".join(field[1] for field in fields[1:]))
    return _der_tlv(0x30, new_tbs + sig_alg + sig_value)


def zone_with_tlsa(*records, owner="_443._tcp.www"):
    lines = [
        "$ORIGIN example.com.",
        "$TTL 300",
        "@ IN SOA ns1 admin 2024010100 600 300 86400 300",
        "@ IN NS ns1",
        "ns1 IN A 192.0.2.10",
        "www IN A 192.0.2.80",
    ]
    lines.extend(f"{owner} IN TLSA {rdata}" for rdata in records)
    return "\n".join(lines) + "\n"


def error_of(payload):
    try:
        verify_tlsa(payload)
    except ReviewError as exc:
        return exc
    raise AssertionError("预期抛出 ReviewError")


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, "缺少 cryptography 依赖")
class TlsaTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pem, cls.der, cls.spki = make_certificate()
        cls.cert_sha256 = hashlib.sha256(cls.der).hexdigest()
        cls.spki_sha256 = hashlib.sha256(cls.spki).hexdigest()
        cls.spki_sha512 = hashlib.sha512(cls.spki).hexdigest()

    def payload(self, zone, dnssec="secure", **overrides):
        payload = {
            "zones": [zone],
            "hostname": "www.example.com",
            "port": 443,
            "protocol": "tcp",
            "certificate": self.pem,
            "dnssec": dnssec,
        }
        payload.update(overrides)
        return payload


class MatchTests(TlsaTestBase):
    """selector/matching-type 各组合与 matched/mismatched 结论。"""

    def test_selector0_exact_match(self):
        zone = zone_with_tlsa(f"3 0 0 {self.der.hex()}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        rec = result["records"][0]
        self.assertTrue(rec["supported"])
        self.assertTrue(rec["matched"])
        self.assertEqual(rec["selector_name"], "cert")
        self.assertEqual(rec["matching_name"], "exact")
        self.assertEqual(rec["computed"], self.der.hex())

    def test_selector1_sha256_match(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        rec = result["records"][0]
        self.assertEqual(rec["selector_name"], "spki")
        self.assertEqual(rec["matching_name"], "sha256")
        self.assertEqual(rec["computed"], self.spki_sha256)

    def test_selector0_sha512_match(self):
        zone = zone_with_tlsa(
            f"3 0 2 {hashlib.sha512(self.der).hexdigest()}"
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["records"][0]["matching_name"], "sha512")

    def test_selector1_sha512_and_exact(self):
        zone = zone_with_tlsa(
            f"3 1 2 {self.spki_sha512}",
            f"3 1 0 {self.spki.hex()}",
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(len(result["records"]), 2)
        self.assertTrue(all(rec["matched"] for rec in result["records"]))

    def test_mismatched_when_nothing_matches(self):
        zone = zone_with_tlsa(f"3 1 1 {'0' * 64}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "mismatched")
        rec = result["records"][0]
        self.assertTrue(rec["supported"])
        self.assertFalse(rec["matched"])
        self.assertEqual(rec["expected"], "0" * 64)
        self.assertEqual(rec["computed"], self.spki_sha256)

    def test_any_single_match_is_enough(self):
        zone = zone_with_tlsa(
            f"3 1 1 {'0' * 64}",
            f"3 0 1 {self.cert_sha256}",
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        matched = [rec["matched"] for rec in result["records"]]
        self.assertEqual(matched.count(True), 1)

    def test_uppercase_and_multitoken_hex_match(self):
        # 大写十六进制与跨记号（括号续行）写法不改变关联数据
        zone = (
            "$ORIGIN example.com.\n$TTL 300\n"
            "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
            "@ IN NS ns1\nns1 IN A 192.0.2.10\nwww IN A 192.0.2.80\n"
            "_443._tcp.www IN TLSA 3 1 1 (\n"
            f"    {self.spki_sha256[:32].upper()}\n"
            f"    {self.spki_sha256[32:].upper()} )\n"
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["records"][0]["expected"], self.spki_sha256)

    def test_qname_and_echo_fields(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(
            self.payload(zone, hostname="WWW.Example.COM", port=443)
        )
        self.assertEqual(result["qname"], "_443._tcp.www.example.com.")
        self.assertEqual(result["hostname"], "www.example.com.")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["protocol"], "tcp")
        self.assertEqual(result["dnssec"], "secure")
        self.assertEqual(
            result["certificate"]["der_sha256"],
            hashlib.sha256(self.der).hexdigest(),
        )
        self.assertEqual(
            result["certificate"]["spki_sha256"], self.spki_sha256
        )
        self.assertEqual(
            result["certificate"]["der_length"], len(self.der)
        )

    def test_other_port_and_protocol(self):
        zone = zone_with_tlsa(
            f"3 1 1 {self.spki_sha256}", owner="_25._tcp.mail"
        )
        result = verify_tlsa(
            self.payload(zone, hostname="mail.example.com", port=25)
        )
        self.assertEqual(result["qname"], "_25._tcp.mail.example.com.")
        self.assertEqual(result["status"], "matched")

    def test_udp_protocol(self):
        zone = zone_with_tlsa(
            f"3 1 1 {self.spki_sha256}", owner="_853._udp.dns"
        )
        result = verify_tlsa(
            self.payload(
                zone, hostname="dns.example.com", port=853, protocol="UDP"
            )
        )
        self.assertEqual(result["qname"], "_853._udp.dns.example.com.")
        self.assertEqual(result["status"], "matched")


class PssSpkiEncodingTests(unittest.TestCase):
    """selector=1 必须使用证书内原始 SPKI（RFC 6698 §2.3）。

    SPKI 算法标识为 id-rsassaPss（RFC 4055）时，原始 SPKI 编码与
    公钥重导出编码不同（重导出退回 rsaEncryption+NULL）；此前实现
    按重导出编码求值，secure 下把正确的 usage=3 记录误判为
    mismatched。
    """

    @classmethod
    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "缺少 cryptography 依赖")
    def setUpClass(cls):
        cls.pem, cls.der, cls.spki_orig, cls.spki_reexport = (
            make_pss_spki_certificate()
        )
        cls.orig_hex = cls.spki_orig.hex()
        cls.orig_sha256 = hashlib.sha256(cls.spki_orig).hexdigest()
        cls.orig_sha512 = hashlib.sha512(cls.spki_orig).hexdigest()
        cls.reexport_sha256 = hashlib.sha256(
            cls.spki_reexport
        ).hexdigest()

    def payload(self, zone, dnssec="secure"):
        return {
            "zones": [zone],
            "hostname": "www.example.com",
            "port": 443,
            "protocol": "tcp",
            "certificate": self.pem,
            "dnssec": dnssec,
        }

    def test_original_and_reexported_spki_differ(self):
        # 前置条件：编码差异真实存在（算法标识不同）
        self.assertNotIn(self.spki_reexport, self.spki_orig)
        self.assertNotEqual(self.orig_sha256, self.reexport_sha256)

    def test_selector1_exact_matches_original_spki(self):
        zone = zone_with_tlsa(f"3 1 0 {self.orig_hex}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        rec = result["records"][0]
        self.assertEqual(rec["matching_name"], "exact")
        self.assertEqual(rec["computed"], self.orig_hex)
        self.assertTrue(rec["matched"])

    def test_selector1_sha256_matches_original_spki(self):
        zone = zone_with_tlsa(f"3 1 1 {self.orig_sha256}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["records"][0]["computed"], self.orig_sha256
        )

    def test_selector1_sha512_matches_original_spki(self):
        zone = zone_with_tlsa(f"3 1 2 {self.orig_sha512}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["records"][0]["computed"], self.orig_sha512
        )

    def test_response_spki_fingerprint_is_original(self):
        zone = zone_with_tlsa(f"3 1 1 {self.orig_sha256}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(
            result["certificate"]["spki_sha256"], self.orig_sha256
        )
        self.assertNotEqual(
            result["certificate"]["spki_sha256"], self.reexport_sha256
        )

    def test_reexported_hash_does_not_match(self):
        # 以重导出编码构造的（错误）记录必须判 mismatched，而不是反过来
        zone = zone_with_tlsa(f"3 1 1 {self.reexport_sha256}")
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "mismatched")
        rec = result["records"][0]
        self.assertFalse(rec["matched"])
        self.assertEqual(rec["computed"], self.orig_sha256)
        self.assertEqual(rec["expected"], self.reexport_sha256)

    def test_insecure_still_indeterminate_with_original_match(self):
        zone = zone_with_tlsa(f"3 1 1 {self.orig_sha256}")
        result = verify_tlsa(self.payload(zone, dnssec="insecure"))
        self.assertEqual(result["status"], "indeterminate")
        self.assertTrue(result["records"][0]["matched"])

    def test_bogus_still_invalid_with_original_match(self):
        zone = zone_with_tlsa(f"3 1 1 {self.orig_sha256}")
        result = verify_tlsa(self.payload(zone, dnssec="bogus"))
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(result["records"][0]["matched"])


class OrdinaryCertificateSpkiTests(unittest.TestCase):
    """普通证书（EC / RSA-PKIX）截取结果与重导出一致，行为不回归。"""

    @classmethod
    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "缺少 cryptography 依赖")
    def setUpClass(cls):
        cls.ec_pem, cls.ec_der, cls.ec_spki = make_certificate()
        cls.rsa_pem, cls.rsa_der, cls.rsa_spki = make_rsa_certificate()

    def _payload(self, pem):
        return {
            "zones": [zone_with_tlsa()],
            "hostname": "www.example.com",
            "port": 443,
            "protocol": "tcp",
            "certificate": pem,
            "dnssec": "secure",
        }

    def test_ec_extraction_equals_reexport(self):
        # EC 叶证书 TBS 通常使用 0x81 长形式长度
        self.assertEqual(_extract_spki(self.ec_der), self.ec_spki)

    def test_rsa_extraction_equals_reexport(self):
        # RSA-2048 叶证书 TBS 使用 0x82 长形式长度
        _, start, _ = _app_read_tlv(self.rsa_der, 0)
        self.assertEqual(self.rsa_der[start + 1], 0x82)
        self.assertEqual(_extract_spki(self.rsa_der), self.rsa_spki)

    def test_rsa_selector1_sha256_matches(self):
        digest = hashlib.sha256(self.rsa_spki).hexdigest()
        payload = self._payload(self.rsa_pem)
        payload["zones"] = [zone_with_tlsa(f"3 1 1 {digest}")]
        result = verify_tlsa(payload)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["certificate"]["spki_sha256"], digest
        )

    def test_rsa_selector0_still_uses_certificate_der(self):
        payload = self._payload(self.rsa_pem)
        payload["zones"] = [
            zone_with_tlsa(f"3 0 0 {self.rsa_der.hex()}")
        ]
        result = verify_tlsa(payload)
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            result["records"][0]["computed"], self.rsa_der.hex()
        )


class ExtractSpkiStructureTests(unittest.TestCase):
    """_extract_spki 对可选 version 字段与畸形 DER 的处理。"""

    @classmethod
    @unittest.skipUnless(HAVE_CRYPTOGRAPHY, "缺少 cryptography 依赖")
    def setUpClass(cls):
        _, cls.ec_der, cls.ec_spki = make_certificate()
        _, cls.rsa_der, _ = make_rsa_certificate()

    def test_v1_certificate_without_version_field(self):
        v1_der = strip_version_field(self.ec_der)
        # v1 TBS 第一个字段是 serialNumber（INTEGER 0x02）
        _, start, _ = _app_read_tlv(v1_der, 0)
        self.assertEqual(v1_der[start], 0x30)
        spki = _extract_spki(v1_der)
        self.assertEqual(spki, self.ec_spki)

    def test_trailing_garbage_rejected(self):
        with self.assertRaises(ValueError):
            _extract_spki(self.ec_der + b"\x00")

    def test_truncated_der_rejected(self):
        with self.assertRaises(ValueError):
            _extract_spki(self.ec_der[:-5])

    def test_non_sequence_outer_rejected(self):
        with self.assertRaises(ValueError):
            _extract_spki(b"\x04\x03abc")

    def test_tampered_spki_tag_rejected(self):
        # 把 TBS 中 SPKI 的 SEQUENCE 标签改成 OCTET STRING -> 结构失配
        _, cert_start, _ = _app_read_tlv(self.rsa_der, 0)
        tbs_tag, tbs_start, tbs_end = _app_read_tlv(
            self.rsa_der, cert_start
        )
        tbs_content = self.rsa_der[tbs_start:tbs_end]
        spki_offset = 0
        for index in range(7):  # version..SPKI
            tag, _, end = _app_read_tlv(tbs_content, spki_offset)
            if index == 6:
                self.assertEqual(tag, 0x30)
                break
            spki_offset = end
        absolute = tbs_start + spki_offset
        tampered = bytearray(self.rsa_der)
        tampered[absolute] = 0x04
        with self.assertRaises(ValueError):
            _extract_spki(bytes(tampered))

    def test_read_tlv_short_and_long_length_forms(self):
        # 短形式
        self.assertEqual(_app_read_tlv(b"\x04\x03abc", 0), (4, 2, 5))
        # 0x81 长形式
        data = b"\x04\x81\x05" + b"abcde"
        self.assertEqual(_app_read_tlv(data, 0), (4, 3, 8))
        # 0x82 长形式，带偏移
        data = b"\x00" + b"\x04\x82\x01\x00" + b"a" * 256
        self.assertEqual(_app_read_tlv(data, 1), (4, 5, 261))
        for bad in (b"", b"\x04", b"\x04\x82\x01", b"\x04\x03ab"):
            with self.assertRaises(ValueError):
                _app_read_tlv(bad, 0)
        # 不确定长度（0x80）与零长度长形式（0x85 无内容）均非法
        with self.assertRaises(ValueError):
            _app_read_tlv(b"\x04\x80\x00", 0)
        with self.assertRaises(ValueError):
            _app_read_tlv(b"\x04\x85", 0)


class DnssecStateTests(TlsaTestBase):
    """外部 DNSSEC 状态决定有支持项时的结论。"""

    def test_insecure_gives_indeterminate_even_when_matching(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(self.payload(zone, dnssec="insecure"))
        self.assertEqual(result["status"], "indeterminate")
        # 逐条结果仍然计算
        self.assertTrue(result["records"][0]["matched"])

    def test_bogus_gives_invalid_even_when_matching(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(self.payload(zone, dnssec="bogus"))
        self.assertEqual(result["status"], "invalid")
        self.assertTrue(result["records"][0]["matched"])

    def test_dnssec_state_case_insensitive(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(self.payload(zone, dnssec="SECURE"))
        self.assertEqual(result["dnssec"], "secure")
        self.assertEqual(result["status"], "matched")

    def test_none_and_unsupported_ignore_dnssec_state(self):
        # 无记录：任何 DNSSEC 状态下都是 none
        zone = zone_with_tlsa()
        for state in ("secure", "insecure", "bogus"):
            result = verify_tlsa(self.payload(zone, dnssec=state))
            self.assertEqual(result["status"], "none", state)
        # 仅不支持项：任何 DNSSEC 状态下都是 unsupported
        zone = zone_with_tlsa(f"0 1 1 {self.spki_sha256}")
        for state in ("secure", "insecure", "bogus"):
            result = verify_tlsa(self.payload(zone, dnssec=state))
            self.assertEqual(result["status"], "unsupported", state)


class CoverageTests(TlsaTestBase):
    """none / unsupported / 委派边界。"""

    def test_none_when_no_tlsa_rrset(self):
        result = verify_tlsa(self.payload(zone_with_tlsa()))
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["records"], [])
        lookup = result["trace"][1]
        self.assertEqual(lookup["action"], "lookup")
        self.assertFalse(lookup["found"])
        self.assertEqual(lookup["reason"], "no_tlsa_rrset")

    def test_none_when_zone_missing(self):
        result = verify_tlsa(
            self.payload(zone_with_tlsa(), hostname="www.elsewhere.test")
        )
        self.assertEqual(result["status"], "none")
        lookup = result["trace"][1]
        self.assertFalse(lookup["found"])
        self.assertEqual(lookup["reason"], "missing_local_zone")

    def test_none_below_undelegated_cut(self):
        # TLSA 位于未提供的委派子区之下 -> 无记录
        zone = (
            "$ORIGIN example.com.\n$TTL 300\n"
            "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
            "@ IN NS ns1\nns1 IN A 192.0.2.10\n"
            "sub IN NS ns1.sub\nns1.sub IN A 192.0.2.20\n"
        )
        result = verify_tlsa(
            self.payload(zone, hostname="www.sub.example.com")
        )
        self.assertEqual(result["status"], "none")
        self.assertEqual(
            result["trace"][1]["reason"], "missing_local_zone"
        )

    def test_tlsa_in_delegated_zone_when_provided(self):
        parent = (
            "$ORIGIN example.com.\n$TTL 300\n"
            "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
            "@ IN NS ns1\nns1 IN A 192.0.2.10\n"
            "sub IN NS ns1.sub\nns1.sub IN A 192.0.2.20\n"
        )
        child = (
            "$ORIGIN sub.example.com.\n$TTL 300\n"
            "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
            "@ IN NS ns1\nns1 IN A 192.0.2.20\n"
            f"_443._tcp.www IN TLSA 3 1 1 {self.spki_sha256}\n"
        )
        result = verify_tlsa(
            self.payload(parent, hostname="www.sub.example.com",
                         zones=[parent, child])
        )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["trace"][1]["zone"], "sub.example.com.")

    def test_unsupported_usages_and_fields(self):
        zone = zone_with_tlsa(
            f"0 1 1 {self.spki_sha256}",   # PKIX-TA：不支持
            f"1 1 1 {self.spki_sha256}",   # PKIX-EE：不支持
            f"2 1 1 {self.spki_sha256}",   # DANE-TA：不支持
            f"3 2 1 {self.spki_sha256}",   # 未知 selector
            f"3 1 3 {self.spki_sha256}",   # 未知 matching type
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(len(result["records"]), 5)
        for rec in result["records"]:
            self.assertFalse(rec["supported"])
            self.assertFalse(rec["matched"])
            self.assertIsNone(rec["computed"])
        # usage 名称仅作展示（RRset 内记录按规范文本排序）
        by_fields = {
            (rec["usage"], rec["selector"], rec["matching_type"]): rec
            for rec in result["records"]
        }
        self.assertEqual(by_fields[(0, 1, 1)]["usage_name"], "pkix-ta")
        self.assertEqual(by_fields[(2, 1, 1)]["usage_name"], "dane-ta")
        self.assertIsNone(by_fields[(3, 2, 1)]["selector_name"])
        self.assertIsNone(by_fields[(3, 1, 3)]["matching_name"])

    def test_unsupported_records_do_not_block_supported_match(self):
        zone = zone_with_tlsa(
            f"2 0 0 {self.der.hex()}",
            f"3 1 1 {self.spki_sha256}",
        )
        result = verify_tlsa(self.payload(zone))
        self.assertEqual(result["status"], "matched")
        self.assertEqual(
            [rec["supported"] for rec in result["records"]], [False, True]
        )


class TraceTests(TlsaTestBase):
    def test_trace_shape_and_result_event(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        result = verify_tlsa(self.payload(zone))
        trace = result["trace"]
        self.assertEqual([event["action"] for event in trace],
                         ["qname", "lookup", "result"])
        self.assertEqual(trace[0]["qname"], "_443._tcp.www.example.com.")
        self.assertEqual(trace[0]["port"], 443)
        self.assertEqual(trace[0]["protocol"], "tcp")
        self.assertTrue(trace[1]["found"])
        self.assertEqual(trace[1]["record_count"], 1)
        self.assertEqual(trace[1]["ttl"], 300)
        final = trace[-1]
        self.assertEqual(final["status"], "matched")
        self.assertEqual(final["dnssec"], "secure")
        self.assertEqual(final["supported"], 1)
        self.assertEqual(final["matched"], 1)

    def test_same_input_stable_output(self):
        zone = zone_with_tlsa(
            f"3 0 1 {self.cert_sha256}",
            f"3 1 1 {self.spki_sha256}",
        )
        r1 = verify_tlsa(self.payload(zone))
        r2 = verify_tlsa(self.payload(zone))
        self.assertEqual(json.dumps(r1, sort_keys=True),
                         json.dumps(r2, sort_keys=True))


class RequestValidationTests(TlsaTestBase):
    def test_zones_validation(self):
        exc = error_of({})
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_request")
        exc = error_of({"zones": []})
        self.assertEqual(exc.status, 400)
        exc = error_of({"zones": [""]})
        self.assertEqual(exc.status, 400)

    def test_hostname_validation(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        for bad in (None, "", "   ", 42, "bad..name", "-x-.example.com"):
            exc = error_of(self.payload(zone, hostname=bad))
            self.assertEqual(exc.status, 400, bad)
            self.assertEqual(exc.code, "invalid_request")

    def test_port_validation(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        for bad in (None, "443", 1.5, True, -1, 65536):
            exc = error_of(self.payload(zone, port=bad))
            self.assertEqual(exc.status, 400, bad)
        # 边界值合法
        for ok in (0, 65535):
            result = verify_tlsa(self.payload(zone, port=ok))
            self.assertEqual(result["port"], ok)

    def test_protocol_validation(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        for bad in (None, "", "http", "tcps", 6):
            exc = error_of(self.payload(zone, protocol=bad))
            self.assertEqual(exc.status, 400, bad)

    def test_dnssec_validation(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        for bad in (None, "", "yes", "unsigned", 1):
            exc = error_of(self.payload(zone, dnssec=bad))
            self.assertEqual(exc.status, 400, bad)

    def test_certificate_validation(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        for bad in (None, "", "   ", 42):
            exc = error_of(self.payload(zone, certificate=bad))
            self.assertEqual(exc.status, 400)
            self.assertEqual(exc.code, "invalid_request")
        exc = error_of(self.payload(zone, certificate="not a pem"))
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_certificate")
        # 合法 PEM 头但内容损坏
        exc = error_of(self.payload(
            zone,
            certificate="-----BEGIN CERTIFICATE-----\nAAAA\n"
                        "-----END CERTIFICATE-----\n",
        ))
        self.assertEqual(exc.status, 400)
        self.assertEqual(exc.code, "invalid_certificate")

    def test_zone_parse_error_422(self):
        exc = error_of(self.payload("$ORIGIN broken.\n@ IN TXT unclosed\""))
        self.assertEqual(exc.status, 422)
        self.assertEqual(exc.code, "zone_parse_error")


class TlsaFieldValidationTests(TlsaTestBase):
    """TLSA 字段或十六进制错误随区域解析以 422 报出。"""

    BASE = (
        "$ORIGIN example.com.\n$TTL 300\n"
        "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.10\n"
    )

    def zone(self, rdata):
        return self.BASE + f"_443._tcp.www IN TLSA {rdata}\n"

    def test_field_range_and_shape_422(self):
        for rdata in (
            "256 1 1 aabb",      # usage 超界
            "3 256 1 aabb",      # selector 超界
            "3 1 256 aabb",      # matching type 超界
            "-1 1 1 aabb",       # 负数
            "x 1 1 aabb",        # 非数字
            "3 1 1",             # 缺关联数据
            "3 1",               # 缺字段
        ):
            exc = error_of(self.payload(self.zone(rdata)))
            self.assertEqual(exc.status, 422, rdata)
            self.assertEqual(exc.code, "zone_parse_error")

    def test_bad_hex_422(self):
        for rdata in (
            "3 1 1 zz",          # 非十六进制
            "3 1 1 abc",         # 奇数长度
            "3 1 1 0x12",        # 带前缀
        ):
            exc = error_of(self.payload(self.zone(rdata)))
            self.assertEqual(exc.status, 422, rdata)
            self.assertEqual(exc.code, "zone_parse_error")

    def test_parse_zone_tlsa_canonical_and_dedup(self):
        zone = parse_zone(
            self.BASE
            + "_443._tcp.www IN TLSA 3 1 1 AABB\n"
            + "_443._tcp.www IN TLSA 3 1 1 aabb\n"
            + "_443._tcp.www IN TLSA 03 1 2 ccdd\n"
        )
        rrset = zone.get("_443._tcp.www.example.com.", "TLSA")
        self.assertIsNotNone(rrset)
        # 大小写等价重复去重；前导零与十六进制统一规范化
        self.assertEqual(rrset.rdata, ("3 1 1 aabb", "3 1 2 ccdd"))

    def test_parse_zone_tlsa_multitoken_hex(self):
        zone = parse_zone(
            self.BASE + "_443._tcp.www IN TLSA 3 1 1 (\n  AA BB\n  cc )\n"
        )
        rrset = zone.get("_443._tcp.www.example.com.", "TLSA")
        self.assertEqual(rrset.rdata, ("3 1 1 aabbcc",))


class ZonemdWithTlsaTests(TlsaTestBase):
    """含 TLSA 的区域仍可校验 ZONEMD 摘要（wire 编码往返）。"""

    ZONE_PREFIX = (
        "$ORIGIN example.com.\n$TTL 300\n"
        "@ IN SOA ns1 admin 2024010100 600 300 86400 300\n"
        "@ IN NS ns1\nns1 IN A 192.0.2.10\n"
        "www IN A 192.0.2.80\n"
    )

    def _zone(self, digest):
        return (
            self.ZONE_PREFIX
            + f"_443._tcp.www IN TLSA 3 1 1 {self.spki_sha256}\n"
            + f"_443._tcp.www IN TLSA 3 0 0 {self.der.hex()}\n"
            + f"@ IN ZONEMD 2024010100 1 1 {digest}\n"
        )

    def test_digest_roundtrip_with_tlsa(self):
        placeholder = self._zone("00" * 48)
        computed = verify_zonemd({"zone": placeholder})["records"][0][
            "computed"
        ]
        self.assertIsNotNone(computed)
        result = verify_zonemd({"zone": self._zone(computed)})
        self.assertEqual(result["status"], "valid")
        self.assertTrue(result["records"][0]["matched"])
        tlsa_entries = [
            entry for entry in result["trace"] if entry["type"] == "TLSA"
        ]
        # 两条 TLSA 都进入摘要轨迹，RDATA 按 wire 字节序排列
        self.assertEqual(len(tlsa_entries), 2)
        self.assertEqual(
            tlsa_entries[0]["owner"], "_443._tcp.www.example.com."
        )
        self.assertLess(
            tlsa_entries[0]["rdata"], tlsa_entries[1]["rdata"]
        )

    def test_tlsa_text_variants_same_digest(self):
        # 等价写法（大写/跨记号/前导零）不改变摘要
        computed = verify_zonemd({"zone": self._zone("00" * 48)})[
            "records"
        ][0]["computed"]
        variant = (
            self.ZONE_PREFIX
            + "_443._TCP.www IN TLSA 03 1 1 (\n"
            + f"  {self.spki_sha256[:32].upper()}\n"
            + f"  {self.spki_sha256[32:].upper()} )\n"
            + f"_443._tcp.www IN TLSA 3 0 0 {self.der.hex()}\n"
            + "@ IN ZONEMD 2024010100 1 1 " + "00" * 48 + "\n"
        )
        result = verify_zonemd({"zone": variant})
        self.assertEqual(result["records"][0]["computed"], computed)

    def test_review_endpoint_accepts_tlsa(self):
        old = (
            "$ORIGIN lab.test.\n$TTL 300\n"
            "@ IN SOA ns1 admin 1 600 300 86400 300\n@ IN NS ns1\n"
            "ns1 IN A 192.0.2.10\n"
        )
        new = (
            "$ORIGIN lab.test.\n$TTL 300\n"
            "@ IN SOA ns1 admin 2 600 300 86400 300\n@ IN NS ns1\n"
            "ns1 IN A 192.0.2.10\n"
            "_443._tcp.www IN TLSA 3 1 1 " + "ab" * 32 + "\n"
        )
        result = perform_review({"old_zone": old, "new_zone": new})
        self.assertTrue(result["safe"])
        added = {
            (entry["new"]["owner"], entry["new"]["type"])
            for entry in result["diff"]
            if entry["action"] == "add"
        }
        self.assertIn(("_443._tcp.www.lab.test.", "TLSA"), added)


class TlsaApiTests(TlsaTestBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
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
            self.base + "/api/tlsa/verify", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_matched_over_http(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        status, body = self._post(self.payload(zone))
        self.assertEqual(status, 200, body)
        tlsa = body["tlsa"]
        self.assertEqual(tlsa["status"], "matched")
        self.assertEqual(tlsa["qname"], "_443._tcp.www.example.com.")
        self.assertTrue(tlsa["records"][0]["matched"])
        self.assertTrue(tlsa["trace"])

    def test_terminal_states_are_200(self):
        zone = zone_with_tlsa(f"3 1 1 {'0' * 64}")
        status, body = self._post(self.payload(zone))
        self.assertEqual(status, 200)
        self.assertEqual(body["tlsa"]["status"], "mismatched")

        status, body = self._post(self.payload(zone, dnssec="bogus"))
        self.assertEqual(status, 200)
        self.assertEqual(body["tlsa"]["status"], "invalid")

        status, body = self._post(self.payload(zone_with_tlsa()))
        self.assertEqual(status, 200)
        self.assertEqual(body["tlsa"]["status"], "none")

    def test_pss_spki_sha256_matched_over_http(self):
        # 回归：SPKI 算法标识为 id-rsassaPss 时，原始 SPKI 与公钥重导出
        # 编码不同；HTTP 路径同样必须按证书内原始 SPKI 判 matched
        pem, _, spki_orig, spki_reexport = make_pss_spki_certificate()
        digest = hashlib.sha256(spki_orig).hexdigest()
        zone = zone_with_tlsa(f"3 1 1 {digest}")
        payload = self.payload(zone, certificate=pem)
        status, body = self._post(payload)
        self.assertEqual(status, 200, body)
        tlsa = body["tlsa"]
        self.assertEqual(tlsa["status"], "matched")
        self.assertTrue(tlsa["records"][0]["matched"])
        self.assertEqual(
            tlsa["certificate"]["spki_sha256"], digest
        )
        self.assertNotEqual(
            tlsa["certificate"]["spki_sha256"],
            hashlib.sha256(spki_reexport).hexdigest(),
        )

    def test_errors_over_http(self):
        zone = zone_with_tlsa(f"3 1 1 {self.spki_sha256}")
        status, body = self._post(self.payload(zone, port="443"))
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_request")

        status, body = self._post(
            self.payload(zone, certificate="not a pem")
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_certificate")

        status, body = self._post(
            self.payload(
                "$ORIGIN example.com.\n$TTL 300\n"
                "@ IN SOA ns1 admin 1 600 300 86400 300\n@ IN NS ns1\n"
                "_443._tcp.www IN TLSA 3 1 1 zz\n"
            )
        )
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "zone_parse_error")


if __name__ == "__main__":
    unittest.main()
