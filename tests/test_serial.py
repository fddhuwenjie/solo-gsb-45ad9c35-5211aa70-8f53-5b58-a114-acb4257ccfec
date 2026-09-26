"""RFC 1982 序列号算术测试。"""

import unittest

from app.serial import SerialError, add, check_zone_serial, compare


class SerialTests(unittest.TestCase):
    def test_forward_within_half(self):
        self.assertEqual(compare(1, 2), -1)
        self.assertEqual(compare(2, 1), 1)
        self.assertEqual(compare(0, 2**31 - 1), -1)
        self.assertEqual(compare(2**31 - 1, 0), 1)

    def test_wraparound(self):
        # 2^32-2 -> 5：5 是“未来”
        self.assertEqual(compare(2**32 - 2, 5), -1)
        self.assertEqual(compare(5, 2**32 - 2), 1)
        self.assertEqual(compare(2**32 - 1, 0), -1)

    def test_equal_and_undefined(self):
        self.assertEqual(compare(7, 7), 0)
        with self.assertRaises(SerialError):
            compare(0, 2**31)
        with self.assertRaises(SerialError):
            compare(123, 123 + 2**31)

    def test_add(self):
        self.assertEqual(add(2**32 - 1), 0)
        self.assertEqual(add(10, 5), 15)
        with self.assertRaises(SerialError):
            add(0, 2**31)

    def test_check_status(self):
        self.assertEqual(check_zone_serial(100, 101), "ok")
        self.assertEqual(check_zone_serial(100, 100), "unchanged")
        self.assertEqual(check_zone_serial(101, 100), "regressed")
        self.assertEqual(check_zone_serial(2**32 - 1, 1), "ok")


if __name__ == "__main__":
    unittest.main()
