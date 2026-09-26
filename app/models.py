"""核心数据模型：RRset 与规范化区域。

一个 RRset 由 (owner, rtype) 唯一标识，共享同一个 TTL，包含一条或多条 RDATA。
owner 一律保存为完全限定名称（以根点结尾的小写绝对名称）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

# 本服务支持的 RR 类型
SUPPORTED_TYPES = frozenset(
    {"SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "SVCB", "HTTPS", "CAA",
     "ZONEMD", "TLSA"}
)
# 单点类型：同一 owner 只能有一条 RDATA
SINGLETON_TYPES = frozenset({"SOA", "CNAME"})


def compare_name(left: str, right: str) -> int:
    """按 RFC 4034 的标签逆序字典序比较两个小写绝对名称。

    标签逆序即先比较最右侧的 TLD 标签，再逐级向左；较短的标签序列排前面。
    返回负数 / 0 / 正数。
    """
    l = tuple(reversed(left.rstrip(".").split("."))) if left != "." else ()
    r = tuple(reversed(right.rstrip(".").split("."))) if right != "." else ()
    if l < r:
        return -1
    if l > r:
        return 1
    return 0


@dataclass(frozen=True)
class RRset:
    """规范化资源记录集。rdata 为去重、排序后的字符串元组。"""

    owner: str
    rtype: str
    ttl: int
    rdata: tuple[str, ...] = field(default_factory=tuple)

    @property
    def key(self) -> tuple[str, str]:
        return self.owner, self.rtype

    @property
    def is_singleton(self) -> bool:
        return self.rtype in SINGLETON_TYPES

    def canonical_lines(self) -> list[str]:
        """主文件风格的规范文本行（用于差异展示与摘要）。

        SOA RDATA 的 7 个字段按独立记号输出，保证文本可重新解析。
        """
        lines = []
        if self.rtype == "SOA":
            fields = " ".join(self.rdata[0]) if self.rdata else ""
            lines.append(f"{self.owner} {self.ttl} IN SOA {fields}".rstrip())
            return lines
        for rr in self.rdata:
            lines.append(f"{self.owner} {self.ttl} IN {self.rtype} {rr}")
        return lines


@dataclass
class Zone:
    """解析并规范化后的区域。"""

    origin: str
    rrsets: dict[tuple[str, str], RRset]

    def get(self, owner: str, rtype: str) -> RRset | None:
        return self.rrsets.get((owner, rtype))

    def at(self, owner: str) -> list[RRset]:
        return [rr for (o, _t), rr in self.rrsets.items() if o == owner]

    def sorted_rrsets(self) -> list[RRset]:
        """按 RFC 4034 规范名称序、再按类型序排列。"""
        return sorted(
            self.rrsets.values(),
            key=lambda rr: (
                tuple(reversed(rr.owner.rstrip(".").split(".")))
                if rr.owner != "."
                else (),
                rr.rtype,
            ),
        )

    def canonical_text(self) -> str:
        lines = [f"$ORIGIN {self.origin}"]
        for rr in self.sorted_rrsets():
            lines.extend(rr.canonical_lines())
        return "\n".join(lines) + "\n"
