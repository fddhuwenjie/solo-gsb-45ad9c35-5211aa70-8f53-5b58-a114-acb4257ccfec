# DNS 区域变更审查 / 离线 SPF 求值 API

接收含 `$ORIGIN`、`$TTL`、`SOA`、`NS`、`A`、`AAAA`、`CNAME`、`MX`、`TXT`
的新旧区域文本，规范化后按 RFC 1982 校验 SOA 序列号，把差异拆成 RRset 级增删，
并在保证**每一个发布中间态都合法**的前提下排序；不存在安全顺序时
只返回最小冲突 RRset，绝不给出发布计划。另提供 `POST /api/spf/evaluate`，
在**完全禁止联网**的前提下，仅依据请求里给出的本地区域文本离线求值 SPF
（RFC 7208）；`POST /api/dnssec/nsec-proof`，离线校验 DNSSEC NSEC
否认证明（NODATA / NXDOMAIN，不校验 RRSIG）；以及
`POST /api/svcb/resolve`，离线解析 SVCB/HTTPS 记录
（RFC 9460 AliasMode/ServiceMode）；以及 `POST /api/caa/authorize`，
在**完全禁止联网**的前提下，按 RFC 8659 离线判定 CAA 签发授权
（`issue`/`issuewild` + critical 未知属性，参数见 RFC 8657）；以及
`POST /api/zonemd/verify`，按 RFC 8976 Simple Scheme 离线校验区顶
ZONEMD 区域摘要（SHA-384/SHA-512，不校验 RRSIG）；以及
`POST /api/tlsa/verify`，按 RFC 6698 离线核对 TLSA（DANE）记录
（仅 usage=3 DANE-EE，不验证 DNSSEC/证书链/主机名）；以及
`POST /api/axfr/inspect`，离线检查 Base64 编码的 TCP AXFR 响应流
（逐帧解析 DNS 头/问题区/回答区，支持名称压缩），判定
complete/incomplete/invalid 并还原可交给审查接口的规范区域文本；以及
`POST /api/dns/delegation-trace`，离线校验一条迭代解析轨迹
（转介/胶水/地址子查询/CNAME 重启，共享 32 跳预算），返回
final_answer、逐记录取舍原因与地址来源图。
除 TLSA 校验的 PEM 证书解析使用 `cryptography`（见
`requirements.txt`，镜像内自动安装）外，仅使用 Python 标准库
（`http.server.ThreadingHTTPServer` + `sqlite3`）。

## 审查规则

### 规范化（乱序与重复记录不改变摘要）

- 相对名相对当前 `$ORIGIN` 补全为小写绝对 FQDN，`@` 表示区顶；
  省略属名的行继承上一条记录的属名；
- 省略 TTL 时取当前 `$TTL`，支持 `300`、`1h`、`2d`、`1w` 等写法；
- 括号跨行续行与 `;` 行注释；A/AAAA 用 `ipaddress` 规范化（AAAA 压缩小写）；
- 同一 RRset 的重复 RDATA 去重；记录书写顺序打乱产生**相同**规范文本与
  SHA-256 摘要（`diff_sha256` / `digest`）。

### SOA 序列号（RFC 1982）

32 位环绕序列号空间：新序列号必须严格“晚于”旧序列号；
相等、回退、相差恰好 2³¹（未定义）都以 `422` 拒绝。

### 每一步都必须保留的不变量

1. 区顶始终有且仅有一个 SOA、至少一个 NS；区顶不得有 CNAME；
2. CNAME 排他：带 CNAME 的 owner 不能同时存在其它类型；CNAME 链不得成环
   （终态环与任何中间态环都会被拒绝）；
3. 委派（非区顶 NS）构成区域切割点：切点子树内只允许切点 NS 与域内胶水；
   in-bailiwick 的 NS 目标必须随切点提供 A/AAAA 胶水；
4. 新委派的“切点 NS + 胶水”会融合成**一个原子步骤**——先加 NS 会缺胶水、
   先加胶水会成为切点下无主数据，单步拆分两种顺序都不合法。

SOA 序列号推进固定排在最后一步。

## 离线 SPF 求值（`POST /api/spf/evaluate`）

不发起任何真实 DNS 查询：把**本地区域文本集合**当作权威数据源，
在其中解析 TXT / MX / A / AAAA。输入 `client_ip`（IPv4/IPv6）、
`mail_from` 与 `helo`；`mail_from` 为空（含 `"<>"`）时回退使用 **HELO 域**
（响应中 `identity` 标注实际使用的身份 `mailfrom` / `helo`）。

- 区域解析新增 **TXT**（RFC 1035 引号/`\DDD` 转义、多 character-string 分组）
  与 **MX**（`<优先级> <交换主机>`）类型；
- 支持机制：`all`、`ip4`、`ip6`、`a`（含 `a/24/64` 双 CIDR）、`mx`
  （含隐式 MX：无 MX RRset 时按 `MX 0 <域自身>`）、`include`，
  以及 `redirect=` 修饰符；限定符 `+`（pass）、`-`（fail）、
  `~`（softfail）、`?`（neutral），缺省为 `+`；
- `include` **仅在子策略结果为 pass 时命中**；子策略 `permerror`/`temperror`
  向上传播，`none`/`fail`/`softfail`/`neutral` 不命中并继续后续机制；
- `redirect` 只在本记录**没有任何机制命中**后才执行；目标无 SPF 记录
  按 `permerror` 处理；
- 整个递归过程**共享 10 次 DNS 查询预算**，计数统一在实际 RRset 查询入口：
  每次读取 **TXT / MX / A / AAAA** RRset 各计一次——包括顶层 SPF TXT、
  `include` 与 `redirect` 目标的 TXT、`a` 的 A 与 AAAA（分别计）、
  `mx` 的 MX 及每个交换主机的 A 与 AAAA（隐式 MX 也计域自身的 A/AAAA）；
  `ip4`/`ip6`/`all` 不产生查询，`include`/`redirect` 机制本身不再单独计费；
  **尝试第 11 次查询即 `permerror`**（该次仍计入 `dns_queries`），
  即使第 11 次查询的名字落在已提供区域之外，预算错误也优先于
  `temperror`；
- include/redirect 递归检测**环**（求值栈上的域再次出现即 `permerror`）；
  菱形引用（同一域被两条路径 include）不是环；
- **宏**（任意 `%`）、`ptr`、`exists`、未知机制、多条 SPF 记录、
  语法非法均为 `permerror`；未知 `name=value` 修饰符按 RFC 忽略；
- 查询的名字不被任何已提供区域覆盖、或落在**未提供的委派子区**
  （越过 NS 切点）时为 `temperror`（缺失本地区域引用）；
- 完全没有 SPF 记录为 `none`；无任何机制命中且无 redirect 为 `neutral`。

终态 `pass` / `fail` / `softfail` / `neutral` / `none` / `permerror` /
`temperror` 都在 **HTTP 200** 响应的 `spf.result` 中返回；只有请求格式
错误（`400`）与区域文本解析失败（`422`）走错误响应。`spf.trace` 是
**有序求值轨迹**（`policy` → `term` / `redirect` → `result`，
`depth` 表示 include/redirect 嵌套深度），`spf.dns_queries` 为真实已尝试的
RRset 查询次数（含触发预算耗尽的第 11 次）；
相同输入产生完全相同的输出（地址、MX 主机均确定性排序）。

请求体：

```json
{
  "zones": ["<区域文本>", "<另一个区域（如被 include/委派的域）>"],
  "client_ip": "192.0.2.77",
  "mail_from": "alice@example.com",
  "helo": "mx.sender.example"
}
```

## NSEC 否认证明校验（`POST /api/dnssec/nsec-proof`）

离线校验一条 DNSSEC NSEC 否认证明（**不校验 RRSIG**）。输入区源点
`zone_origin`、该区**完整 NSEC 链**（`nsec` 数组，元素
`{owner, next, types}`）与一条查询 `query={name, type, expected}`
（`expected` 取 `nodata` / `nxdomain`）。

链校验（任一违反即 `422`）：

- 名称一律规范化为小写绝对名（相对名相对 `zone_origin` 补全，
  `@` 表示区顶；查询名与通配符 `*` 标签同样允许）；
- owner 唯一（`duplicate_owner`）；owner 与 next 均须在区内
  （`name_out_of_zone`）；
- `types` 去重（重复项不报错）且必须包含 `NSEC`
  （`missing_nsec_type`）；
- 按 RFC 4034 规范名称序，每条 `next` 必须指向后继 owner，
  最大 owner 的 `next` 必须绕回最小 owner 构成闭合环
  （`nsec_chain_error`）。

证明规则：

- **NODATA**：须存在与查询名同名的 NSEC，且其 `types` 同时缺少
  查询类型与 `CNAME`；
- **NXDOMAIN**：须由环形区间覆盖查询名的 NSEC，并证明
  `*.<closest-encloser>` 不存在——最近封闭名取 NSEC owner 集合中
  查询名的最长真祖先，覆盖该通配符的 NSEC 即其不存在性证明。

响应 `nsec_proof` 中：`valid` 为总结论，`proof` 为**最小证明记录集**
（NODATA 一条；NXDOMAIN 为覆盖查询名与覆盖通配符的记录，去重后按
规范序排列；证明不成立时为空），`reason` 为结论说明；`checks` 逐条
给出每个证明步骤的 `valid` / `records` / `reason`。NSEC 列表顺序与
`types` 顺序不影响结果；`valid` 与 `invalid` 都是 **HTTP 200** 下的
证明结论，只有请求格式错误（`400`）与链错误（`422`）走错误响应。

请求体：

```json
{
  "zone_origin": "example.com.",
  "nsec": [
    {"owner": "example.com.", "next": "a.example.com.",
     "types": ["SOA", "NS", "A", "NSEC"]},
    {"owner": "a.example.com.", "next": "example.com.",
     "types": ["A", "NSEC"]}
  ],
  "query": {"name": "ghost.example.com.", "type": "A",
            "expected": "nxdomain"}
}
```

## 离线 SVCB/HTTPS 解析（`POST /api/svcb/resolve`）

不发起任何真实 DNS 查询：把**本地区域文本集合**当作权威数据源，
按 RFC 9460 解析 SVCB/HTTPS 记录（区域解析新增 **SVCB** 与 **HTTPS**
类型，RDATA 为 `<优先级> <目标> [参数...]`）。

记录校验（任一违反即 `422`，随区域解析一同报出）：

- 优先级为 `0..65535` 的整数；目标为合法域名（`.` 原样保留）；
- **参数键唯一**；结构化支持 `mandatory`、`alpn`、`no-default-alpn`、
  `port`、`ipv4hint`、`ipv6hint`，未知键只接受 RFC 9460 通用形式
  `keyNNNNN`（键号落在已知键上时归一到对应名称，如 `key3` ≡ `port`；
  `key65535` 为保留键）；参数值可带引号与 `\DDD` 转义，列表值按
  未转义逗号切分（`\,` 保留字面逗号），解码后须为合法 UTF-8；
- `mandatory` 不得引用自身，且**引用的每个键都必须出现在同一条记录中**
  （引用缺失参数即 `422`）；
- `no-default-alpn` 必须与 `alpn` 同时出现（缺 `alpn` 即 `422`）；
- AliasMode（优先级 0）记录不得携带任何参数。

解析规则：

- `priority=0` 为 **AliasMode**：沿**同类型**（SVCB 或 HTTPS）别名链
  逐跳解析；同一 RRset 中别名记录与其它记录共存（多个别名）`422`、
  链成环 `422`、超过 **8 跳** `422`；别名目标 `.` 表示**服务不可用**；
- `priority>0` 为 **ServiceMode**：目标 `.` 回落为记录属名（owner）；
- 按客户端能力过滤 ServiceMode 记录：`mandatory` 含客户端不支持的
  参数键（`mandatory_unknown_key`）、或记录的 `alpn` 与客户端 ALPN
  列表无交集（`alpn_no_overlap`）的记录被丢弃；未提供 `client_alpn`
  时不做 ALPN 过滤，无 `alpn` 的记录不受 ALPN 过滤影响；
- 存活记录按 `(priority, target)` 稳定排序输出端点。

响应 `svcb` 中：`status` 为 `ok`（有端点）/ `unavailable`（别名目标
`.`）/ `nodata`（查询名无该类型记录）/ `filtered`（记录全部被过滤）/
`unresolvable`（名字不被任何已提供区域覆盖，或落在未提供的委派子区），
均为 **HTTP 200** 下的解析终态；`endpoints` 为排序后的端点列表
（含 `priority`、`target`、`alpn`、`port`、`ipv4hint`、`ipv6hint`、
`mandatory`、`no_default_alpn` 与原始 `params`）；`trace` 为**逐跳轨迹**
（`alias` 跳含目标、`service` 跳含逐记录的可用性判定与过滤原因）；
`alias_hops` 为实际经过的别名跳数。只有请求格式错误（`400`）与
记录/别名链错误（`422`）走错误响应。

请求体（`client_keys` 缺省为本服务已知的全部六个键，`client_alpn`
缺省表示不过滤）：

```json
{
  "zones": ["<区域文本>", "<另一个区域（如别名目标所在区）>"],
  "qname": "www.example.com.",
  "qtype": "HTTPS",
  "client_keys": ["mandatory", "alpn", "no-default-alpn", "port",
                  "ipv4hint", "ipv6hint"],
  "client_alpn": ["h2", "h3"]
}
```

## 离线 CAA 签发授权（`POST /api/caa/authorize`）

不发起任何真实 DNS 查询：把**本地区域文本集合**当作权威数据源，
按 RFC 8659 判定某个 CA 是否允许为域名签发证书（区域解析新增
**CAA** 类型，RDATA 为 `<flags> <tag> <value>`）。

记录校验（任一违反即 `422`，随区域解析一同报出）：

- `flags` 为 `0..255` 的无符号整数；`tag` 为 1..255 字节的**非空
  字母数字串**（`[A-Za-z0-9]+`，大小写归一）；
- `value` 必须恰好由一个 `<character-string>` 组成（RFC 1035 引号/
  `\DDD` 转义），解码后为合法 UTF-8、不超过 512 字节；
- `issue` / `issuewild` 的 value 进一步解析为
  `<签发者>(;name=value)*`：签发者须为空（`;`）或合法域名；
  参数名为字母数字串且不重复；`accounturi` 与 `validationmethods`
  （RFC 8657，后者为非空逗号分隔列表）结构化保存；参数按名排序、
  验证方式按值排序后重组，故书写顺序不改变规范文本与去重结果。

授权规则：

- 从请求 `domain` 起沿名字树逐级（含自身）向区顶查找**首个 CAA
  RRset**；某一级存在 **CNAME** 时沿目标**重新开始**整个查找；
  CNAME 链**成环**或**超过 8 跳**返回 `422`（`caa_cname_loop` /
  `caa_too_many_cname_hops`）；
- 查找中名字不被任何已提供区域覆盖、或越过**未提供的委派**
  （严格位于未提供的 NS 切点之下；切点自身仍由父区回答）时，
  结论为 `indeterminate`（`missing_local_zone`）；
- **通配符**（`wildcard=true`）优先使用 `issuewild`：相关 RRset 中
  没有任何 issuewild 属性时才回退 `issue`；非通配符请求只看 `issue`；
- **空签发者**（`issue ";"`）禁止任何 CA 签发；记录须同时匹配
  `ca_domain` 与参数——记录带 `accounturi` 时请求 `account` 必须相同，
  带 `validationmethods` 时请求 `validation_method` 必须在其列表中；
  RRset 中至少一条记录完全匹配即允许签发；
- **未知 tag**（非 `issue`/`issuewild`/`iodef`）设置 critical 位
  （`flags & 128`）时禁止签发（`unknown_critical_property`），
  未设置则忽略；
- 一直查到区顶仍没有 CAA RRset 则**允许签发**（`no_caa_record`）。

响应 `caa` 中：`allowed` 为最终布尔结论，`status` 为 `allowed` /
`denied` / `indeterminate`（均为 **HTTP 200** 下的判定终态），
`reason` 为结论码；`relevant` 为命中的首个 CAA RRset（`owner`、
`ttl`、`applicable_tag` 及逐记录的 `flags`/`critical`/`tag`/`value`/
`issuer`/`params`/`accounturi`/`validationmethods`/`matched`/`reason`）；
`matched` 为其中匹配且适用的 issue/issuewild 记录；`trace` 为
**有序轨迹**（`climb` → `cname`/`found` → `result`），`cname_hops`
为实际经过的 CNAME 跳数。只有请求格式错误（`400`）、区域解析失败
（`422`）与 CNAME 环/超跳（`422`）走错误响应。

请求体（`account` 与 `validation_method` 可选；`wildcard` 缺省为
`false`）：

```json
{
  "zones": ["<区域文本>", "<另一个区域（如被委派的子区）>"],
  "domain": "www.example.com.",
  "wildcard": false,
  "ca_domain": "letsencrypt.org",
  "account": "https://acme.example/account/42",
  "validation_method": "http-01"
}
```

## ZONEMD 区域摘要校验（`POST /api/zonemd/verify`）

不发起任何真实 DNS 查询：输入一段区域文本，解析**仅位于区顶**的
ZONEMD RRset（区域解析新增 **ZONEMD** 类型，RDATA 为
`<serial> <scheme> <hash-algorithm> <digest>`，digest 可跨记号书写），
按 RFC 8976 **Simple Scheme**（scheme 1）重算区域摘要并逐条核对；
**不校验 RRSIG**。

摘要计算（RFC 8976 §3.3.1 + RFC 4034 §6）：

- 各类 RR 编为 DNSSEC 规范 wire format：名称小写 wire 编码、不压缩；
  同一 owner 的 RRset 按**类型号**升序；RRset 内 RDATA 按 wire 字节序
  排列；重复 RR 只取一份；
- **排除区顶 ZONEMD RRset** 后按规范顺序拼接，对拼接结果计算摘要；
- 区域文本重排、重复 RDATA 与等价写法（相对名/`@`/时长单位/大小写等）
  **不改变**摘要。

逐条核对（RFC 8976 §4 步骤 5）：

- 支持 scheme 1（SIMPLE）与 SHA-384（算法 1）/SHA-512（算法 2）；
  **未知 scheme 或摘要算法**的记录标为 `supported=false`（unsupported），
  不参与结论；
- 每条受支持记录要求 `serial` 等于 SOA serial、digest 长度匹配算法
  （SHA-384 为 48 字节、SHA-512 为 64 字节），再比较摘要值。

响应 `zonemd` 中：`status` 为总结论——有受支持记录匹配为 `valid`，
受支持记录均不匹配为 `invalid`，全部不受支持（含没有 ZONEMD 记录）
为 `unsupported`，均为 **HTTP 200** 下的校验终态；`records` 逐条给出
`serial`/`scheme`/`hash_algorithm`/`supported`/`expected`（记录中的
摘要）/`computed`（重算摘要，不受支持时为 `null`）/`matched`/`reason`；
`trace` 为**有序 RR 轨迹**（按摘要输入顺序，`seq` 从 1 开始，可见
ZONEMD RRset 已被排除）。只有请求格式错误（`400`）、区域解析失败
（`422`，含非区顶 ZONEMD）与缺少区顶 SOA（`422`）走错误响应。

请求体：

```json
{
  "zone": "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1 admin 2024010100 600 300 86400 300\n@ IN NS ns1\nns1 IN A 192.0.2.10\n@ IN ZONEMD 2024010100 1 1 <48 字节十六进制摘要>\n"
}
```

## 离线 TLSA（DANE）校验（`POST /api/tlsa/verify`）

不发起任何真实 DNS 查询：把**本地区域文本集合**当作权威数据源，
查询 `_<端口>._<协议>.<主机名>` 的 TLSA RRset（区域解析新增
**TLSA** 类型，RDATA 为 `<usage> <selector> <matching-type>
<关联数据>`，关联数据可跨记号书写），与请求给出的 **PEM 叶证书**
逐条核对。证书由 `cryptography` 解析校验，但 `selector=1` 使用的
**SPKI 直接从证书 DER 的 `tbsCertificate` 中按 ASN.1 结构截取完整
`SubjectPublicKeyInfo` TLV（原始编码，兼容可选 `version` 字段及
短/长形式长度编码），不做字节搜索，也不用公钥对象重导出**——部分
证书（典型为算法标识 id-RSASSA-PSS，见 RFC 4055）的原始 SPKI 与
重导出编码不同（重导出会退回 `rsaEncryption`），按重导出求值会把
RFC 6698 §2.3 本应匹配的记录误判为 mismatched。
**不验证 DNSSEC**（验证状态由请求 `dnssec` 字段外部给出）、
**不验证证书链**、**不验证证书与主机名的匹配**。

记录校验（任一违反即 `422`，随区域解析一同报出）：

- `usage` / `selector` / `matching-type` 为 `0..255` 的整数；
- 关联数据是非空的偶数长度十六进制串（大小写、跨记号写法等价）。

核对规则（RFC 6698 §2.1）：

- 仅支持 **usage=3（DANE-EE）**：`selector=0` 取**证书 DER 原始
  字节**、`selector=1` 取 **tbsCertificate 中截取的原始 SPKI DER**；
  `matching-type=0` 直接比较原始字节、`1` 比较 SHA-256、`2` 比较
  SHA-512；逐条记录的 `computed` 与 `certificate.spki_sha256` 均以
  该原始编码求值；其余组合的记录标为 `supported=false`，不参与结论；
- 有受支持记录时按外部 DNSSEC 状态给结论：`secure` 下任一记录
  匹配为 `matched`、均不匹配为 `mismatched`；`insecure` 为
  `indeterminate`；`bogus` 为 `invalid`；
- 查询名没有 TLSA 记录（含名字不被任何已提供区域覆盖、或落在
  未提供的委派子区）为 `none`；只有不受支持记录为 `unsupported`。

响应 `tlsa` 中：`status` 为总结论（均为 **HTTP 200** 下的校验终态），
`qname` 为实际查询名；`records` 逐条给出
`usage`/`selector`/`matching_type`（及名称）、`supported`、
`expected`（记录中的关联数据）/`computed`（由证书算出的关联数据，
不受支持时为 `null`）/`matched`/`reason`；`certificate` 给出叶证书
DER 长度与 DER/SPKI 的 SHA-256 指纹；`trace` 为**有序轨迹**
（`qname` → `lookup` → `result`）。只有请求格式错误（`400`，
含 PEM 证书解析失败）与区域解析失败（`422`，含 TLSA 字段/
十六进制错误）走错误响应。

请求体（`dnssec` 取 `secure`/`insecure`/`bogus`，`protocol` 取
`tcp`/`udp`/`sctp`）：

```json
{
  "zones": ["<区域文本>", "<另一个区域（如被委派的子区）>"],
  "hostname": "www.example.com",
  "port": 443,
  "protocol": "tcp",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "dnssec": "secure"
}
```

## 离线 AXFR 响应流检查（`POST /api/axfr/inspect`）

不发起任何真实 DNS 查询：输入区源点 `zone_origin` 与 Base64 编码的
**带两字节长度前缀的 TCP DNS 响应流**（`stream` 字段），逐帧解析
DNS 头、问题区与回答区（授权区/附加区不解析、不参与判定），支持
名称压缩（RFC 1035 §4.1.4，指针可指向报文内任意先前位置）与本服务
全部记录类型（SOA/NS/A/AAAA/CNAME/MX/TXT/SVCB/HTTPS/CAA/ZONEMD/TLSA），
并按区传送的结构规则给出结论。

解析错误（均为 `422`）：

- 长度前缀或帧体截断（`frame_truncated`）；
- 压缩指针成环（`compression_pointer_loop`）或越界
  （`compression_pointer_out_of_bounds`）；
- RDATA 长度不符（`rdata_length_mismatch`：定长类型长度不对、
  名称/字段消费的字节数与 RDLENGTH 不一致）；
- 其它 RDATA 内容非法（`invalid_rdata`）、TTL 超出 31 位
  （`invalid_record`）、不支持的 RR 类型（`unsupported_type`）、
  名称无法规范化为合法主机名（`invalid_name`）。

结构规则（违反时 `status=invalid`）：

- 首帧问题区必须恰好是目标区的 `IN AXFR` 查询；后续帧问题区可为空
  或与首帧完全相同；
- 所有帧 ID 一致、QR=1、opcode=0、RCODE=0、TC=0；
- 回答必须以目标区 SOA 开始、以**完全相同**（owner/TTL/RDATA）的
  SOA 结束，中间不得再有 SOA；
- 所有回答 owner 必须位于区内；相同记录（owner/type/TTL/RDATA）
  不得重复（首尾 SOA 对除外）；同一 RRset 的 TTL 必须一致；
  回答记录的类必须为 IN；ZONEMD 只能位于区顶。

`status=incomplete`：响应流为空、没有任何回答记录、缺少闭合 SOA，
或闭合 SOA 之后仍有回答记录。

三种状态都是 **HTTP 200** 下的检查终态；只有请求格式错误（`400`）
与上述解析错误（`422`）走错误响应。任何 200 响应的 `axfr` 都包含
`message_count`（报文数）、`record_count`（回答记录数）与 `trace`
（按帧及记录排列的轨迹：每帧给出 `message_id`、问题区与回答记录，
记录 `seq` 跨帧连续编号）；`status=complete` 时额外包含 `zone`——
按规范序生成的区域文本，可直接作为 `/api/reviews` 的
`old_zone` / `new_zone`。

请求体：

```json
{
  "zone_origin": "example.com.",
  "stream": "<Base64 编码的 TCP DNS 响应流（每个报文带两字节长度前缀）>"
}
```

## 离线迭代解析轨迹校验（`POST /api/dns/delegation-trace`）

不发起任何真实 DNS 查询：输入查询名 `qname`、类型 `qtype`
（**仅 `A`/`AAAA`/`NS`/`CNAME`**）、根服务器地址 `root_addresses`
与一串 `hops`，离线校验这条迭代解析轨迹是否合法。每跳给出
`server`、`question`（`{name, type}`）与 `answer`/`authority`/
`additional` 三个记录区；记录为 `{name, type, ttl?, rdata}`
（`ttl` 省略为 0），A/AAAA 地址与 NS/CNAME 目标会规范化
（IPv6 压缩小写、名字补全为小写绝对名）。**不校验 DNSSEC 与
否定应答**——既非终答、CNAME 也非转介的响应视为无法识别。

结构规则（违反即 `invalid` 并给出首个失败跳 `failed_hop`）：

- **首跳只能用根地址**；CNAME 重启与地址子查询同样从根开始；
- **转介须来自当前委派区**：authority 中 NS 的属名（子区）必须位于
  当前区内、严格更长、且包含查询名，否则为越权转介
  （`referral_out_of_bailiwick` / `referral_not_deeper` /
  `referral_misses_qname`；多个不同属名为
  `referral_multiple_zones`）；
- **additional 只接纳子区内 NS 的 A/AAAA 胶水**；区外 NS 的地址
  须由**独立的地址子查询**（从根开始的 A/AAAA 查询）取得，
  additional 中区外 NS 的地址记录被丢弃（`out_of_bailiwick_glue`）；
- **后续 server 须有已接纳来源**：根地址、已接纳胶水或已完成的
  地址子查询（否则 `server_no_source`）；
- **权威终答结束当前（子）查询**；主查询终答后仍有多余跳为
  `trailing_hops`，跳用完仍未完成为 `incomplete_trace`；
- 问题与当前查询不符且不是合法的地址子查询即 `question_mismatch`；
- **地址子查询与 CNAME 别名共享 32 跳预算**（`hop_budget_exceeded`）
  并检测循环（`address_query_loop` / `cname_loop`）。

响应 `delegation_trace` 中：`status` 为 `valid` / `invalid`（均为
**HTTP 200** 下的校验终态）；`final_answer` 为最终回答记录
（含 CNAME 链）；`hops` 为逐跳轨迹——每跳给出 server 来源
（`server_source`）、所属解析线（`context` 为 `main`/`address`，
地址子查询带 `for`）、动作（`referral`/`answer`/`cname`/`invalid`）
与**逐记录取舍原因**（`accepted`：`final_answer`/`cname_restart`/
`referral_ns`/`glue`；`discarded`：`owner_mismatch`/`type_mismatch`/
`out_of_bailiwick_glue`/`unexpected_*`/`unsupported_type` 等）；
`address_sources` 为**地址来源图**（每个已接纳地址来自根、哪一跳的
胶水或哪个地址子查询）。只有请求格式错误（`400`）与记录内容错误
（`422`，`invalid_record`）走错误响应。

请求体（完整示例见 `examples/delegation_trace.json`：区外 NS 触发
地址子查询后主查询继续，最终 `valid`）：

```json
{
  "qname": "www.example.com.",
  "qtype": "A",
  "root_addresses": ["192.0.2.1"],
  "hops": [
    {"server": "192.0.2.1",
     "question": {"name": "www.example.com.", "type": "A"},
     "answer": [],
     "authority": [{"name": "com.", "type": "NS", "ttl": 172800,
                    "rdata": "ns1.com."}],
     "additional": [{"name": "ns1.com.", "type": "A", "ttl": 172800,
                     "rdata": "192.0.2.2"}]},
    {"server": "192.0.2.2",
     "question": {"name": "www.example.com.", "type": "A"},
     "answer": [{"name": "www.example.com.", "type": "A", "ttl": 300,
                 "rdata": "192.0.2.80"}]}
  ]
}
```

## API

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| `POST` | `/api/reviews` | 执行审查，不落库 |
| `POST` | `/api/reviews/confirm` | 审查通过则保存**规范差异 + 复演请求**，返回记录 id；不安全/非法时拒绝（`422`/`409`），不保存 |
| `POST` | `/api/spf/evaluate` | 基于本地区域文本离线求值 SPF，返回终态与有序轨迹 |
| `POST` | `/api/dnssec/nsec-proof` | 校验 NSEC 链并判定 NODATA/NXDOMAIN 否认证明，返回最小证明记录 |
| `POST` | `/api/svcb/resolve` | 离线解析 SVCB/HTTPS（AliasMode 链 + ServiceMode 过滤），返回端点与逐跳轨迹 |
| `POST` | `/api/caa/authorize` | 离线判定 CAA 签发授权（issue/issuewild + critical 未知属性），返回 allowed/命中记录/轨迹 |
| `POST` | `/api/zonemd/verify` | 校验区顶 ZONEMD 区域摘要（RFC 8976 Simple，SHA-384/SHA-512），返回逐条结果与有序 RR 轨迹 |
| `POST` | `/api/tlsa/verify` | 离线核对 TLSA（DANE）记录（RFC 6698，仅 usage=3；selector 0/1，matching 0/1/2），返回逐条结果与有序轨迹 |
| `POST` | `/api/axfr/inspect` | 离线检查 Base64 编码的 TCP AXFR 响应流（逐帧解析/名称解压/结构校验），返回状态、按帧轨迹与规范区域文本 |
| `POST` | `/api/dns/delegation-trace` | 离线校验迭代解析轨迹（转介/胶水/地址子查询/CNAME 重启，共享 32 跳预算），返回 final_answer、逐记录取舍与地址来源图 |
| `GET`  | `/api/reviews` | 已确认审查列表 |
| `GET`  | `/api/reviews/<id>` | 读取一条确认（含 `replay_request` 可原样复演） |
| `GET`  | `/healthz` | 健康检查 |

请求体：`{"old_zone": "<区域文本>", "new_zone": "<区域文本>", "default_ttl": 3600}`
（`default_ttl` 可选。）

成功响应中的 `review.plan` 是有序步骤列表；`action=delegation` 的步骤
含 `members`，表示必须原子生效的多条 RRset 变更。不安全时
`review.safe=false`、`review.plan=null`，`review.conflicts` 是
最小冲突 RRset 见证（owner/type + 原因码）。

## 一键启动（Docker Compose）

```bash
docker compose up --build -d
# 服务监听宿主机 8080 端口
curl -s http://localhost:8080/healthz
```

停止与清理：

```bash
docker compose down          # 停止（保留数据卷）
docker compose down -v       # 同时删除审查记录数据卷
```

## 本地运行（无需 Docker）

需要 Python 3.10+；TLSA 校验（`/api/tlsa/verify`）额外需要
`cryptography`（其余接口仅用标准库）：

```bash
pip install -r requirements.txt   # 仅 TLSA 证书解析需要
python3 -m app.server
# 可用环境变量：HOST=0.0.0.0 PORT=8080 DATABASE=./data/reviews.db
```

运行测试（缺少 `cryptography` 时 TLSA 测试自动跳过）：

```bash
python3 -m unittest discover -s tests -v
```

## 快速试用

```bash
# 一次存在安全顺序的变更（www: A -> CNAME，先删 A 再建 CNAME）
curl -s http://localhost:8080/api/reviews \
  -H 'Content-Type: application/json' \
  --data @examples/review.json | python3 -m json.tool

# 确认并保存
curl -s -X POST http://localhost:8080/api/reviews/confirm \
  -H 'Content-Type: application/json' \
  --data @examples/review.json | python3 -m json.tool

# 不安全变更：新委派缺少域内胶水 -> 返回最小冲突 RRset，无发布计划
curl -s http://localhost:8080/api/reviews \
  -H 'Content-Type: application/json' \
  --data @examples/review_unsafe.json | python3 -m json.tool

# 离线 SPF 求值（include 命中 example.net 的 ip6 -> pass）
curl -s http://localhost:8080/api/spf/evaluate \
  -H 'Content-Type: application/json' \
  --data @examples/spf_evaluate.json | python3 -m json.tool

# NSEC 否认证明校验（ghost.example.com. 的 NXDOMAIN 证明成立）
curl -s http://localhost:8080/api/dnssec/nsec-proof \
  -H 'Content-Type: application/json' \
  --data @examples/nsec_proof.json | python3 -m json.tool

# 离线 SVCB/HTTPS 解析（www 别名到 svc，返回两个按优先级排序的端点）
curl -s http://localhost:8080/api/svcb/resolve \
  -H 'Content-Type: application/json' \
  --data @examples/svcb_resolve.json | python3 -m json.tool

# 离线 CAA 签发授权（www 匹配 letsencrypt.org 及账户/验证方式 -> allowed）
curl -s http://localhost:8080/api/caa/authorize \
  -H 'Content-Type: application/json' \
  --data @examples/caa_authorize.json | python3 -m json.tool

# ZONEMD 区域摘要校验（SHA-384 与 SHA-512 两条记录均匹配 -> valid）
curl -s http://localhost:8080/api/zonemd/verify \
  -H 'Content-Type: application/json' \
  --data @examples/zonemd_verify.json | python3 -m json.tool

# 离线 TLSA 校验（SPKI 与证书两条记录均与 PEM 叶证书匹配 -> matched）
curl -s http://localhost:8080/api/tlsa/verify \
  -H 'Content-Type: application/json' \
  --data @examples/tlsa_verify.json | python3 -m json.tool

# 离线 AXFR 响应流检查（两帧区传送、SOA 首尾一致 -> complete，
# 响应中的 axfr.zone 可作为 old_zone/new_zone 交给 /api/reviews）
curl -s http://localhost:8080/api/axfr/inspect \
  -H 'Content-Type: application/json' \
  --data @examples/axfr_inspect.json | python3 -m json.tool

# 离线迭代解析轨迹校验（区外 NS 触发地址子查询后继续主查询 -> valid）
curl -s http://localhost:8080/api/dns/delegation-trace \
  -H 'Content-Type: application/json' \
  --data @examples/delegation_trace.json | python3 -m json.tool
```

`/api/spf/evaluate` 的最小内联示例：

```bash
curl -s http://localhost:8080/api/spf/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "zones": [
      "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns h 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\n@ IN TXT \"v=spf1 ip4:192.0.2.0/24 -all\"\n"
    ],
    "client_ip": "192.0.2.55",
    "mail_from": "alice@example.com",
    "helo": "mx.sender.example"
  }' | python3 -m json.tool
# -> spf.result = "pass"；client_ip 改为 8.8.8.8 则为 "fail"
```

`/api/caa/authorize` 的最小内联示例：

```bash
curl -s http://localhost:8080/api/caa/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "zones": [
      "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns h 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\nwww IN CAA 0 issue \"letsencrypt.org\"\n"
    ],
    "domain": "www.example.com",
    "wildcard": false,
    "ca_domain": "letsencrypt.org"
  }' | python3 -m json.tool
# -> caa.status = "allowed"；ca_domain 改为 "other-ca.net" 则为 "denied"
```

`/api/zonemd/verify` 的最小内联示例（RFC 8976 Appendix A.1 官方向量）：

```bash
curl -s http://localhost:8080/api/zonemd/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "zone": "$ORIGIN example.\n$TTL 86400\n@ IN SOA ns1 admin 2018031900 1800 900 604800 86400\n@ IN NS ns1\n@ IN NS ns2\n@ IN ZONEMD 2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c\nns1 3600 IN A 203.0.113.63\nns2 3600 IN AAAA 2001:db8::63\n"
  }' | python3 -m json.tool
# -> zonemd.status = "valid"；把摘要末位改掉则为 "invalid"
```

`/api/tlsa/verify` 的最小内联示例（证书 PEM 见
`examples/tlsa_verify.json`，此处 `<SPKI 的 SHA-256>` 为**证书
`tbsCertificate` 中原始 SPKI DER**（非公钥重导出）的 SHA-256
十六进制）：

```bash
curl -s http://localhost:8080/api/tlsa/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "zones": [
      "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns h 1 1h 1h 1w 1h\n@ IN NS ns\nns IN A 192.0.2.1\n_443._tcp.www IN TLSA 3 1 1 <SPKI 的 SHA-256>\n"
    ],
    "hostname": "www.example.com",
    "port": 443,
    "protocol": "tcp",
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
    "dnssec": "secure"
  }' | python3 -m json.tool
# -> tlsa.status = "matched"；dnssec 改为 "insecure" 得 "indeterminate"、
#    改为 "bogus" 得 "invalid"
```

## 端口与数据

- 默认端口：**8080**（`docker-compose.yml` 中映射 `8080:8080`，可用
  `PORT` 环境变量修改容器内端口）；SPF/TLSA 等离线接口与审查接口
  共用同一端口；
- SQLite 数据库：容器内 `/data/reviews.db`，由 Compose 命名卷
  `dns-review-data` 持久化（SPF 求值与 TLSA 校验等离线接口不落库）。

## 目录结构

```
app/
  models.py     # RRset / Zone 数据模型与规范序
  zoneparse.py  # 区域解析与名称/TTL/地址/TXT/MX/SVCB/HTTPS/CAA/ZONEMD/TLSA 规范化
  serial.py     # RFC 1982 序列号算术
  validity.py   # SOA/NS、CNAME 排他与环、委派与胶水不变量
  planner.py    # RRset 差异、委派宏、先后边、回溯安全排序、最小环见证
  digest.py     # 规范化 JSON 与 SHA-256 摘要
  review.py     # 审查编排
  spf.py        # 离线 SPF 解析与求值（机制/限定符/include/redirect/预算/环）
  nsec.py       # NSEC 链校验与 NODATA/NXDOMAIN 否认证明（不校验 RRSIG）
  svcb.py       # 离线 SVCB/HTTPS 解析（AliasMode 链/ServiceMode 过滤/逐跳轨迹）
  caa.py        # 离线 CAA 签发授权（树顶攀爬/CNAME 重启/issue·issuewild 匹配）
  zonemd.py     # ZONEMD 区域摘要校验（RFC 8976 Simple，wire 编码/逐条核对）
  tlsa.py       # 离线 TLSA（DANE）校验（RFC 6698，仅 usage=3；PEM 证书解析）
  axfr.py       # 离线 AXFR 响应流检查（TCP 帧切分/名称解压/SOA 首尾结构判定）
  delegation.py # 离线迭代解析轨迹校验（转介/胶水/地址子查询/CNAME 重启/32 跳预算）
  storage.py    # SQLite 持久化
  server.py     # ThreadingHTTPServer HTTP API
requirements.txt # TLSA 证书解析依赖（cryptography；镜像内安装）
tests/          # 单元与端到端测试
examples/       # curl 示例请求（review.json / spf_evaluate.json / nsec_proof.json / svcb_resolve.json / caa_authorize.json / zonemd_verify.json / tlsa_verify.json / axfr_inspect.json / delegation_trace.json 等）
```
