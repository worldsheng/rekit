# rekit

零依赖逆向工程工具包。纯标准库，`python src/main.py` 直接跑。

存在的理由：分析一个陌生二进制，头 30 秒要回答的问题只有几个——**这是什么、有没有壳、导入了什么、字符串里藏了什么、有没有加密块**。现有工具要么要装一堆依赖（pefile/lief/capstone），要么输出给人看的格式不可编程。rekit 把这些做成一个 CLI，输出可选 JSON，方便接管道。

## 快速开始

```powershell
$py = 'C:\Python 3.14\python.exe'

& $py src\main.py info    C:\Windows\System32\notepad.exe
& $py src\main.py pe      C:\Windows\System32\notepad.exe --imports
& $py src\main.py strings C:\Windows\System32\notepad.exe --grep kernel
& $py src\main.py xor     .\blob.bin
& $py src\main.py scan    C:\Windows\System32\drivers --min-score 50
& $py src\main.py hash    .\sample.exe
```

自测：

```powershell
& $py tests\selftest.py     # 43 checks, 合成 PE + 各模块单元测试
```

## 子命令

| 命令 | 作用 | 关键参数 |
|---|---|---|
| `info` | 格式识别、哈希、全局熵、高熵区段 | `--json` |
| `strings` | ASCII / UTF-16LE / UTF-8 字符串，带文件偏移 | `-n` 最小长度、`--kind`、`--grep` |
| `pe` | PE 头、节区表（逐节熵）、导入表、导出表、TLS 回调、Rich header、加壳评分 | `--imports` 展开函数名、`--json` |
| `xor` | 单字节暴破 / 指定 key 解密 / 已知明文(crib)恢复多字节 key | `--key`、`--crib`、`-o` |
| `scan` | 递归扫描目录，给每个 PE 打加壳分 | `--min-score`、`--max-size` |
| `hash` | sha256 / md5 / 大小 | |

## 加壳评分怎么算

`pe` 和 `scan` 输出的 `packer_score` 是若干条启发式规则的加权和：

| 权重 | 规则 | 含义 |
|---|---|---|
| 60 | `packer-section` | 节区名命中已知壳（UPX/ASPack/Themida/VMProtect/Enigma/MPRESS…） |
| 40 | `no-imports` | 导入表为空 |
| 35 | `high-entropy-code` | 可执行节熵 ≥ 7.2 |
| 30 | `minimal-imports` | ≤10 个导入函数 |
| 30 | `entry-outside-code` | 入口点不在任何可执行节 |
| 25 | `wx-section` | 节区同时可写可执行（W^X 违反） |
| 20 | `tls-callbacks` | 有 TLS 回调（入口前执行，常见反调试） |
| 15 | `uninitialized-section` | raw=0 但 virtual_size 很大 |
| 10 | `injection-apis` / `anti-debug-apis` / `keyboard-hooks` / `network-apis` / `persistence-apis` | 危险 API 面 |
| 5 | `overlay` | 末尾有附加数据 |

资源镜像（`.mui`、卫星 DLL）会被单独识别为 `resource-only-image`，不触发 `no-imports` 和 `entry-outside-code`——否则扫描 Windows 目录会满屏假阳性（实测 118 个误报 → 修掉后 1 个）。

**分数是提示不是判决。** 75 分的 ClipSp.sys 是微软签名驱动，不是恶意软件。

## 已验证

在真实系统文件上跑过：

| 样本 | 结果 |
|---|---|
| `System32\notepad.exe` (x64) | PE32+, 8 节, 16 个导入 DLL, score 10 |
| `SysWOW64\notepad.exe` (x86) | PE32, image base 0x400000, score 10 |
| `System32\drivers\tcpip.sys` | kind=driver, subsystem=NATIVE |
| `System32\drivers` 全目录 | 扫描 ~7.6s，1 个命中（ClipSp.sys） |

## 目录

```
src/main.py          入口
src/rekit/cli.py     命令行
src/rekit/pe.py      PE 解析 + 加壳启发式
src/rekit/formats.py 魔数识别（PE/ELF/Mach-O/APK/DEX/Office…）
src/rekit/strings.py 字符串提取（含 CJK wide）
src/rekit/entropy.py 香农熵 + 滑动窗口
src/rekit/xor.py     XOR 恢复
tests/selftest.py    43 项自测
docs/                路线图与接单手册
```

## 依赖

无。Python 3.10+（用了 `X | None` 语法；实测 3.14.5）。

## 状态

可用。核心解析与启发式已验证；下一步见 `docs/roadmap.md`。

## 已知限制

- 只做静态分析，不含反汇编（要看指令得上 IDA/Ghidra/capstone）
- 不做脱壳，只告诉你"这是壳"
- PE32+ 的 CLR 头没有解析
- 不支持 ARM64 的异常表解析
- 熵阈值是经验值，对特定语言/编译器可能偏
