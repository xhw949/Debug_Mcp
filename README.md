# Debug_Mcp

一个基于 [pyOCD](https://github.com/pyocd/pyOCD) 的嵌入式实时调试 **MCP（Model Context Protocol）** 工具，为 AI 助手提供 **IAR 风格的非阻塞实时附件调试** 能力。

> 与传统的"下载后停在断点"调试方式不同，本工具以 `connect_mode=attach` 方式连接到**正在运行**的 Cortex-M 设备：不复位、不停机、不打断目标程序，直接实时读取内存、符号和 C 变量。

## 目录

- [特性](#特性)
- [工作原理](#工作原理)
- [工具一览](#工具一览)
- [工具参数说明](#工具参数说明)
- [通信协议](#通信协议)
- [支持的变量表达式语法](#支持的变量表达式语法)
- [快速开始](#快速开始)
- [与 MCP 集成](#与-mcp-集成)
- [项目结构](#项目结构)
- [注意事项与限制](#注意事项与限制)
- [许可证](#许可证)

## 特性

- **实时附件（Live Attach）**：`connect_mode=attach` 接入正在运行的 Cortex-M，完全不影响设备运行。
- **非阻塞读取**：内存读取、符号解析、变量读取均为非暂停操作。
- **DWARF 变量解析**：通过匹配的 AXF 调试信息，将 C 变量表达式解析为真实地址并解码出当前值。
- **快照（Snapshot）**：短暂停机后**连贯**读取多个变量与内核寄存器，随后自动恢复运行。
- **AXF 自动查找**：在项目目录递归搜索最新构建产物（`.axf` / `.elf` / `.out`）。
- **安全性设计**：不暴露任何写、擦除、烧录、断点、复位、运行控制操作；探测器的连接状态始终保持一致。

## 工作原理

`live_attach.py` 是一个 **JSON-lines 助手进程**，通过 `stdin` / `stdout` 与 MCP 服务端通信：

```
┌──────────────┐   每行一个JSON请求    ┌──────────────────────────┐
│  MCP 服务端  │ ──────────────────→ │  live_attach.py 助手进程   │
│ (DebugMcp)   │ ←─────────────────── │   ├─ DWARFResolver        │
└──────────────┘   每行一个JSON响应    │   │   解析 .axf 调试信息   │
                                      │   └─ pyOCD session        │
                                      │       附件到目标 Cortex-M  │
                                      └──────────────────────────┘
```

核心组件：

- **DWARFResolver**：读取 AXF（`.axf` / `.elf` / `.out`）的 DWARF 调试信息，建立 `符号名 → DIE → 地址` 映射，支持结构体成员偏移计算、数组下标定位、位域提取（兼容 DWARF3 的 MSB 偏移与 DWARF4 的 LSB 偏移）、枚举名映射，以及运行时指针解引用。
- **pyOCD 会话**：以 `connect_mode=attach`、`auto_unlock=False`、`jlink.power=False` 打开探测设备，不做任何运行控制。
- **JSON-lines 主循环**：逐行读请求、分发处理、逐行回写结果，每个请求独立成功/失败，互不影响。

## 工具一览

| 工具 | 说明 | 是否停机 |
| --- | --- | --- |
| `attach` | 附件到指定探测器的 Cortex-M 目标 | 否 |
| `detach` | 关闭附件连接，恢复探测器原状态 | 否 |
| `status` | 查询附件状态与目标运行状态 | 否 |
| `read_memory` | 读取 1~256 字节内存 | 否 |
| `resolve_symbol` | 从 AXF 解析符号地址与大小 | 否 |
| `read_symbol` | 解析符号并读取其存储内容 | 否 |
| `read_variable` | 读取单个 C 变量（结构体成员、数组、指针解引用） | 否 |
| `read_variables` | 批量读取（最多 64 个变量），每个独立成功/失败 | 否 |
| `read_registers` | 读取 r0~r12、sp、lr、pc、xpsr | 是（自动恢复） |
| `snapshot` | 停机后连贯读取变量 + 寄存器，再恢复 | 是（自动恢复） |
| `find_axf` | 递归查找最新构建产物 | 否 |
| `shutdown` | 优雅退出并断开 | 否 |

## 工具参数说明

### attach

| 参数 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- |
| `probe_serial` | ✔ | — | 探索器 USB 序列号（如 J-Link / ST-Link / CMSIS-DAP） |
| `target` | | `cortex_m` | pyOCD 目标类型，通用 CoreSight 访问保持 `cortex_m` |
| `protocol` | | `swd` | 调试协议，`swd` 或 `jtag` |
| `clock_hz` | | `2000000` | 调试时钟频率，范围 1000 ~ 50,000,000 |

### read_memory

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `address` | ✔ | 32 位起始地址，例如 `0x200031EC` |
| `length` | ✔ | 字节数，1 ~ 256 |

### resolve_symbol / read_symbol

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `axf_file` | ✔ | 正在运行的固件所对应的 AXF 绝对路径 |
| `symbol` | ✔ | 精确链接符号名，例如 `SystemCoreClock` |
| `length` | | （仅 `read_symbol`）读取字节数，缺省为符号的链接大小 |

### read_variable / read_variables

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `axf_file` | ✔ | 与运行固件**完全一致**的 AXF 绝对路径 |
| `expression` / `expressions` | ✔ | C 变量路径；批量版为字符串数组，最多 64 个，逐条独立成功/失败 |

### read_registers / snapshot

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `axf_file` | ✔ | （仅 `snapshot`）用于 DWARF 变量解析的 AXF |
| `expressions` | ✔ | （仅 `snapshot`）变量表达式数组，最多 64 个 |

### find_axf

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `root` | ✔ | 递归搜索的项目根目录 |

## 通信协议

JSON lines：向 `stdin` 逐行写入请求，从 `stdout` 逐行读取响应，每个响应带请求的 `id` 对应。

请求示例：

```json
{"id": 1, "operation": "attach", "arguments": {"probe_serial": "J-LINK-SN1234", "target": "cortex_m", "protocol": "swd", "clock_hz": 2000000}}
{"id": 2, "operation": "read_variable", "arguments": {"axf_file": "C:/build/app.axf", "expression": "g_bms.pack[2].soc"}}
{"id": 3, "operation": "snapshot", "arguments": {"axf_file": "C:/build/app.axf", "expressions": ["sys->voltage", "*p_cfg", "opmode"]}}
```

响应示例：

```json
{"id": 1, "ok": true, "result": {"state": "attached", "probe_serial": "J-LINK-SN1234", "target": "cortex_m", "protocol": "swd", "clock_hz": 2000000, "connect_mode": "attach", "auto_unlock": false, "jlink_power": false}}
{"id": 2, "ok": true, "result": {"expression": "g_bms.pack[2].soc", "address": "0x200031EC", "bytes_hex": "57", "decoded_value": 87}}
{"id": 3, "ok": false, "error": "expression must be a string"}
```

错误统一为 `{"id": <id>, "ok": false, "error": "..."}` 格式，JSON 解析失败时会附带头部输入以便诊断。

## 支持的变量表达式语法

- 普通全局变量：`g_flag`
- 结构体成员：`g_bms.pack[2].soc`、`sys_status.mode`
- 数组下标：`adc_buf[5]`
- 指针解引用：`*p_cfg`、`node->next`

函数调用、取地址（`&x`）、类型转换、赋值、任意算术表达式一律**拒绝**。

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

（`DebugMcp.exe` 已打包环境中所有依赖，可直接使用，无需安装 Python。）

### 2. 启动助手并读取一个变量

```python
import json
import subprocess

proc = subprocess.Popen(
    [r"C:\tools\debug-mcp\DebugMcp.exe"],   # 或 python live_attach.py
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True,
)

def call(msg: dict) -> dict:
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

print(call({"id": 1, "operation": "attach",
            "arguments": {"probe_serial": "J-LINK-SN1234"}}))
print(call({"id": 2, "operation": "read_variable",
            "arguments": {"axf_file": r"C:\build\app.axf",
                          "expression": "g_bms.pack[2].soc"}}))
call({"id": 3, "operation": "shutdown", "arguments": {}})
```

### 3. 调试流程建议

1. 用 `find_axf` 在工程目录定位最新的 AXF（按修改时间排序，自动选中最新）。
2. 用 `attach` 附件到探测器，确认返回 `state: attached`。
3. 用 `status` 确认目标运行状态（`running` / `sleeping` / `halted`）。
4. 之后即可随意 `read_memory`、`read_variable`、`read_registers`、`snapshot`，无需再打扰目标。

## 与 MCP 集成

本仓库的服务端二进制为 `DebugMcp.exe`（打包自 `live_attach.py`）。在支持 MCP 的客户端（如 Claude Desktop、ZCode 等）中按标准 MCP 配置注册：

```json
{
  "mcpServers": {
    "Debug_Mcp": {
      "command": "C:\tools\debug-mcp\DebugMcp.exe",
      "args": []
    }
  }
}
```

配置完成后，AI 助手即可调用本仓库提供的 11 个调试工具，直接对运行中的目标进行实时读取。

## 项目结构

```
debug-mcp/
├── live_attach.py      # 核心助手：DWARF 解析、pyOCD 附件、JSON-lines 服务
├── DebugMcp.exe        # 打包好的可执行服务端
├── requirements.txt    # Python 依赖清单
├── README.md
└── .gitignore
```

## 注意事项与限制

- **AXF 必须匹配**：`live_attach.py` 需与正在运行的目标使用**完全一致**的 AXF，符号与类型错误时会逐条报错，不会误读其他固件的地址。
- **非停机读取的时效性**：`read_memory` 为非暂停采样，读取期间目标可能仍在运行，值可能变化；需要一致性时请使用 `snapshot`。
- **外设寄存器副作用**：对内存映射外设寄存器做读取采样可能产生目标特定副作用，请谨慎使用。
- **批量上限**：`read_variables` / `snapshot` 单批最多 64 个变量表达式；单个非原始内存读取内部按 256 字节分块，总上限 64 KiB。
- **无写能力**：本工具只读，不做任何写、擦除、烧录、断点、复位与运行控制，请配合正常烧录流程使用。

## 许可证

MIT License

Copyright (c) 2026 xhw949
