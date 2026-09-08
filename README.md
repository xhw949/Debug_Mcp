# Debug_Mcp

**IAR-style non-halting live-attach debug tool for Cortex-M via pyOCD**

Debug_Mcp is a read-only MCP (Model Context Protocol) server that connects to a running Cortex-M target **without resetting or halting it** (connect_mode=attach). It provides DWARF-based C variable resolution, symbol lookup, memory read, register snapshot, and more - all through a JSON-lines stdio interface.

## Features

- **Non-halting live attach** - connects to a running Cortex-M via pyOCD without reset or halt (connect_mode=attach, auto_unlock=false, jlink.power=false)
- **C variable expression resolver** - resolves symbols through DWARF debug info from the matching AXF/ELF/OUT file
- **Read-only safety** - no write, flash, erase, breakpoint, reset, or run-control operations are exposed
- **Snapshot mode** - halts the target briefly, reads multiple variables coherently, then resumes
- **Register read** - captures r0-r12, sp, lr, pc, xpsr (halts briefly if running)
- **Memory read** - chunked reads up to a 64 KB safety cap
- **Auto-discovery** of AXF/ELF/OUT files under a project root directory
- **Symtab fallback** - when DWARF is not available, falls back to the ELF symbol table
- **Bitfield support** - decodes DWARF4 LSB-based and DWARF3 MSB-based bitfields
- **Enum mapping** - resolves enum names from debug info
- **JSON-lines stdio** - stdin/stdout MCP protocol

## Operations (MCP tools)

| Operation | Description |
|-----------|-------------|
| attach | Select a pyOCD probe (J-Link, ST-Link, CMSIS-DAP) and attach via SWD/JTAG |
| detach | Close the pyOCD session and release the probe |
| status | Return current connection state and target run status |
| read_memory | Read raw bytes from target memory at a given address |
| resolve_symbol | Look up a linker symbol address and size from the AXF |
| read_symbol | Resolve a symbol, then read its stored bytes from target memory |
| read_variable | Read a single C variable (DWARF-resolved, supports member/array/pointer) |
| read_variables | Batch read up to 64 C variables in one call |
| read_registers | Read core registers (halts briefly if running, then resumes) |
| snapshot | Halt, read registers + variables coherently in one instant, then resume |
| find_axf | Recursively search a directory for .axf/.elf/.out files |
| shutdown | Detach and exit |

## C Expression Support

The DWARF resolver supports:
- symbol
- symbol.member
- symbol.arr[5]
- symbol.member[2].subfield
- Pointer dereference: *ptr or ptr->field

Function calls, address-of, and casts are rejected.

## Requirements

- Python 3.10+
- pyocd >= 0.45.0
- pyelftools >= 0.33
- cmsis-pack-manager >= 0.6.0
- pylink-square >= 1.7.0
- A supported debug probe (J-Link, ST-Link, CMSIS-DAP, etc.)
- A Cortex-M target built with debug symbols (AXF/ELF/OUT, e.g. Keil MDK output)

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. List probes

```bash
python -m pyocd list
```

Take note of the probe serial number, e.g. J-Link [000123456789].

### 3. Connect as an MCP server

The server speaks JSON-lines over stdin/stdout. Register it in your MCP client (Claude Desktop, Claude Code, etc.):

```json
{
  "command": "python",
  "args": ["live_attach.py"]
}
```

Example JSON-lines transcript:

```json
{"id": 1, "operation": "attach", "arguments": {"probe_serial": "000123456789", "protocol": "swd", "clock_hz": 2000000}}
{"id": 2, "operation": "read_variable", "arguments": {"axf_file": "C:/firmware/project.axf", "expression": "g_bms.pack[2].soc"}}
{"id": 3, "operation": "read_registers"}
{"id": 4, "operation": "shutdown"}
```

### 4. Using the pre-built executable

A pre-built Windows executable (DebugMcp.exe) is included. Run it directly; it behaves exactly like live_attach.py:

```bash
DebugMcp.exe
```

## Safety

- **connect_mode=attach** - the target is never reset or halted on connect
- **No write tools** - there are no variable-write, memory-write, flash, erase, breakpoint, reset, or run-control operations
- **Read failure is not zero** - errors are returned faithfully; callers must not treat a failed read as a zero value
- **Probe state preserved** - the probe is left in its original connection state when the session ends

## Notes

- This project does not use Keil UVSC64.dll / UVSOCK; it talks to the probe directly via pyOCD, so it does not require Keil MDK.
- It works with any toolchain that produces DWARF debug info: Keil MDK (.axf), GCC (.elf), IAR (.out).
- snapshot and read_registers halt the target briefly; everything else is non-halting.

## License

MIT - see LICENSE.
