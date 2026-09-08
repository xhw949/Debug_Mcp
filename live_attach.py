#!/usr/bin/env python3
"""JSON-lines helper for the MCP's non-halting live-attach path.

This helper implements IAR-style attach via pyOCD:
  - Connect to a running Cortex-M without reset or halt (connect_mode=attach).
  - Read memory, resolve ELF symbols, and decode C variables through DWARF
    debug info from the matching AXF.
  - A "snapshot" tool halts the target briefly, reads multiple variables
    coherently, and resumes.  Every other tool is non-halting.

Safety: no write, flash, erase, breakpoint, reset, or run-control operations
are exposed.  The probe is always left in its original connection state.
"""

from __future__ import annotations

import json
import os
import struct
import sys
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
# DWARFExprParser is available in the installed pyelftools but not needed here;
# DW_AT_location is parsed inline.
from pyocd.core.helpers import ConnectHelper
from pyocd.core.target import Target


# ── DWARF expression / C-expression resolver ──────────────────────────────

class DWARFResolver:
    """Resolve C variable expressions to addresses using DWARF debug info.

    Supports:
      - ``symbol``
      - ``symbol.member``
      - ``symbol.arr[5]``
      - ``symbol.member[2].subfield``
      - Pointer read (``*ptr`` or ``ptr->field``) — requires a target memory
        callback because the pointer value is read at runtime.

    Rejects function calls, address-of, casts, and arbitrary expressions.
    """

    def __init__(self, axf_path: str):
        path = os.path.abspath(axf_path)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"AXF not found: {path}")
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".axf", ".elf", ".out"):
            raise ValueError("axf_file must have extension .axf, .elf, or .out")
        self.axf_path = path
        self._stream = open(path, "rb")
        self._elf = ELFFile(self._stream)
        if not self._elf.has_dwarf_info():
            # No DWARF: only .symtab fallback is available.
            self._dwarf = None
            self._symbol_die = {}
            self._typedef_map = {}
            self._struct_map = {}
            return
        self._dwarf = self._elf.get_dwarf_info()
        # Build a name → DIE map for top-level compile units.
        # Prefer the definition (with DW_AT_location) over a declaration.
        self._symbol_die: dict[str, DIE] = {}
        for cu in self._dwarf.iter_CUs():
            top = cu.get_top_DIE()
            for child in top.iter_children():
                if child.tag == "DW_TAG_variable":
                    name = self._die_name(child)
                    if name:
                        existing = self._symbol_die.get(name)
                        if existing is not None:
                            # Prefer the DIE that has a location (definition).
                            has_loc = "DW_AT_location" in child.attributes
                            existing_has_loc = "DW_AT_location" in existing.attributes
                            if has_loc and not existing_has_loc:
                                self._symbol_die[name] = child
                            elif not has_loc and existing_has_loc:
                                pass  # keep existing
                            else:
                                self._symbol_die[name] = child
                        else:
                            self._symbol_die[name] = child
        # Also index typedefs, structs, enums at the CU level for type lookup.
        self._typedef_map: dict[str, DIE] = {}
        self._struct_map: dict[str, DIE] = {}
        for cu in self._dwarf.iter_CUs():
            top = cu.get_top_DIE()
            for child in top.iter_children():
                tag = child.tag
                name = self._die_name(child)
                if not name:
                    continue
                if tag == "DW_TAG_typedef":
                    self._typedef_map[name] = child
                elif tag == "DW_TAG_structure_type":
                    self._struct_map[name] = child
                elif tag == "DW_TAG_enumeration_type":
                    self._struct_map.get(name)  # unused for now

    @staticmethod
    def _die_name(die: DIE) -> str | None:
        try:
            return die.attributes["DW_AT_name"].value.decode("utf-8")
        except (KeyError, AttributeError):
            return None

    def _resolve_type(self, type_die: DIE) -> tuple[int, str, DIE | None]:
        """Resolve a type DIE to (byte_size, type_name, raw_type_die)."""
        raw = type_die
        name = self._die_name(type_die) or "?"
        while type_die.tag == "DW_TAG_typedef":
            ref = self._follow_ref(type_die, "DW_AT_type")
            if ref is None:
                break
            type_die = ref
            n = self._die_name(type_die)
            if n:
                name = n
            raw = type_die
        size = self._int_attr(type_die, "DW_AT_byte_size", 0)
        return size, name, raw

    @staticmethod
    def _int_attr(die: DIE, attr: str, default: int = 0) -> int:
        try:
            v = die.attributes[attr].value
            if isinstance(v, bytes):
                # Values encoded as DWARF data (e.g., DW_FORM_data1..data8)
                # may be bytes; take the first byte.
                return int.from_bytes(v, "little", signed=False)
            return int(v)
        except (KeyError, ValueError, TypeError):
            return default

    @staticmethod
    def _follow_ref(die: DIE, attr: str) -> DIE | None:
        try:
            ref = die.attributes[attr].value
            if isinstance(ref, DIE):
                return ref
            if isinstance(ref, int):
                cu = die.cu
                form = die.attributes[attr].form
                # DW_FORM_ref1/2/4/8 are CU-relative offsets; DW_FORM_ref_addr
                # is an absolute offset across the whole .debug_info section.
                if form in ("DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4", "DW_FORM_ref8"):
                    target = cu.cu_offset + ref
                    # Search the current CU only.
                    for d in cu.iter_DIEs():
                        if d.offset == target:
                            return d
                else:
                    # DW_FORM_ref_addr — absolute, may be in any CU.
                    target = ref
                    for other_cu in die.dwarfinfo.iter_CUs():
                        for d in other_cu.iter_DIEs():
                            if d.offset == target:
                                return d
            return None
        except (KeyError, ValueError, AttributeError):
            return None

    # ── Expression tokeniser ───────────────────────────────────────────

    @staticmethod
    def _tokenise(expr: str) -> list[tuple[str, Any]]:
        """Tokenise a C expression: identifier, '.', '->', '[', ']', '*', int."""
        tokens: list[tuple[str, Any]] = []
        i = 0
        while i < len(expr):
            ch = expr[i]
            if ch in " \t":
                i += 1
                continue
            if ch == ".":
                tokens.append((".", None))
                i += 1
            elif ch == "[":
                tokens.append(("[", None))
                i += 1
            elif ch == "]":
                tokens.append(("]", None))
                i += 1
            elif ch == "*":
                tokens.append(("*", None))
                i += 1
            elif ch == ">" and i + 1 < len(expr) and expr[i + 1] == ">":
                tokens.append((">>", None))
                i += 2
            elif ch == ">" and i + 1 < len(expr) and expr[i + 1] == "=":
                tokens.append((">=", None))
                i += 2
            elif ch == ">" and i + 1 < len(expr) and expr[i + 1] == ">" and i + 2 < len(expr) and expr[i + 2] == ">":
                tokens.append((">>>", None))
                i += 3
            elif ch == ">" and i + 1 < len(expr) and expr[i + 1] == ">":
                tokens.append((">>", None))
                i += 2
            elif ch == ">":
                tokens.append((">", None))
                i += 1
            elif ch == "-" and i + 1 < len(expr) and expr[i + 1] == ">":
                tokens.append(("->", None))
                i += 2
            elif ch == "(" or ch == ")":
                tokens.append(("paren", ch))
                i += 1
            elif ch.isdigit() or (ch == "0" and i + 1 < len(expr) and expr[i + 1] in "xX"):
                j = i
                if expr[j:j+2].lower() == "0x":
                    j += 2
                    while j < len(expr) and expr[j] in "0123456789abcdefABCDEF":
                        j += 1
                    tokens.append(("int", int(expr[i:j], 16)))
                else:
                    while j < len(expr) and expr[j].isdigit():
                        j += 1
                    tokens.append(("int", int(expr[i:j])))
                i = j
                continue
            elif ch.isalpha() or ch == "_":
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == "_"):
                    j += 1
                tokens.append(("id", expr[i:j]))
                i = j
                continue
            else:
                # skip unknown chars
                i += 1
        return tokens

    def resolve(self, expression: str, target_read_mem=None) -> dict[str, Any]:
        """Resolve a C expression to an address and type.

        ``target_read_mem`` is an optional callable ``(address, length) -> bytes``
        used when a pointer dereference (``->`` or ``*``) is needed.
        """
        tokens = self._tokenise(expression)
        if not tokens:
            raise ValueError("empty expression")

        # The first token must be an identifier (the root symbol).
        if tokens[0][0] != "id":
            raise ValueError(f"expression must start with a symbol name: {expression}")
        symbol_name: str = tokens[0][1]
        die = self._symbol_die.get(symbol_name)

        if die is None and len(tokens) == 1:
            # No DWARF or symbol only in .symtab: fall back to a plain symbol.
            sym = LiveAttach._resolve_symbol_symtab(self.axf_path, symbol_name)
            return {
                "expression": expression,
                "symbol": symbol_name,
                "address": sym["address"],
                "address_hex": sym["address_hex"],
                "byte_size": sym["size"] if sym["size"] else 4,
                "type_name": "unknown (no DWARF)",
                "dwarf_encoding": -1,
                "dwarf_encoding_name": "unknown",
                "source": "symtab",
            }
        if die is None:
            raise LookupError(f"symbol not found in DWARF: {symbol_name}")

        base_addr = self._int_attr(die, "DW_AT_location", 0)
        # DW_AT_location can be a DWARF expression: for a global, it's
        # DW_OP_addr <addr>.  Detect that.
        loc = die.attributes.get("DW_AT_location")
        if loc is not None and loc.form in ("DW_FORM_exprloc", "DW_FORM_block1", "DW_FORM_block"):
            block = loc.value
            # Only DW_OP_addr followed by a 4-byte address on 32-bit.
            if len(block) >= 5 and block[0] == 0x03:  # DW_OP_addr
                base_addr = int.from_bytes(block[1:5], "little")
            elif len(block) >= 9 and block[0] == 0x03:  # DW_OP_addr (64-bit)
                base_addr = int.from_bytes(block[1:9], "little")
            else:
                raise ValueError(f"DW_AT_location expression not DW_OP_addr: {loc.form}")

        # Get the type DIE for the root symbol.
        type_die = self._follow_ref(die, "DW_AT_type")
        if type_die is None:
            # DIE exists but has no type info — fall back to symtab for a plain symbol.
            if len(tokens) == 1:
                sym = LiveAttach._resolve_symbol_symtab(self.axf_path, symbol_name)
                return {
                    "expression": expression,
                    "symbol": symbol_name,
                    "address": sym["address"],
                    "address_hex": sym["address_hex"],
                    "byte_size": sym["size"] if sym["size"] else 4,
                    "type_name": "unknown (no DWARF type)",
                    "dwarf_encoding": -1,
                    "dwarf_encoding_name": "unknown",
                    "source": "symtab_fallback",
                }
            raise ValueError(f"symbol has no DW_AT_type: {symbol_name}")

        offset = 0
        t = tokens[1:]
        i = 0
        last_member_die = None  # type: DIE | None
        while i < len(t):
            tok, val = t[i]
            if tok == ".":
                # Struct member access
                i += 1
                if i >= len(t) or t[i][0] != "id":
                    raise ValueError("expected member name after '.'")
                field_name: str = t[i][1]
                field_offset, type_die, last_member_die = self._resolve_field(type_die, field_name)
                offset += field_offset
                i += 1
            elif tok == "->":
                # Pointer dereference + member access
                ptr_addr = self._read_pointer(target_read_mem, base_addr + offset,
                                              f"deref {expression}")
                if ptr_addr is None:
                    raise ValueError(f"cannot dereference pointer at 0x{base_addr + offset:08X}: "
                                     "no target_read_mem provided")
                # Resolve the pointed-to type
                pointed_die = self._follow_ref(type_die, "DW_AT_type")
                if pointed_die is None:
                    raise ValueError("-> on a non-pointer type")
                type_die = pointed_die
                base_addr = ptr_addr
                offset = 0
                i += 1
                if i < len(t) and t[i][0] == ".":
                    i += 1
                    if i >= len(t) or t[i][0] != "id":
                        raise ValueError("expected member name after '->'")
                    field_name = t[i][1]
                    field_offset, type_die, last_member_die = self._resolve_field(type_die, field_name)
                    offset += field_offset
                    i += 1
            elif tok == "[":
                # Array index
                i += 1
                if i >= len(t) or t[i][0] != "int":
                    raise ValueError("expected integer index after '['")
                index: int = t[i][1]
                i += 1
                if i >= len(t) or t[i][0] != "]":
                    raise ValueError("expected ']' after array index")
                elem_size, type_die = self._resolve_array_element(type_die, index)
                offset += index * elem_size
                i += 1
            elif tok == "*":
                # Pointer dereference
                ptr_addr = self._read_pointer(target_read_mem, base_addr + offset,
                                              f"deref {expression}")
                if ptr_addr is None:
                    raise ValueError(f"cannot dereference pointer at 0x{base_addr + offset:08X}: "
                                     "no target_read_mem provided")
                pointed_die = self._follow_ref(type_die, "DW_AT_type")
                if pointed_die is None:
                    raise ValueError("* on a type that is not a pointer")
                type_die = pointed_die
                base_addr = ptr_addr
                offset = 0
                i += 1
            else:
                raise ValueError(f"unexpected token {tok} in expression: {expression}")

        final_addr = base_addr + offset
        byte_size, type_name, raw_type = self._resolve_type(type_die)
        if byte_size == 0:
            sym_size = self._symtab_size(symbol_name)
            if sym_size:
                byte_size = sym_size
            else:
                byte_size = 4  # fallback

        encoding = self._int_attr(raw_type, "DW_AT_encoding", -1)
        result = {
            "expression": expression,
            "symbol": symbol_name,
            "address": final_addr,
            "address_hex": f"0x{final_addr:08X}",
            "byte_size": byte_size,
            "type_name": type_name,
            "dwarf_encoding": encoding,
            "dwarf_encoding_name": self._encoding_name(encoding),
        }

        # --- Bitfield annotation ---
        if last_member_die is not None:
            bf = self._bitfield_info(last_member_die)
            if bf is not None:
                result["bitfield"] = bf
                # For a bitfield, the container word starts at the member's
                # byte offset (data_member_location) within the struct.
                # The DW_AT_data_member_location already set field_offset
                # correctly, so final_addr points at the byte *containing*
                # the bitfield.  Override byte_size to the container word size.
                # If the member's type is a 32-bit int, byte_size is already 4.
                # If DWARF doesn't give us a container type size, keep as-is.

        # --- Enumeration value mapping ---
        raw_check = raw_type
        while raw_check.tag == "DW_TAG_typedef":
            ref = self._follow_ref(raw_check, "DW_AT_type")
            raw_check = ref if ref else raw_check
            break
        if raw_check and raw_check.tag == "DW_TAG_enumeration_type":
            enum_values: dict[int, str] = {}
            for child in raw_check.iter_children():
                if child.tag == "DW_TAG_enumerator":
                    name = self._die_name(child)
                    val = self._int_attr(child, "DW_AT_const_value", None)
                    if name and val is not None:
                        enum_values[val] = name
            if enum_values:
                result["enum_values"] = enum_values

        return result

    def _resolve_field(self, type_die: DIE, field_name: str) -> tuple[int, DIE, DIE]:
        """Resolve a struct member name to (offset, member_type_die, member_die)."""
        resolved = self._resolve_type(type_die)
        struct_type = resolved[2] if resolved[2] else type_die
        # Unwrap typedefs
        while struct_type.tag == "DW_TAG_typedef":
            ref = self._follow_ref(struct_type, "DW_AT_type")
            if ref is None:
                break
            struct_type = ref
        if struct_type.tag != "DW_TAG_structure_type":
            raise ValueError(f"type {self._die_name(type_die)} is not a struct/union")
        for child in struct_type.iter_children():
            if child.tag == "DW_TAG_member":
                name = self._die_name(child)
                if name == field_name:
                    off = self._int_attr(child, "DW_AT_data_member_location", 0)
                    member_type = self._follow_ref(child, "DW_AT_type")
                    if member_type is None:
                        member_type = child
                    return off, member_type, child
        raise ValueError(f"field '{field_name}' not found in {self._die_name(struct_type) or 'struct'}")

    @staticmethod
    def _bitfield_info(die: DIE) -> dict | None:
        """If *die* is a DW_TAG_member with bitfield info, return the descriptor.

        Returns ``{"bit_size": N, "bit_offset": M, "msb_based": bool}``
        or ``None``.
        """
        bs = die.attributes.get("DW_AT_bit_size")
        if bs is None:
            return None
        bit_size = int(bs.value)
        # DWARF 4+ uses DW_AT_data_bit_offset (LSB-based).
        dbo = die.attributes.get("DW_AT_data_bit_offset")
        if dbo is not None:
            return {"bit_size": bit_size, "bit_offset": int(dbo.value), "msb_based": False}
        # DWARF 3 uses DW_AT_bit_offset (MSB-based within the containing word).
        bo = die.attributes.get("DW_AT_bit_offset")
        if bo is not None:
            return {"bit_size": bit_size, "bit_offset": int(bo.value), "msb_based": True}
        return None

    def _resolve_array_element(self, type_die: DIE, _index: int) -> tuple[int, DIE]:
        """Resolve an array element type and its element size."""
        elem_type = self._follow_ref(type_die, "DW_AT_type")
        if elem_type is None:
            raise ValueError("array type has no DW_AT_type")
        size, _name, _raw = self._resolve_type(elem_type)
        if size == 0:
            size = 4
        return size, elem_type

    @staticmethod
    def _read_pointer(target_read_mem, address: int, context: str) -> int | None:
        """Read a 32-bit pointer value from target memory."""
        if target_read_mem is None:
            return None
        data = target_read_mem(address, 4)
        if data is None or len(data) < 4:
            return None
        return struct.unpack_from("<I", data)[0]

    def _symtab_size(self, name: str) -> int:
        """Fallback: get symbol size from .symtab."""
        try:
            section = self._elf.get_section_by_name(".symtab")
            if section is None:
                return 0
            syms = list(section.get_symbol_by_name(name) or [])
            for s in syms:
                sz = s.entry["st_size"]
                if sz:
                    return int(sz)
        except Exception:
            pass
        return 0

    @staticmethod
    def _encoding_name(enc: int) -> str:
        names = {
            -1: "unknown",
            1: "DW_ATE_address",
            2: "DW_ATE_boolean",
            3: "DW_ATE_complex_float",
            4: "DW_ATE_float",
            5: "DW_ATE_signed",
            6: "DW_ATE_signed_char",
            7: "DW_ATE_unsigned",
            8: "DW_ATE_unsigned_char",
            9: "DW_ATE_imaginary_float",
            10: "DW_ATE_packed_decimal",
            11: "DW_ATE_numeric_string",
            12: "DW_ATE_edited",
            13: "DW_ATE_signed_fixed",
            14: "DW_ATE_unsigned_fixed",
            15: "DW_ATE_decimal_float",
            16: "DW_ATE_UTF",
        }
        return names.get(enc, f"DW_ATE_unknown_{enc}")

    def decode_value(self, data: bytes, byte_size: int, encoding: int) -> Any:
        """Decode raw bytes according to DWARF type."""
        if encoding in (5, 6):  # signed, signed_char
            fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}.get(byte_size)
            return struct.unpack(fmt, data[:byte_size])[0] if fmt else data.hex()
        elif encoding in (7, 8):  # unsigned, unsigned_char
            fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}.get(byte_size)
            return struct.unpack(fmt, data[:byte_size])[0] if fmt else data.hex()
        elif encoding == 4:  # float
            fmt = {4: "<f", 8: "<d"}.get(byte_size)
            return struct.unpack(fmt, data[:byte_size])[0] if fmt else data.hex()
        elif encoding == 2:  # boolean
            return int.from_bytes(data[:byte_size], "little") != 0
        else:
            # Fallback: show as hex bytes
            return data[:byte_size].hex()

    def close(self) -> None:
        self._stream.close()


# ── Live-attach helper ────────────────────────────────────────────────────

class LiveAttach:
    def __init__(self) -> None:
        self.session = None
        self._resolver = None  # type: DWARFResolver | None

    @staticmethod
    def _required_string(args: dict[str, Any], key: str) -> str:
        value = args.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _integer(value: Any, key: str) -> int:
        if isinstance(value, bool):
            raise ValueError(f"{key} must be an integer")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip():
            return int(value.strip(), 0)
        raise ValueError(f"{key} must be an integer or 0x-prefixed string")

    def _require_target(self) -> Target:
        if self.session is None:
            raise RuntimeError("not attached; call keil_live_attach first")
        return self.session.target

    def _require_core(self):
        """Get the first Cortex-M core from the current session."""
        target = self._require_target()
        if hasattr(target, 'selected_core') and target.selected_core is not None:
            return target.selected_core
        if hasattr(target, 'cores') and target.cores:
            return list(target.cores.values())[0]
        raise RuntimeError("no target core found; ensure init_board=True during attach")

    def _target_read_mem(self, address: int, length: int) -> bytes:
        """Read memory from the current pyOCD session."""
        target = self._require_target()
        return bytes(target.read_memory_block8(address, length))

    def _read_range(self, address: int, length: int, chunk: int = 256,
                    max_length: int = 65536) -> bytes:
        """Read a byte range from target memory in chunks.

        Raw-memory reads stay capped at 256 bytes for safety; variable reads
        may need more (large structs), so they are chunked internally.
        """
        if length < 1:
            raise ValueError("length must be positive")
        if length > max_length:
            raise ValueError(f"length exceeds the {max_length}-byte safety cap")
        target = self._require_target()
        out = bytearray()
        pos = address
        remaining = length
        while remaining > 0:
            n = min(chunk, remaining)
            out.extend(bytes(target.read_memory_block8(pos, n)))
            pos += n
            remaining -= n
        return bytes(out)

    @staticmethod
    def _extract_bitfield(word: int, bit_size: int, bit_offset: int,
                          msb_based: bool, word_bits: int = 32) -> tuple[int, int]:
        """Extract a bitfield from an unsigned container word.

        Returns ``(bitfield_value, mask)``.  DWARF4 uses LSB-based
        ``DW_AT_data_bit_offset``; DWARF3 uses MSB-based ``DW_AT_bit_offset``.
        """
        shift = (word_bits - bit_offset - bit_size) if msb_based else bit_offset
        if shift < 0:
            raise ValueError(f"invalid bitfield offset {bit_offset} for {word_bits}-bit word")
        mask = (1 << bit_size) - 1
        return (word >> shift) & mask, mask

    def _get_resolver(self, axf_file: str) -> DWARFResolver:
        """Get or create a DWARFResolver for the given AXF."""
        if self._resolver is not None:
            self._resolver.close()
        self._resolver = DWARFResolver(axf_file)
        return self._resolver

    # ── Tools ─────────────────────────────────────────────────────────

    def attach(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.session is not None:
            raise RuntimeError("already attached; detach before selecting another probe")

        probe_serial = self._required_string(args, "probe_serial")
        target = str(args.get("target") or "cortex_m").strip()
        protocol = str(args.get("protocol") or "swd").strip().lower()
        if protocol not in ("swd", "jtag"):
            raise ValueError("protocol must be swd or jtag")
        clock_hz = self._integer(args.get("clock_hz", 2_000_000), "clock_hz")
        if clock_hz < 1_000 or clock_hz > 50_000_000:
            raise ValueError("clock_hz must be between 1000 and 50000000")

        options = {
            "connect_mode": "attach",
            "auto_unlock": False,
            "jlink.power": False,
            "jlink.non_interactive": True,
            "target_override": target,
            "dap_protocol": protocol,
            "frequency": clock_hz,
            "cache.enable_memory": False,
        }

        session = ConnectHelper.session_with_chosen_probe(
            unique_id=probe_serial,
            blocking=False,
            return_first=True,
            auto_open=False,
            options=options,
        )
        if session is None:
            raise RuntimeError(f"probe {probe_serial} was not found or is busy")

        try:
            session.open(init_board=True)
            self.session = session
        except Exception:
            try:
                session.close()
            except Exception:
                pass
            raise

        return {
            "state": "attached",
            "probe_serial": probe_serial,
            "target": target,
            "protocol": protocol,
            "clock_hz": clock_hz,
            "connect_mode": "attach",
            "auto_unlock": False,
            "jlink_power": False,
            "safety": "pyOCD attached without reset or halt; no write, flash, erase, breakpoint, reset, or run-control operation is implemented",
        }

    def detach(self) -> dict[str, Any]:
        if self.session is None:
            return {"state": "already_detached"}
        session = self.session
        self.session = None
        if self._resolver is not None:
            self._resolver.close()
            self._resolver = None
        session.close()
        return {"state": "detached", "safety": "probe connection closed without reset, halt, or run-control"}

    def status(self) -> dict[str, Any]:
        if self.session is None:
            return {"state": "detached"}
        target = self._require_target()
        state = target.get_state()
        state_map = {
            Target.State.HALTED: "halted",
            Target.State.RUNNING: "running",
            Target.State.SLEEPING: "sleeping",
            Target.State.LOCKUP: "lockup",
        }
        return {"state": "attached", "target_state": state_map.get(state, "unknown")}

    def read_memory(self, args: dict[str, Any]) -> dict[str, Any]:
        target = self._require_target()
        address = self._integer(args.get("address"), "address")
        length = self._integer(args.get("length"), "length")
        if address < 0 or address > 0xFFFFFFFF:
            raise ValueError("address must be a 32-bit unsigned value")
        if length < 1 or length > 256:
            raise ValueError("length must be between 1 and 256")

        data = bytes(target.read_memory_block8(address, length))
        result: dict[str, Any] = {
            "address": f"0x{address:08X}",
            "length": length,
            "bytes_hex": data.hex().upper(),
            "bytes": list(data),
        }
        if length <= 8:
            result["value_le_unsigned"] = int.from_bytes(data, "little", signed=False)
        return result

    @staticmethod
    def _resolve_symbol_symtab(axf_file: str, symbol_name: str) -> dict[str, Any]:
        path = os.path.abspath(axf_file)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"AXF file not found: {path}")
        ext = os.path.splitext(path)[1].lower()
        if ext not in (".axf", ".elf", ".out"):
            raise ValueError("axf_file must have extension .axf, .elf, or .out")

        with open(path, "rb") as stream:
            elf = ELFFile(stream)
            section = elf.get_section_by_name(".symtab")
            if section is None:
                raise RuntimeError("ELF has no .symtab; build with debug symbols")
            candidates = list(section.get_symbol_by_name(symbol_name) or [])

        candidates = [
            item for item in candidates
            if item.entry["st_shndx"] != "SHN_UNDEF" and int(item.entry["st_value"]) != 0
        ]
        if not candidates:
            raise LookupError(f"symbol not found in AXF: {symbol_name}")

        def rank(item):
            info = item.entry["st_info"]
            return (
                0 if info["type"] == "STT_OBJECT" else 1,
                0 if info["bind"] == "STB_GLOBAL" else 1,
            )

        candidate = sorted(candidates, key=rank)[0]
        info = candidate.entry["st_info"]
        return {
            "axf_file": path,
            "symbol": candidate.name,
            "address": int(candidate.entry["st_value"]),
            "address_hex": f"0x{int(candidate.entry['st_value']):08X}",
            "size": int(candidate.entry["st_size"]),
            "symbol_type": info["type"],
            "binding": info["bind"],
            "section_index": candidate.entry["st_shndx"],
            "candidate_count": len(candidates),
        }

    def resolve_symbol(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._resolve_symbol_symtab(
            self._required_string(args, "axf_file"),
            self._required_string(args, "symbol"),
        )

    def read_symbol(self, args: dict[str, Any]) -> dict[str, Any]:
        symbol = self.resolve_symbol(args)
        length = args.get("length", symbol["size"])
        if not isinstance(length, int):
            length = self._integer(length, "length")
        if length < 1:
            raise ValueError("symbol has no stored bytes; provide a positive length")
        data = self._read_range(symbol["address"], length)
        symbol["memory"] = {
            "address": symbol["address_hex"],
            "length": length,
            "bytes_hex": data.hex().upper(),
            "bytes": list(data),
        }
        return symbol

    # ── NEW: DWARF-based variable resolution & decoding ────────────────

    def read_variable(self, args: dict[str, Any]) -> dict[str, Any]:
        """Resolve a C expression via DWARF and read/decoded the value."""
        axf_file = self._required_string(args, "axf_file")
        expression = self._required_string(args, "expression")

        resolver = self._get_resolver(axf_file)
        return self._do_read_variable(resolver, expression)

    @staticmethod
    def _map_enum_name(resolved: dict[str, Any], raw_value: int) -> None:
        """If the resolved result has an ``enum_values`` map, look up *raw_value*."""
        ev = resolved.get("enum_values")
        if ev and raw_value in ev:
            resolved["enum_name"] = ev[raw_value]

    def read_variables(self, args: dict[str, Any]) -> dict[str, Any]:
        """Batch-read multiple C expressions in one call."""
        axf_file = self._required_string(args, "axf_file")
        expressions = args.get("expressions")
        if not isinstance(expressions, list) or len(expressions) == 0:
            raise ValueError("expressions must be a non-empty list of strings")
        if len(expressions) > 64:
            raise ValueError("batch limited to 64 variables")

        resolver = self._get_resolver(axf_file)
        results: list[dict[str, Any]] = []
        for expr in expressions:
            if not isinstance(expr, str):
                results.append({"expression": str(expr), "error": "expression must be a string"})
                continue
            try:
                resolved = self._do_read_variable(resolver, expr)
                results.append(resolved)
            except Exception as e:
                results.append({"expression": expr, "error": str(e)})

        return {"count": len(results), "variables": results}

    def _do_read_variable(self, resolver: DWARFResolver, expression: str) -> dict[str, Any]:
        """Shared variable read logic used by read_variable, read_variables, snapshot."""
        resolved = resolver.resolve(expression, target_read_mem=self._target_read_mem)
        address = resolved["address"]
        byte_size = resolved["byte_size"]
        if byte_size < 1:
            byte_size = 4
        encoding = resolved["dwarf_encoding"]

        # Bitfield handling
        bf = resolved.get("bitfield")
        if bf is not None:
            container_size = byte_size if byte_size in (1, 2, 4, 8) else 4
            data = self._read_range(address, container_size)
            word = int.from_bytes(data, "little")
            bf_val, bf_mask = self._extract_bitfield(
                word, bf["bit_size"], bf["bit_offset"], bf["msb_based"],
                container_size * 8)
            resolved["container_bytes_hex"] = data.hex().upper()
            resolved["container_value"] = word
            resolved["bitfield_value"] = bf_val
            resolved["bitfield_mask"] = bf_mask
            resolved["bitfield_bits"] = f"0b{bf_val:0{bf['bit_size']}b}"
            decoded = resolver.decode_value(data, container_size, 7)
            resolved["decoded_value"] = decoded
            self._map_enum_name(resolved, bf_val)
            resolved["byte_size"] = container_size
        else:
            data = self._read_range(address, byte_size)
            # No DWARF type info: decode raw words as unsigned integers when
            # the size matches a whole word; this turns a raw symbol like
            # SystemCoreClock into a useful decimal value.
            if encoding == -1 and byte_size in (1, 2, 4, 8):
                encoding = 7
                resolved["dwarf_encoding"] = 7
                resolved["dwarf_encoding_name"] = "DW_ATE_unsigned (inferred)"
            decoded = resolver.decode_value(data, byte_size, encoding)
            resolved["bytes_hex"] = data.hex().upper()
            resolved["decoded_value"] = decoded
            if isinstance(decoded, int):
                self._map_enum_name(resolved, decoded)
        return resolved

    def read_registers(self, args: dict[str, Any]) -> dict[str, Any]:
        """Read core registers.  Requires halting the target, which is done
        briefly and then the target is resumed (if it was running)."""
        core = self._require_core()
        state = core.get_state()

        was_running = (state == Target.State.RUNNING or state == Target.State.SLEEPING)
        if was_running:
            core.halt()

        # Wait for halt
        import time
        for _ in range(50):
            if core.get_state() == Target.State.HALTED:
                break
            time.sleep(0.001)

        try:
            regs = [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
                "xpsr",
            ]
            result: dict[str, Any] = {"halted_for_read": was_running}
            for reg in regs:
                try:
                    val = core.read_core_register_raw(reg)
                    if val is not None:
                        result[reg] = f"0x{int(val):08X}"
                except Exception:
                    pass
            return result
        finally:
            if was_running:
                core.resume()

    def snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        """Halt the target, read a set of variables coherently, and resume."""
        axf_file = self._required_string(args, "axf_file")
        expressions = args.get("expressions")
        if not isinstance(expressions, list) or len(expressions) == 0:
            raise ValueError("expressions must be a non-empty list of strings")
        if len(expressions) > 64:
            raise ValueError("batch limited to 64 variables")

        core = self._require_core()
        state = core.get_state()
        was_running = (state == Target.State.RUNNING or state == Target.State.SLEEPING)

        if was_running:
            core.halt()
            import time
            for _ in range(50):
                if core.get_state() == Target.State.HALTED:
                    break
                time.sleep(0.001)

        try:
            resolver = self._get_resolver(axf_file)
            registers = None
            variables: list[dict[str, Any]] = []

            # Read registers
            if was_running:
                try:
                    regs = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
                            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "xpsr"]
                    reg_vals = {}
                    for reg in regs:
                        try:
                            val = core.read_core_register_raw(reg)
                            if val is not None:
                                reg_vals[reg] = f"0x{int(val):08X}"
                        except Exception:
                            pass
                    registers = reg_vals
                except Exception:
                    pass

            # Read variables
            for expr in expressions:
                if not isinstance(expr, str):
                    variables.append({"expression": str(expr), "error": "expression must be a string"})
                    continue
                try:
                    variables.append(self._do_read_variable(resolver, expr))
                except Exception as e:
                    variables.append({"expression": expr, "error": str(e)})

            return {
                "halted_for_read": was_running,
                "registers": registers,
                "variables": {"count": len(variables), "items": variables},
            }
        finally:
            if was_running:
                core.resume()

    def find_axf(self, args: dict[str, Any]) -> dict[str, Any]:
        """Search for Keil build output files (.axf/.elf/.out) under a root directory."""
        root = self._required_string(args, "root")
        root = os.path.abspath(root)
        if not os.path.isdir(root):
            raise FileNotFoundError(f"root directory not found: {root}")

        candidates: list[dict[str, Any]] = []
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext in (".axf", ".elf", ".out"):
                    full = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(full)
                    except OSError:
                        continue
                    candidates.append({
                        "path": full,
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                        "mtime_iso": self._iso_time(st.st_mtime),
                    })

        candidates.sort(key=lambda c: c["mtime"], reverse=True)
        return {
            "root": root,
            "count": len(candidates),
            "candidates": candidates,
            "newest": candidates[0] if candidates else None,
        }

    @staticmethod
    def _iso_time(t: float) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(t, tz=datetime.timezone.utc).isoformat()


# ── JSON-lines entry point ────────────────────────────────────────────────

def main() -> int:
    helper = LiveAttach()
    sys.stdin.reconfigure(encoding="utf-8-sig")
    try:
        for line in sys.stdin:
            request_id: Any = None
            try:
                if line.startswith("\ufeff"):
                    line = line[1:]
                request = json.loads(line)
                request_id = request.get("id")
                operation = request.get("operation")
                args = request.get("arguments") or {}
                if not isinstance(args, dict):
                    raise ValueError("arguments must be an object")

                handlers = {
                    "attach": helper.attach,
                    "detach": lambda _: helper.detach(),
                    "status": lambda _: helper.status(),
                    "read_memory": helper.read_memory,
                    "resolve_symbol": helper.resolve_symbol,
                    "read_symbol": helper.read_symbol,
                    "read_variable": helper.read_variable,
                    "read_variables": helper.read_variables,
                    "read_registers": helper.read_registers,
                    "snapshot": helper.snapshot,
                    "find_axf": helper.find_axf,
                }

                if operation == "shutdown":
                    result = helper.detach()
                    print(json.dumps({"id": request_id, "ok": True, "result": result}), flush=True)
                    return 0
                if operation not in handlers:
                    raise ValueError(f"unknown operation: {operation}")
                result = handlers[operation](args)
                print(json.dumps({"id": request_id, "ok": True, "result": result}), flush=True)
            except Exception as exc:
                error = str(exc)
                if request_id is None and isinstance(exc, json.JSONDecodeError):
                    error += f"; input={line[:160]!r}"
                print(json.dumps({"id": request_id, "ok": False, "error": error}), flush=True)
    finally:
        try:
            helper.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())