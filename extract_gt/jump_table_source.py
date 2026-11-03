"""Build-bound source facts for the jump-table proof coordinator.

The provider consumes a declarative build manifest and the unresolved requests
from binary analysis.  Source object names come from ELF/DWARF bindings and
the matching source declarations; neither jump addresses nor selector sets are
part of the manifest.  Every accepted fact is rechecked against the original
binary before it can discharge an obligation.
"""

import ast
from collections import Counter, defaultdict
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import struct

import capstone
from capstone import x86_const as X
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from jump_table_data_invariants import WritableTableAudit


SCHEMA_VERSION = 1
DEFAULT_CONTRACT = [
    "The original binary is the product of correct compilation of the manifest source configuration.",
    "GT covers defined executions of that source program; undefined C behavior is outside its domain.",
]


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _without_comments(text):
    text = re.sub(r"/\*.*?\*/", lambda match: "\n" * match.group(0).count("\n"),
                  text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def _integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("manifest addresses and selectors must be integers")
    return int(value, 0) if isinstance(value, str) else int(value)


def _safe_integer(expression):
    """Evaluate a C integer literal expression without executing source text."""
    expression = expression.strip()
    expression = re.sub(r"(?<=\d)[uUlL]+\b", "", expression)
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.Constant, ast.UnaryOp, ast.BinOp, ast.UAdd,
               ast.USub, ast.Invert, ast.Add, ast.Sub, ast.Mult, ast.FloorDiv,
               ast.Mod, ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError("unsupported source integer expression: " + expression)
    value = eval(compile(tree, "<source-initializer>", "eval"), {"__builtins__": {}}, {})
    if type(value) is not int:
        raise ValueError("source initializer is not an integer")
    return value


def _split_initializer(body):
    values, start, depth = [], 0, 0
    for index, char in enumerate(body):
        if char in "({":
            depth += 1
        elif char in ")}":
            depth -= 1
        elif char == "," and depth == 0:
            values.append(body[start:index].strip())
            start = index + 1
    tail = body[start:].strip()
    if tail:
        values.append(tail)
    return [value for value in values if value]


def _type_size(head, bits, type_macros=None):
    compact = re.sub(r"\s+", " ", head).strip()
    for name, replacement in (type_macros or {}).items():
        compact = re.sub(r"\b" + re.escape(name) + r"\b", replacement, compact)
    if "*" in compact:
        return bits // 8
    if re.search(r"\bchar\b", compact):
        return 1
    if re.search(r"\bshort\b", compact):
        return 2
    if re.search(r"\blong\s+long\b", compact) or (bits == 64 and re.search(r"\blong\b", compact)):
        return bits // 8
    if re.search(r"\b(?:long|int|U32|uint32_t)\b", compact):
        return 4
    return None


def _expand_initializer_macros(text):
    text = text.replace("\\\n", "")
    function_macros = {}
    object_macros = {}
    for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_]\w*)\(([^)]*)\)\s*(.*)$",
                             text, re.M):
        parameters = [part.strip() for part in match.group(2).split(",") if part.strip()]
        function_macros[match.group(1)] = (parameters, match.group(3).strip())
    for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+([^\n]+)", text, re.M):
        object_macros[match.group(1)] = match.group(2).strip()

    def expand_function(match):
        specification = function_macros.get(match.group(1))
        if specification is None:
            return match.group(0)
        parameters, replacement = specification
        arguments = [part.strip() for part in match.group(2).split(",")]
        if len(parameters) != len(arguments):
            return match.group(0)
        for parameter, argument in zip(parameters, arguments):
            replacement = replacement.replace("##" + parameter, argument)
            replacement = replacement.replace(parameter + "##", argument)
            replacement = re.sub(r"\b" + re.escape(parameter) + r"\b",
                                 lambda _: argument, replacement)
        for object_name, object_value in object_macros.items():
            replacement = re.sub(r"\b" + re.escape(object_name) + r"\b",
                                 lambda _: object_value, replacement)
        return replacement.replace("##", "")

    for _ in range(4):
        expanded = re.sub(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)", expand_function, text)
        if expanded == text:
            break
        text = expanded
    return text


def _source_arrays(text, bits, type_macros=None):
    arrays = []
    text = _expand_initializer_macros(text)
    pattern = re.compile(
        r"(?P<head>(?:(?:static|extern|EXT)[ \t]+)?"
        r"(?:(?:const|volatile|unsigned|signed)[ \t]+)*"
        r"[A-Za-z_]\w*[ \t]*\*?[ \t]+)"
        r"(?P<name>[A-Za-z_]\w*)\s*\[[^\]]*\]\s*=\s*\{(?P<body>.*?)\}\s*;?",
        re.S)
    for match in pattern.finditer(text):
        body, head, name = match.group("body"), match.group("head"), match.group("name")
        entry_size = _type_size(head, bits, type_macros)
        if entry_size is None or "#" in body:
            continue
        expressions = _split_initializer(body)
        numeric, label_edges, unsupported = [], [], []
        for expression in expressions:
            compact = re.sub(r"\s+", "", expression)
            relative = re.fullmatch(
                r"(?:\([^)]*\))?&?&([A-Za-z_]\w*)-(?:\([^)]*\))?&?&([A-Za-z_]\w*)",
                compact)
            if relative:
                label_edges.append((relative.group(1), relative.group(2)))
                continue
            try:
                numeric.append(_safe_integer(expression))
            except (SyntaxError, ValueError, TypeError):
                unsupported.append(expression)
        if not expressions or (numeric and label_edges) or unsupported:
            continue
        arrays.append({
            "name": name, "entry_size": entry_size,
            "values": numeric if numeric else [],
            "label_edges": label_edges,
            "line": text.count("\n", 0, match.start()) + 1,
        })
    return arrays


def _evaluate_condition(expression, definitions):
    expression = re.sub(r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)",
                        lambda match: "1" if match.group(1) in definitions else "0", expression)
    expression = re.sub(r"defined\s+([A-Za-z_]\w*)",
                        lambda match: "1" if match.group(1) in definitions else "0", expression)
    expression = re.sub(r"\b[A-Za-z_]\w*\b",
                        lambda match: str(definitions.get(match.group(0), 0)), expression)
    expression = expression.replace("&&", " and ").replace("||", " or ")
    expression = re.sub(r"!(?!=)", " not ", expression)
    expression = re.sub(r"\b[A-Za-z_]\w*\s*\([^)]*\)", "0", expression)
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.Constant, ast.UnaryOp, ast.BoolOp, ast.BinOp,
               ast.Not, ast.And, ast.Or, ast.Eq, ast.NotEq, ast.Lt, ast.LtE,
               ast.Gt, ast.GtE, ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod,
               ast.LShift, ast.RShift, ast.BitAnd, ast.BitOr, ast.BitXor)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise ValueError("unsupported source conditional: " + expression)
    return bool(eval(compile(tree, "<source-condition>", "eval"),
                     {"__builtins__": {}}, {}))


def _select_conditionals(text, definitions):
    """Apply simple manifest-controlled ccpp conditionals with line stability."""
    active, stack, result = True, [], []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        directive = re.match(r"#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)", stripped)
        if directive is None:
            result.append(line if active else "\n" if line.endswith("\n") else "")
            continue
        kind, tail = directive.group(1), directive.group(2).strip()
        if kind in ("ifdef", "ifndef", "if"):
            parent = active
            if kind == "ifdef":
                condition = tail.split()[0] in definitions
            elif kind == "ifndef":
                condition = tail.split()[0] not in definitions
            else:
                try:
                    condition = _evaluate_condition(tail, definitions)
                except (SyntaxError, ValueError, TypeError):
                    condition = False
            stack.append({"parent": parent, "taken": condition})
            active = parent and condition
        elif kind == "elif":
            _require(stack and not stack[-1].get("else"), "invalid source #elif")
            frame = stack[-1]
            try:
                condition = (not frame["taken"] and _evaluate_condition(tail, definitions))
            except (SyntaxError, ValueError, TypeError):
                condition = False
            active = frame["parent"] and condition
            frame["taken"] = frame["taken"] or condition
        elif kind == "else":
            _require(stack and not stack[-1].get("else"), "invalid source #else")
            frame = stack[-1]
            active = frame["parent"] and not frame["taken"]
            frame["taken"], frame["else"] = True, True
        else:
            _require(stack, "unmatched source #endif")
            frame = stack.pop()
            active = frame["parent"]
        result.append("\n" if line.endswith("\n") else "")
    _require(not stack, "unterminated source conditional")
    return "".join(result)


def _resolve_source_files(build, manifest_path):
    root = Path(build.get("source_root", manifest_path.parent)).resolve()
    specifications = build.get("source_files")
    if not isinstance(specifications, list) or not specifications:
        raise ValueError("source build requires a nonempty source_files list")
    files = []
    for specification in specifications:
        path = Path(specification)
        if not path.is_absolute():
            path = root / path
        pattern = str(path)
        matches = sorted(root.glob(specification)) if any(char in str(specification) for char in "*?[") else [path]
        files.extend(matches)
    files = sorted({path.resolve() for path in files})
    _require(files and all(path.is_file() for path in files), "source build has missing source files")
    return root, files


def load_build_manifest(path, binary):
    """Load and hash the build matching ``binary`` without accepting GT rows."""
    path = Path(path).resolve()
    manifest = json.loads(path.read_text())
    _require(isinstance(manifest, dict) and manifest.get("schema_version") == SCHEMA_VERSION,
             "unsupported source build manifest schema")
    builds = manifest.get("builds")
    _require(isinstance(builds, list) and builds, "source build manifest requires builds")
    binary_hash = sha256_file(binary)
    matches = [build for build in builds if isinstance(build, dict)
               and build.get("binary_sha256") == binary_hash]
    _require(len(matches) == 1, "source manifest must contain exactly one build for this binary")
    build = matches[0]
    root, files = _resolve_source_files(build, path)
    definitions = build.get("definitions", {})
    _require(isinstance(definitions, dict) and
             all(isinstance(key, str) and re.fullmatch(r"[A-Za-z_]\w*", key)
                 and type(value) is int for key, value in definitions.items()),
             "source build definitions must map macro names to integers")
    contract = build.get("contract", DEFAULT_CONTRACT)
    _require(isinstance(contract, list) and contract and
             all(isinstance(item, str) and item.strip() for item in contract),
             "source build contract must be a nonempty string list")
    expected_hashes = build.get("source_sha256", {})
    _require(isinstance(expected_hashes, dict), "source_sha256 must be an object")
    hashes = {str(file): sha256_file(file) for file in files}
    for name, expected in expected_hashes.items():
        candidate = Path(name)
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        _require(candidate in files and hashes[str(candidate)] == expected,
                 "source file hash differs from the build manifest: " + str(candidate))
    linked = build.get("linked_inputs", [])
    _require(isinstance(linked, list), "linked_inputs must be a list")
    compile_commands = build.get("compile_commands", [])
    _require(isinstance(compile_commands, list) and
             all(isinstance(command, str) and command.strip() for command in compile_commands),
             "compile_commands must be a string list")
    documents = {}
    for file in files:
        text = _without_comments(file.read_text(errors="replace"))
        try:
            selected = _select_conditionals(text, definitions)
        except ValueError:
            # Some legacy sources are intended to be preprocessed with a
            # generated include set. Parsing the conservative union of their
            # branches is still safe because initializer and binary binding
            # checks reject any ambiguity.
            selected = text
        type_macros = {}
        for match in re.finditer(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s+([^\n]+)", selected, re.M):
            if "*" in match.group(2) or re.search(r"\b(?:char|short|int|long)\b", match.group(2)):
                type_macros[match.group(1)] = match.group(2).strip()
        documents[file] = {
            "text": selected,
            "type_macros": type_macros,
            "source": {"path": str(file), "sha256": hashes[str(file)]},
        }
    return {
        "manifest_path": str(path), "manifest_sha256": sha256_file(path),
        "binary_sha256": binary_hash, "source_root": str(root),
        "files": files, "file_hashes": hashes, "definitions": dict(definitions),
        "compile_commands": list(compile_commands), "linked_inputs": list(linked),
        "dwarf_source_files": dict(build.get("dwarf_source_files", {})),
        "contract": list(contract), "documents": documents,
    }


def _descendants(die):
    for child in die.iter_children():
        yield child
        yield from _descendants(child)


def _die_value(die, name, default=None):
    attribute = die.attributes.get(name)
    return attribute.value if attribute else default


class BinaryBinding:
    def __init__(self, binary):
        self.path = Path(binary)
        self.raw = self.path.read_bytes()
        self.elf = ELFFile(BytesIO(self.raw))
        self.bits = self.elf.elfclass
        self.objects = defaultdict(list)
        self.functions = defaultdict(list)
        for section in self.elf.iter_sections():
            if section["sh_type"] not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                continue
            for symbol in section.iter_symbols():
                if not symbol.name or not isinstance(symbol["st_shndx"], int):
                    continue
                row = {"address": int(symbol["st_value"]), "size": int(symbol["st_size"]),
                       "section": symbol["st_shndx"], "exported": section["sh_type"] == "SHT_DYNSYM"
                       and symbol["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK")}
                if symbol["st_info"]["type"] == "STT_OBJECT":
                    self.objects[symbol.name].append(row)
                elif symbol["st_info"]["type"] == "STT_FUNC":
                    self.functions[symbol.name].append(row)
        self._dwarf = {}

    def read(self, address, size):
        for segment in self.elf.iter_segments():
            offset = address - segment["p_vaddr"]
            if (segment["p_type"] == "PT_LOAD" and offset >= 0
                    and offset + size <= segment["p_filesz"]):
                start = segment["p_offset"] + offset
                result = self.raw[start:start + size]
                if len(result) == size:
                    return result
        raise ValueError("source binding read is outside file-backed ELF data")

    def object(self, name):
        rows = self.objects.get(name, [])
        unique = {(row["address"], row["size"], row["section"]) for row in rows}
        _require(len(unique) == 1 and all(row["size"] for row in rows),
                 "source object does not bind to exactly one sized ELF symbol: " + name)
        address, size, section_index = next(iter(unique))
        section = self.elf.get_section(section_index)
        return {"name": name, "address": address, "size": size,
                "section": section.name, "section_writable": bool(section["sh_flags"] & 1),
                "exported": any(row["exported"] for row in rows)}

    def dwarf_function(self, address):
        if address in self._dwarf:
            return self._dwarf[address]
        dwarf = self.elf.get_dwarf_info()
        parser = DWARFExprParser(dwarf.structs)
        found = []
        for cu in dwarf.iter_CUs():
            top = cu.get_top_DIE()
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram" or _die_value(die, "DW_AT_low_pc") != address:
                    continue
                name = _die_value(die, "DW_AT_name", b"").decode(errors="replace")
                labels, variables = {}, {}
                for item in _descendants(die):
                    item_name = _die_value(item, "DW_AT_name", b"").decode(errors="replace")
                    low_pc = _die_value(item, "DW_AT_low_pc")
                    if item.tag == "DW_TAG_label" and low_pc is not None:
                        labels[item_name] = int(low_pc)
                    elif item.tag == "DW_TAG_variable":
                        location = _die_value(item, "DW_AT_location")
                        if location is None:
                            continue
                        if isinstance(location, (bytes, list)):
                            expression = parser.parse_expr(location)
                        else:
                            continue
                        if len(expression) == 1 and expression[0].op_name == "DW_OP_addr":
                            variables[item_name] = {"address": int(expression[0].args[0]),
                                                    "source_line": _die_value(item, "DW_AT_decl_line")}
                found.append({
                    "address": address, "name": name, "cu_offset": cu.cu_offset,
                    "compilation_unit": _die_value(top, "DW_AT_name", b"").decode(errors="replace"),
                    "compilation_directory": _die_value(top, "DW_AT_comp_dir", b"").decode(errors="replace"),
                    "compiler": _die_value(top, "DW_AT_producer", b"").decode(errors="replace"),
                    "declaration_line": _die_value(die, "DW_AT_decl_line"),
                    "labels": labels, "variables": variables,
                })
        self._dwarf[address] = found[0] if len(found) == 1 else None
        return self._dwarf[address]

    def source_location(self, address):
        """Bind an instruction to its DWARF line-table source name and line."""
        key = ("line", address)
        if key in self._dwarf:
            return self._dwarf[key]
        dwarf = self.elf.get_dwarf_info()
        found = []
        for cu in dwarf.iter_CUs():
            program = dwarf.line_program_for_CU(cu)
            if program is None:
                continue
            rows = [entry.state for entry in program.get_entries()
                    if entry.state and not entry.state.end_sequence
                    and entry.state.address == address]
            if not rows:
                continue
            rows.sort(key=lambda state: (state.line, state.column, state.discriminator))
            row = rows[0]
            files = program.header["file_entry"]
            file_index = row.file if program.header["version"] >= 5 else row.file - 1
            if not 0 <= file_index < len(files):
                raise ValueError("DWARF line-table file index is out of range")
            source_name = files[file_index].name
            if isinstance(source_name, bytes):
                source_name = source_name.decode(errors="replace")
            found.append({
                "compilation_unit":
                    _die_value(cu.get_top_DIE(), "DW_AT_name", b"").decode(errors="replace"),
                "file": source_name,
                "line": int(row.line),
                "column": int(row.column),
                "discriminator": int(row.discriminator),
            })
        identities = {(row["file"], row["line"], row["column"], row["discriminator"])
                      for row in found}
        self._dwarf[key] = found[0] if len(found) == 1 or len(identities) == 1 else None
        return self._dwarf[key]


def _source_for_dwarf_name(manifest, dwarf_name):
    if dwarf_name in manifest["dwarf_source_files"]:
        requested = Path(manifest["dwarf_source_files"][dwarf_name])
        if not requested.is_absolute():
            requested = Path(manifest["source_root"]) / requested
        requested = requested.resolve()
        if requested in manifest["documents"]:
            return requested
    basename = Path(dwarf_name).name
    matches = [path for path in manifest["documents"] if path.name == basename]
    if len(matches) == 1:
        return matches[0]
    suffix_matches = [path for path in manifest["documents"]
                      if str(path).endswith(dwarf_name)]
    _require(len(suffix_matches) == 1,
             "DWARF compilation unit does not bind to one manifest source: " + dwarf_name)
    return suffix_matches[0]


def _source_for_binding(manifest, binding):
    return _source_for_dwarf_name(manifest, binding.get("compilation_unit", ""))


def _source_for_location(manifest, location):
    if not isinstance(location, dict):
        raise ValueError("binary site has no DWARF source location")
    for name in (location.get("file"), location.get("compilation_unit")):
        if not name:
            continue
        try:
            return _source_for_dwarf_name(manifest, name)
        except ValueError:
            continue
    raise ValueError("DWARF source location does not bind to one manifest source: " +
                     str(location.get("file") or location.get("compilation_unit")))


def _resolve_label(binding, name):
    for candidate in (name, "do_" + name):
        if candidate in binding["labels"]:
            return candidate, binding["labels"][candidate]
    return None


def _relative_table(array, binary, binding):
    if not array["label_edges"]:
        return None
    bases = {base for _, base in array["label_edges"]}
    _require(len(bases) == 1, "source table initializers use multiple relative bases")
    base_name = next(iter(bases))
    resolved_base = _resolve_label(binding, base_name)
    _require(resolved_base is not None, "source table relative base has no DWARF label: " + base_name)
    _, base_address = resolved_base
    variable = binding["variables"].get(array["name"])
    _require(variable is not None, "source table has no address-bearing DWARF variable: " + array["name"])
    table_address = variable["address"]
    raw = binary.read(table_address, len(array["label_edges"]) * array["entry_size"])
    edges = []
    for selector, (source_label, entry_base) in enumerate(array["label_edges"]):
        _require(entry_base == base_name, "source table entry uses a different relative base")
        resolved_label = _resolve_label(binding, source_label)
        _require(resolved_label is not None, "source table label has no DWARF address: " + source_label)
        expected = resolved_label[1] - base_address
        actual = int.from_bytes(raw[selector * array["entry_size"]:(selector + 1) * array["entry_size"]],
                                "little", signed=True)
        _require(actual == expected,
                 "binary table offset differs from source/DWARF label at entry %d" % selector)
        edges.append({"selector": selector, "source_label": source_label,
                      "label": resolved_label[0], "target": resolved_label[1],
                      "signed_relative": actual})
    return {
        "name": array["name"], "table_address": table_address,
        "entry_size": array["entry_size"], "entry_encoding": "signed_relative",
        "relative_base": base_address, "base_label": resolved_base[0],
        "selector_values": list(range(len(edges))), "edges": edges,
    }


def _computed_goto_fact(request, manifest, binary):
    address = request.get("function")
    if address is None:
        return None
    binding = binary.dwarf_function(_integer(address))
    if binding is None:
        return None
    source = _source_for_binding(manifest, binding)
    document = manifest["documents"][source]["text"]
    expanded = _expand_initializer_macros(document)
    arrays = _source_arrays(expanded, binary.bits, manifest["documents"][source]["type_macros"])
    by_name = {array["name"]: array for array in arrays}
    relative_arrays = [array for array in arrays if array["label_edges"]]
    _require(all(array["name"] in binding["variables"] for array in relative_arrays),
             "a relative source table lacks an address-bearing DWARF variable")
    tables = []
    for name in binding["variables"]:
        if name in by_name and by_name[name]["label_edges"]:
            table = _relative_table(by_name[name], binary, binding)
            if table is not None:
                tables.append(table)
    if not tables:
        return None
    bases = {(table["relative_base"], table["base_label"]) for table in tables}
    _require(len(bases) == 1, "computed-goto source tables do not share one dispatch base")
    base, base_label = next(iter(bases))
    site = _integer(request["site"])
    location = binary.source_location(site)
    location_source = _source_for_location(manifest, location)
    _require(location_source == source,
             "computed-goto site line table binds to a different source file")
    symbol_rows = binary.functions.get(binding.get("name", ""), [])
    _require(any(row["address"] <= site < row["address"] + row["size"] for row in symbol_rows),
             "computed-goto source function does not contain the binary dispatch site")
    dispatches = _dispatch_association(expanded, tables, base_label, binding, binary.bits)
    targets = {edge["target"] for table in tables for edge in table["edges"]}
    fallback = dispatches["fallback"]
    _require(fallback["target"] in targets,
             "computed-goto fallback is absent from the source table union")
    return {
        "status": "proved", "kind": "computed_goto_dispatch", "site": site,
        "tables": [{key: value for key, value in table.items() if key != "edges"} for table in tables],
        "targets": sorted(targets),
        "fallback": fallback,
        "proved_obligations": ["computed_goto_target_domain", "fallback_destination"],
        "requests": [request], "source_contract": manifest["contract"],
        "binding": {key: value for key, value in binding.items() if key not in ("labels", "variables")},
        "source_file": dict(manifest["documents"][source]["source"]),
        "source_location": location,
        "table_names": sorted(table["name"] for table in tables),
        "table_dispatch_uses": dispatches["table_dispatch_uses"],
        "validated_entries": sum(len(table["selector_values"]) for table in tables),
        "scope": "source_expression_with_elf_and_dwarf",
        "provenance": "Every stage table is used by the same fallback-bearing computed-goto shape; labels, offsets, bytes and the site line table were rebound to the original ELF.",
    }


def _dispatch_association(expanded, tables, base_label, binding, bits):
    """Require every relative table to feed the same source dispatch shape."""
    compact = re.sub(r"\s+", "", expanded)
    table_names = {table["name"] for table in tables}
    shape = re.compile(
        r"offset=(?P<expression>[^;]*):(?P<table>[A-Za-z_]\w*)\[(?:[^\[\]]|\[[^\]]*\])*\];"
        r"ptr=(?:(?:\([^()]*\))*)&&(?P<base>[A-Za-z_]\w*)\+offset\)*;goto\*[A-Za-z_]\w*")
    uses = {name: 0 for name in table_names}
    fallbacks = set()
    for match in shape.finditer(compact):
        name = match.group("table")
        if name not in table_names:
            continue
        _require(match.group("base") == base_label,
                 "computed-goto dispatch does not use the source table base")
        expression = match.group("expression").rsplit("?", 1)[-1]
        labels = re.findall(r"&&([A-Za-z_]\w*)", expression)
        _require(labels and len(labels) <= 2 and
                 len(re.findall(r"&&", expression)) == len(labels),
                 "unsupported computed-goto fallback expression")
        resolved = [_resolve_label(binding, label) for label in labels]
        _require(all(item is not None for item in resolved),
                 "computed-goto fallback label has no DWARF address")
        target = resolved[0][1]
        offset = 0
        if len(labels) == 2:
            offset = target - resolved[1][1]
            target = (binding["labels"][base_label] + offset) & ((1 << bits) - 1)
            offset &= (1 << bits) - 1
        fallbacks.add((resolved[0][0], binding["labels"][base_label], offset, target))
        uses[name] += 1
    missing = sorted(name for name, count in uses.items() if not count)
    _require(not missing,
             "source stage tables have no contributing computed-goto dispatch: " +
             ", ".join(missing))
    _require(len(fallbacks) == 1,
             "contributing computed-goto dispatches use different fallback expressions")
    source_label, dwarf_label, offset, target = next(iter(fallbacks))
    return {
        "table_dispatch_uses": dict(sorted(uses.items())),
        "fallback": {"source_label": source_label.removeprefix("do_"),
                     "dwarf_label": dwarf_label, "offset": offset, "target": target},
    }


def _function_before(text, offset):
    prefix = text[:offset]
    matches = list(re.finditer(
        r"(?:^|\n)\s*(?:PERL_CALLCONV\s+)?[A-Za-z_][\w\s*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{",
        prefix))
    return matches[-1].group(1) if matches else None


def _source_object_inventory(manifest, object_name):
    reads, writes, returns, escapes = [], [], [], []
    for path, document in manifest["documents"].items():
        text = document["text"]
        for match in re.finditer(r"\b" + re.escape(object_name) + r"\b", text):
            line = text.count("\n", 0, match.start()) + 1
            line_start, line_end = text.rfind("\n", 0, match.start()) + 1, text.find("\n", match.start())
            statement = text[line_start:line_end if line_end >= 0 else len(text)]
            tail = text[match.end():line_end if line_end >= 0 else len(text)]
            record = {"path": str(path), "line": line, "statement": statement.strip()}
            declaration = re.match(r"\s*\[[^\]]*\]\s*=\s*\{\s*$", tail)
            if re.match(r"\s*\[[^\]]*\]\s*=\s*\{.*\}\s*;?$", tail, re.S):
                continue
            if re.match(r"\s*\[", tail):
                # A write must modify the subscripted object itself.  An
                # assignment to another variable on the left is still a read.
                modified = re.search(r"\b" + re.escape(object_name) +
                                     r"\s*\[[^\]]*\]\s*(?:\+\+|--|[-+*/%&|^]?=)",
                                     statement)
                if modified and not declaration:
                    writes.append(record)
                else:
                    reads.append(record)
            elif declaration or re.fullmatch(r"\s*=\s*\{\s*$", statement[statement.find(object_name) + len(object_name):]):
                continue
            elif re.search(r"\breturn\s+" + re.escape(object_name) + r"\s*;", statement):
                function = _function_before(text, match.start())
                _require(function is not None, "source table-returning function has no bindable name")
                returns.append(dict(record, function=function))
            elif re.search(r"&\s*" + re.escape(object_name) + r"\b", statement):
                escapes.append(record)
            elif re.search(r"\b(?:typedef|extern|EXT)\b", statement):
                continue
            else:
                escapes.append(dict(record, reason="object pointer appears outside an indexed load or getter return"))
    _require(reads and not writes and not escapes,
             "source analysis found a write or pointer escape of " + object_name)
    return {"reads": reads, "writes": writes, "returns": returns, "escapes": escapes}


def _pointer_value(instruction, table_address, bits):
    operands = instruction.operands
    if (instruction.mnemonic in ("mov", "movabs") and len(operands) == 2
            and operands[0].type == X.X86_OP_REG and operands[1].type == X.X86_OP_IMM):
        return operands[1].imm & ((1 << bits) - 1)
    return None


def _linked_object_evidence(binary, inventory):
    audit = WritableTableAudit(binary.path)
    object_row = binary.object(inventory["name"])
    address, size = object_row["address"], object_row["size"]
    getter_names = {row["function"] for row in inventory["returns"]}
    getter_addresses = set()
    for name in getter_names:
        getter_addresses.update(row["address"] for row in binary.functions.get(name, []))
    pointer_returns = [] if not getter_addresses else audit.pointer_returns(address, size)
    if getter_addresses:
        _require(any(item["function"] in getter_addresses for item in pointer_returns),
                 "source getter return is not present in the linked executable")

    decoder = capstone.Cs(capstone.CS_ARCH_X86,
                          capstone.CS_MODE_64 if binary.bits == 64 else capstone.CS_MODE_32)
    decoder.detail = True
    refs, getter_refs, gaps = [], [], []
    seen_functions = set()
    for symbols in binary.functions.values():
        for symbol in symbols:
            start, length = symbol["address"], symbol["size"]
            if not length or (start, length) in seen_functions:
                continue
            seen_functions.add((start, length))
            try:
                body = binary.read(start, length)
            except ValueError:
                gaps.append({"address": start, "size": length})
                continue
            decoded = list(decoder.disasm(body, start))
            if sum(instruction.size for instruction in decoded) != length:
                gaps.append({"address": start, "size": length})
            for instruction in decoded:
                for operand in instruction.operands:
                    target = None
                    if operand.type == X.X86_OP_MEM:
                        if operand.mem.disp == address:
                            target = address
                        elif operand.mem.base == X.X86_REG_RIP:
                            target = instruction.address + instruction.size + operand.mem.disp
                        elif operand.mem.disp in getter_addresses:
                            target = operand.mem.disp
                    elif operand.type == X.X86_OP_IMM and operand.imm in getter_addresses:
                        target = operand.imm
                    if target == address:
                        refs.append({"address": instruction.address, "access": operand.access,
                                     "instruction": instruction.mnemonic + " " + instruction.op_str})
                    elif target in getter_addresses:
                        getter_refs.append({"address": instruction.address, "target": target})
    _require(not gaps, "linked function-symbol scan has undecoded bytes")
    _require(refs and not any(row["access"] & 2 for row in refs),
             "linked executable contains a write through the source object")
    _require(not getter_refs, "linked executable references the source getter")
    stored = []
    for section in binary.elf.iter_sections():
        if (not section["sh_flags"] & 2 or section["sh_flags"] & 4
                or section["sh_type"] == "SHT_NOBITS" or not section["sh_size"]):
            continue
        data, needle = section.data(), struct.pack("<Q", address)
        offset = data.find(needle)
        while offset >= 0:
            stored.append(int(section["sh_addr"]) + offset)
            offset = data.find(needle, offset + 1)
    _require(not stored, "linked executable stores a source-object pointer")
    relocations, loader_functions = [], []
    for section in binary.elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        linked = binary.elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            symbol = linked.get_symbol(relocation["r_info_sym"]).name if relocation["r_info_sym"] else ""
            if address <= relocation["r_offset"] < address + size or symbol == inventory["name"]:
                relocations.append(int(relocation["r_offset"]))
    dynsym = binary.elf.get_section_by_name(".dynsym")
    queried = {inventory["name"]} | getter_names
    for symbol in dynsym.iter_symbols() if dynsym is not None else ():
        if symbol.name in ("dlopen", "dlsym", "dlclose", "dladdr", "dlmopen"):
            loader_functions.append(symbol.name)
        if symbol.name in queried and symbol["st_shndx"] != "SHN_UNDEF" and symbol["st_value"]:
            raise ValueError("source object or getter is dynamically exported")
    _require(not relocations and not loader_functions,
             "linked executable can rebind or dynamically load the source object")
    _require(binary.elf["e_type"] == "ET_EXEC", "source object stability requires a fixed executable")
    return {
        "status": "proved", "object": object_row, "getter_returns": pointer_returns,
        "getter_references": getter_refs, "table_references": refs,
        "function_symbols_scanned": len(seen_functions), "relocations": relocations,
        "stored_object_pointers": stored, "loader_functions": loader_functions,
        "elf_type": binary.elf["e_type"],
    }


def _writable_fact(request, manifest, binary):
    table_address = _integer(request["table_address"])
    candidates = []
    for name, rows in binary.objects.items():
        if any(row["address"] == table_address for row in rows):
            candidates.append(name)
    if not candidates:
        return None
    facts = []
    for name in sorted(set(candidates)):
        arrays = [array for document in manifest["documents"].values()
                  for array in _source_arrays(document["text"], binary.bits, document["type_macros"])
                  if array["name"] == name
                  and not array["label_edges"]]
        if len(arrays) != 1:
            continue
        array = arrays[0]
        object_row = binary.object(name)
        raw = binary.read(object_row["address"], object_row["size"])
        expected = b"".join((value & ((1 << (array["entry_size"] * 8)) - 1)).to_bytes(
            array["entry_size"], "little") for value in array["values"])
        _require(raw == expected, "source initializer does not match the original binary object")
        inventory = _source_object_inventory(manifest, name)
        inventory["name"] = name
        linked = _linked_object_evidence(binary, inventory)
        requested = set(request.get("obligations", []))
        supported = {"index_bounds", "data_stability", "no_pointer_escape",
                     "closed_executable", "code_effect_coverage"}
        _require(requested <= supported, "source provider cannot discharge writable obligations: " +
                 ", ".join(sorted(requested - supported)))
        facts.append({
            "status": "proved", "kind": "writable_object_invariant",
            "site": _integer(request["site"]), "table_address": table_address,
            "table": {"table_address": table_address, "entry_size": array["entry_size"],
                      "entry_encoding": "absolute", "source_name": name},
            "proved_obligations": sorted(requested),
            "object_source": {"name": name, "entry_count": len(array["values"]),
                              "initializer_line": array["line"], "source_inventory": inventory},
            "linked_evidence": linked, "requests": [request],
            "source_contract": manifest["contract"],
            "scope": "source_invariant_with_linked_binary_audit",
            "provenance": "The full source initializer matches file-backed ELF bytes; source uses are read-only and the linked function scan finds no mutation, export, relocation or getter reference.",
        })
    _require(len(facts) <= 1, "writable table address binds to multiple source objects")
    return facts[0] if facts else None


def analyze_source_build(manifest_path, binary, requests):
    """Resolve binary requests from one hash-bound source/build configuration."""
    manifest = load_build_manifest(manifest_path, binary)
    binding = BinaryBinding(binary)
    facts, unresolved = [], []
    for request in requests:
        if not isinstance(request, dict):
            continue
        try:
            if request.get("kind") == "writable_object_invariant":
                fact = _writable_fact(request, manifest, binding)
            elif request.get("kind") == "computed_goto_dispatch":
                fact = _computed_goto_fact(request, manifest, binding)
            else:
                fact = None
        except (ValueError, KeyError, TypeError) as error:
            fact = {"status": "unresolved", "kind": request.get("kind"),
                    "site": request.get("site"), "reason": str(error),
                    "requests": [request]}
        if fact is None:
            unresolved.append({"request_id": request.get("request_id"),
                               "reason": "no matching source declaration and binary binding"})
        else:
            facts.append(fact)
    return {
        "status": "source_analysis_complete", "manifest": manifest,
        "requests": len(requests), "facts": facts, "unresolved_requests": unresolved,
        "proved_sites": sorted({fact["site"] for fact in facts if fact.get("status") == "proved"}),
    }
