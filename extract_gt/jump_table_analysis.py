"""Conservative x86 table recovery from the emitted instruction CFG.

Finite selector domains are replayed against immutable ELF bytes.  A result
covers every incoming path in the inspected CFG suffix; unknown prefixes are
unconstrained, never silently dropped.  This proves a local upper bound on
successors, not whole-program input reachability or source/data invariants.
Unsupported instructions kill their written registers and unsupported paths
prevent a result.  No table addresses or application-specific rules are used.
"""
from collections import defaultdict, deque
from io import BytesIO

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile

try:
    from jump_table_constants import entry_region_constants
    from jump_table_reaching import recover_reaching_tables
    from jump_table_dataflow import function_dataflow
except ModuleNotFoundError:
    from extract_gt.jump_table_constants import entry_region_constants
    from extract_gt.jump_table_reaching import recover_reaching_tables
    from extract_gt.jump_table_dataflow import function_dataflow


MAX_VALUES = 4096
MAX_PATHS = 64
MAX_BLOCKS = 12
MAX_INSTRUCTIONS = 256


class Unresolved(Exception):
    pass


class Infeasible(Exception):
    pass


def _bits(expr):
    return expr[-1]


def _const(value, bits):
    return ('const', value & ((1 << bits) - 1), bits)


def _extract(expr, offset, bits):
    if offset == 0 and bits == _bits(expr):
        return expr
    if expr[0] == 'const':
        return _const(expr[1] >> offset, bits)
    if expr[0] in ('zext', 'sext') and offset + bits <= _bits(expr[1]):
        return _extract(expr[1], offset, bits)
    if expr[0] == 'extract':
        return _extract(expr[1], offset + expr[2], bits)
    if offset == 0 and bits < _bits(expr) and expr[0] in ('add', 'sub', 'mul', 'and', 'or', 'xor'):
        # Low-byte guards often use LEA/SUB in a wider register while the
        # dispatch sign-extends the original byte. Modular low bits commute
        # with these operations, so both paths must name the same byte value.
        return _binary(expr[0], _extract(expr[1], 0, bits), _extract(expr[2], 0, bits), bits)
    if expr[0] == 'insert' and offset >= expr[3] and offset + bits <= expr[3] + _bits(expr[2]):
        return _extract(expr[2], offset - expr[3], bits)
    return ('extract', expr, offset, bits)


def _extend(expr, bits, signed=False):
    if _bits(expr) >= bits:
        return _extract(expr, 0, bits)
    if expr[0] == 'const':
        value = expr[1]
        if signed and value & (1 << (_bits(expr) - 1)):
            value -= 1 << _bits(expr)
        return _const(value, bits)
    return ('sext' if signed else 'zext', expr, bits)


def _binary(op, left, right, bits):
    left, right = _extend(left, bits), _extend(right, bits)
    if op == 'and':
        for value, mask in ((left, right), (right, left)):
            if (value[0] == 'zext' and mask[0] == 'const'
                    and mask[1] < 1 << _bits(value[1])):
                # A copied byte may be guarded through CL while EAX is used
                # for indexing. Preserve their identical low-bit expression.
                return _extend(_binary('and', value[1],
                                       _const(mask[1], _bits(value[1])), _bits(value[1])), bits)
    if left == right and op in ('xor', 'sub'):
        return _const(0, bits)
    if left == right and op in ('and', 'or'):
        return left
    if right[0] == 'const' and right[1] == 0 and op in ('add', 'sub', 'or', 'xor', 'shl', 'shr', 'sar'):
        return left
    if left[0] == 'const' and left[1] == 0 and op == 'add':
        return right
    if left[0] == right[0] == 'const':
        return _const(_operation(op, left[1], right[1], bits), bits)
    return (op, left, right, bits)


def _operation(op, a, b, bits):
    if op == 'add': return a + b
    if op == 'sub': return a - b
    if op == 'mul': return a * b
    if op == 'and': return a & b
    if op == 'or': return a | b
    if op == 'xor': return a ^ b
    if op == 'shl': return a << (b & (63 if bits == 64 else 31))
    if op == 'shr': return a >> (b & (63 if bits == 64 else 31))
    if op == 'sar':
        if a & (1 << (bits - 1)): a -= 1 << bits
        return a >> (b & (63 if bits == 64 else 31))
    raise Unresolved('unsupported arithmetic')


def _address_parts(expr):
    if expr[0] == 'const': return None, expr[1]
    if expr[0] == 'add':
        for left, right in [(expr[1], expr[2]), (expr[2], expr[1])]:
            if right[0] == 'const':
                base, offset = _address_parts(left)
                return base, (offset + right[1]) & ((1 << _bits(expr)) - 1)
    return expr, 0


def _disjoint(address, size, other, other_size):
    base, offset = _address_parts(address)
    other_base, other_offset = _address_parts(other)
    if base != other_base or _bits(address) != _bits(other): return False
    mask = (1 << _bits(address)) - 1
    return ((offset - other_offset) & mask) >= other_size and ((other_offset - offset) & mask) >= size


_ALIASES = {}
for _family in [('rax', 'eax', 'ax', 'al', 'ah'), ('rbx', 'ebx', 'bx', 'bl', 'bh'),
                ('rcx', 'ecx', 'cx', 'cl', 'ch'), ('rdx', 'edx', 'dx', 'dl', 'dh'),
                ('rsi', 'esi', 'si', 'sil'), ('rdi', 'edi', 'di', 'dil'),
                ('rbp', 'ebp', 'bp', 'bpl'), ('rsp', 'esp', 'sp', 'spl')]:
    for _name, _width, _offset in zip(_family, (64, 32, 16, 8, 8), (0, 0, 0, 0, 8)):
        _ALIASES[_name] = (_family[0], _width, _offset)
for _number in range(8, 16):
    for _suffix, _width in [('', 64), ('d', 32), ('w', 16), ('b', 8)]:
        _ALIASES['r%d%s' % (_number, _suffix)] = ('r%d' % _number, _width, 0)


class _Image:
    def __init__(self, path):
        with open(path, 'rb') as stream:
            self.data = stream.read()
        elf = ELFFile(BytesIO(self.data))
        if elf['e_machine'] not in ('EM_X86_64', 'EM_386'):
            raise Unresolved('only x86 ELF is supported')
        self.bits = elf.elfclass
        self.segments = [(int(s['p_vaddr']), int(s['p_vaddr']) + int(s['p_filesz']),
                          int(s['p_offset'])) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        self.readonly_segments = [(int(s['p_vaddr']), int(s['p_vaddr']) + int(s['p_filesz']))
                                  for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and not int(s['p_flags']) & 2]
        self.immutable = [(int(s['sh_addr']), int(s['sh_addr']) + int(s['sh_size']))
                          for s in elf.iter_sections() if int(s['sh_flags']) & 2 and not int(s['sh_flags']) & 1
                          and s['sh_type'] != 'SHT_NOBITS']
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.bits == 64 else capstone.CS_MODE_32)
        self.md.detail = True

    def read(self, address, size, immutable=False):
        if immutable and not any(start <= address and address + size <= end for start, end in self.immutable):
            raise Unresolved('table load is outside immutable ELF data')
        if immutable and not any(start <= address and address + size <= end for start, end in self.readonly_segments):
            raise Unresolved('table load is in a writable ELF segment')
        for start, end, offset in self.segments:
            if start <= address and address + size <= end:
                data = self.data[offset + address - start:offset + address - start + size]
                if len(data) != size: raise Unresolved('ELF segment extends past the file')
                return data
        raise Unresolved('ELF read is not fully file-backed')


class _Domains:
    def __init__(self):
        self.ranges = {}
        self.guards = []

    def restrict(self, expr, relation, bound, signed, address):
        bits = _bits(expr)
        maximum = (1 << bits) - 1
        if signed:
            bound = bound & maximum
            if bound & (1 << (bits - 1)): bound -= 1 << bits
            low, high = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        else:
            low, high = 0, maximum
            bound &= maximum
        ranges = {'eq': [(bound, bound)], 'ne': [(low, bound - 1), (bound + 1, high)],
                  'lt': [(low, bound - 1)], 'le': [(low, bound)],
                  'gt': [(bound + 1, high)], 'ge': [(bound, high)]}[relation]
        unsigned = []
        for start, end in ranges:
            start, end = max(start, low), min(end, high)
            if start > end: continue
            if start < 0:
                unsigned.append((start + (1 << bits), min(end, -1) + (1 << bits)))
            if end >= 0:
                unsigned.append((max(start, 0), end))
        previous = self.ranges.get(expr, [(0, maximum)])
        intersection = [(max(a, c), min(b, d)) for a, b in previous for c, d in unsigned
                        if max(a, c) <= min(b, d)]
        if not intersection or (expr[0] == 'const' and not any(a <= expr[1] <= b for a, b in intersection)):
            raise Infeasible()
        self.ranges[expr] = intersection
        self.guards.append({'instruction': address, 'relation': relation, 'bound': bound, 'signed': signed})
        self._project(expr)

    def _project(self, expr):
        """Invert lossless unary operations to constrain their input value."""
        values = self.finite(expr)
        if values is None: return
        child, incoming = None, None
        if expr[0] in ('add', 'sub'):
            left, right, bits = expr[1], expr[2], _bits(expr)
            mask = (1 << bits) - 1
            if right[0] == 'const':
                child = left
                incoming = {(v - right[1] if expr[0] == 'add' else v + right[1]) & mask for v in values}
            elif left[0] == 'const':
                child = right
                incoming = {(v - left[1] if expr[0] == 'add' else left[1] - v) & mask for v in values}
        elif expr[0] in ('zext', 'sext'):
            child = expr[1]
            mask = (1 << _bits(child)) - 1
            incoming = {v & mask for v in values
                        if _extend(_const(v & mask, _bits(child)), _bits(expr), expr[0] == 'sext')[1] == v}
        if child is None: return
        if child in self.ranges:
            incoming = {v for v in incoming if self.contains(child, v)}
        if not incoming: raise Infeasible()
        intervals = []
        for value in sorted(incoming):
            if intervals and intervals[-1][1] + 1 == value:
                intervals[-1] = (intervals[-1][0], value)
            else:
                intervals.append((value, value))
        self.ranges[child] = intervals
        self._project(child)

    def contains(self, expr, value):
        return any(a <= value <= b for a, b in self.ranges[expr])

    def finite(self, expr):
        ranges = self.ranges.get(expr)
        if ranges is None or sum(b - a + 1 for a, b in ranges) > MAX_VALUES:
            return None
        return {v for a, b in ranges for v in range(a, b + 1)}


class _Evaluator:
    def __init__(self, image, domains):
        self.image, self.domains = image, domains
        self.memo, self.loads = {}, {}

    def values(self, expr):
        if expr in self.memo: return self.memo[expr]
        constrained = self.domains.finite(expr)
        try:
            values = self._values(expr)
        except Unresolved:
            if constrained is None: raise
            values = constrained
        if expr in self.domains.ranges:
            values = {v for v in values if self.domains.contains(expr, v)}
        if not values: raise Infeasible()
        if len(values) > MAX_VALUES: raise Unresolved('selector domain exceeds analysis limit')
        self.memo[expr] = values
        return values

    def _values(self, expr):
        op, bits = expr[0], _bits(expr)
        mask = (1 << bits) - 1
        if op == 'const': return {expr[1]}
        if op == 'var':
            if bits <= 8: return set(range(1 << bits))
            raise Unresolved('unbounded input to table dispatch')
        if op in ('extract', 'zext', 'sext'):
            try:
                values = self.values(expr[1])
            except Unresolved:
                if op == 'extract' and bits <= 8: return set(range(1 << bits))
                raise
            if op == 'extract': return {(v >> expr[2]) & mask for v in values}
            if op == 'sext':
                oldbits = _bits(expr[1])
                return {(v - (1 << oldbits) if v & (1 << (oldbits - 1)) else v) & mask for v in values}
            return values
        if op == 'load':
            addresses = self.values(expr[1])
            values = set()
            rows = []
            for address in sorted(addresses):
                value = int.from_bytes(self.image.read(address, bits // 8, immutable=True), 'little')
                rows.append({'address': address, 'value': value})
                values.add(value)
            self.loads[expr] = {'instruction': expr[2], 'entry_size': bits // 8, 'entries': rows}
            return values
        if op == 'insert':
            old, new = self.values(expr[1]), self.values(expr[2])
            if len(old) * len(new) > MAX_VALUES: raise Unresolved('partial-register state is too broad')
            fieldmask = ((1 << _bits(expr[2])) - 1) << expr[3]
            return {((a & ~fieldmask) | (b << expr[3])) & mask for a in old for b in new}
        if op == 'and':
            for a, b in [(expr[1], expr[2]), (expr[2], expr[1])]:
                if b[0] == 'const' and b[1].bit_count() <= 12:
                    try: return {v & b[1] for v in self.values(a)}
                    except Unresolved:
                        result, bit = {0}, 1
                        while bit <= b[1]:
                            if bit & b[1]: result |= {v | bit for v in list(result)}
                            bit <<= 1
                        return result
        if op in ('shr', 'sar') and expr[2][0] == 'const':
            shift = expr[2][1] & (63 if bits == 64 else 31)
            try:
                values = self.values(expr[1])
                return {_operation(op, v, shift, bits) & mask for v in values}
            except Unresolved:
                remaining = bits - shift
                if (1 << remaining) <= MAX_VALUES:
                    if op == 'shr': return set(range(1 << remaining))
                    half = 1 << (remaining - 1)
                    return set(range(half)) | {v & mask for v in range(-half, 0)}
                raise
        left, right = self.values(expr[1]), self.values(expr[2])
        if len(left) * len(right) > MAX_VALUES * 4:
            raise Unresolved('arithmetic domain exceeds analysis limit')
        return {_operation(op, a, b, bits) & mask for a in left for b in right}


class _State:
    def __init__(self, image, initial=None, origin=0):
        self.image, self.origin = image, origin
        self.regs = {name: _const(value, image.bits) for name, value in (initial or {}).items()}
        self.stack, self.memory, self.flags = {}, {}, None
        self.domains = _Domains()

    def alias(self, ins, reg):
        name = ins.reg_name(reg)
        if name not in _ALIASES: raise Unresolved('unsupported register %s' % name)
        canonical, bits, offset = _ALIASES[name]
        return canonical, min(bits, self.image.bits), offset

    def register(self, ins, reg):
        canonical, bits, offset = self.alias(ins, reg)
        value = self.regs.setdefault(canonical, ('var', '%x:%s' % (self.origin, canonical), self.image.bits))
        return _extract(value, offset, bits)

    def assign(self, ins, reg, value):
        canonical, bits, offset = self.alias(ins, reg)
        value = _extend(value, bits)
        if bits == self.image.bits or bits == 32:
            self.regs[canonical] = _extend(value, self.image.bits)
        else:
            old = self.regs.get(canonical, ('var', '%x:%s' % (self.origin, canonical), self.image.bits))
            self.regs[canonical] = ('insert', old, value, offset, self.image.bits)

    def address(self, ins, operand):
        if ins.addr_size * 8 != self.image.bits:
            raise Unresolved('address-size override is not modeled')
        mem = operand.mem
        if mem.segment: raise Unresolved('segmented memory operand')
        value = _const(mem.disp, self.image.bits)
        if mem.base in (X.X86_REG_RIP, X.X86_REG_EIP):
            value = _binary('add', value, _const(ins.address + ins.size, self.image.bits), self.image.bits)
        elif mem.base:
            value = _binary('add', value, self.register(ins, mem.base), self.image.bits)
        if mem.index:
            index = _binary('mul', self.register(ins, mem.index), _const(mem.scale, self.image.bits), self.image.bits)
            value = _binary('add', value, index, self.image.bits)
        return value

    def operand(self, ins, operand):
        bits = operand.size * 8 or self.image.bits
        if operand.type == X.X86_OP_REG: return self.register(ins, operand.reg)
        if operand.type == X.X86_OP_IMM: return _const(operand.imm, bits)
        if operand.type == X.X86_OP_MEM:
            addr = self.address(ins, operand)
            if addr in self.stack and _bits(self.stack[addr]) == bits:
                return self.stack[addr]
            # Repeated reads of the same address/width retain their identity
            # until a potentially aliasing write or call invalidates it.
            return self.memory.setdefault((addr, bits), ('load', addr, ins.address, bits))
        raise Unresolved('unsupported operand')

    def kill(self, ins):
        # Unsupported instructions may write memory implicitly (push/pop,
        # string operations) or overlap a remembered stack slot.
        self.stack.clear()
        self.memory.clear()
        try:
            _, written = ins.regs_access()
        except capstone.CsError:
            self.regs.clear()
            self.flags = None
            return
        for reg in written:
            name = ins.reg_name(reg)
            if name in _ALIASES:
                canonical, _, _ = _ALIASES[name]
                self.regs[canonical] = ('var', '%x:%s' % (ins.address, canonical), self.image.bits)
            if name in ('eflags', 'rflags'): self.flags = None

    def step(self, ins):
        mnemonic, ops = ins.mnemonic, ins.operands
        try:
            if mnemonic in ('cmp', 'test') and len(ops) == 2:
                a, b = self.operand(ins, ops[0]), self.operand(ins, ops[1])
                self.flags = (a, _extend(b, _bits(a)), ins.address) if mnemonic == 'cmp' else (
                    _binary('and', a, b, _bits(a)), _const(0, _bits(a)), ins.address)
            elif mnemonic in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd') and len(ops) == 2:
                value = self.operand(ins, ops[1])
                if ops[0].type == X.X86_OP_REG:
                    value = _extend(value, ops[0].size * 8, mnemonic in ('movsx', 'movsxd'))
                    self.assign(ins, ops[0].reg, value)
                elif ops[0].type == X.X86_OP_MEM:
                    # Different offsets of the same symbolic base are provably
                    # disjoint. Every unknown alias and every overlap expires.
                    address, size = self.address(ins, ops[0]), ops[0].size
                    self.stack = {old: value for old, value in self.stack.items()
                                  if _disjoint(address, size, old, _bits(value) // 8)}
                    self.memory = {key: value for key, value in self.memory.items()
                                   if _disjoint(address, size, key[0], key[1] // 8)}
                    if ins.reg_name(ops[0].mem.base) in ('rsp', 'esp', 'rbp', 'ebp') and not ops[0].mem.index:
                        self.stack[address] = _extend(value, ops[0].size * 8)
            elif mnemonic == 'lea' and len(ops) == 2:
                self.assign(ins, ops[0].reg, self.address(ins, ops[1]))
            elif mnemonic in ('add', 'sub', 'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar') and len(ops) == 2 and ops[0].type == X.X86_OP_REG:
                op = 'shl' if mnemonic == 'sal' else mnemonic
                value = _binary(op, self.operand(ins, ops[0]), self.operand(ins, ops[1]), ops[0].size * 8)
                self.assign(ins, ops[0].reg, value)
                self.flags = None
            elif mnemonic == 'imul' and len(ops) in (2, 3) and ops[0].type == X.X86_OP_REG:
                a, b = (ops[0], ops[1]) if len(ops) == 2 else (ops[1], ops[2])
                self.assign(ins, ops[0].reg, _binary('mul', self.operand(ins, a), self.operand(ins, b), ops[0].size * 8))
                self.flags = None
            elif mnemonic in ('inc', 'dec') and ops[0].type == X.X86_OP_REG:
                self.assign(ins, ops[0].reg, _binary('add' if mnemonic == 'inc' else 'sub', self.operand(ins, ops[0]), _const(1, ops[0].size * 8), ops[0].size * 8))
                self.flags = None
            elif mnemonic in ('cdqe', 'cwde', 'cbw'):
                src, dst = {'cdqe': (X.X86_REG_EAX, X.X86_REG_RAX), 'cwde': (X.X86_REG_AX, X.X86_REG_EAX), 'cbw': (X.X86_REG_AL, X.X86_REG_AX)}[mnemonic]
                self.assign(ins, dst, _extend(self.register(ins, src), self.alias(ins, dst)[1], True))
            elif ins.group(capstone.CS_GRP_CALL):
                caller_saved = ('rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11') if self.image.bits == 64 else ('rax', 'rcx', 'rdx')
                for reg in caller_saved:
                    self.regs[reg] = ('var', '%x:call:%s' % (ins.address, reg), self.image.bits)
                self.stack.clear()
                self.memory.clear()
                self.flags = None
            elif mnemonic in ('syscall', 'sysenter', 'int', 'int1', 'int3', 'into'):
                # Capstone does not describe all ABI-defined clobbers.
                for reg in {alias[0] for alias in _ALIASES.values()}:
                    self.regs[reg] = ('var', '%x:system:%s' % (ins.address, reg), self.image.bits)
                self.stack.clear()
                self.memory.clear()
                self.flags = None
            elif mnemonic == 'xbegin':
                self.kill(ins)
                self.regs['rax'] = ('var', '%x:abort:rax' % ins.address, self.image.bits)
            elif ins.group(capstone.CS_GRP_JUMP) or mnemonic in ('nop', 'endbr64', 'endbr32'):
                pass
            else:
                self.kill(ins)
        except (Unresolved, capstone.CsError):
            self.kill(ins)

    def branch(self, ins, successor):
        if not self.flags or not ins.operands or ins.operands[0].type != X.X86_OP_IMM:
            return
        if ins.operands[0].imm == ins.address + ins.size:
            # Both outcomes enter the same instruction; this edge proves no
            # predicate even though it is also the encoded taken target.
            return
        condition = {'je': ('eq', False), 'jz': ('eq', False), 'jne': ('ne', False), 'jnz': ('ne', False),
                     'ja': ('gt', False), 'jae': ('ge', False), 'jb': ('lt', False), 'jbe': ('le', False),
                     'jg': ('gt', True), 'jge': ('ge', True), 'jl': ('lt', True), 'jle': ('le', True)}.get(ins.mnemonic)
        if condition is None: return
        relation, signed = condition
        if successor != ins.operands[0].imm:
            relation = {'eq': 'ne', 'ne': 'eq', 'gt': 'le', 'ge': 'lt', 'lt': 'ge', 'le': 'gt'}[relation]
        left, right, address = self.flags
        if right[0] != 'const': return
        self.domains.restrict(left, relation, right[1], signed, address)


def _indirect(ins):
    return ins.mnemonic == 'jmp' and len(ins.operands) == 1 and ins.operands[0].type != X.X86_OP_IMM


def _is_branch(ins):
    # Capstone 4/5 omits LOOP-family instructions from CS_GRP_JUMP.
    return ins.group(capstone.CS_GRP_JUMP) or ins.mnemonic in ('loop', 'loope', 'loopne')


def _successors(ins):
    end = ins.address + ins.size
    if ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('ud2', 'hlt'): return []
    if _is_branch(ins):
        if not ins.operands or ins.operands[0].type != X.X86_OP_IMM: return []
        return [ins.operands[0].imm] + ([] if ins.mnemonic == 'jmp' else [end])
    return [end]


class _Function:
    def __init__(self, function, image, entries, external_entries=None):
        self.va, self.image, self.entries = function.va, image, entries
        self.handwritten = getattr(function, 'type', 0) != 0
        self.external_entries = frozenset(external_entries or ())
        self.instructions, self.known_edges = {}, defaultdict(set)
        self.nonreturn = set()
        self.invalid = bool(self.external_entries)
        for block in function.bb:
            for item in block.instructions:
                try:
                    # A final instruction may be less than 15 bytes from the
                    # file-backed segment boundary; its recorded size is exact.
                    size = item.size or 15
                    ins = next(image.md.disasm(image.read(item.va, size), item.va, count=1), None)
                    if ins is None or (item.size and ins.size != item.size):
                        self.invalid = True
                        continue
                    self.instructions[ins.address] = ins
                except Unresolved:
                    self.invalid = True
            if block.instructions:
                self.known_edges[block.instructions[-1].va].update(c.va for c in block.child)
                if getattr(block, 'type', 0) == 8:
                    self.nonreturn.add(block.instructions[-1].va)
        self.metadata_leaders = {function.va} | {b.va for b in function.bb}
        self.rebuild_graph()

    def _fill_nop_gaps(self):
        ordered = sorted(self.instructions)
        for before, after in zip(ordered, ordered[1:]):
            previous = self.instructions[before]
            end = previous.address + previous.size
            if (not 0 < after - end <= 64 or end not in _successors(previous)
                    or previous.address in self.nonreturn):
                continue
            try:
                padding = list(self.image.md.disasm(self.image.read(end, after - end), end))
            except Unresolved:
                continue
            if (padding and padding[-1].address + padding[-1].size == after
                    and all(ins.mnemonic == 'nop' for ins in padding)):
                self.instructions.update((ins.address, ins) for ins in padding)

    def direct_successors(self, ins):
        return [] if ins.address in self.nonreturn else _successors(ins)

    def rebuild_graph(self):
        self._fill_nop_gaps()
        leaders = set(self.metadata_leaders)
        for targets in self.known_edges.values(): leaders.update(targets)
        for ins in self.instructions.values():
            if _is_branch(ins):
                leaders.update(_successors(ins))
                leaders.add(ins.address + ins.size)
            if ins.address in self.nonreturn:
                leaders.add(ins.address + ins.size)
        self.blocks, self.owner = {}, {}
        for address in sorted(self.instructions):
            if address in self.owner: continue
            chunk, current = [], address
            while current in self.instructions and current not in self.owner:
                ins = self.instructions[current]
                chunk.append(ins)
                self.owner[current] = address
                current = ins.address + ins.size
                if (_is_branch(ins) or ins.group(capstone.CS_GRP_RET)
                        or ins.address in self.nonreturn or current in leaders): break
            self.blocks[address] = chunk
        self.preds, self.succs = defaultdict(set), defaultdict(set)
        lower = min(self.instructions, default=0)
        upper = max((ins.address + ins.size for ins in self.instructions.values()), default=0)
        for start, chunk in self.blocks.items():
            last = chunk[-1]
            if last.address in self.nonreturn: continue
            direct_targets = set(self.direct_successors(last))
            if any(lower <= target < upper and target not in self.instructions for target in direct_targets):
                # Missing local code may contain another incoming path to a
                # dispatch. Dropping that edge could incorrectly make a guard
                # appear to dominate the site and remove feasible selectors.
                self.invalid = True
            for target in direct_targets | (self.known_edges[last.address] if _indirect(last) else set()):
                if target in self.owner:
                    successor = self.owner[target]
                    # Targeting an instruction in a chunk must never skip the
                    # instructions before it during symbolic execution.
                    if successor != target:
                        self.invalid = True
                        continue
                    self.preds[successor].add(start)
                    self.succs[start].add(successor)
        self.constants = None

    def entry_invariants(self):
        return entry_region_constants(self, _State, _const, _is_branch)

    def constant_inputs(self):
        if self.constants is not None: return self.constants
        inputs, outputs = {}, {}
        invariants = self.entry_invariants()
        roots = [b for b in self.blocks if not self.preds[b] or b == self.va]
        queue = deque(roots)
        for root in roots: inputs[root] = {} if root == self.va else dict(invariants)
        limit = max(100, len(self.blocks) * 32)
        steps = 0
        while len(outputs) < len(self.blocks) or queue:
            if steps >= limit:
                self.constants = {}
                return self.constants
            if not queue:
                # A disconnected cycle may still feed a reachable block.
                # Seed it with arbitrary state and include its contribution
                # in downstream joins before exposing any constants.
                root = min(set(self.blocks) - set(outputs))
                inputs[root] = dict(invariants)
                queue.append(root)
            start = queue.popleft()
            steps += 1
            state = _State(self.image, inputs[start], start)
            for ins in self.blocks[start]: state.step(ins)
            values = {reg: value[1] for reg, value in state.regs.items() if value[0] == 'const'}
            if outputs.get(start) == values: continue
            outputs[start] = values
            for successor in self.succs[start]:
                merged = dict(values) if successor not in inputs else {
                    reg: value for reg, value in inputs[successor].items() if values.get(reg) == value}
                if successor not in inputs or inputs[successor] != merged:
                    inputs[successor] = merged
                    queue.append(successor)
        # A budget cannot be treated as convergence.
        self.constants = inputs if not queue else {}
        return self.constants

    def paths(self, site):
        start = self.owner[site]
        pending = [(start, [start], len(self.blocks[start]))]
        result = []
        while pending:
            current, path, count = pending.pop()
            predecessors = self.preds[current]
            # Cutting off a prefix means arbitrary incoming values. It never
            # removes an incoming edge, including loop backedges.
            if (not predecessors or len(path) >= MAX_BLOCKS or count >= MAX_INSTRUCTIONS
                    or len(pending) + len(result) + len(predecessors) > MAX_PATHS):
                result.append(list(reversed(path)))
                continue
            for pred in sorted(predecessors):
                if pred in path or _indirect(self.blocks[pred][-1]):
                    result.append(list(reversed(path)))
                else:
                    pending.append((pred, path + [pred], count + len(self.blocks[pred])))
        return result


def _table_shape(expr):
    """Find the actual terminal table load, independently of its selector map."""
    if expr[0] in ('zext', 'sext', 'extract'):
        return _table_shape(expr[1])
    if expr[0] == 'load': return expr
    if expr[0] == 'add':
        if expr[1][0] == 'const': return _table_shape(expr[2])
        if expr[2][0] == 'const': return _table_shape(expr[1])
    raise Unresolved('indirect target is not a table load plus a constant code base')


def _has_variable(expr):
    if expr[0] in ('var', 'load'): return True
    return any(_has_variable(item) for item in expr[1:] if isinstance(item, tuple))


def _analyze_site(function, site):
    if function.invalid:
        raise Unresolved('function metadata has an undecodable instruction or internal CFG edge')
    constants = function.constant_inputs()
    initializer = getattr(function, 'initial_state', None)

    def replay(path):
        state = (initializer(path[0]) if initializer is not None else
                 _State(function.image, constants.get(path[0]), path[0]))
        for index, start in enumerate(path):
            for ins in function.blocks[start]:
                if ins.address == site:
                    break
                state.step(ins)
            if index + 1 < len(path):
                state.branch(function.blocks[start][-1], path[index + 1])
        jump = function.instructions[site]
        expression = state.operand(jump, jump.operands[0])
        evaluator = _Evaluator(function.image, state.domains)
        try:
            terminal_load = _table_shape(expression)
            if not _has_variable(terminal_load[1]):
                raise Unresolved('target does not use a variable table index')
        except Unresolved:
            # A shared suffix can also receive a proved constant default target.
            values = evaluator.values(expression)
            if len(values) != 1:
                raise Unresolved('non-table incoming path has no unique proved target')
            kind = 'constant'
        else:
            values = evaluator.values(expression)
            evaluator.values(terminal_load)
            if terminal_load not in evaluator.loads:
                raise Unresolved('terminal table bytes were not replayed')
            kind = 'table'
        if any(value not in function.instructions or value in function.entries for value in values):
            raise Unresolved('table target is not a local non-entry instruction boundary')
        return {'blocks': path, 'guards': state.domains.guards,
                'loads': list(evaluator.loads.values()), 'targets': sorted(values), 'kind': kind}

    paths = function.paths(site)
    evidence, strategy, expansions = [], 'bounded_cfg_suffixes', 0
    try:
        for path in paths:
            try:
                evidence.append(replay(path))
            except Infeasible:
                continue
    except Unresolved as bounded_error:
        # A shared dispatch may have many independent selector preparations.
        # Expanding every one back toward the function entry can exhaust the
        # global path budget before visiting even a nearby defining load.
        # Retry each suffix from the site, expanding every incoming edge only
        # while the suffix still depends on an arbitrary prefix. Successful
        # replay covers that arbitrary prefix, so it needs no further history.
        # Keep the original analysis first: it may prove tighter guard holes.
        strategy, evidence = 'adaptive_cfg_suffixes', []
        start = function.owner[site]
        pending = [(start, [start], len(function.blocks[start]))]
        maximum_suffixes, maximum_expansions = MAX_PATHS * 4, MAX_PATHS * MAX_BLOCKS * 4
        paths = []
        while pending:
            if expansions >= maximum_expansions:
                raise Unresolved('adaptive CFG suffix proof exceeded its expansion budget')
            current, backwards, count = pending.pop()
            expansions += 1
            path = list(reversed(backwards))
            try:
                proved = replay(path)
            except Infeasible:
                paths.append(path)
                continue
            except Unresolved as suffix_error:
                predecessors = function.preds[current]
                if not predecessors or len(backwards) >= MAX_BLOCKS or count >= MAX_INSTRUCTIONS:
                    raise Unresolved('adaptive CFG suffix has an unproved incoming prefix at 0x%x: %s; bounded replay: %s' %
                                     (current, suffix_error, bounded_error))
                if any(pred in backwards or _indirect(function.blocks[pred][-1]) for pred in predecessors):
                    raise Unresolved('adaptive CFG suffix reaches an unproved loop or indirect prefix at 0x%x: %s' %
                                     (current, suffix_error))
                if len(pending) + len(paths) + len(predecessors) > maximum_suffixes:
                    raise Unresolved('adaptive CFG suffix proof exceeded its path budget')
                for pred in sorted(predecessors):
                    pending.append((pred, backwards + [pred], count + len(function.blocks[pred])))
                continue
            paths.append(path)
            evidence.append(proved)
    targets = {target for item in evidence for target in item['targets']}
    if not evidence or not any(item['kind'] == 'table' for item in evidence) or len(targets) < 2:
        raise Unresolved('no multi-target local table domain was proved')
    limits = {'blocks': MAX_BLOCKS, 'instructions': MAX_INSTRUCTIONS, 'paths': MAX_PATHS, 'values': MAX_VALUES}
    if strategy == 'adaptive_cfg_suffixes':
        limits.update({'adaptive_paths': maximum_suffixes, 'adaptive_expansions': maximum_expansions})
    return {'site': site, 'status': 'resolved', 'reason': 'finite table replay covers every incoming CFG suffix',
            'targets': sorted(targets), 'evidence': {'scope': 'local_cfg_selector_domain',
            'function': function.va, 'paths': evidence, 'path_count': len(paths),
            'strategy': strategy, 'expansions': expansions, 'limits': limits}}


def analyze_jump_tables(binary_path, module, source_facts=None):
    """Return JSON-serializable resolved/unresolved records keyed by jump site.

    Existing type-7 children are not used as recovered targets. They are used
    only as incoming CFG edges when analyzing another site's predecessors.
    Known metadata edges from another function into an interior
    instruction invalidate the local proof: that entry could bypass guards.
    This detects recorded external entries; it does not prove the absence of
    unrecorded indirect edges or other entry points.
    The caller decides how to apply records and preserve provenance.
    """
    image = _Image(binary_path)
    writable_audit = None
    entries = {function.va for function in module.fuc}
    # Keep ownership only for edge destinations, not every instruction in the
    # binary. None means two or more distinct source functions reach a target.
    incoming_sources = {}
    for item in module.fuc:
        for block in item.bb:
            for child in block.child:
                if child.va not in incoming_sources:
                    incoming_sources[child.va] = item.va
                elif incoming_sources[child.va] != item.va:
                    incoming_sources[child.va] = None
    records = []
    for item in module.fuc:
        external_entries = {ins.va for block in item.bb for ins in block.instructions
                            if ins.va != item.va and ins.va in incoming_sources
                            and incoming_sources[ins.va] != item.va}
        function = _Function(item, image, entries, external_entries)
        original_edges = {site: set(targets) for site, targets in function.known_edges.items()}
        sites = sorted(ins.address for ins in function.instructions.values() if _indirect(ins))
        while sites:
            current, added_edges = [], False
            for site in sites:
                try:
                    if function.external_entries:
                        raise Unresolved('known external CFG edge enters non-entry instruction 0x%x' %
                                         min(function.external_entries))
                    record = _analyze_site(function, site)
                    new = set(record['targets']) - function.known_edges[site]
                    if new:
                        function.known_edges[site].update(new)
                        added_edges = True
                    current.append(record)
                except (Unresolved, RecursionError) as error:
                    current.append({'site': site, 'status': 'unresolved', 'reason': str(error) or 'expression depth exceeded',
                                    'evidence': {'function': item.va, 'scope': 'local_cfg_selector_domain'}})
            if not added_edges:
                if any(record['status'] != 'resolved' for record in current):
                    # Closure must start from metadata, without treating the
                    # provisional edges from the local pass as trusted input.
                    from copy import copy
                    original = copy(function)
                    original.known_edges = defaultdict(set, original_edges)
                    original.rebuild_graph()
                    reaching = recover_reaching_tables(original, _analyze_site, _State,
                                                       _indirect, Unresolved)
                    recovered = {record['site']: record for record in reaching['records']}
                    frame_reaching = None
                    if any(record['status'] != 'resolved' and record['site'] not in recovered
                           for record in current):
                        frame_reaching = recover_reaching_tables(
                            original, _analyze_site, _State, _indirect, Unresolved,
                            dataflow=function_dataflow)
                        recovered.update((record['site'], record) for record in frame_reaching['records'])
                    for index, record in enumerate(current):
                        if record['status'] == 'resolved':
                            continue
                        if record['site'] in recovered:
                            current[index] = recovered[record['site']]
                        else:
                            record['evidence']['reaching_definitions'] = {
                                key: value for key, value in reaching.items()
                                if key not in ('records', 'proof')}
                            if frame_reaching is not None:
                                record['evidence']['frame_dataflow'] = {
                                    key: value for key, value in frame_reaching.items()
                                    if key not in ('records', 'proof')}
                # A packed selector loaded from writable global data needs
                # separate bounds, stability and loop proofs. Reading initial
                # bytes must never silently remove a selector from this site.
                has_writable_indexed_load = any(
                    ins.mnemonic == 'mov' and len(ins.operands) == 2
                    and ins.operands[1].type == X.X86_OP_MEM
                    and not ins.operands[1].mem.base and ins.operands[1].mem.index
                    and any(lo <= ins.operands[1].mem.disp < hi for lo, hi, _ in image.segments)
                    and not any(lo <= ins.operands[1].mem.disp < hi for lo, hi in image.readonly_segments)
                    for ins in function.instructions.values())
                if has_writable_indexed_load:
                    if writable_audit is None:
                        try:
                            from jump_table_data_invariants import WritableTableAudit
                        except ModuleNotFoundError:
                            from extract_gt.jump_table_data_invariants import WritableTableAudit
                        writable_audit = WritableTableAudit(binary_path)
                    for record in current:
                        obligations = writable_audit.inspect(function, record['site'])
                        if obligations:
                            if record['status'] == 'resolved':
                                record['local_upper_bound'] = record.pop('targets')
                            record['status'] = 'unresolved'
                            missing = sorted({item['kind'] for audit in obligations
                                              for item in audit['obligations'] if not item['proved']})
                            record['reason'] = 'writable selector data has unproved obligations: ' + ', '.join(missing)
                            record['evidence']['writable_selector_data'] = obligations
                records.extend(current)
                break
            # A recovered first-stage dispatch supplies previously missing
            # incoming edges to later dispatches. Recompute constants and
            # recheck every site; never reuse a proof against a changed CFG.
            function.rebuild_graph()
    if source_facts:
        try:
            from jump_table_proofs import apply_source_facts
        except ModuleNotFoundError:
            from extract_gt.jump_table_proofs import apply_source_facts
        records = apply_source_facts(records, source_facts, binary_path)
    else:
        for record in records:
            if isinstance(record, dict) and record.get("status") == "resolved":
                record.setdefault("proof_mode", "binary_only")
    return records
