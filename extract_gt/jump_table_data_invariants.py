"""Fail-closed obligations for selectors derived from writable packed tables.

Initial ELF data is a snapshot, not an invariant. This module keeps a numeric
shift-loop closure separate from proofs of stable memory, bounded indexing,
and the actual machine-code loop. Snapshot selectors are diagnostic evidence
only and are never returned as an automatically proved site domain.
"""
import hashlib
from io import BytesIO

import capstone
from capstone import x86_const as X
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def shift_loop_domain(values, bit_width, initial_shift, loop_shift, selector_mask,
                      clear_masks=(), initial_signed=False, loop_signed=False,
                      nonzero_guard=True, max_states=65536):
    """Prove closure of a supplied finite state set under a shift-loop summary.

    This arithmetic lemma does not prove that binary memory retains ``values``
    or that the code implements the supplied summary. Callers must discharge
    those independent obligations before using its selectors to refine GT.
    Every shift/clear transition is included, in every order; zero states exit
    only when the summary has a proven nonzero guard.
    """
    integers = (bit_width, initial_shift, loop_shift, selector_mask, max_states)
    if any(type(value) is not int for value in integers):
        raise ValueError('loop widths, shifts and mask must be integers')
    if bit_width not in (8, 16, 32, 64) or not 0 <= initial_shift < bit_width:
        raise ValueError('unsupported initial shift or bit width')
    if not 0 < loop_shift < bit_width or max_states < 1:
        raise ValueError('loop must make progress with a positive in-range shift')
    maximum = (1 << bit_width) - 1
    if not 0 < selector_mask <= maximum:
        raise ValueError('selector mask is outside the state width')
    clear_masks = tuple(clear_masks)
    if any(type(mask) is not int or not 0 <= mask <= maximum for mask in clear_masks):
        raise ValueError('clear masks must fit the state width')

    def shift(value, amount, signed):
        if signed and value & (1 << (bit_width - 1)):
            value -= 1 << bit_width
        return (value >> amount) & maximum

    seeds = set()
    for value in values:
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('initial value does not fit the state width')
        seeds.add(shift(value, initial_shift, initial_signed))
    if not seeds:
        raise ValueError('empty initial value domain')
    reached, pending, selectors = set(), list(seeds), set()
    while pending:
        state = pending.pop()
        if state in reached:
            continue
        reached.add(state)
        if len(reached) > max_states:
            return {'status': 'unresolved', 'reason': 'shift-loop state budget exceeded'}
        if state == 0 and nonzero_guard:
            continue
        selectors.add(state & selector_mask)
        transitions = [shift(state, loop_shift, loop_signed)]
        transitions.extend(state & mask for mask in clear_masks)
        pending.extend(value for value in transitions if value not in reached)
    return {'status': 'proved_arithmetic_closure', 'selectors': sorted(selectors),
            'state_count': len(reached), 'seed_count': len(seeds),
            'assumptions': ['initial values are invariant at every seed load',
                            'all loop entries and state writes implement this summary',
                            'zero states exit before dispatch' if nonzero_guard else
                            'zero states may reach dispatch']}


def _family(instruction, register):
    name = instruction.reg_name(register)
    for family in ('a', 'b', 'c', 'd'):
        if name in (family + 'l', family + 'h', family + 'x', 'e' + family + 'x', 'r' + family + 'x'):
            return 'r' + family + 'x'
    for family in ('si', 'di', 'sp', 'bp'):
        if name in (family, family + 'l', 'e' + family, 'r' + family):
            return 'r' + family
    if name.startswith('r') and name[1:].rstrip('dwb').isdigit():
        return name.rstrip('dwb')
    return name


def _writes(instruction, family):
    try:
        return any(_family(instruction, register) == family
                   for register in instruction.regs_access()[1])
    except capstone.CsError:
        return True


def _static_address(instruction, operand):
    memory = operand.mem
    if memory.segment or memory.index:
        return None
    if memory.base in (X.X86_REG_RIP, X.X86_REG_EIP):
        return instruction.address + instruction.size + memory.disp
    return memory.disp if not memory.base else None


class WritableTableAudit:
    """Cache one ELF and conservative whole-image effect audit per binary.

    ``prove_object`` can establish invariance for closed simple binaries. An
    unknown store, call, return, indirect transfer, loader relocation into the
    object, exported object, or undecoded executable bytes prevents the proof.
    No assumption that a stack/heap pointer cannot alias the table is made.
    Real-world binaries commonly leave these obligations unresolved.
    """
    def __init__(self, binary):
        with open(binary, 'rb') as source:
            self.data = source.read()
        self.binary_sha256 = hashlib.sha256(self.data).hexdigest()
        self.elf = ELFFile(BytesIO(self.data))
        if self.elf['e_machine'] not in ('EM_386', 'EM_X86_64'):
            raise ValueError('writable-table audit supports x86 ELF only')
        self.bits = self.elf.elfclass
        self.sections = list(self.elf.iter_sections())
        self.objects = {}
        self.functions = {}
        for section in self.sections:
            if section['sh_type'] not in ('SHT_SYMTAB', 'SHT_DYNSYM'):
                continue
            for symbol in section.iter_symbols():
                if (symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size']
                        and isinstance(symbol['st_shndx'], int)):
                    self.functions.setdefault(int(symbol['st_value']), []).append({
                        'size': int(symbol['st_size']), 'name': symbol.name,
                        'exported': section['sh_type'] == 'SHT_DYNSYM'
                        and symbol['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK')
                        and symbol['st_other']['visibility'] == 'STV_DEFAULT'})
                if (symbol['st_info']['type'] == 'STT_OBJECT' and symbol['st_size']
                        and isinstance(symbol['st_shndx'], int)):
                    self.objects.setdefault(int(symbol['st_value']), []).append({
                        'size': int(symbol['st_size']), 'section': symbol['st_shndx'],
                        'exported': section['sh_type'] == 'SHT_DYNSYM'
                        and symbol['st_info']['bind'] in ('STB_GLOBAL', 'STB_WEAK')
                        and symbol['st_other']['visibility'] == 'STV_DEFAULT'})
        self.decoder = capstone.Cs(capstone.CS_ARCH_X86,
                                   capstone.CS_MODE_64 if self.bits == 64 else capstone.CS_MODE_32)
        self.decoder.detail = True
        self._effects = None
        self._object_audits = {}
        self._pointer_returns = None

    def _read(self, address, size):
        for segment in self.elf.iter_segments():
            offset = address - segment['p_vaddr']
            if (segment['p_type'] == 'PT_LOAD' and offset >= 0
                    and offset + size <= segment['p_filesz']):
                start = segment['p_offset'] + offset
                result = self.data[start:start + size]
                if len(result) == size:
                    return result
        raise ValueError('object is not fully file-backed')

    def pointer_returns(self, address, size):
        """Find byte-proved simple functions returning an object's address.

        This is escape evidence, not a claim that the getter is reachable or
        that any caller writes through it. Symbol names are labels only. Scan
        each small function at its declared entry: an earlier linear-decoding
        gap elsewhere must not hide a concrete address-returning body.
        """
        if self._pointer_returns is None:
            self._pointer_returns = []
            for start, symbols in sorted(self.functions.items()):
                sizes = {symbol['size'] for symbol in symbols}
                if len(sizes) != 1 or not 0 < next(iter(sizes)) <= 64:
                    continue
                length = next(iter(sizes))
                try:
                    raw = self._read(start, length)
                except ValueError:
                    continue
                body = list(self.decoder.disasm(raw, start))
                if not body or sum(instruction.size for instruction in body) != length:
                    continue
                value, materialization = None, None
                for instruction in body:
                    operands = instruction.operands
                    if instruction.mnemonic == 'ret' and not operands and not any(instruction.prefix):
                        if value is not None:
                            self._pointer_returns.append({
                                'function': start, 'function_names': sorted({symbol['name'] for symbol in symbols}),
                                'dynamically_exported': any(symbol['exported'] for symbol in symbols),
                                'returned_address': value, 'materialization': materialization,
                                'return_instruction': instruction.address, 'bytes': raw.hex(),
                                'caller_reachability_proved': False})
                        break
                    if instruction.mnemonic in ('nop', 'endbr32', 'endbr64'):
                        continue
                    if (instruction.mnemonic in ('mov', 'movabs', 'lea') and len(operands) == 2
                            and operands[0].type == X.X86_OP_REG
                            and instruction.reg_name(operands[0].reg) in ('eax', 'rax')):
                        source = operands[1]
                        if source.type == X.X86_OP_IMM and instruction.mnemonic != 'lea':
                            value = source.imm & ((1 << (operands[0].size * 8)) - 1)
                        elif (source.type == X.X86_OP_MEM and instruction.mnemonic == 'lea'
                              and instruction.addr_size * 8 == self.bits):
                            value = _static_address(instruction, source)
                            if value is not None:
                                value &= (1 << (operands[0].size * 8)) - 1
                        else:
                            value = None
                        materialization = instruction.address
                        continue
                    # A branch, call, changed return register, or unsupported
                    # transfer prevents this deliberately small body proof.
                    break
        return [dict(item) for item in self._pointer_returns
                if address <= item['returned_address'] < address + size]

    def _scan_effects(self):
        if self._effects is not None:
            return self._effects
        effects = {'unknown_effects': [], 'unknown_count': 0, 'direct_writes': [],
                   'unknown_classes': {}, 'address_values': [],
                   'decoded_instructions': 0, 'coverage_complete': True, 'coverage_gaps': []}

        def unknown(instruction, reason):
            effects['unknown_count'] += 1
            category = effects['unknown_classes'].setdefault(reason, {'count': 0, 'examples': []})
            category['count'] += 1
            if len(category['examples']) < 4:
                category['examples'].append(instruction.address)
            if len(effects['unknown_effects']) < 12:
                effects['unknown_effects'].append({'instruction': instruction.address,
                                                   'mnemonic': instruction.mnemonic, 'reason': reason})

        simple = {'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'cmp', 'test',
                  'add', 'sub', 'and', 'or', 'xor', 'not', 'neg', 'inc', 'dec',
                  'shl', 'sal', 'shr', 'sar', 'imul', 'cdqe', 'cwde', 'cbw',
                  'nop', 'endbr32', 'endbr64', 'hlt', 'ud2'}
        starts, targets = set(), set()
        for section in self.sections:
            if not section['sh_flags'] & 2 or not section['sh_flags'] & 4:
                continue
            data, start = section.data(), int(section['sh_addr'])
            cursor = start
            for instruction in self.decoder.disasm(data, start):
                starts.add(instruction.address)
                cursor = instruction.address + instruction.size
                effects['decoded_instructions'] += 1
                if instruction.group(capstone.CS_GRP_CALL):
                    unknown(instruction, 'call effects/argument escapes are not proved')
                elif instruction.group(capstone.CS_GRP_RET):
                    unknown(instruction, 'return targets and external callers are not proved')
                elif instruction.group(capstone.CS_GRP_JUMP) or instruction.mnemonic in ('loop', 'loope', 'loopne'):
                    if instruction.operands and instruction.operands[0].type == X.X86_OP_IMM:
                        targets.add(instruction.operands[0].imm)
                    else:
                        unknown(instruction, 'indirect control-flow destinations are not proved')
                elif instruction.mnemonic not in simple:
                    unknown(instruction, 'instruction memory/escape effects are not modeled')
                for operand in instruction.operands:
                    if operand.type == X.X86_OP_MEM and operand.access & capstone.CS_AC_WRITE:
                        address = _static_address(instruction, operand)
                        if (address is None or instruction.addr_size * 8 != self.bits
                                or address < 0 or address + operand.size > 1 << self.bits):
                            unknown(instruction, 'indirect store may alias the writable object')
                        else:
                            effects['direct_writes'].append((instruction.address, address, operand.size))
                    if instruction.mnemonic in ('lea', 'mov', 'movabs'):
                        if operand.type == X.X86_OP_IMM:
                            effects['address_values'].append((instruction.address, operand.imm))
                        elif instruction.mnemonic == 'lea' and operand.type == X.X86_OP_MEM:
                            address = _static_address(instruction, operand)
                            if address is not None:
                                effects['address_values'].append((instruction.address, address))
            if cursor != start + len(data):
                effects['coverage_complete'] = False
                if len(effects['coverage_gaps']) < 8:
                    effects['coverage_gaps'].append({'start': cursor, 'end': start + len(data),
                                                     'reason': 'executable section not fully decoded'})
        # A linear decode cannot certify alternate entries into instruction
        # interiors, or executable code that has no executable section.
        if self.elf['e_entry'] not in starts or not targets <= starts:
            effects['coverage_complete'] = False
            if len(effects['coverage_gaps']) < 8:
                effects['coverage_gaps'].append({'reason': 'entry or direct branch target lacks a decoded boundary',
                                                 'targets': sorted(targets - starts)[:8]})
        executable = [(int(section['sh_addr']), int(section['sh_addr']) + int(section['sh_size']))
                      for section in self.sections if section['sh_flags'] & 2 and section['sh_flags'] & 4]
        for segment in self.elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 1:
                low, high = segment['p_vaddr'], segment['p_vaddr'] + segment['p_filesz']
                intervals = sorted((max(low, start), min(high, end)) for start, end in executable
                                   if start < high and low < end)
                cursor = low
                for start, end in intervals:
                    if start > cursor:
                        effects['coverage_complete'] = False
                        if len(effects['coverage_gaps']) < 8:
                            effects['coverage_gaps'].append({'start': cursor, 'end': start,
                                                             'reason': 'executable segment bytes outside code sections'})
                    cursor = max(cursor, end)
                if cursor < high:
                    effects['coverage_complete'] = False
                    if len(effects['coverage_gaps']) < 8:
                        effects['coverage_gaps'].append({'start': cursor, 'end': high,
                                                         'reason': 'executable segment bytes outside code sections'})
        self._effects = effects
        return effects

    def prove_object(self, address, entry_size, index_values=None):
        """Keep object extent, index bounds and memory stability independent."""
        if type(address) is not int or type(entry_size) is not int or entry_size not in (1, 2, 4, 8):
            raise ValueError('invalid object address or entry size')
        objects = self.objects.get(address, [])
        sizes = {item['size'] for item in objects}
        extent = len(sizes) == 1 and next(iter(sizes)) % entry_size == 0
        count = next(iter(sizes)) // entry_size if extent else None
        indices = set(index_values) if index_values is not None else None
        if indices is not None and any(type(value) is not int for value in indices):
            raise ValueError('index domain must contain integers')
        bounded = extent and indices is not None and bool(indices) and all(0 <= value < count for value in indices)
        obligations = [
            {'kind': 'object_extent', 'proved': extent, 'entry_count': count},
            {'kind': 'index_bounds', 'proved': bool(bounded),
             'reason': 'finite index proof is required independently of symbol size' if indices is None else
                       'proven index domain must be contained in the object',
             'minimum': min(indices) if indices else None, 'maximum': max(indices) if indices else None},
        ]
        if not extent:
            return {'status': 'unresolved', 'obligations': obligations}
        key = (address, next(iter(sizes)))
        if key not in self._object_audits:
            size = key[1]
            effects = self._scan_effects()
            writes = [site for site, target, width in effects['direct_writes']
                      if address < target + width and target < address + size]
            escapes = [site for site, value in effects['address_values'] if address <= value < address + size]
            stored_addresses = []
            pointer_size = self.bits // 8
            for section in self.sections:
                if (not section['sh_flags'] & 2 or section['sh_flags'] & 4
                        or section['sh_type'] == 'SHT_NOBITS'):
                    continue
                data = section.data()
                for offset in range(max(0, len(data) - pointer_size + 1)):
                    value = int.from_bytes(data[offset:offset + pointer_size], 'little')
                    if address <= value < address + size:
                        stored_addresses.append(int(section['sh_addr']) + offset)
                        if len(stored_addresses) >= 12:
                            break
                if len(stored_addresses) >= 12:
                    break
            relocations = []
            for section in self.sections:
                if isinstance(section, RelocationSection):
                    for relocation in section.iter_relocations():
                        if address <= relocation['r_offset'] < address + size:
                            relocations.append(int(relocation['r_offset']))
            exported = any(item['exported'] for item in objects)
            pointer_returns = self.pointer_returns(address, size)
            dynamic_environment = (self.elf['e_type'] != 'ET_EXEC' or
                                   any(segment['p_type'] in ('PT_INTERP', 'PT_DYNAMIC')
                                       for segment in self.elf.iter_segments()))
            self._object_audits[key] = [
                {'kind': 'code_effect_coverage', 'proved': effects['coverage_complete'],
                 'decoded_instructions': effects['decoded_instructions'],
                 'gaps': effects['coverage_gaps']},
                {'kind': 'data_stability', 'proved': bool(effects['coverage_complete'] and
                 not effects['unknown_count'] and not writes and not relocations),
                 'unknown_effect_count': effects['unknown_count'], 'unknown_effects': effects['unknown_effects'],
                 'unknown_effect_classes': effects['unknown_classes'],
                 'direct_writes': writes[:12], 'loader_writes': relocations[:12]},
                {'kind': 'closed_executable', 'proved': not dynamic_environment,
                 'reason': 'dynamic-loader/library initialization effects are not proved'},
                {'kind': 'no_pointer_escape', 'proved': not exported and not escapes
                 and not stored_addresses and not pointer_returns and not effects['unknown_count'],
                 'exported': exported, 'address_materializations': escapes[:12],
                 'stored_object_addresses': stored_addresses,
                 'pointer_returning_functions': pointer_returns,
                 'reason': 'unknown calls/stores and materialized object pointers require alias/escape proof'},
            ]
        obligations.extend(self._object_audits[key])
        result = {'status': 'proved' if all(item['proved'] for item in obligations) else 'unresolved',
                  'table_address': address, 'entry_size': entry_size, 'entry_count': count,
                  'obligations': obligations}
        if result['status'] == 'proved':
            raw = self._read(address, count * entry_size)
            result['values'] = sorted({int.from_bytes(raw[value * entry_size:(value + 1) * entry_size], 'little')
                                       for value in indices})
        return result

    def inspect(self, function, site):
        """Discover writable-table/shift candidates and expose missing proofs.

        Pattern discovery supplies diagnostics, never a selector restriction.
        In particular a 16-bit field load is not silently narrowed to the size
        of an adjacent ELF object, and recognizing shifts does not prove that
        every incoming loop path follows them.
        """
        instructions = sorted(function.instructions.values(), key=lambda instruction: instruction.address)
        positions = {instruction.address: index for index, instruction in enumerate(instructions)}
        jump = function.instructions.get(site)
        if jump is None or not jump.operands:
            return []
        operand = jump.operands[0]
        register = operand.mem.index if operand.type == X.X86_OP_MEM else operand.reg if operand.type == X.X86_OP_REG else 0
        if not register:
            return []
        family, mask = _family(jump, register), None
        for instruction in reversed(instructions[max(0, positions[site] - 8):positions[site]]):
            operands = instruction.operands
            if not _writes(instruction, family):
                continue
            if (instruction.mnemonic == 'and' and len(operands) == 2
                    and operands[0].type == X.X86_OP_REG and operands[1].type == X.X86_OP_IMM and mask is None):
                mask = operands[1].imm & ((1 << (operands[0].size * 8)) - 1)
            elif (instruction.mnemonic == 'mov' and len(operands) == 2
                  and operands[0].type == operands[1].type == X.X86_OP_REG):
                family = _family(instruction, operands[1].reg)
                if mask is not None:
                    break
            else:
                break
        if mask is None or mask <= 0 or mask & (mask + 1):
            return []
        results = []
        for index, instruction in enumerate(instructions):
            operands = instruction.operands
            if (instruction.mnemonic not in ('shr', 'sar') or len(operands) != 2
                    or operands[0].type != X.X86_OP_REG or operands[1].type != X.X86_OP_IMM
                    or _family(instruction, operands[0].reg) != family):
                continue
            source_family, load = family, None
            for previous in reversed(instructions[max(0, index - 12):index]):
                if not _writes(previous, source_family):
                    continue
                source = previous.operands
                if previous.mnemonic == 'mov' and len(source) == 2 and source[0].type == X.X86_OP_REG:
                    if source[1].type == X.X86_OP_REG:
                        source_family = _family(previous, source[1].reg)
                        continue
                    if source[1].type == X.X86_OP_MEM:
                        load = previous
                break
            if load is None:
                continue
            memory = load.operands[1].mem
            table, width = memory.disp, load.operands[1].size
            if memory.base or not memory.index or memory.scale != width or table not in self.objects:
                continue
            object_section = self.sections[self.objects[table][0]['section']]
            if not object_section['sh_flags'] & 1:
                continue
            shifts = sorted({other.operands[1].imm for other in instructions
                             if other.address != instruction.address and other.mnemonic in ('shr', 'sar')
                             and len(other.operands) == 2 and other.operands[0].type == X.X86_OP_REG
                             and other.operands[1].type == X.X86_OP_IMM
                             and _family(other, other.operands[0].reg) == family})
            if len(shifts) != 1:
                continue
            index_bits = None
            index_family = _family(load, memory.index)
            for previous in reversed(instructions[max(0, positions[load.address] - 12):positions[load.address]]):
                if previous.mnemonic == 'cdqe' and index_family == 'rax':
                    continue
                if not _writes(previous, index_family):
                    continue
                source = previous.operands
                if (previous.mnemonic == 'movzx' and len(source) == 2
                        and source[1].type == X.X86_OP_MEM):
                    index_bits = source[1].size * 8
                break
            proof = self.prove_object(table, width, range(1 << index_bits) if index_bits and index_bits <= 16 else None)
            count = proof.get('entry_count')
            if count is None:
                continue
            raw = self._read(table, count * width)
            values = [int.from_bytes(raw[offset:offset + width], 'little') for offset in range(0, len(raw), width)]
            closure = shift_loop_domain(values, width * 8, operands[1].imm, shifts[0], mask,
                                        initial_signed=instruction.mnemonic == 'sar', loop_signed=True)
            # Pattern recognition and arithmetic closure remain diagnostic.
            # The separate CFG proof checks all actual transfers and joins,
            # conditional on every seed load supplying a value from this set.
            loop_proof = {'status': 'unresolved', 'proved': False,
                          'reason': 'complete CFG metadata is required for the seeded loop proof'}
            if all(hasattr(function, name) for name in ('blocks', 'preds', 'succs', 'owner', 'known_edges')):
                try:
                    from jump_table_analysis import _State
                    from jump_table_loop_invariants import prove_seeded_selector_loop
                except ModuleNotFoundError:
                    from extract_gt.jump_table_analysis import _State
                    from extract_gt.jump_table_loop_invariants import prove_seeded_selector_loop
                loop_proof = prove_seeded_selector_loop(function, site, load.address, values,
                                                       _State, state_register=family)
            preserved = bool(loop_proof.get('proved') and closure.get('selectors') is not None
                             and set(loop_proof.get('selectors', ())) <= set(closure['selectors']))
            proof['obligations'].append({
                'kind': 'loop_transfer', 'proved': preserved,
                'status': 'proved_conditional_loop' if preserved else 'unresolved',
                'reason': 'emitted CFG preserves the initialized selector domain under the seed assumption'
                          if preserved else 'emitted CFG has not proved the initialized selector domain',
                'selectors': loop_proof.get('selectors'), 'conditional_proof': loop_proof})
            proof.update({'status': 'unresolved', 'site': site, 'load_instruction': load.address,
                          'binary_sha256': self.binary_sha256, 'state_register': family,
                          'initial_shift': operands[1].imm, 'loop_shift': shifts[0],
                          'selector_mask': mask, 'index_source_bits': index_bits,
                          'snapshot_closure': dict(closure, status='conditional_initial_bytes')})
            proof.pop('values', None)
            results.append(proof)
        return results
