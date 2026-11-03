"""Branch-sensitive constants and frame slots over an entry-reachable CFG.

Only facts common to every incoming edge survive a join. Frame addresses have
one symbolic entry-stack identity, so disjoint slots can survive stores without
assuming that an unknown pointer cannot alias them. Unknown calls invalidate
all frame facts; a directly called, fully decoded write-free function may
preserve them. An unfinished fixed point never publishes partial facts.
"""
from collections import deque
from dataclasses import dataclass, field
import sys
from types import SimpleNamespace

import capstone
from capstone import x86_const as X


@dataclass(eq=True)
class FrameSnapshot:
    registers: dict = field(default_factory=dict)
    slots: dict = field(default_factory=dict)

    def join(self, other):
        return FrameSnapshot(
            {name: fact for name, fact in self.registers.items()
             if other.registers.get(name) == fact},
            {address: fact for address, fact in self.slots.items()
             if other.slots.get(address) == fact})


@dataclass
class DataflowResult:
    status: str
    inputs: dict
    constants: dict
    steps: int
    reason: str
    diagnostics: list = field(default_factory=list)
    _state_class: object = field(default=None, repr=False)

    def initial_state(self, block):
        """Return a fresh transfer state; unproved block inputs stay arbitrary."""
        return self._state_class(self.inputs.get(block, FrameSnapshot()), block)

    def proof_inputs(self):
        """Serialize converged facts without exposing mutable transfer states."""
        def describe(value):
            return {'kind': value[0], 'value': value[1], 'bits': value[2]}
        return [{'block': block,
                 'registers': {name: describe(value) for name, value in sorted(snapshot.registers.items())},
                 'frame_slots': [{'offset': offset, **describe(value)}
                                 for offset, value in sorted(snapshot.slots.items())]}
                for block, snapshot in sorted(self.inputs.items())
                if snapshot.registers or snapshot.slots]


def function_dataflow(function, state_class, max_steps=None):
    """Compute entry-reaching register/frame facts or return no facts.

    The caller must close missing indirect successors before publishing a
    proof based on entry reachability. This routine only traverses the supplied
    CFG. ``initial_state`` is suitable for the analyzer's suffix replay hook.
    """
    engine = sys.modules.get(state_class.__module__) or SimpleNamespace(**state_class.step.__globals__)
    image = function.image
    bits, word = image.bits, image.bits // 8
    frame = ('var', 'entry-frame:%x' % function.va, bits)
    diagnostics, callee_cache = set(), {}

    def frame_offset(expression):
        if expression[0] == 'sub' and expression[2][0] == 'const':
            previous = frame_offset(expression[1])
            if previous is not None:
                offset = (previous - expression[2][1]) & ((1 << bits) - 1)
                return offset if offset < 1 << (bits - 1) else offset - (1 << bits)
        base, offset = engine._address_parts(expression)
        if base != frame:
            return None
        return offset if offset < 1 << (bits - 1) else offset - (1 << bits)

    def expression(fact):
        if fact[0] == 'constant':
            return engine._const(fact[1], fact[2])
        return engine._binary('add', frame, engine._const(fact[1], bits), bits)

    def fact(value, evaluator):
        offset = frame_offset(value)
        if offset is not None:
            return ('frame', offset, bits)
        try:
            values = evaluator.values(value)
        except (engine.Unresolved, engine.Infeasible, RecursionError):
            return None
        if len(values) == 1:
            return ('constant', next(iter(values)), engine._bits(value))
        return None

    def write_free_callee(target):
        """Prove all reachable instructions of a direct callee cannot store.

        This intentionally small body proof uses emitted bytes, not callee
        names or presumed library effects. Unknown instructions, other calls,
        indirect transfers, stack operations, and incomplete decoding refuse
        the summary. We also require preserved-register compliance explicitly.
        """
        if target in callee_cache:
            return callee_cache[target]
        callee_cache[target] = False
        if target not in function.entries or target == function.va:
            return False
        pending, visited, returned = [target], set(), False
        allowed = {'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea', 'add', 'sub',
                   'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar', 'imul', 'inc',
                   'dec', 'cmp', 'test', 'cdqe', 'cwde', 'cbw', 'nop', 'endbr64',
                   'endbr32'}
        near_branches = {'jmp', 'je', 'jz', 'jne', 'jnz', 'ja', 'jae', 'jb', 'jbe',
                         'jg', 'jge', 'jl', 'jle', 'jo', 'jno', 'js', 'jns', 'jp',
                         'jnp', 'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne'}
        protected = {'rsp', 'rbp', 'rbx', 'r12', 'r13', 'r14', 'r15'} if bits == 64 else {
            'rsp', 'rbp', 'rbx', 'rsi', 'rdi'}
        while pending:
            address = pending.pop()
            if address in visited:
                continue
            if len(visited) >= 256:
                return False
            visited.add(address)
            try:
                available = [end - address for start, end in image.immutable
                             if start <= address < end]
                if not available:
                    return False
                ins = next(image.md.disasm(image.read(address, min(15, max(available)), immutable=True), address, count=1), None)
                if ins is None:
                    return False
                if ins.mnemonic == 'ret' and not ins.operands and not any(ins.prefix):
                    returned = True
                    continue
                if engine._is_branch(ins):
                    if ins.mnemonic not in near_branches:
                        return False
                    if len(ins.operands) != 1 or ins.operands[0].type != X.X86_OP_IMM:
                        return False
                    pending.extend(engine._successors(ins))
                    continue
                if ins.mnemonic not in allowed:
                    return False
                # A destination memory operand is a write for every allowed
                # two-operand instruction except CMP/TEST. Do not rely on
                # Capstone access flags, which differ across supported versions.
                if ins.operands and ins.operands[0].type == X.X86_OP_MEM and ins.mnemonic not in ('cmp', 'test'):
                    return False
                _, written = ins.regs_access()
                if any(engine._ALIASES.get(ins.reg_name(reg), (None,))[0] in protected for reg in written):
                    return False
            except (engine.Unresolved, capstone.CsError, StopIteration):
                return False
            pending.append(ins.address + ins.size)
        callee_cache[target] = returned
        return returned

    class FrameState(state_class):
        def __init__(self, snapshot=None, origin=0):
            super().__init__(image, origin=origin)
            snapshot = snapshot or FrameSnapshot()
            self.regs = {name: expression(value) for name, value in snapshot.registers.items()}
            self.stack = {engine._binary('add', frame, engine._const(offset, bits), bits): expression(value)
                          for offset, value in snapshot.slots.items()}
            self.zero_flags_only = False

        def address(self, ins, operand):
            value = super().address(ins, operand)
            offset = frame_offset(value)
            return expression(('frame', offset, bits)) if offset is not None else value

        def snapshot(self):
            evaluator = engine._Evaluator(image, self.domains)
            registers, slots = {}, {}
            for name, value in self.regs.items():
                value_fact = fact(value, evaluator)
                if value_fact is not None:
                    registers[name] = value_fact
            for address, value in self.stack.items():
                offset, value_fact = frame_offset(address), fact(value, evaluator)
                if offset is not None and value_fact is not None:
                    slots[offset] = value_fact
            return FrameSnapshot(registers, slots)

        def kill(self, ins):
            # Failure to model a computed value need not invalidate memory.
            # These forms have no implicit stores: a segmented source load or
            # an unsupported register rotate can only change registers/flags.
            # Do not infer this from the absence of an explicit memory operand
            # alone (PUSH, string operations and system instructions can store
            # implicitly), nor from optional Capstone operand access flags.
            scalar_destination = {
                'mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea',
                'add', 'sub', 'and', 'or', 'xor', 'shl', 'sal', 'shr', 'sar',
                'rol', 'ror', 'rcl', 'rcr', 'imul', 'inc', 'dec', 'neg', 'not',
                'bsf', 'bsr', 'tzcnt', 'lzcnt', 'popcnt', 'bswap',
            }
            ops = ins.operands
            read_only = (ins.mnemonic in ('cmp', 'test') and len(ops) == 2) or (
                ins.mnemonic in scalar_destination and ops and ops[0].type == X.X86_OP_REG
                and ins.reg_name(ops[0].reg) in engine._ALIASES)
            saved_stack, saved_memory = dict(self.stack), dict(self.memory)
            super().kill(ins)
            if read_only:
                self.stack, self.memory = saved_stack, saved_memory
                if saved_stack:
                    diagnostics.add((ins.address, 'read_only_instruction_preserves_frame_slots'))

        def step(self, ins):
            mnemonic, ops = ins.mnemonic, ins.operands
            if mnemonic in ('movdqu', 'movdqa', 'movups', 'movaps') and len(ops) == 2:
                # SIMD copies do not write flags or GPRs. Track their memory
                # effects even though the copied vector value is unknown.
                if ops[0].type == X.X86_OP_MEM:
                    try:
                        address, size = self.address(ins, ops[0]), ops[0].size
                        self.stack = {old: value for old, value in self.stack.items()
                                      if engine._disjoint(address, size, old, engine._bits(value) // 8)}
                        self.memory = {key: value for key, value in self.memory.items()
                                       if engine._disjoint(address, size, key[0], key[1] // 8)}
                    except (engine.Unresolved, capstone.CsError):
                        self.stack.clear()
                        self.memory.clear()
                return
            if ins.group(capstone.CS_GRP_CALL):
                saved = dict(self.stack)
                stack_pointer = self.regs.get('rsp')
                direct = len(ops) == 1 and ops[0].type == X.X86_OP_IMM
                safe = direct and 0x66 not in ins.prefix and write_free_callee(ops[0].imm)
                super().step(ins)
                self.zero_flags_only = False
                if safe and stack_pointer is not None:
                    call_slot = engine._binary('add', stack_pointer, engine._const(-word, bits), bits)
                    self.stack = {address: value for address, value in saved.items()
                                  if engine._disjoint(call_slot, word, address, engine._bits(value) // 8)}
                    diagnostics.add((ins.address, 'binary_proved_write_free_callee'))
                elif saved:
                    diagnostics.add((ins.address, 'call_invalidates_frame_slots'))
                return
            if mnemonic in ('push', 'pop') and len(ops) == 1 and ops[0].type == X.X86_OP_REG and ops[0].size == word:
                try:
                    pointer = self.regs.get('rsp')
                    if pointer is None or frame_offset(pointer) is None:
                        raise engine.Unresolved('unknown stack pointer')
                    if mnemonic == 'push':
                        value = self.operand(ins, ops[0])
                        pointer = engine._binary('add', pointer, engine._const(-word, bits), bits)
                        self.stack = {address: old for address, old in self.stack.items()
                                      if engine._disjoint(pointer, word, address, engine._bits(old) // 8)}
                        self.stack[pointer] = value
                        self.regs['rsp'] = pointer
                    else:
                        value = self.stack.get(pointer, ('var', '%x:pop' % ins.address, bits))
                        if engine._bits(value) != bits:
                            value = ('var', '%x:partial-pop' % ins.address, bits)
                        self.stack = {address: old for address, old in self.stack.items()
                                      if engine._disjoint(pointer, word, address, engine._bits(old) // 8)}
                        self.regs['rsp'] = engine._binary('add', pointer, engine._const(word, bits), bits)
                        self.assign(ins, ops[0].reg, value)
                    self.memory.clear()
                    return
                except (engine.Unresolved, capstone.CsError):
                    self.kill(ins)
                    return
            if mnemonic == 'leave' and not ops:
                if 0x66 in ins.prefix:
                    self.kill(ins)
                    return
                pointer = self.regs.get('rbp')
                if pointer is None or frame_offset(pointer) is None:
                    self.kill(ins)
                    return
                value = self.stack.get(pointer, ('var', '%x:leave' % ins.address, bits))
                self.regs['rbp'] = value if engine._bits(value) == bits else (
                    'var', '%x:partial-leave' % ins.address, bits)
                self.regs['rsp'] = engine._binary('add', pointer, engine._const(word, bits), bits)
                self.stack = {address: old for address, old in self.stack.items()
                              if engine._disjoint(pointer, word, address, engine._bits(old) // 8)}
                self.memory.clear()
                return
            super().step(ins)
            if mnemonic in ('add', 'sub') and ops and ops[0].type == X.X86_OP_REG:
                name, _, _ = self.alias(ins, ops[0].reg)
                offset = frame_offset(self.regs[name])
                if offset is not None:
                    self.regs[name] = expression(('frame', offset, bits))
            result_flags = mnemonic in ('add', 'sub', 'and', 'or', 'xor', 'inc', 'dec')
            if mnemonic in ('shl', 'sal', 'shr', 'sar') and len(ops) == 2:
                result_flags = ops[1].type == X.X86_OP_IMM and bool(ops[1].imm & (63 if ops[0].size == 8 else 31))
            if result_flags and ops and ops[0].type == X.X86_OP_REG:
                # Equality after arithmetic tests the result. Other conditions
                # also depend on carry/overflow and must retain no such claim.
                value = self.register(ins, ops[0].reg)
                self.flags = (value, engine._const(0, engine._bits(value)), ins.address)
                self.zero_flags_only = True
            elif mnemonic in ('cmp', 'test'):
                self.zero_flags_only = False

        def branch(self, ins, successor):
            if self.zero_flags_only and ins.mnemonic not in ('je', 'jz', 'jne', 'jnz'):
                return
            super().branch(ins, successor)

    def failed(reason, steps=0):
        return DataflowResult('unresolved', {}, {}, steps, reason,
                              [{'instruction': address, 'effect': effect}
                               for address, effect in sorted(diagnostics)], FrameState)

    if function.invalid or function.va not in function.blocks:
        return failed('entry-reaching frame proof requires complete function metadata')
    if function.handwritten or getattr(function, 'external_entries', ()) or any(
            entry != function.va and entry in function.instructions for entry in function.entries):
        return failed('entry-reaching frame proof requires a single compiler function entry')
    inputs = {function.va: FrameSnapshot({'rsp': ('frame', 0, bits)})}
    edge_outputs, queue, queued = {}, deque([function.va]), {function.va}
    limit = max_steps if max_steps is not None else max(100, len(function.blocks) * 32)
    steps = 0
    while queue:
        if steps >= limit:
            return failed('frame dataflow fixed point exceeded its budget', steps)
        start = queue.popleft()
        queued.discard(start)
        steps += 1
        state = FrameState(inputs[start], start)
        for ins in function.blocks[start]:
            state.step(ins)
        for successor in function.succs[start]:
            # Restore the full transient expression state for each branch;
            # expressions sharing a spilled value retain their identity until
            # the branch predicate is converted into edge constants.
            edge = FrameState(origin=start)
            edge.regs, edge.stack, edge.memory = dict(state.regs), dict(state.stack), dict(state.memory)
            edge.flags, edge.zero_flags_only = state.flags, state.zero_flags_only
            edge.domains.ranges = dict(state.domains.ranges)
            edge.domains.guards = list(state.domains.guards)
            try:
                edge.branch(function.blocks[start][-1], successor)
                snapshot = edge.snapshot()
            except engine.Infeasible:
                continue
            if edge_outputs.get((start, successor)) == snapshot:
                continue
            edge_outputs[start, successor] = snapshot
            merged = snapshot if successor not in inputs else inputs[successor].join(snapshot)
            if successor not in inputs or inputs[successor] != merged:
                inputs[successor] = merged
                if successor not in queued:
                    queue.append(successor)
                    queued.add(successor)
    constants = {start: {name: value[1] for name, value in snapshot.registers.items()
                         if value[0] == 'constant'} for start, snapshot in inputs.items()}
    return DataflowResult('converged', inputs, constants, steps,
                          'all entry-reaching frame facts reached a fixed point',
                          [{'instruction': address, 'effect': effect}
                           for address, effect in sorted(diagnostics)], FrameState)
