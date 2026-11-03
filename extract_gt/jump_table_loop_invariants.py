"""Conditional finite-state proofs for selectors seeded by a data load.

The supplied values are an assumption about every execution of the seed load.
This module proves the emitted CFG's transfers and joins under that assumption;
it does not prove the source memory is immutable or the table index is valid.
"""
from collections import deque
import sys
from types import SimpleNamespace

import capstone
from capstone import x86_const as X


def prove_seeded_selector_loop(function, site, load_address, seed_values,
                               state_class, state_register=None, max_values=4096, max_steps=None):
    """Propagate finite register sets over every entry-reachable CFG edge.

    Unknown values are top; an absent block is unreachable. Joins union known
    values and discard a register when any incoming value is unknown. Existing
    indirect successors must cover every reachable indirect transfer. The
    result is conditional on valid, stable values at ``load_address`` and the
    same x86 call ABI used by the ordinary analyzer.
    """
    engine = sys.modules.get(state_class.__module__) or SimpleNamespace(**state_class.step.__globals__)
    bits = function.image.bits
    seed = function.instructions.get(load_address)
    jump = function.instructions.get(site)
    steps, dropped = 0, 0

    def failure(reason):
        return {'status': 'unresolved', 'proved': False, 'reason': reason,
                'steps': steps, 'seed_load': load_address, 'site': site}

    if (function.invalid or function.handwritten or function.va not in function.blocks
            or getattr(function, 'external_entries', ())
            or any(address != function.va and address in function.instructions
                   for address in function.entries)):
        return failure('loop proof requires complete single-entry compiler function metadata')
    if (seed is None or seed.mnemonic != 'mov' or len(seed.operands) != 2
            or seed.operands[0].type != X.X86_OP_REG or seed.operands[1].type != X.X86_OP_MEM):
        return failure('loop seed is not a decoded memory-to-register load')
    if (jump is None or not engine._indirect(jump) or jump.operands[0].type != X.X86_OP_MEM
            or not jump.operands[0].mem.index):
        return failure('loop selector is not an indexed indirect memory jump')
    seed_width = seed.operands[1].size * 8
    tracked = {engine._ALIASES.get(seed.reg_name(seed.operands[0].reg), (None,))[0],
               engine._ALIASES.get(jump.reg_name(jump.operands[0].mem.index), (None,))[0]}
    if state_register is not None:
        tracked.add(state_register)
    tracked.discard(None)
    values = frozenset(seed_values)
    if (not values or len(values) > max_values
            or any(type(value) is not int or not 0 <= value < 1 << seed_width for value in values)):
        return failure('invalid or excessive seed value domain')

    def intervals(numbers):
        result = []
        for number in sorted(numbers):
            if result and result[-1][1] + 1 == number:
                result[-1] = (result[-1][0], number)
            else:
                result.append((number, number))
        return result

    class LoopState(state_class):
        def __init__(self, incoming, origin):
            super().__init__(function.image, origin=origin)
            self.zero_flags_only = False
            for register, domain in incoming.items():
                if len(domain) == 1:
                    self.regs[register] = engine._const(next(iter(domain)), bits)
                else:
                    expression = ('var', 'loop-input:%x:%s' % (origin, register), bits)
                    self.regs[register] = expression
                    self.domains.ranges[expression] = intervals(domain)

        def step(self, instruction):
            if instruction.address == load_address:
                expression = ('var', 'conditional-seed:%x' % load_address, seed_width)
                self.domains.ranges[expression] = intervals(values)
                self.assign(instruction, instruction.operands[0].reg, expression)
                return
            super().step(instruction)
            operands, mnemonic = instruction.operands, instruction.mnemonic
            arithmetic_flags = mnemonic in ('add', 'sub', 'and', 'or', 'xor', 'inc', 'dec')
            if mnemonic in ('shl', 'sal', 'shr', 'sar') and len(operands) == 2:
                arithmetic_flags = (operands[1].type == X.X86_OP_IMM
                                    and bool(operands[1].imm & (63 if operands[0].size == 8 else 31)))
            if arithmetic_flags and operands and operands[0].type == X.X86_OP_REG:
                value = self.register(instruction, operands[0].reg)
                self.flags = (value, engine._const(0, engine._bits(value)), instruction.address)
                self.zero_flags_only = True
            elif mnemonic in ('cmp', 'test') or instruction.group(capstone.CS_GRP_CALL):
                self.zero_flags_only = False

        def branch(self, instruction, successor):
            if self.zero_flags_only and instruction.mnemonic not in ('je', 'jz', 'jne', 'jnz'):
                return
            super().branch(instruction, successor)
            # A guard on EBP must constrain the finite incoming RBP values.
            # Project a one-variable expression by enumerating that variable's
            # existing finite domain. No relation between distinct variables
            # is invented, and unbounded/unsupported projections retain top.
            def variables(expression):
                if expression[0] == 'var':
                    return {expression}
                return {value for item in expression[1:] if isinstance(item, tuple)
                        for value in variables(item)}

            def replace(expression, variable, value):
                if expression == variable:
                    return engine._const(value, engine._bits(variable))
                return tuple(replace(item, variable, value) if isinstance(item, tuple) else item
                             for item in expression)

            for guarded in list(self.domains.ranges):
                names = variables(guarded)
                if len(names) != 1 or guarded[0] == 'var':
                    continue
                variable = next(iter(names))
                domain = self.domains.finite(variable)
                if domain is None:
                    continue
                allowed = set()
                for value in domain:
                    try:
                        outcomes = engine._Evaluator(function.image, engine._Domains()).values(
                            replace(guarded, variable, value))
                    except (engine.Unresolved, engine.Infeasible, RecursionError):
                        allowed.add(value)
                        continue
                    if any(self.domains.contains(guarded, result) for result in outcomes):
                        allowed.add(value)
                if not allowed:
                    raise engine.Infeasible()
                self.domains.ranges[variable] = intervals(allowed)

        def snapshot(self):
            result = {}
            evaluator = engine._Evaluator(function.image, self.domains)
            for register, expression in self.regs.items():
                if register not in tracked:
                    continue
                try:
                    domain = frozenset(evaluator.values(expression))
                except (engine.Unresolved, engine.Infeasible, RecursionError):
                    continue
                if domain and len(domain) <= max_values:
                    result[register] = domain
            return result

    inputs = {function.va: {}}
    queue, queued = deque([function.va]), {function.va}
    limit = max_steps if max_steps is not None else max(100, len(function.blocks) * 128)
    while queue:
        if steps >= limit:
            return failure('conditional loop fixed point exceeded its step budget')
        block = queue.popleft()
        queued.discard(block)
        steps += 1
        state = LoopState(inputs[block], block)
        for instruction in function.blocks[block]:
            state.step(instruction)
        last = function.blocks[block][-1]
        if engine._indirect(last):
            successors = function.known_edges[last.address]
            if not successors or any(target not in function.instructions and target not in function.entries
                                     for target in successors):
                return failure('reachable indirect transfer has no conservative successor coverage')
        for successor in function.succs[block]:
            edge = LoopState({}, block)
            edge.regs, edge.stack, edge.memory = dict(state.regs), dict(state.stack), dict(state.memory)
            edge.flags, edge.zero_flags_only = state.flags, state.zero_flags_only
            edge.domains.ranges = dict(state.domains.ranges)
            edge.domains.guards = list(state.domains.guards)
            try:
                edge.branch(last, successor)
                outgoing = edge.snapshot()
            except engine.Infeasible:
                continue
            if successor not in inputs:
                merged = outgoing
            else:
                merged = {}
                for register in inputs[successor].keys() & outgoing.keys():
                    domain = inputs[successor][register] | outgoing[register]
                    if len(domain) <= max_values:
                        merged[register] = domain
                    else:
                        dropped += 1
            if successor not in inputs or merged != inputs[successor]:
                inputs[successor] = merged
                if successor not in queued:
                    queue.append(successor)
                    queued.add(successor)

    block = function.owner[site]
    if block not in inputs:
        return failure('requested selector is not entry-reachable under the seed assumption')
    state = LoopState(inputs[block], block)
    for instruction in function.blocks[block]:
        if instruction.address == site:
            break
        state.step(instruction)
    try:
        selectors = sorted(engine._Evaluator(function.image, state.domains).values(
            state.register(jump, jump.operands[0].mem.index)))
    except (engine.Unresolved, engine.Infeasible, RecursionError):
        return failure('selector remains unbounded after conditional loop convergence')
    return {'status': 'proved_conditional_loop', 'proved': True,
            'scope': 'machine_cfg_under_seed_load_assumption', 'site': site,
            'seed_load': load_address, 'seed_value_count': len(values), 'seed_values': sorted(values),
            'selectors': selectors,
            'steps': steps, 'reachable_blocks': sorted(inputs), 'dropped_domains': dropped,
            'tracked_registers': sorted(tracked),
            'indirect_successors': [{'site': function.blocks[block][-1].address,
                                     'targets': sorted(function.known_edges[function.blocks[block][-1].address])}
                                    for block in sorted(inputs) if engine._indirect(function.blocks[block][-1])],
            'assumptions': ['every seed load is in bounds and returns a supplied value',
                            'recorded indirect successors cover every reachable indirect transfer',
                            'calls obey the modeled x86 ABI'],
            'limits': {'steps': limit, 'values': max_values},
            'selector_block_inputs': {register: sorted(domain) for register, domain in sorted(inputs[block].items())}}
