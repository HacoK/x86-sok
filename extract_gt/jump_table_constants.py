"""Prove register constants at dispatches despite omitted switch CFG edges."""
from collections import defaultdict, deque
from bisect import bisect_left

import capstone
from capstone import x86_const as X


def entry_region_constants(function, state_class, const, is_branch, max_steps=None):
    """Return constants shared by every first indirect jump from the entry.

    Follow direct edges until an indirect jump or exit. Unknown inputs remain
    unknown, incoming states are intersected, and an unfinished fixed point
    yields no facts. The dependency arguments are the analyzer's transfer
    functions; keeping them explicit avoids importing its private classes.

    Additional checks prove preservation after a dispatch, including reentry
    into the initialization region. This is deliberately a function-wide
    invariant: different constants at two first dispatches cannot be merged.
    """
    if function.invalid or function.handwritten or function.va not in function.blocks:
        return {}
    if any(entry != function.va and entry in function.instructions
           for entry in function.entries):
        return {}

    image = function.image
    instructions = function.instructions
    minimum, maximum = min(instructions), max(instructions)
    instruction_addresses = sorted(instructions)
    limit = max_steps if max_steps is not None else max(100, len(function.blocks) * 32)
    inputs, outputs = {function.va: {}}, {}
    queue = deque([function.va])
    frontiers, region, predecessors = set(), set(), defaultdict(set)
    steps = 0

    def indirect(ins):
        return is_branch(ins) and (not ins.operands or ins.operands[0].type != X.X86_OP_IMM)

    def exits(ins):
        return (ins.group(capstone.CS_GRP_RET) or ins.mnemonic in ('ud2', 'hlt')
                or ins.address in function.nonreturn)

    def bridge_padding(target):
        if target in function.blocks or not minimum <= target <= maximum:
            return target
        index = bisect_left(instruction_addresses, target)
        following = instruction_addresses[index]
        if following == target or following not in function.blocks or following - target > 64:
            return None
        # Compiler metadata excludes alignment NOPs from block instructions.
        # Verify every omitted byte rather than treating an address gap as an
        # edge or allowing a missing state-changing instruction to disappear.
        try:
            padding = image.read(target, following - target)
            decoded = list(image.md.disasm(padding, target))
        except Exception:
            return None
        if not decoded or sum(ins.size for ins in decoded) != len(padding):
            return None
        for ins in decoded:
            if ins.mnemonic == 'nop':
                continue
            return None
        return following

    while queue:
        if steps >= limit:
            return {}
        steps += 1
        start = queue.popleft()
        chunk = function.blocks[start]
        state = state_class(image, inputs[start], start)
        for index, ins in enumerate(chunk):
            region.add(ins.address)
            if index:
                predecessors[ins.address].add(chunk[index - 1].address)
            state.step(ins)
        values = {reg: expr[1] for reg, expr in state.regs.items()
                  if expr[0] == 'const' and reg != 'rsp'}
        last = chunk[-1]
        if indirect(last):
            frontiers.add(start)
            outputs[start] = values
            continue
        if exits(last):
            outputs[start] = values
            continue

        # A missing local instruction can hide another first dispatch. Never
        # turn that incomplete path into a proof by silently dropping it.
        if hasattr(function, 'direct_successors'):
            targets = function.direct_successors(last)
        else:
            targets = ([last.operands[0].imm] +
                       ([] if last.mnemonic == 'jmp' else [last.address + last.size])
                       if is_branch(last) else [last.address + last.size])
        targets = [bridge_padding(target) for target in targets]
        for target in targets:
            if target is None:
                return {}
        successors = [target for target in targets if target in function.blocks]
        for successor in successors:
            predecessors[successor].add(last.address)
        if outputs.get(start) == values:
            continue
        outputs[start] = values
        for successor in successors:
            merged = dict(values) if successor not in inputs else {
                reg: value for reg, value in inputs[successor].items()
                if values.get(reg) == value}
            if successor not in inputs or inputs[successor] != merged:
                inputs[successor] = merged
                queue.append(successor)

    if not frontiers:
        return {}
    frontier_states = [outputs[start] for start in sorted(frontiers)]
    candidates = dict(frontier_states[0])
    for values in frontier_states[1:]:
        candidates = {reg: value for reg, value in candidates.items()
                      if values.get(reg) == value}

    def returns_without_branch(ins):
        address = ins.address + ins.size
        for _ in range(16):
            following = instructions.get(address)
            if following is None:
                return False
            if following.group(capstone.CS_GRP_RET):
                return True
            if is_branch(following) or following.group(capstone.CS_GRP_CALL):
                return False
            address += following.size
        return False

    def preserves(ins, reg, value):
        state = state_class(image, {reg: value}, ins.address)
        state.step(ins)
        return state.regs.get(reg) == const(value, image.bits)

    for reg, value in list(candidates.items()):
        # Unknown switch targets may reenter the initialization region. Walk
        # backwards from its frontiers and stop only at a reset independent of
        # incoming state. Every intervening instruction must preserve the value.
        pending = [function.blocks[start][-1].address for start in frontiers]
        checked, valid = set(), True
        while pending and valid:
            address = pending.pop()
            if address in checked:
                continue
            checked.add(address)
            ins = instructions[address]
            state = state_class(image, origin=address)
            state.step(ins)
            if state.regs.get(reg) == const(value, image.bits):
                continue
            if not preserves(ins, reg, value):
                valid = False
                break
            pending.extend(predecessors[address])
        if valid:
            for address, ins in instructions.items():
                if address in region:
                    continue
                if not preserves(ins, reg, value) and not returns_without_branch(ins):
                    valid = False
                    break
        if not valid:
            del candidates[reg]
    return candidates
