"""Close an entry-reachable CFG before publishing local table-base proofs.

Disconnected switch cases cannot be assigned guessed register values. Instead
start at the declared entry, replay reachable dispatches, add their proved
edges, and repeat. A result is publishable only when all reachable indirect
frontiers are covered and every proof has been rechecked against the final
incoming states. Register constants are specific to each program point.
"""
from collections import defaultdict, deque
from copy import copy, deepcopy


def entry_reaching_constants(function, state_class, max_steps=None):
    """Meet constant registers over all entry-reachable paths to a fixed point.

    A missing register denotes an arbitrary value; an absent block state
    denotes an unreachable block. These are intentionally different lattice
    elements. A loop cannot introduce a fact into the arbitrary entry state.
    """
    if function.va not in function.blocks:
        return None, 0
    inputs, outputs = {function.va: {}}, {}
    queue = deque([function.va])
    limit = max_steps if max_steps is not None else max(100, len(function.blocks) * 32)
    steps = 0
    while queue:
        if steps >= limit:
            return None, steps
        steps += 1
        start = queue.popleft()
        state = state_class(function.image, inputs[start], start)
        for instruction in function.blocks[start]:
            state.step(instruction)
        values = {reg: expr[1] for reg, expr in state.regs.items() if expr[0] == 'const'}
        if outputs.get(start) == values:
            continue
        outputs[start] = values
        for successor in function.succs[start]:
            joined = dict(values) if successor not in inputs else {
                reg: value for reg, value in inputs[successor].items()
                if values.get(reg) == value}
            if successor not in inputs or joined != inputs[successor]:
                inputs[successor] = joined
                queue.append(successor)
    return inputs, steps


def recover_reaching_tables(function, analyze_site, state_class, indirect,
                            unresolved_error, max_rounds=32, max_steps=None,
                            dataflow=None):
    """Return closed-CFG records, or no records when the proof is incomplete.

    ``function`` is an analyzer _Function constructed from original metadata.
    Its existing indirect successors are trusted conservative CFG edges, as in
    the ordinary analyzer; speculative discoveries must not be passed as that
    original metadata. ``analyze_site(view, site)`` must replay immutable table
    bytes and account for all paths in ``view.preds``. The view's
    ``constant_inputs()`` returns the converged entry-reaching register facts.
    An optional ``dataflow(function, state_class, max_steps=...)`` may supply
    richer snapshots. Its converged result provides ``inputs``, ``constants``,
    ``steps`` and ``initial_state(block)``; the site callback must use that
    initializer to replay suffixes without losing the extra proved facts.
    Its optional ``proof_inputs()`` supplies serializable input snapshots.

    The function is not mutated. Provisional edges support exploration only;
    failed closure, a changed proof, or an exhausted budget emits no records.
    """
    diagnostics, replay_failures = [], []

    def failure(reason, frontiers=()):
        return {'status': 'unresolved', 'reason': reason, 'records': [],
                'unresolved_frontiers': list(frontiers),
                'replay_failures': list(replay_failures),
                'dataflow_diagnostics': list(diagnostics)}

    if function.invalid or function.handwritten or function.va not in function.blocks:
        return failure('entry-reaching proof requires complete compiler function metadata')
    if getattr(function, 'external_entries', ()) or any(
            address != function.va and address in function.instructions for address in function.entries):
        return failure('entry-reaching proof does not allow additional function entries')

    view = copy(function)
    view.instructions = dict(function.instructions)
    view.known_edges = defaultdict(set, {site: set(targets)
                                       for site, targets in function.known_edges.items()})
    original_edges = {site: set(targets) for site, targets in function.known_edges.items()
                      if targets and site in function.instructions
                      and indirect(function.instructions[site])
                      and all(target in function.instructions or target in function.entries
                              for target in targets)}
    total_steps = 0
    for iteration in range(1, max_rounds + 1):
        view.rebuild_graph()
        if view.invalid:
            return failure('recovered CFG contains an invalid local edge')
        flow = None
        if dataflow is None:
            view.__dict__.pop('initial_state', None)
            inputs, steps = entry_reaching_constants(view, state_class, max_steps)
        else:
            flow = dataflow(view, state_class, max_steps=max_steps)
            diagnostics = list(flow.diagnostics)
            steps = flow.steps
            inputs = ({block: flow.constants.get(block, {}) for block in flow.inputs}
                      if flow.status == 'converged' else None)
            if inputs is not None:
                view.initial_state = flow.initial_state
        total_steps += steps
        if inputs is None:
            return failure(flow.reason if flow is not None else
                           'entry-reaching constant fixed point exceeded its budget')
        reachable = set(inputs)
        # _Function.paths uses this restricted predecessor relation. It still
        # retains every predecessor reachable through the current CFG, while
        # newly decoded edges trigger a full recomputation in the next round.
        view.preds = defaultdict(set, {
            block: {pred for pred in predecessors if pred in reachable}
            for block, predecessors in view.preds.items() if block in reachable})
        view.constants = inputs
        sites = sorted(view.blocks[block][-1].address for block in reachable
                       if indirect(view.blocks[block][-1]))
        records, pending, additions, replay_failures = [], [], {}, []
        for site in sites:
            try:
                record = analyze_site(view, site)
            except (unresolved_error, RecursionError) as error:
                replay_failure = {'site': site, 'reason': str(error) or 'expression depth exceeded'}
                replay_failures.append(replay_failure)
                if site not in original_edges:
                    pending.append(replay_failure)
                continue
            if record.get('status') != 'resolved' or not record.get('targets'):
                replay_failure = {'site': site, 'reason': record.get('reason') or
                                  'table replay did not produce successors'}
                replay_failures.append(replay_failure)
                if site not in original_edges:
                    pending.append(replay_failure)
                continue
            records.append(record)
            new = set(record['targets']) - view.known_edges[site]
            if new:
                additions[site] = new
        if additions:
            for site, targets in additions.items():
                view.known_edges[site].update(targets)
            continue
        if pending:
            return failure('reachable indirect frontier lacks a complete successor proof', pending)

        # Every reachable indirect transfer now has a conservative successor
        # set. By induction from the entry, no omitted disconnected case can
        # add an incoming state to this final graph. All records above were
        # replayed against that same graph and its converged states.
        proof = {
            'scope': 'entry_reachable_closed_cfg', 'entry': function.va,
            'iterations': iteration, 'dataflow_steps': total_steps,
            'reachable_blocks': sorted(reachable),
            'indirect_successors': [
                {'site': site, 'targets': sorted(view.known_edges[site]),
                 'source': 'metadata_and_replayed_bytes' if site in original_edges else 'replayed_bytes'}
                for site in sites],
            'constant_inputs': [
                {'block': block, 'registers': inputs[block]} for block in sorted(reachable)
                if inputs[block]],
            'limits': {'rounds': max_rounds, 'dataflow_steps_per_round':
                       max_steps if max_steps is not None else max(100, len(view.blocks) * 32)},
        }
        if flow is not None:
            proof['dataflow_diagnostics'] = list(diagnostics)
            if hasattr(flow, 'proof_inputs'):
                proof['frame_inputs'] = flow.proof_inputs()
        proof['replay_failures'] = list(replay_failures)
        for record in records:
            record['evidence'] = deepcopy(record.get('evidence', {}))
            record['evidence']['reaching_definitions'] = proof
        return {'status': 'closed', 'reason': 'every entry-reachable indirect frontier is covered',
                'records': records, 'proof': proof, 'unresolved_frontiers': [],
                'replay_failures': list(replay_failures),
                'dataflow_diagnostics': list(diagnostics)}
    return failure('indirect-frontier closure exceeded its iteration budget')
