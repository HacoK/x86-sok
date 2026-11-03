# Jump-table ground truth

See the [validation results](JUMP_TABLE_VALIDATION.md) for regression coverage,
corpus replay and additional refinements beyond the supplied repair list.

The x86 ELF extractor now refines physical table entries using the instructions
and incoming CFG paths at each indirect jump. It also examines unmarked jumps,
so recovery does not require a compiler `numJTEntries` annotation or a
handwritten-assembly region. It supports absolute and signed relative tables,
finite masks, conditional bounds and equality holes, register aliases, and
selector-table lookups followed by offset-table lookups.

```sh
python3 extract_gt/extractBB.py -b program -m program.gt -o gtBlock_program.pb
```

The output includes `gtBlock_program.pb.jumptables.json`. This records binary,
metadata, generator-source and output protobuf hashes, old/new successors, the action at each
site, and the inspected paths, guards and table bytes. Keep this sidecar with
the protobuf. A binary hash mismatch means a selector certificate cannot be
reused; a protobuf hash mismatch means the sidecar does not describe that GT.

Use a Python environment with `capstone`, `pyelftools` and `protobuf` installed.
The checked-in protobuf bindings predate current protobuf releases. With a
modern runtime, set `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python`, or use a
compatible older protobuf runtime.

## Regeneration and analysis modes

Regenerate stale corpus protobufs from their original binary and raw `.gt`
metadata. Revisiting just the existing protobuf cannot recover instruction or
function metadata missing from that snapshot. To refine an existing protobuf
that already contains the relevant instructions:

```sh
python3 extract_gt/jump_table_gt.py \
  -b program -g old_gtBlock_program.pb -o new_gtBlock_program.pb
```

By default, resolved sites replace their children with unique decoded targets;
previously unmarked sites become type 7. Unresolved existing type-7 rows retain
their physical children and receive `preserved_physical_table` in the sidecar.
Unresolved indirect jumps are not promoted.

`--require-resolved-jump-tables` rejects generation if an existing type-7 row
has no selector evidence. It leaves previous output files intact. This flag
checks the existing table rows; it does not assert that every unresolved
indirect jump is or is not a jump table. `--jump-table-report PATH` chooses the
sidecar path. For comparison with physical-entry extraction,
`extractBB.py --disable-jump-table-analysis` disables this refinement pass.
The existing `--disable-postaa` flag disables both the legacy gap/handwritten
passes and this refinement. ARM and MIPS retain their existing extraction paths.

## Meaning and limits of selector evidence

An automatic `resolved` status means finite table replay covers every incoming suffix in the
decoded local CFG. It is a local upper bound on successors, not a proof of
whole-program input reachability. Unknown prefixes begin with unconstrained
registers. A bound on path length, expression size or selector cardinality
must not silently discard a path or table entry. Unsupported operations kill
dependent information; incomplete decoding or invalid targets prevent recovery.
Table bytes must be immutable and file-backed, and targets must be local
instruction boundaries rather than function entries. This prevents bounded
static function-pointer dispatch from being promoted as switch-only GT.

The analysis does not infer arbitrary caller, wrapper or mutable-data
invariants. For example, the local `Perl_ck_fun` mask admits `0..7`. The
source-validated GT instead uses the 352 initialized `PL_opargs` values, the
verified shift loop, and an explicit defined-C contract. Source validation and
automatic binary analysis are reported separately. Packed selectors derived
from writable global tables still receive index, data-stability,
pointer-escape and loop obligations. Initial-byte enumeration alone remains
conditional evidence. A finite-state pass proves the emitted loop transfers;
the source audit establishes the valid input and linked-build data-stability
contract. A failed automatic obligation leaves `binary_analysis` unresolved
even when a source certificate supplies the GT row.

For regional table bases, entry-reaching register facts are propagated to a
fixed point. Reachable table jumps supply byte-replayed successors; the
analysis then recomputes and rechecks every frontier. Results are published
only after the reachable CFG closes. This handles reused table-base registers
without assuming one constant throughout the function. Its sidecar records
the converged per-block constants and successor evidence. Existing incomplete CFG metadata and unknown
indirect control flow also limit what local analysis can establish. Inspect
the sidecar when using the output as a strict evaluation oracle.

The fallback also tracks frame addresses and spills to a fixed point. Calls
invalidate memory facts unless a decoded callee proves the necessary memory
effects. Unsupported register-only arithmetic and segmented reads preserve
memory facts while their computed register values remain unknown; memory
writes and special-register effects remain conservative. Adaptive suffix exploration stops a branch once a complete proof
covers its unknown prefix, which avoids spending the path budget on irrelevant
history in shared dispatches. Unknown paths and unfinished fixed points still
fail closed.

## Source-assisted proofs

Pass `--source-build-manifest source_builds/gt_six_builds.json` to run binary
analysis, ask the source provider for only the missing obligations, validate
those facts against the original ELF/DWARF, and repeat the affected site
analysis. The manifest selects a build by complete-binary SHA-256 and records
source files, preprocessing definitions, compilation commands and linked
inputs; it contains no jump addresses or selector lists.

For a computed goto, source analysis must bind every contributing relative
table and its fallback expression to DWARF labels and original table bytes.
For writable selector data, source analysis discharges bounds, stability and
escape premises, while the binary proof still supplies loop transfer and
replays selectors through its immutable terminal target table. An undischarged
fact leaves the site unresolved.

Resolved rows carry `proof_mode: binary_only` or
`combined_binary_source`. The protobuf and JSON sidecar are staged together;
the sidecar records the source/build binding, initial binary obligations,
combined obligation statuses and every replayed table.

Legacy `--jump-table-certificates` remains available for compatibility, but
those manifests are human-audited overrides rather than reproducible
source-assisted proofs.

## Audited selector domains

Both entry points accept `--jump-table-certificates audit.json`. A certificate
binds the table association and feasible selector values to a reviewed source
or binary audit.
The generator validates the binary hash, indirect-jump site, table reads and
local instruction targets, then decodes the actual bytes. It does not verify
the cited source audit or prove the asserted table-to-jump association.

```json
{
  "schema_version": 2,
  "binary_sha256": "SHA256_OF_THE_COMPLETE_BINARY",
  "sites": [{
    "site": "0x401020",
    "switch_only": true,
    "evidence_kind": "source_invariant",
    "source_contract": ["GT covers defined matching-source executions only"],
    "tables": [{
      "table_address": "0x402000",
      "entry_size": 4,
      "entry_encoding": "signed_relative",
      "relative_base": "0x402000",
      "selector_values": [1, 2, 3, 4, 5, 6, 7]
    }],
    "evidence": "path/to/source-and-binary-audit.md#selector-proof"
  }]
}
```

`absolute` encoding omits `relative_base`. Signed relative entries can use a
code base different from the table address. Schema 2 permits up to 64 tables
per site and requires an explicit `source_contract` for source certificates;
schema 1 remains accepted for one-table manifests. Certificates override local
analysis in the GT row, retaining it under `binary_analysis`. They contain
selector values, not a copied successor list. Duplicate sites, stale hashes,
invalid selectors, writable jump tables and nonlocal targets are rejected
before output is replaced.

Source-dependent Perl corrections from the supplied report are available as
[audited certificates](certificates/README.md), bound to the original
non-stripped binaries. The eight formerly certified V8 associations and two
Os formatter sites are now proved automatically; their manifests have been
removed. The Os sets contain 31 targets each: their former 30-target
certificates omitted a later parsing-stage target sharing the same jump.
The corrected O1 certificate lists all six stage tables. Each site has 31
source-validated targets, including the missing `hh` handler and the offset-zero
`form_unknown` fallback. The automatic analyzer remains unresolved for those
two sites. Four Perl certificates use the source-initializer, loop and closed-
build stability audit; their automatic binary analysis also remains unresolved.

Certificates can set `evidence_kind` to `binary_audit`; the default is
`source_invariant`. Source certificate rows include `validation_status`,
`source_contract` and the decoded per-table targets. The top-level sidecar
uses `local_cfg_selector_domain_with_audited_overrides` when explicit evidence
is used.

## Regression checks

```sh
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
  python3 -m unittest discover -s tests -v
```

Tests assemble real ELF fixtures for selector bounds, holes, masks, sparse
two-stage tables, signed offsets and unsupported paths. Additional regressions
cover shared references, stale conditional-fallthrough metadata, taint-state
joins, x86 aliases/spills, certificate validation and artifact write failures.
Metadata splitting is also checked: original block counts delimit input
functions, while expanded counts assign the output blocks. Mixing these counts
previously shifted later blocks into the wrong functions.
The x86 comparison scripts now require exact successor address sets, including
equal-cardinality substitutions and extra-target errors.

The handwritten-range builder is intentionally unchanged: the root-cause
report demonstrated that changing its range assignment alone alters 29
previously matching child sets. Shared-table references are instead partitioned
without consuming candidates, and conditional association edges are recovered
from decoded instructions.
