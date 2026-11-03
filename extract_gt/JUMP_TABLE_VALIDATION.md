# Jump-table generation validation

Validated against the supplied root-cause report and its frozen 372-row
`frozen_gt_repair_diff.csv`. Dataset binaries and oracle protobufs were read
only. Generated protobufs and sidecars are under `/tmp`; durable evidence is
under `/mnt/nvme1/sba/reports`.

## Regression suite

```sh
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
  python3.12 -m unittest discover -s tests -q
```

All **188 tests pass**. Python compilation and whitespace checks pass
(`git -c core.whitespace=cr-at-eol diff --check`). Coverage includes real ELF
fixtures, regional register reuse, CFG closure and changed backedges, fixed
points and budgets, spills and aliasing stores, call effects, partial-width
stack loads, arithmetic flags, adaptive shared-suffix analysis, writable-data
obligations, exact target comparison and output rollback.

## Status of the 16 previously manual entries

| Group | Automatic binary result | GT evidence |
| --- | --- | --- |
| 8 V8 sites | All eight match the audited target sets without certificates. | Automatic; O3/Of require corrected raw-metadata ownership. |
| 2 libc Os sites | Both resolve to 31 targets. | Automatic; the earlier 30-target certificates omitted `hh`. |
| 2 libc O1 sites | Unresolved at the fallback spill. | Source-validated at 31 using all six stage tables and offset-zero `form_unknown`. |
| 4 Perl sites | Unresolved; eight physical targets preserved. | Source-validated at seven under the defined-C and closed-build data-stability contract. |

All 16 original entries now have accepted GT evidence: **10 are automatic**
and **six are source-validated**. The six source cases still fail automatic
binary analysis, and their sidecars retain that status under `binary_analysis`.
The old incomplete 30-target libc certificates are not restored.

Perl's initialized-data observation is independently confirmed: all 352
`PL_opargs` entries in each original binary produce only selectors 1..7 after
`>> 13`, then repeated `>> 4` while nonzero. This needs no wrapper filtering.
The new finite-state CFG pass verifies all loop transfers and joins. Under the
defined-C contract, out-of-bounds `PL_opargs[type]` execution is excluded as
undefined behavior, so the binary-local 16-bit domain does not invalidate the
source GT. The source has 28 read uses and no write or getter caller. Scanning
all 6,947 sized function symbols decoded 899,205 instructions with no
undecoded function body: all 94 `PL_opargs` references are reads, and there is
no getter reference or stored table/getter pointer. SPEC disables dynamic
loading, and the original fixed-address executables export or import no table
alias. The table therefore remains at its initial 352 values in defined closed
executions. Sidecars still retain every failed automatic obligation.

Unicorn replay of the original bytes reaches selector zero with synthetic
out-of-range indices 352/1072/630/630 for O1/O2/O3/Of, before any call. These
are not source-valid Perl executions and do not refute its seven-target
oracle; they show that function-local assumptions alone cannot prove the
required bounds. The defined-C contract excludes these executions.

## Current corpus replay without certificates

All four libc builds were regenerated from their original binaries and raw
`.gt` metadata. The other 37 report sites use complete containing-function
fixtures plus the other function-entry addresses; V8 O3/Of use corrected raw
reconstruction. This is not a whole-corpus extraction for those 19 binaries.

| Libc build | Generated type-7 sites | Report sites | Sets equal to the prior repaired oracle | Automatically resolved report sites |
| --- | ---: | ---: | ---: | ---: |
| GCC O1 | 340 | 274 | 268 | 7 |
| GCC O2 | 362 | 29 | 29 | 28 |
| GCC O3 | 368 | 26 | 26 | 25 |
| GCC Os | 305 | 6 | 4 | 5 |

Across the 372 report rows, **360 target sets match** the prior repaired
oracle. **98 sites have automatic selector proofs**; 92 match that oracle and
six have independently verified corrections below. Another 268 matching sets
are preserved physical rows with unresolved selector analysis, mostly due to
incomplete instruction/CFG metadata. Set equality is not a selector proof.

Without certificates, the remaining six rows are the two unpromoted O1
formatter sites and four Perl sites whose eight physical targets are retained
instead of the audited seven. Overall, 370 of the 372 report rows are present
as type 7. The frozen ledger remains 347 additions + 25 shrinks.

The source-assisted fixture set additionally applies the corrected O1 and Perl
certificates. Combining those six leaves with the unchanged automatic rows
produces all **372 rows as type 7**, with **98 automatic proofs** and **six
source-validated proofs**. The other 268 matching rows remain unresolved
physical tables. The two O1 sites now contain 31 targets including
`0x50d24`/`0x5c074`; the four Perl sites contain seven targets. These corrected
sets do not rewrite the frozen ledger's original-zero O1 rows or eight-target
Perl rows.

## Corrections beyond the earlier repaired oracle

Four O1 `__wmemcmp_sse4_1` sites (`0x14f154`, `0x14f350`, `0x14f65d`,
`0x14f868`) safely refine **21 to 9 local target bounds**. One incoming path
has unsigned `rdx < 32`; the other has `32 <= rdx < 64` then subtracts 32.
The 32 relevant slots of the 80-slot table at `0x178ee0` give nine targets.
Independent disassembly checks the whole function and all recorded direct
and child edges for guard bypasses. This does not prove caller reachability
of all nine retained targets: alignment may exclude non-multiple-of-four
slots, and unrecorded incoming transfers are outside the evidence scope.

Both Os formatter sets expand **30 to 31**. Site `0x48776` needs `0x48eb0`,
and `0x50e80` needs `0x5157f`; `%hhd` and its wide-character equivalent reach
these second-`h` handlers through a later stage table sharing the same jump.
The independently decoded six-table unions match the generated sets.

O1 has the same earlier audit omission: table-driven paths need `0x50d24` at
`0x514b9` and `0x5c074` at `0x5cb3f`. The glibc source binds all 360 offsets to
the six DWARF-labelled stage tables. `form_unknown` is also the relative-address
base, so the fallback offset is zero and its target is already in the 31-label
union. Both sites are therefore exact under the source contract, while their
automatic spill proof remains unresolved.

The follow-up preserves spills across register-only rotates and segmented
reads, eliminating an unnecessary loss of facts. DWARF confirms that the
cleanup buffer is separate from the fallback spills. A diagnostic experiment
produces 31 targets for both sites when unknown memory effects are assumed
not to access private spills; dynamic frame-address and callback provenance
remain unproved. This conditional experiment is not a GT input; the separate
defined-source certificate supplies the 31-target GT without claiming a
binary-only fallback proof.

The 13 additional sparse formatter promotions from the previous run remain:
five in O2 and eight in O3. They are outside the frozen 372-row comparison.
The corpus audit also records all other full-libc differences rather than
silently treating them as accepted repairs.

## Reproduction and evidence

```sh
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
  python3.12 extract_gt/audit_report_sites.py
```

To reproduce the integrated source-assisted libc result from an existing
protobuf:

```sh
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
  python3.12 extract_gt/jump_table_gt.py \
  -b /mnt/nvme1/sba/x86_dataset/linux/libs/gcc_O1/libc-2.27.so \
  -g /tmp/x86-sok-current-raw-libc-O1.pb \
  -o /tmp/x86-sok-integrated-libc-O1.pb \
  --source-build-manifest extract_gt/source_builds/gt_six_builds.json
```

The same manifest resolves both libc O1 formatter sites and all four Perl
builds. Their sidecars mark the rows `combined_binary_source`; libc emits 31
targets per site and Perl emits seven. The earlier certificate commands and
audit report below remain useful as historical evidence for the prior
manual workflow.

After generating the five source-assisted outputs used by the report, run
`python3.12 extract_gt/audit_source_certified_gt.py`. It checks certificate,
binary and sidecar hashes, independently decodes the target tables, verifies
the emitted type-7 sets and requires each automatic result to remain
`unresolved`.

Use `--help` to select dataset, CSV, oracle, fixture and output paths. The
verifier checks the CSV target hashes, binary/protobuf/source hashes, exact
sets, analysis status and certificate use independently. It rejects stale
sidecars by default. It expects the generated libc outputs at
`/tmp/x86-sok-current-raw-libc-{O1,O2,O3,Os}.pb` and the containing-function
fixtures described above.

Durable report artifacts:

- `x86_sok_automatic_report_site_validation.json`: all 372 rows and provenance.
- `x86_sok_source_certified_gt_validation.json`: six source-certified rows and retained binary status.
- `x86_sok_v8_automatic_validation.json`: dedicated V8 proof evidence.
- `x86_sok_perl_data_invariants.json`: four writable-table obligation audits.
- `x86_sok_perl_loop_invariants.json`: conditional proofs of the emitted loops.
- `x86_sok_perl_source_initializers.json`: initializer, source-use and linked-build mutation audit.
- `x86_sok_perl_local_counterexamples.json`: scoped concrete entry witnesses.
- `x86_sok_perl_writable_pointer_audit.json`: getter and reference checks.
- `x86_sok_perl_bounds_source_audit.json`: constructor/type provenance.
- `x86_sok_libc_o1_frame_diagnostics.json`: unresolved fallback evidence.
- `x86_sok_libc_o1_conditional_frame_experiment.json`: explicit memory-contract experiment.
- `x86_sok_libc_{o1,os}_shared_suffix_audit.json`: independent stage-table audits.
- `x86_sok_libc_o1_source_validation.json`: six-table source/DWARF validation.
- `x86_sok_wmemcmp_refinement_audit.json`: independent four-site bounds audit.

The independent verifiers are `audit_libc_shared_suffix.py`,
`audit_libc_o1_source.py`, `audit_perl_source_initializers.py`,
`audit_source_certified_gt.py` and `audit_wmemcmp_refinement.py`; none uses
copied successor lists for its source proof.
See [generation options](JUMP_TABLES.md) and
[remaining audit inputs](certificates/README.md).
