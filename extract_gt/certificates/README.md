# Audited selector certificates

These manifests preserve source-validated corrections from the root-cause
reports. They apply only to the exact non-stripped binaries named below.
SHA-256 validation rejects other builds, including stripped versions of the
same executable. Schema 2 binds each certificate to an explicit source
contract and can list every table feeding one shared jump.

| Manifest | Input binary | Jump site |
| --- | --- | --- |
| `perlbench-gcc_O1.json` | `perlbench_base.amd64-m64-gcc81-O1` | `0x429c54` |
| `perlbench-gcc_O2.json` | `perlbench_base.amd64-m64-gcc81-O2` | `0x42d16a` |
| `perlbench-gcc_O3.json` | `perlbench_base.amd64-m64-gcc81-O3` | `0x432c42` |
| `perlbench-gcc_Of.json` | `perlbench_base.amd64-m64-gcc81-Of` | `0x432c62` |
| `libc-gcc_O1.json` | `libc-2.27.so` (GCC O1) | `0x514b9`, `0x5cb3f` |

The audit used CPU2006 `400.perlbench`, source version 109. `Perl_ck_fun`
dispatches on `oa & 7` from packed `PL_opargs` nibbles. In each of the four
binaries, reading all 352 initialized entries, shifting right by 13, and
repeatedly shifting right by 4 while the value is nonzero produces exactly
selectors `{1,2,3,4,5,6,7}`. This initialized-table property excludes zero
without filtering `PL_check` or enumerating callers and wrappers. The earlier
wrapper audit explains selector 5's runtime feasibility; it is not required
to establish the property of all initialized entries.

The certificates use a defined-C contract: GT covers executions of the
matching source under correct compilation, and an out-of-bounds
`PL_opargs[type]` access is excluded as undefined behavior. Table stability is
still required. The source has 28 read uses, two definition occurrences and
one pointer-returning getter, with no getter caller. The SPEC configuration
disables dynamic loading. All four original executables are fixed-address
`ET_EXEC` files; they do not export the queried symbols, import loader
functions or contain relevant relocations. A complete scan of all 6,947 sized
function symbols decoded 899,205 instructions with no undecoded function
body. It found 94 `PL_opargs` references, all reads, plus no getter reference
and no stored table/getter pointer. Under the source contract, the writable
table therefore remains at its verified initial values.

`jump_table_data_invariants.py` discovers this pattern without application
names or address rules and records the initial-byte arithmetic closure
separately from those obligations. All four builds remain unresolved to the
automatic binary analyzer: normal generation without an explicit certificate
preserves their eight physical successors, and strict automatic generation
rejects them. The source certificates produce the seven-target rows while the
sidecar retains the failed binary proof.

Concrete emulation of the original bytes confirms that synthetic out-of-range
`op_type` inputs can reach selector zero before any call. These are undefined
C executions and are excluded by the source contract; they explain why the
local binary analyzer fails closed and do not refute the seven-target source
GT. `audit_perl_local_entry.py` reproduces this check.

The certificates store this domain and the audited table association. The
generator reads the table bytes from the hash-matched input. All four
manifests were checked against the report's repaired protobufs: each decodes
exactly the seven accepted targets, with no copied target list in the manifest.
The source and linked-build audit is reproducible with
`extract_gt/audit_perl_source_initializers.py` and is recorded in
`/mnt/nvme1/sba/reports/x86_sok_perl_source_initializers.json`.

Example, from the repository root:

```sh
python3 extract_gt/extractBB.py \
  -b /dataset/cpu2006/gcc_O1/perlbench_base.amd64-m64-gcc81-O1 \
  -m /dataset/cpu2006/gcc_O1/perlbench_base.amd64-m64-gcc81-O1.gt \
  -o /tmp/gtBlock_perlbench.pb \
  --jump-table-certificates extract_gt/certificates/perlbench-gcc_O1.json
```

The `jump_table_gt.py` entry point accepts the same certificate option when
refining an existing protobuf. Certificates are explicit inputs and are never
selected automatically by filename or address.

## Sparse formatter fallback paths

The old O1 and Os certificates were withdrawn because their 30-target sets
covered only `step0` and omitted the feasible second-`h` handler reached by
`%hhd`. The shared jumps serve six parser-stage tables. A corrected schema-2
O1 certificate now includes all six tables; the Os sites need no certificate
because automatic analysis proves their 31-target unions.

| Build | Shared jump | Omitted `hh` target | Current status |
| --- | --- | --- | --- |
| GCC O1 | `0x514b9` | `0x50d24` | 31 targets source-validated; binary analysis unresolved |
| GCC O1 | `0x5cb3f` | `0x5c074` | 31 targets source-validated; binary analysis unresolved |
| GCC Os | `0x48776` | `0x48eb0` | 31 targets automatically proved |
| GCC Os | `0x50e80` | `0x5157f` | 31 targets automatically proved |

All four immutable character maps contain 30 selector classes. The union of
six stage tables has 31 targets for each shared jump. In GCC O1, the guarded
`hh` path loads its target from `step3a` and overwrites the unknown fallback
value, so the additional target is independently established. The source
defines `form_unknown` as both the out-of-range fallback and the relative base,
making its offset zero. The fallback target is therefore already among the 31
table targets in defined source execution. The automatic analyzer cannot yet
prove that the stored fallback spill survives the intervening calls, so those
sites remain unresolved in `binary_analysis` while the source-validated GT is
exact. The other 57 reported formatter sites recover automatically, including
both GCC Os shared sites.

The independent verifier `extract_gt/audit_libc_shared_suffix.py` reads the
hash-matched O1 or Os ELF directly. It records all six immutable stage tables,
emitted code around their references and the `hh` character witness. Its
31-target Os union agrees exactly with automatic generation. The O1
source-level extension also binds all 360 table entries to DWARF labels and
applies the defined-source fallback expression. The binary-only frame proof
remains unresolved. Evidence is recorded in
`/mnt/nvme1/sba/reports/x86_sok_libc_os_shared_suffix_audit.json`,
`/mnt/nvme1/sba/reports/x86_sok_libc_o1_shared_suffix_audit.json` and
`/mnt/nvme1/sba/reports/x86_sok_libc_o1_source_validation.json`.

```sh
python3 extract_gt/audit_libc_shared_suffix.py \
  --binary /dataset/libs/gcc_Os/libc-2.27.so \
  --output /tmp/libc-os-shared-suffix-audit.json
```

## Automatic V8 table associations

All eight V8 sites formerly supplied by the `libv8-clang_O1`,
`libv8-clang_O3`, `libv8-clang_Of` and `libv8-clang_Os` manifests are now
recovered automatically. Those manifests have been removed.

The generator propagates register constants from each function entry to
individual dispatch regions, replays the bounded tables, adds their decoded
CFG edges, and recomputes incoming states until the reachable CFG is closed.
Every reachable indirect frontier must have conservative metadata successors
or a valid binary replay proof before the new associations are published.
Register reuse, loop backedges and call clobbers are included in the proof;
an unknown frontier or an exhausted analysis budget leaves the result unresolved.
The Os copied-byte guard and its equivalent wider masked index share the same
selector constraint.

| Build | Automatically recovered sites | Unique targets per site |
| --- | --- | ---: |
| Clang O1 | `0x130c934`, `0x130cf42`, `0x130d5a0`, `0x130dcf1` | 8 |
| Clang O3 | `0x75ac41` | 4 |
| Clang Of | `0x759431` | 4 |
| Clang Os | `0x7f3413`, `0x7f3b18` | 8 |

O3 and Of require fresh raw-metadata reconstruction. Their shipped protobufs
misassign the dispatch blocks to earlier functions; the corrected block
splitting preserves their actual owners, `0x75a450` and `0x758c40`, respectively.
The analysis does not repair a missing function entry by guessing its address.

Integrated `refine_jump_tables` validation, with no certificate argument,
matched all eight audited successor sets exactly and also preserved the
previously automatic O1 site `0x130b847`. The evidence is recorded in
`/mnt/nvme1/sba/reports/x86_sok_v8_automatic_validation.json`, including binary,
input/output protobuf and generator hashes, final CFG edges, register facts,
and table-byte replay proofs. The upstream repair ledger remains the comparison
reference and is not an input to automatic analysis.
