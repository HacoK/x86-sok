# Corpus 1 Two-Layer Oracle

## Published layers

- `T_phys(s)`: all physically evidenced jump-table targets at site `s`. It
  combines compiler/linker-bound physical entries for compiler-marked sites
  with the 347 audited computed-goto and other physical site additions already
  present in the Corpus 1 repair history. It restores the 25 compiler-physical
  successor sets that the prior accepted GT had shrunk for feasibility.
- `T_feas(s)`: the guarded site-feasible successor subset. Every site key from
  `T_phys` is retained and every `T_feas(s)` target must be in `T_phys(s)`.

The guarded layer is produced by the independent finite path/table replay in
`extract_gt/`; no SMT solver is invoked. Guarded targets outside `T_phys` are
clipped and recorded rather than admitted into the feasible oracle.

## Current counts

| Property | Count |
| --- | ---: |
| Binaries | 2,026 |
| `T_phys` sites | 61,249 |
| Audited physical site additions | 347 |
| Restored compiler-physical target sets | 25 |
| Guarded feasible target-set refinements | 811 |
| Non-physical guarded edges clipped | 23 |
| `T_phys` / `T_feas` hash mismatches | 0 / 0 |
| Recorded subset violations | 0 |

## Reproduction

```sh
python3 artifact_eval/build_two_oracle_layers.py \
  --output-root /mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2

python3 artifact_eval/rescore_two_oracle_layers.py \
  --layer-root /mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2

python3 artifact_eval/audit_two_oracle_layers.py \
  --layer-root /mnt/nvme1/sba/tmp/x86-sok-corpus1-two-layer-v2
```

The side-by-side metrics and audit summary are in `summary.md` and
`summary.json`. Per-binary scores are under `scores/T_phys/` and
`scores/T_feas/`. The complete discrepancy ledger is
`all_discrepancies_audited.csv`.
