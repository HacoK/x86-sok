# Corpus 1: Explicit Physical and Feasible Oracles

We publish two explicit oracles: T_phys contains all physically evidenced table targets, including compiler/linker-bound entries and audited computed-goto and other physical-site additions; T_feas is its independently guarded site-feasible subset.

## Definitions

- **T_phys:** All physically evidenced jump-table site targets: compiler/linker physical entries for compiler-marked sites, plus audited existing computed-goto and other omitted physical sites. Feasibility filtering is not applied.
- **T_feas:** Guarded site-feasible successors. Each site retains its T_phys site key and every T_feas target must be a member of its T_phys target set.

## Correction

This report supersedes artifact_eval/corpus1_audit. The earlier audit treated the accepted repaired tree as T_phys, which mixed 347 real physical-site additions with 25 feasibility-oriented successor shrinks. The corrected T_phys retains every evidenced site and restores the 25 compiler-physical target sets.

## Oracle Integrity

- Physical sites: `61249`.
- Audited physical site additions: `347`.
- Restored compiler-physical target sets: `25`.
- Guarded feasible refinements: `811`.
- Non-physical guarded edges clipped: `23`.
- Layer hash mismatches: `0`.
- Recorded subset violations: `0`.

## Tool Metrics

| Tool | GT | Truth | Detected | Exact | FP | FN | WS | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ProofJTR | T_phys | 61249 | 61249 | 61224 | 0 | 0 | 25 | 99.96% | 99.96% |
| ProofJTR | T_feas | 61249 | 61249 | 60449 | 0 | 0 | 800 | 98.69% | 98.69% |
| IDA Pro 9.0 | T_phys | 61249 | 61242 | 61096 | 22 | 29 | 124 | 99.76% | 99.75% |
| IDA Pro 9.0 | T_feas | 61249 | 61242 | 60297 | 22 | 29 | 923 | 98.46% | 98.45% |
| Ghidra 12 | T_phys | 61249 | 49209 | 48438 | 22 | 12062 | 749 | 98.43% | 79.08% |
| Ghidra 12 | T_feas | 61249 | 49209 | 48020 | 22 | 12062 | 1167 | 97.58% | 78.40% |
| angr | T_phys | 61249 | 50859 | 49220 | 10 | 10400 | 1629 | 96.78% | 80.36% |
| angr | T_feas | 61249 | 50859 | 48535 | 10 | 10400 | 2314 | 95.43% | 79.24% |
| Dyninst | T_phys | 61249 | 32847 | 32716 | 7 | 28409 | 124 | 99.60% | 53.41% |
| Dyninst | T_feas | 61249 | 32847 | 32486 | 7 | 28409 | 354 | 98.90% | 53.04% |
| SJA | T_phys | 61249 | 61909 | 59502 | 740 | 80 | 1667 | 96.11% | 97.15% |
| SJA | T_feas | 61249 | 61909 | 58747 | 740 | 80 | 2422 | 94.89% | 95.92% |

## Discrepancy Audit

| Tool | T_phys discrepancies | Resolved under T_feas | Confirmed |
| --- | ---: | ---: | ---: |
| ProofJTR | 25 | 18 | 7 |
| IDA Pro 9.0 | 175 | 4 | 171 |
| Ghidra 12 | 12833 | 172 | 12661 |
| angr | 12039 | 13 | 12026 |
| Dyninst | 28540 | 0 | 28540 |
| SJA | 2487 | 12 | 2475 |

Per-row evidence is in the `audit_<tool>_<rows>.csv` files and `all_discrepancies_audited.csv`.
