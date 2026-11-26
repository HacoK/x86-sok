# Corpus 1 Symmetric Audit

> **Superseded.** This audit used the accepted repaired GT tree as
> `T_phys`. That tree mixes 347 real physical-site additions with 25
> feasibility-oriented successor shrinks. Use
> [`../corpus1_two_layer_audit/summary.md`](../corpus1_two_layer_audit/summary.md)
> for the corrected physical/feasible split.

The unchanged positive jump-only comparator scores each tool against T_phys and T_feas. Every T_phys incorrect row is then re-evaluated against the hash-bound T_feas protobuf and its extract_gt jump-table sidecar.

Every discrepancy between any evaluated tool and x86-sok was audited under the identical protocol: the same frozen physical truth, the same hash-bound clean-room refinement, and the same extract_gt jump-table validator.

## Tool Metrics

| Tool | GT | Truth | Detected | Exact | FP | FN | WS | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ProofJTR | T_phys | 61249 | 61249 | 61249 | 0 | 0 | 0 | 100.00% | 100.00% |
| ProofJTR | T_feas | 61249 | 61249 | 60447 | 0 | 0 | 802 | 98.69% | 98.69% |
| IDA Pro 9.0 | T_phys | 61249 | 61242 | 61071 | 22 | 29 | 149 | 99.72% | 99.71% |
| IDA Pro 9.0 | T_feas | 61249 | 61242 | 60289 | 22 | 29 | 931 | 98.44% | 98.43% |
| Ghidra 12 | T_phys | 61249 | 49209 | 48435 | 22 | 12062 | 752 | 98.43% | 79.08% |
| Ghidra 12 | T_feas | 61249 | 49209 | 48016 | 22 | 12062 | 1171 | 97.58% | 78.39% |
| angr | T_phys | 61249 | 50859 | 49207 | 10 | 10400 | 1642 | 96.75% | 80.34% |
| angr | T_feas | 61249 | 50859 | 48538 | 10 | 10400 | 2311 | 95.44% | 79.25% |
| Dyninst | T_phys | 61249 | 32847 | 32713 | 7 | 28409 | 127 | 99.59% | 53.41% |
| Dyninst | T_feas | 61249 | 32847 | 32480 | 7 | 28409 | 360 | 98.88% | 53.03% |
| SJA | T_phys | 61249 | 61909 | 59482 | 740 | 80 | 1687 | 96.08% | 97.12% |
| SJA | T_feas | 61249 | 61909 | 58739 | 740 | 80 | 2430 | 94.88% | 95.90% |

## Physical Error-Row Audit

| Tool | T_phys errors | Truth changed | Resolved | Confirmed |
| --- | ---: | ---: | ---: | ---: |
| ProofJTR | 0 | 0 | 0 | 0 |
| IDA Pro 9.0 | 200 | 34 | 8 | 192 |
| Ghidra 12 | 12836 | 238 | 167 | 12669 |
| angr | 12052 | 128 | 15 | 12037 |
| Dyninst | 28543 | 576 | 0 | 28543 |
| SJA | 2507 | 785 | 14 | 2493 |

## Evidence Integrity

- Refined files verified: `2026`.
- Analyzed indirect-jump sites: `100080`.
- Materialized type-7 truth sites: `61249`.
- Binary hash mismatches: `0`.
- Protobuf hash mismatches: `0`.
- Sidecar/type-7 target-set mismatches: `0`.
- Comparator SHA-256: `cdc015c755f7bd4f275fb24d5f5ad130fff61fbe9e6ce70a58a746eff5648622`.
- Refinement manifest SHA-256: `0530eb6b85dc40bb321f559899faaecfce4912159a57a666f4f4b65fa33a03f9`.

The exact IDA 200-row and SJA 2,507-row ledgers are written as `audit_idapro_200.csv` and `audit_sja_2507.csv`. A combined ledger contains every physical discrepancy for all six tools.
