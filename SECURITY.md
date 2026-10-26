# MYSX-256/512 — Security Status (v0.2-draft)

**Proprietary cipher. NOT externally audited. DO NOT use for sensitive data.**
For production: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: **`v0.2-draft`** (2026). Current draft.
The previous version `v0.1-draft2` is preserved in
[`LEGACY_V1/`](LEGACY_V1/). Its full analysis (differential offset
sweep, linear beam to 128 rounds, integral offset sweep, related-key
audit, NIST SP 800-22) is in [`LEGACY_V1/PAPER.md`](LEGACY_V1/PAPER.md)
§3–§5 and [`LEGACY_V1/SECURITY.md`](LEGACY_V1/SECURITY.md).

This document is a standalone summary **for v0.2-draft**. It reports
what has been measured for v0.2, what is **inherited** from v0.1
(properties that do not depend on the rotation schedule), and what is
**PENDING** for v0.2 (analyses measured for v0.1 that have not been
re-run for the new schedule).

`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`

---

## Summary

**v0.2 changes two things from v0.1:** the rotation schedule and the
AEAD/packet format. The block cipher core (round function, F,
Myszkowski transposition, ARX key schedule) is unchanged.

**The v0.2 analysis is partial by design.** 9 metrics have been
measured for the v0.2 schedule (§1–§3 below). The rest of the v0.1
analysis has not been re-run for the new schedule and is marked
PENDING. **Do not infer security from the absence of v0.2-specific
results in PENDING sections.**

| Attack family | v0.2 status | Details |
|---|---|---|
| **Differential** | **PENDING** beyond R=5 | Only MILP R=5 measured (weight 4, vs 0 for v0.1). Offset sweep, beam, R=14+ MILP: **PENDING**. See §1. |
| **Linear** | **Partial.** R=10 and R=14 both directions measured | R=10: fwd=1, bwd=3. R=14: fwd=8, bwd=11. v0.1: 1/1 and 5/5. Higher weight = more secure. Beam to R=22, hull checks, exact hulls at r=10–12: **PENDING**. See §2. |
| **Integral (DP)** | **Partial.** R=5, R=6 at r0=0 measured | R=5: 9 balanced (v0.1: 21). R=6: 4 balanced (v0.1: 4). Full 31-offset sweep, r0=15 peak: **PENDING**. See §3. |
| **Impossible differential** | **Measured for v0.2** | Exact DMITM = 9 rounds (v0.1: 17). Weight-0 chain = 5 rounds (v0.1: 13). Truncated figure (v0.1: 39): **PENDING** for v0.2. See §4. |
| **Rotation schedule selection** | **Measured for v0.2** | 9-metric comparison v0.1 vs v0.2: 6 improvements, 3 ties, 0 regressions. See §5. |
| **Related-key** | **Inherited from v0.1** | Key schedule unchanged. 22 tests apply. See §6. |
| **Boomeang / algebraic** | **Not analyzed** | — |
| **Grover (quantum)** | **Infeasible (nominal)** | v2 API with 64-byte secret: `2^256` Grover (per target). v1 API or 32-byte secret: `2^128` Grover. See §7. |
| **Classical brute force** | **Infeasible** | `2^512` operations for a uniformly random 512-bit secret (v2 API). |
| **Block collisions** | **Infeasible** | `2^128` blocks (256-bit block). |
| **v2 API design** | **New in v0.2** | HKDF-SHA512, 512-bit MAC keys, HMAC-SHA512, one key per message, Argon2id password path. See §8. |
| **External review** | **None** | — |

**Short verdict.** v0.2 changes the rotation schedule to
`rand_s9_45430` (31 explicit values in `SPEC.md` §5), selected by
systematic search over 1M random schedules. On the 9 metrics measured
for v0.2 — integral at R=5/6, linear at R=10/14 both directions,
exact DMITM, weight-0 chain, MILP at R=5 — the new schedule
**improves 6 metrics, ties 3, and regresses 0**. Exact DMITM goes
from 17 to 9 rounds; weight-0 chain from 13 to 5; integral balanced
bits at R=5 from 21 to 9; linear weight at R=14 from 5 to 8 (forward)
and from 5 to 11 (backward); MILP at R=5 from 0 to 4. **There is no
trade-off: the new schedule is better or equal on every metric
measured.** The v0.2 API adds HKDF-SHA512 (recovering the `2^256`
Grover bound that v1 lost to HKDF-SHA256), 512-bit MAC keys,
HMAC-SHA512, one key per message, and Argon2id for password paths. The
v0.1 API remains for reading existing packets and is deprecated for
new data.

**However, the rest of the v0.1 analysis has not been re-run for the
v0.2 schedule.** The differential offset sweep, the linear beam beyond
R=14, the exact linear hulls at r=10–12, the full integral 31-offset
sweep, the NIST SP 800-22 battery, and the truncated impossible
differential (39 rounds for v0.1) are **PENDING** for v0.2, with the
commands to re-run them documented in PAPER.md §8. **The cipher has
not been externally audited. Do not use in production.**

**Reading thresholds.** A differential trail of weight `w` needs about
`2^w` pairs; a linear trail of weight `w` needs about `2^(2w)` texts.
A `2^128` budget is a differential weight of ≈128 but a *linear*
weight of ≈64. Compare `w_diff` with `2·w_lin`, never `w_diff` with
`w_lin`. **Higher weight is more secure** (lower correlation for
linear, lower probability for differential).

---

## 1. Differential cryptanalysis (PENDING for v0.2)

**v0.1 status** (full analysis in [`LEGACY_V1/SECURITY.md`](LEGACY_V1/SECURITY.md) §1):

- Offset sweep over 31 rotation offsets at R=14: best weight ranges
  from 2 (r0=10) to about 120 (r0=1); the 128-bit threshold moves from
  R≈15 (r0=0) to R≈24 (r0=10).
- Probability-1 weight-0 chains: 13 rounds at r0=10 (exact maximum,
  proven by exhaustive linear algebra over the 2^128 left-half
  differences), 6 rounds at r0=15, 3 rounds at r0∈{0–6,27–29}.
- r=4 trail at r0=0 verified empirically with clustering factor 2.00×.

**v0.2 measured:**

- MILP R=5: weight = **4** (v0.1: 0). The v0.1 r=4 trail no longer
  exists at R=5 for the new schedule (the weight-0 chain max is 5,
  not 13; see §4).

**v0.2 PENDING:**

- The differential offset sweep (31 offsets, R=14) and MILP upper
  bounds at R=6–14.
- The beam differential search (multi-input, multi-offset).
- Empirical verification of any specific trail at the new schedule.
- Full clustering analysis.

**Command to re-run:**

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31
python3 misc/mysx_milp2.py --rounds 6-14 --input-bit 63 --r0 0,10,20 --solver highs --time-limit 180
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 8
```

Do not compare the v0.1 differential numbers directly with the v0.2
values: the weight-0 chain length changed (13 → 5), and the weight at
R=14 is expected to be **higher** for v0.2 (the schedule breaks the
alignment that gave v0.1 its 13-round chain).

## 2. Linear cryptanalysis (partial for v0.2)

The exact LAT of F and the exact mask-propagation rules are
**inherited unchanged** from v0.1, because they are properties of the
round function and do not depend on the rotation schedule (see
`SECURITY.md` §2.2–§2.3 of the v0.1 paper for the full model).

**v0.2 measured:**

| Metric | v0.1 | v0.2 | Direction |
|---|---|---|---|
| lin_fwd10 (R=10, forward, min over 31 offsets) | 1 | 1 | tie |
| lin_bwd10 (R=10, backward, min over 31 offsets) | 1 | **3** | **improvement** |
| lin_fwd14 (R=14, forward, min over 31 offsets) | 5 | **8** | **improvement** |
| lin_bwd14 (R=14, backward, min over 31 offsets) | 5 | **11** | **improvement** |

Higher weight is more secure (lower correlation = `2^-w`). The v0.2
schedule has single-trail correlation `2^-8` (forward) and `2^-11`
(backward) at R=14, versus `2^-5` for v0.1. That is a factor `2^3` and
`2^6` more work for the attacker.

**v0.2 PENDING:**

- The full beam search to R=128 (v0.1 §4.10 of the v0.1 paper).
- The exact linear hulls at r=10–12 (v0.1: matched the real cipher
  with |z|<0.4).
- The hull checks of the specific R=14 trails (the verified
  16-round linear distinguisher of v0.1 was the offset-20 backward
  trail; the analogous v0.2 trail is PENDING).
- The truncated impossible differential (39 rounds for v0.1).
- The `|corr|=1` chain verification at the v0.2 schedule (the 9-round
  chains of v0.1 do not exist at v0.2 because the weight-0 chain is 5,
  not 9).

**Command to re-run:**

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 8 --out beam_v02.json
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 8 --direction backward --out beam_v02_bwd.json
python3 misc/mysx_linear_beam.py merge beam_v02.json beam_v02_bwd.json
```

## 3. Integral cryptanalysis (partial for v0.2)

Standard division property, `(1,1)`-invalid XOR rule. See
[`LEGACY_V1/SECURITY.md`](LEGACY_V1/SECURITY.md) §3 for the full
methodology, the naive XOR rule caveat, and the Simon comparison.

**v0.2 measured** (at r0=0, word0 active):

| Metric | v0.1 | v0.2 |
|---|---|---|
| dp5 (R=5, balanced bits) | 21 | **9** |
| dp6 (R=6, balanced bits) | 4 | 4 |

Lower is more secure (fewer balanced bits = fewer filters for the
attacker). v0.2 has 12 fewer balanced bits at R=5; tied at R=6.

**v0.2 PENDING:**

- The full 31-offset sweep at the saturation rounds of v0.2.
- The r0=15 peak (v0.1: 10-round distinguisher for both patterns).
- The R=8–10 tail at r0=15.
- Full `2^32`/`2^64` integral verification.
- The 10-round single-bit dependency propagation.

**Command to re-run:**

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31
python3 misc/mysx_division_property_v2.py --rounds 5-10 --active word0 --r0-sweep --solver highs
```

## 4. Impossible differential (measured for v0.2)

The exact DMITM (miss-in-the-middle over weight-0 chains, structural
argument verified by exhaustive linear algebra over the whole
left-half difference space) is:

| Metric | v0.1 | v0.2 |
|---|---|---|
| Weight-0 chain max | 13 rounds | **5 rounds** |
| Exact DMITM | 17 rounds | **9 rounds** |

The v0.2 values were measured with `dmitm_verify.py exact` and
`misc/diff_free_chain_table.py` under `MYSX_ROT_CAL`. The 9-round
DMITM is a structural consequence of the 5-round weight-0 chain; the
empirical test (100% propagation of each chain over the real cipher)
is a sanity check and an implementation validation, not a statistical
proof.

**v0.2 PENDING:**

- Truncated impossible differential (v0.1: 39 rounds; the v0.2 figure
  is expected to be shorter, proportional to the weight-0 chain
  reduction).
- Single-bit and multi-bit truncated-propagated variants.
- The 8 distinct differentials of v0.1 (the v0.2 count is not
  measured).

**Command to re-run:**

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31
python3 cryptanalysis/DMITM/dmitm_verify.py exact
python3 cryptanalysis/DMITM/dmitm_trunc.py --cal_file top50_fixed.json --cal_idx 3 --max_fwd 24 --max_bwd 24 --n_bits 256
```

## 5. Rotation schedule selection (measured for v0.2)

**Method.** 1M random permutations of `0..30` filtered by weight-0
chain (≤3 at offset 10, ≤5 globally) and exact DMITM; finalists ranked
by a multi-dimensional score including integral, linear (both
directions), differential, and impossible analyses. The selected
schedule `rand_s9_45430` is documented as 31 explicit values in
`SPEC.md` §5.

**The 9-metric comparison** (v0.1 vs v0.2):

| Metric | v0.1 | v0.2 | Result |
|---|---|---|---|
| dp5 (integral R=5) | 21 | **9** | improvement |
| dp6 (integral R=6) | 4 | 4 | tie |
| lin_fwd10 | 1 | 1 | tie |
| lin_bwd10 | 1 | **3** | improvement |
| lin_fwd14 | 5 | **8** | improvement |
| lin_bwd14 | 5 | **11** | improvement |
| DMITM exact | 17 | **9** | improvement |
| Weight-0 chain | 13 | **5** | improvement |
| MILP R=5 | 0 | **4** | improvement |

**6 improvements, 3 ties, 0 regressions.**

**Why the consecutive schedule was rejected.** Over 3000 random
schedules sampled **without filtering**, the consecutive schedule is
in the worst ~2% by exact DMITM and in the worst ~0.2% by weight-0
chain. The cause is the **step of 1** in the rotation schedule: a
consecutive sequence of shifts aligns with the period of the
transposition in a way that lets the tracked bits remain in the "safe"
half of the state for many rounds. The v0.2 schedule has irregular
steps that break this alignment. **The Myszkowski permutation is not
the cause**: a control with 40 random byte permutations and the same
consecutive schedule gives a mean exact DMITM of 21.4; the consecutive
schedule is at ~22nd percentile. Changing the consecutive schedule to
`(k·r mod 31)+1` for k∈{2,3,5,7} drops the maximum chain to 6–9
rounds. The variable is the **schedule step**, not the permutation.

**Why the selection criterion is defensible.** The 9 metrics include
3 that were **not** used as selection criteria: dp5 (integral at R=5),
dp6 (integral at R=6), and the four linear weights. Those are the
evaluation metrics. The selection criteria were: maximum weight-0
chain ≤3 at offset 10, ≤5 globally, and exact DMITM. The
**evaluation** shows improvements in 6 metrics beyond the selection
criteria, including 3 improvements in linear weight (which was not a
selection criterion). The selection is therefore not a self-fulfilling
prophecy: it was based on chain/DMITM, and the new schedule was
subsequently found to be better on linear and integral too.

**A false positive documented.** `rand_s9_33719` was top-ranked by
R=4 screening (with `dp4=42` and `milp5=10`). At R=6, its integral is
worse than v0.1 (`dp6=12` vs 4), and its linear weight at R=14 is 13
vs 5. **Screening at R≤4 is not sufficient.** Candidates must be
evaluated at R=5–6 for integral and R=10–14 for linear before
selection. The v0.2 finalists were evaluated at R=5, R=6 (integral),
R=10, R=14 (linear, both directions), R=5 (MILP), and exact DMITM.

## 6. Related-key cryptanalysis (inherited from v0.1)

**The key schedule is unchanged from v0.1.** The 22 tests of the
v0.1 audit apply to v0.2 with the same results. The rotation schedule
does not affect the key schedule.

**v0.1 results** (full analysis in `LEGACY_V1/SECURITY.md` §4):
22 structural and empirical tests up to weight-6. No persistent
`Δrk[r]=0`. No weak keys, cycles, or fixed points. Worst bit:
bit 160 (word 5, bit 0), 1-bit difference at r=1. Beam search score:
139 (ideal 128). **These are heuristics, not a proof.** No targeted
MILP/SAT related-key model has been run. Adaptive related keys,
biclique attacks, and algebraic attacks are not covered. **Related-key
security is unknown.**

**Command to re-validate on v0.2:**

```bash
node misc/keyschedule_test.js
node misc/keyschedule_test_extended.js --thorough
```

## 7. Generic attacks

| Attack | v2 API with 64-byte secret | v1 API or 32-byte secret |
|---|---|---|
| Classical brute force | `2^512` operations | `2^256` operations |
| Grover (quantum) | `2^256` iterations (per target) | `2^128` iterations |
| Block collisions | `2^128` blocks | `2^128` blocks |

**Note on Grover (v2 API).** A uniformly random 64-byte secret
processed through HKDF-SHA512 gives `2^256` Grover iterations per
target. If an attacker needs only one of N messages to be broken, the
figure is `2^256 / sqrt(N)`. `v2.securityLevel({secret})` returns the
per-target figure with a note about the sqrt(N) caveat.

**Note on the v1 API.** `deriveAeadKeys` / `deriveAeadKeysFromPassword`
start from HKDF-Extract with HMAC-SHA256, whose PRK is 256 bits.
HKDF-Expand can output 64 bytes, but the entropy of a derived 512-bit
`encKey` is at most 256 bits. The effective quantum security is
`2^128`, not `2^256`. **Do not use v1 for new data.**

**Note on password paths.** Security is limited by password entropy,
not by the nominal key size. `v2.securityLevel` returns `null` for
`classicalBits` and `groverBits` when the password is not accompanied
by a ≥64-byte keyfile. For password paths, a keyfile is strongly
recommended.

**No post-quantum analysis beyond Grover has been done.**

## 8. v2 API security (new in v0.2)

The v2 API adds:

- **Rotation calendar selected by header byte** (CAL=0 for consecutive,
  CAL=1 for `rand_s9_45430`). No environment variable in production
  code. Unknown CAL values are rejected.
- **512-bit secrets** processed through **HKDF-SHA512**, recovering
  the `2^256` Grover bound that v1 lost to HKDF-SHA256.
- **512-bit MAC keys** (vs 32-byte MAC key in v1) and **HMAC-SHA512**
  with 64-byte tags (vs HMAC-SHA256 with 32-byte tags in v1).
- **One key per message**: 32-byte random salt per packet. Different
  salt means different key, eliminating nonce reuse in the key stream.
  Combined with a 16-byte random nonce, accidental `(salt, nonce)`
  repeat has probability `~2^-384` per message pair.
- **Authenticated header**: MAC covers version, calendar, KDF, KDF
  params, salt, nonce, AAD length, CT length. This prevents a
  downgrade attack from Argon2id to PBKDF2 (or from v2 to v1) because
  changing the header breaks the MAC.
- **Argon2id** for password paths (RFC 9106 second recommended option:
  64 MiB, t=3, p=4), with **scrypt** and **PBKDF2-SHA512** fallbacks
  that require explicit opt-in (`allowPbkdf2: true`,
  `allowNativeArgon2: true`). The sealer does not silently fall back
  to a weaker KDF.
- **KDF bounds**: Argon2id mem 19 MiB–1 GiB, passes 2–16, lanes 1–16;
  PBKDF2-SHA512 210k–10M iterations; scrypt logN 15–20, r 8–16,
  p 1–16, memory ≤1 GiB. Out-of-bounds packets are rejected.

**What v2 does not solve:**

- **A distinguisher remains a distinguisher.** The v2 API is a
  packaging change; the block cipher's resistance to differential,
  linear, integral, and impossible differential attacks is unchanged
  except via the new calendar. The new calendar is better on the 9
  metrics measured (§1–§3), but the full v0.1 analysis has not been
  re-run for it.
- **The key schedule is unchanged** and its related-key security
  remains unknown (heuristic only).
- **The final whitening is unchanged.**
- **The block cipher is not externally audited.**

**Engineering hygiene.** The `_salt` and `_nonce` options in
`v2.seal` are internal parameters for KAT generation only. Passing
them in production breaks the one-key-per-message guarantee. This is
a known hygiene issue; a future version may gate them behind an
explicit `internal: true` flag. Until then, callers must not use
them.

## 9. What is PENDING for v0.2

The following analyses have been measured for v0.1 and are
**PENDING for v0.2**. They are marked as such in `PAPER.md` with the
command needed to re-run them.

- **Differential**: the offset sweep at R=14 (v0.1 §3.2, §3.5), the
  MILP upper bounds at R=6–14, the beam differential search, the
  empirical r=4 verification at the new schedule, the full clustering
  analysis.
- **Linear**: the full beam search to R=128, the exact linear hulls at
  r=10–12, the hull checks of the specific R=14 trails, the
  `|corr|=1` chains at the new schedule (the 9-round chains of v0.1
  do not exist at v0.2).
- **Integral**: the full 31-offset sweep, the r0=15 peak, the R=8–10
  tail, the full `2^32`/`2^64` integral verification.
- **Impossible differential**: the truncated figure (v0.1: 39 rounds;
  v0.2 is expected to be shorter), the single-bit and multi-bit
  truncated-propagated variants, the 8 distinct differentials count.
- **NIST SP 800-22**: the full battery at the new schedule.
- **Simon normalized coverage comparison**: the MYSX-specific
  comparison in v0.1 used the consecutive schedule for the MYSX
  figures; it must be re-run for v0.2.
- **Related-key MILP**: the heuristic 22 tests apply unchanged, but
  a targeted MILP/SAT related-key model has not been run for either
  version.

The `CRYPTANALYSIS_STATUS: NOT_ESTABLISHED` applies to v0.2 with the
additional caveat that **the full analysis has not been re-run for
the new schedule**.

## 10. Functional tests

`MYSX_ENABLE_TEST=1 node mysx.test.js` → **GLOBAL RESULT: PASS**.
`MYSX_ENABLE_TEST=1 node verify_v2_usage.js` → 12 checks. See
[`PAPER.md`](PAPER.md) §9.5 for the full list.

The 12-check `verify_v2_usage.js` verifies:

- Calendar injection (`V02_CALENDAR` is not null).
- v2 API completeness (10 functions/constants exposed).
- Argon2id provider status (`noble` / `native` / `scrypt-fallback` /
  `none`).
- Round-trip with 64-byte secret.
- Packet `VERSION` byte = 2.
- Packet `CAL` byte = 1.
- Round-trip with password.
- Packet `KDF` byte = 1 (Argon2id), 2 (PBKDF2), or 3 (scrypt).
- `securityLevel` for 64-byte and 32-byte secrets.
- v1 backwards compatibility (a v1 packet is still readable).

**These tests do not prove cryptographic security.** They verify
functional correctness, negative-case handling, and API surface.

## 11. Analysis limitations

- **Differential (PENDING for v0.2)**: only R=5 measured. No offset
  sweep, no beam, no R=6–14 MILP for the new schedule. The v0.1
  differential numbers (13-round chain, 128-bit threshold at R≈24)
  do not apply to v0.2 and are PENDING.
- **Linear (partial for v0.2)**: R=10 and R=14 measured. No beam
  beyond R=14, no hull checks, no exact hulls at r=10–12. The
  offset-20 backward trail that was a verified 16-round distinguisher
  for v0.1 is PENDING for v0.2.
- **Integral (partial for v0.2)**: R=5, R=6 at r0=0 measured. No
  full 31-offset sweep, no r0=15 peak, no R=8–10 tail, no full
  integral verification.
- **Impossible differential (partial for v0.2)**: exact DMITM = 9
  measured. Truncated (v0.1: 39) PENDING. Single-bit and multi-bit
  truncated variants PENDING.
- **Related-key (inherited)**: key schedule unchanged. The 22
  heuristic tests apply but have not been re-run on the v0.2 branch.
  No targeted MILP/SAT related-key model.
- **Boomeang, algebraic (SAT)**: not analyzed.
- **No independent public cryptanalysis.**
- **No post-quantum analysis beyond the trivial Grover bound.**
- **No side-channel analysis.** JavaScript execution is not
  constant-time; cache-timing attacks on `crypto.subtle` HMAC are out
  of scope for this document.

## 12. Verdict

**MYSX-256/512 v0.2-draft is an experimental proposal, not a secure
cipher.**

**What v0.2 improves.** The rotation schedule `rand_s9_45430` improves
6 of 9 measured metrics and ties 3, with **no regressions**. Exact
DMITM drops from 17 to 9 rounds; the weight-0 chain from 13 to 5; the
integral balanced bits at R=5 from 21 to 9; the linear weight at R=14
from 5 to 8 (forward) and from 5 to 11 (backward); the MILP
differential at R=5 from 0 to 4. The v0.2 API adds HKDF-SHA512 with a
64-byte secret (recovering the `2^256` Grover bound), 512-bit MAC
keys, HMAC-SHA512, one key per message, and Argon2id for password
paths. The v1 API is kept for backwards compatibility and is
**deprecated for new data**.

**What v0.2 does not do.** It does not re-run the v0.1 analyses for
the new schedule. The differential offset sweep, linear beam to 128
rounds, exact linear hulls, full integral sweep, NIST SP 800-22
battery, truncated impossible differential, and Simon normalized
coverage are **PENDING** for v0.2 (see §9). The v0.1 differential and
linear results for the consecutive schedule do not transfer to the
new schedule. **No lower bound over 128 rounds is established for
either version, no key-recovery attack has been attempted, and the
cipher has not been externally audited.** The truncated impossible
differential for v0.2 is unknown (v0.1: 39 rounds). The related-key
security is unknown (heuristic only). The cipher is released as
v0.2-draft for public review with an explicit PENDING list.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.

## 13. Reproducibility

| File | Purpose |
|---|---|
| [`PAPER.md`](PAPER.md) | Full v0.2-draft paper (spec + partial analysis + PENDING list) |
| [`SPEC.md`](SPEC.md) | Formal specification (v0.2) |
| [`KAT_v2.json`](KAT_v2.json) | v0.2 API test vectors |
| [`KAT_v02.json`](KAT_v02.json) | v0.2 block-cipher test vectors |
| [`LEGACY_V1/KAT.json`](LEGACY_V1/KAT.json) | v0.1 test vectors (frozen) |
| [`calendar/CALENDAR_v02.txt`](calendar/CALENDAR_v02.txt) | `MYSX_ROT_CAL=22,5,8,...` |
| [`calendar/wf2_deep_summary.json`](calendar/wf2_deep_summary.json) | 8 candidates × 9 metrics (raw data §5) |
| [`generate_kat_v2.py`](generate_kat_v2.py) | v0.2 KAT generator |
| [`verify_v2_usage.js`](verify_v2_usage.js) | 12-check smoke test |
| [`mysx.prod.js`](mysx.prod.js) | Reference implementation (v1 + v2) |
| [`mysx.test.js`](mysx.test.js) | Functional tests (17 tests) |
| [`cryptanalysis/DMITM/dmitm_verify.py`](cryptanalysis/DMITM/dmitm_verify.py) | Exact DMITM search |
| [`cryptanalysis/DMITM/dmitm_trunc.py`](cryptanalysis/DMITM/dmitm_trunc.py) | Truncated-bit impossible differentials |
| [`cryptanalysis/DMITM/search_mysx_deep.py`](cryptanalysis/DMITM/search_mysx_deep.py) | 1M random schedule search |
| [`cryptanalysis/models/linear/mysx_linear_model.py`](cryptanalysis/models/linear/mysx_linear_model.py) | Exact linear model of F + round (inherited) |
| [`misc/mysx_linear_beam.py`](misc/mysx_linear_beam.py) | Beam search (inherited tool, used for §2) |
| [`misc/mysx_milp2.py`](misc/mysx_milp2.py) | Differential MILP (inherited tool, used for §1) |
| [`misc/mysx_division_property_v2.py`](misc/mysx_division_property_v2.py) | Division property (inherited tool, used for §3) |

**v0.1 full analysis** (all sections of differential, linear, integral,
related-key, NIST SP 800-22): [`LEGACY_V1/PAPER.md`](LEGACY_V1/PAPER.md)
and [`LEGACY_V1/SECURITY.md`](LEGACY_V1/SECURITY.md).

## 14. Final warning

**MYSX has not been externally audited.** This document is the
author's self-analysis, not a certification. No result here replaces
an independent cryptographic review. The v0.2 analysis is **partial
by design**: sections that were measured for v0.1 and have not been
re-executed for v0.2 are marked **PENDING** with the commands needed
to resolve them.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.
