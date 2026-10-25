# MYSX-256/512 — Security Status (v0.1-draft2)

**Proprietary cipher. NOT externally audited. DO NOT use for sensitive data.**
For production: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: `v0.1-draft2` (2026). The reference implementation
(`mysx.prod.js`) is `v0.1-draft` and has not changed; `v0.1-draft2` is
the second documentation draft of the same design. (An earlier revision
of this text was labelled `v0.2-draft`; that label is withdrawn.)
This document is a standalone summary. The full analysis (with
methodology and data) is in [PAPER.md](PAPER.md) §3–§5.

`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`

## Summary

| Attack family | Status | What this means |
|---|---|---|
| Differential (MILP) | **Upper bounds observed + r=4 trail verified** | Weight 114 at r=14, extrapolating to the 128-bit threshold at r≈15. r=4 trail verified at w=32: observed 2⁻⁷ vs MILP 2⁻⁸, clustering factor **2.00×**. Not a proof: single-trail, one input, rotation offset not varied (the linear analysis shows the offset changes weights by an order of magnitude, so the extrapolation is likely optimistic), `gapRel=0.2`, Markov-independence not satisfied. |
| Linear (exact model) | **Exact F model; beam search both directions on all 31 offsets; verified distinguisher on a 16-round window; hull effects observed; no bound** | LAT of F in closed form (`|corr|=2^{-h}`, `h=rank(A_b)/2`). `|corr|=1` chains verified up to 9 rounds (3 keys). Exact signed hulls match the real cipher at r=10,11,12 (|z|<0.4). Combined forward+backward achievable single-trail weight: 2 at R=12, 5 at R=14, 38 at R=20, below 64 only up to R=22 (63, tie with threshold), 2248 at R=128 (offset 3 backward). The offset-20 backward trail is **isolated in its hull** at R=14 (weight 5, rounds 100–113, empirical correlation 2⁻⁵) and an exact budgeted hull extends it to R=16 (rounds 98–113, |corr| = 2⁻¹¹, two trails of weight 12 adding; one-key measurement within 1.9σ): this is a **verified linear distinguisher on a 16-round window** (seven weighted rounds followed by a 9-round weight-0 chain), not an attack on the full cipher. At R=17 the best end pairs of offsets 20 backward and 23 forward cancel within the enumerated budget. Other trails are ≈2× larger or exactly cancelled, so single-trail weight is not universally a distinguisher length. **No lower bound over 128 rounds.** |
| Integral (DP) | **Preliminary: 5–6 round distinguishers (multi-bit inputs); 10-round single-bit dependency** | Standard (1,1)-invalid DP rules. 6-round distinguisher with 2³² texts (word 0 active), 5-round with 2⁶⁴ texts (words 0,4 active). A 10-round single-bit dependency propagation is reported but is **not** an integral distinguisher (2 texts). Only r0=0 tested. No key-recovery attack attempted. |
| Related-key | **Heuristic coverage** | 22 tests up to weight-6 with no persistent `Δrk=0`. No targeted MILP; security unknown. |
| Impossible differential | **Not analyzed** | — |
| Boomerang | **Not analyzed** | — |
| Algebraic (SAT) | **Not analyzed** | — |
| Grover (quantum) | **Infeasible (trivial estimate)** | 2²⁵⁶ iterations for a *uniformly random* 512-bit key; 2¹²⁸ for keys derived with the HKDF-based API from a 256-bit secret. No post-quantum analysis beyond Grover. |
| Classical brute force | **Infeasible** | 2⁵¹² operations for a uniformly random 512-bit key (2²⁵⁶ for HKDF-derived keys). |
| Block collisions | **Infeasible** | 2¹²⁸ blocks (256-bit block). |

**Short verdict.** Differential resistance is reported as an *observed
upper bound* with **one trail verified at r=4** (clustering factor 2×),
not a proof, for one input and without varying the rotation offset. The
linear side has an **exact model of F**: the LAT has a closed form, mask
propagation is bit-exact, every trail carries an exact key-dependent
sign, `|corr|=1` chains are verified up to 9 rounds, and exact signed
hulls match the real cipher at r=10–12. A beam search over that model —
run in **both directions** (forward and backward) across all 31 rotation
offsets, up to 128 rounds, and merged — finds that cheap single trails
end at roughly 20 rounds: weight 38 at R=20, below 64 only up to R=22
(63, a tie with the threshold), then roughly 12–21 more per round up to
R=112. The offset-20 backward trail is **isolated in its hull** at R=14
(weight 5, rounds 100–113), and an exact budgeted hull extends it to
R=16 (rounds 98–113, |corr| = 2⁻¹¹), with an empirical measurement
within 1.9σ of the prediction: that is a verified linear distinguisher
on a 16-round window. For other trails, a check against the real cipher shows that
single-trail weight can be exact, ≈2× too low, or exactly cancelled
(r0=23 was observed to cancel from R=8), so these numbers say where
cheap trails end, not universally how long a distinguisher is. It is
**not** an attack on the 128-round cipher: no lower bound over 128
rounds, no hull-aware bound beyond R=17, no key-recovery estimate.
Multi-bit starts (pairs47, rand:5000:4) were explored and did not
improve on single-bit starts; the random sample is too small to be
conclusive for structured multi-bit masks. The integral side is
preliminary: 5–6 round distinguishers with multi-bit inputs (2³² and
2⁶⁴ texts), a 10-round single-bit dependency propagation, and only r0=0
tested; no key-recovery attack is proposed. Related-key security is
*unknown* (heuristic only). The cipher is a `v0.1-draft2` awaiting
external review. Do not use in production.

**Reading thresholds.** A differential trail of weight `w` needs about
2^w pairs; a linear trail of weight `w` needs about 2^{2w} texts. A
2¹²⁸ budget is a differential weight of ≈128 but a *linear* weight of
≈64. Compare `w_diff` with `2·w_lin`, never `w_diff` with `w_lin`.

---

## 1. Differential cryptanalysis

### 1.1. Model

Tool: `misc/mysx_milp.py` (PuLP + CBC/HiGHS), `a = Δx ∨ Δy`, `gapRel=0.2`,
`timeLimit=300`. Single-bit input at r=12–14 (w2b30). No run varying the
rotation offset (first round mod 31) is reported.

### 1.2. Observed upper bounds

| Rounds | Input | Weight (upper bound) | Single-trail prob. |
|---|---|---|---|
| 5 | w1b24 | 2 | 2⁻² |
| 6 | w1b24 | 6 | 2⁻⁶ |
| 7 | w2b30 | 10 | 2⁻¹⁰ |
| 8 | w2b30 | 18 | 2⁻¹⁸ |
| 12 | w2b30 | 68 | 2⁻⁶⁸ |
| 14 | w2b30 | 114 | 2⁻¹¹⁴ |

Extrapolation: the 128-bit threshold is reached at r≈15. This is an
extrapolation, not a proof, and it is specific to the input and offset
tried.

At 14 rounds the linear side now has a **verified distinguisher on a
14-round window** (offset 20 backward, rounds 100–113, weight 5,
≈2¹⁰ texts, isolated hull; §2.9) which is far below the differential
bound (≈2¹¹⁴ pairs). Part of that gap is probably not intrinsic: the
linear figure is the minimum over all 31 offsets, the differential
figure is for one input at one position. A differential analysis with
inputs placed in the free windows and over all offsets has not been
done.

### 1.3. Direct verification of the r=4 trail at w=32

Trail (not a row of the table above): Δin = {w0b0}, Δout = {w0b4,
w1b10, w1b16, w1b30, w6b4}, MILP weight 8 (8 active ANDs; Hamming
weight of Δout is 5).

- **Sample size**: 8 fixed keys × 2¹⁷ pairs each = 1,048,576 pairs.
- **Observed hit rate**: 7.802×10⁻³ (8181 hits).
- **Expected from MILP**: 2⁻⁸ = 3.906×10⁻³.
- **Ratio**: **2.00×**.

The trail exists. The single-trail probability is a factor 2 higher
than the MILP predicts. Either differential **clustering** (multiple
trails with the same Δout) or a one-bit overestimate of the cost by the
AND model (true weight 7, not 8) explains it; without a full clustering
analysis the two cannot be told apart, and in both cases the MILP weight
is the pessimistic side. The MILP model is correct within a factor of 2
at this round count.

A *constant* factor 2 is one bit of weight; at the observed 8–23 bits
per round it moves the "128-bit threshold at r≈15" by a small fraction
of a round. Only a factor that grows with the weight (for example 7/8
applied to the whole trail) would matter, moving the crossing to roughly
r≈16–17. The extrapolation should be read as approximate.

### 1.4. What this does not establish

- No lower bounds (requires gap=0 and multi-bit input search).
- No full clustering analysis (sum over all trails with the same
  Δin, Δout).
- No related-key differentials.
- No differential inputs placed in the free windows.
- No variation of the rotation offset.

---

## 2. Linear cryptanalysis

### 2.1. What changed

The previous version of this document reported three approximate linear
MILP models (`misc/mysx_linear_milp.py`), none of which produced trails
that verified empirically at w=32. That negative result is now explained:
**the models used per-cell AND activity (`act = α ∨ β ∨ γ`) as a proxy
for F's correlation, which is not the correct structure of F.** The "no
signal" was a property of the model, not of the cipher.

The correct model is implemented in
`cryptanalysis/models/linear/mysx_linear_model.py` (documented in
`cryptanalysis/models/linear/LINEAR_MODEL.md`, raw data in
`cryptanalysis/models/linear/linear_model_data.json`). It is
machine-checked against the real cipher by
`python3 cryptanalysis/models/linear/mysx_linear_model.py selftest`.

The beam search of §2.8 (`misc/mysx_linear_beam.py`) is a second,
self-contained implementation of the same exact rules. It reproduces the
beam table of §2.6 exactly and passes its own `selftest` against the real
cipher in both directions (forward and backward). In this draft it also
supports `--direction backward` and a `merge` command that combines
results from both directions; the merged minimum is what §2.8 reports.

### 2.2. Exact LAT of F

For output mask `b` and input mask `g`:

```
b.F(x) ⊕ g.x  =  Q_b(x) ⊕ l.x ,   l = rotr(b,2) ⊕ g ,
Q_b(x) = ⊕_j b_{j+1} x_j x_{j−7} .
```

`Q_b` is a quadratic form whose graph `G_b` is a subgraph of the
32-cycle `j ↔ j−7` (edge `(j, j−7)` present iff `b_{j+1}=1`; a single
cycle because `gcd(7,32)=1`). Let `A_b` be the GF(2) adjacency matrix
of `G_b`. Then:

- `corr(b,g) ≠ 0` iff `l = A_b y` for some `y`. There are exactly
  `2^{rank(A_b)} = 4^{h(b)}` valid `g`.
- For each valid `g`, `corr(b,g) = (−1)^{Q_b(y)} · c_0(b)` with
  `|c_0(b)| = 2^{−h(b)}`, where `h(b) = rank(A_b)/2`.
- `h(b)` equals the maximum matching = minimum vertex cover of `G_b`
  (König). The only graph that is not a forest is `b = 0xFFFFFFFF`
  (full cycle), where `rank = 30` and `h = 15`.
- Parseval holds: `Σ_g corr(b,g)² = 1`.

This is exact and machine-checked against brute-force LAT of F for
random `b` of Hamming weight up to 8.

**Cost data.**

- Single-bit `b`: `h = 1`, four valid `g`, `|corr| = 1/2`.
- Two-bit `b` (496 masks): histogram `{2: 464, 1: 32}` (the 32 pairs
  at bit distance 7 are adjacent edges).
- Uniform random 32-bit `b` (16384 samples): histogram of `h` peaks
  at `h = 11` (4130 samples).
- Densest masks per unit of weight (bits `(1−7t) mod 32`, `t < 2m`):
  every extra 2 consecutive edges costs 1; cost per active mask bit
  approaches 1/2 in the best case, never below 15/32.

### 2.3. Exact mask propagation and key sign

For a round `r`, with input mask `m` on `s[r]` and cells `p = 0..3`
(`L = s[r][p]`, `R = s[r][p+4]`):

```
b_p     = m[p]                          (only words 0..3 decide the cost)
g_p     ∈ valid_gammas(b_p)             (4^{h(b_p)} choices, each |corr| = 2^{−h(b_p)})
n[p+4]  = m[p] ;  n[p]  = m[p+4] ⊕ g_p
m_next  = lin_fwd(n, r)                 (byte transposition, then rotl by (r mod 31)+1)
w_r     = Σ_p h(m[p])
sign    = (Π_p sign_p) · (−1)^{m · rk[r]}
```

Every trail carries its exact key-dependent sign. The linear hull at a
fixed key is the exact sum over all trails with the same `(m_0, m_R)`;
`propagate()` computes it by correlation-vector propagation (pruned by
weight). ELP mode (`propagate(..., elp=True)`) gives the key-independent
potential under the (incorrect for a deterministic schedule)
independent-round-key assumption.

The **backward step** uses the same rules with the roles of `n[p]` and
`m[p+4]` exchanged: `n = lin_inv(m)`, `m[p] = n[p+4]` (this is `b_p`,
cost `h(b_p)`), `m[p+4] = n[p] ⊕ g_p` with `g_p` valid for `b_p`. The
`selftest` verifies that every forward edge is a backward edge with the
same cost (325 edges checked).

**Free-chain structure.** A round has weight 0 iff words 0..3 of its
input mask are zero; the round then acts as a pure bit permutation and
the tracked bit never meets `F`. Since the rotation schedule has
period 31, there are only 31 distinct windows. The exact free-chain
table (all 128 single-bit masks in words 4..7, 31 windows) is in
`LINEAR_MODEL.md` §4 and `linear_model_data.json`. Headline: the
longest weight-0 chain is **9 consecutive rounds**, at windows
`r ≡ 12 (mod 31)` and `r ≡ 27 (mod 31)`.

### 2.4. Verified `|corr| = 1` chains

Each of the 9-round chains has been checked against the real cipher
(fixed random keys, 2²¹ plaintexts, reduced rounds, final whitening
disabled to isolate the round function). Representative results:

| window r0 | rounds | start bit | end bit | key seed | predicted sign | empirical corr | σ |
|---|---|---|---|---|---|---|---|
| 12 | 9 | s[12].174 | s[21].79 | 1 | +1 | +1.00000 | 6.9e-04 |
| 12 | 9 | s[12].174 | s[21].79 | 2 | −1 | −1.00000 | 6.9e-04 |
| 12 | 9 | s[12].174 | s[21].79 | 3 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 1 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 2 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 3 | +1 | +1.00000 | 6.9e-04 |
| 0 | 5 | s[0].208 | s[5].55 | 1 | −1 | −1.00000 | 6.9e-04 |
| 0 | 5 | s[0].208 | s[5].55 | 2 | −1 | −1.00000 | 6.9e-04 |
| 0 | 5 | s[0].208 | s[5].55 | 3 | −1 | −1.00000 | 6.9e-04 |

The magnitude is 1 for every key. Only the sign depends on the key,
through `Σ_r m_r · rk[r]`. The model predicts that sign exactly.

The backward search finds the same 9-round weight-0 chains at the
corresponding end residues (20 and 4 mod 31); the `selftest` verifies
`|corr|=1` on the real cipher for both.

### 2.5. Exact signed hulls match the real cipher

For three trails at r0 = 12 with weights 1, 2, 3, the model produces
an exact signed prediction (fixed key, sum over all trails of weight
≤ w+4 with the same end masks) and the real cipher produces an
empirical correlation over 2²² plaintexts.

| window r0 | R | best-trail w | hull masks kept | predicted corr | empirical corr | σ | z |
|---|---|---|---|---|---|---|---|
| 12 | 10 | 1 | 4 | +0.500000 | +0.499997 | 4.9e-04 | −0.01 |
| 12 | 11 | 2 | 40 | −0.250000 | −0.250008 | 4.9e-04 | −0.02 |
| 12 | 12 | 3 | 3152 | −0.125000 | −0.124813 | 4.9e-04 | +0.38 |

Three independent predictions, three matches, |z| < 0.4 in every case.
The hull sum is not an approximation here; it is the exact polynomial
expansion of the trail system in the model, and it is what the real
cipher produces within sampling error.

### 2.6. Beam-search upper bounds, windows 12 and 27 (earlier run)

Layered beam search with the exact rules, starts = all 256 single-bit
masks, beam 1200, cells with `h ≤ 2` expanded. Each reported weight is
an **achievable single-trail weight**, i.e. an upper bound on the best
weight, not a minimum.

| rounds R | 1–9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|
| best weight, window r0=12 | 0 | 1 | 2 | 3 | 7 | 12 |
| best weight, window r0=27 | 0 | 1 | 3 | 3 | 6 | 11 |

This table covers only the two windows with the longest free chain.
§2.8 searches all 31 offsets and supersedes it: from R=13 on other
offsets (notably r0=23 forward and r0=20 backward) give lower
single-trail weights.

### 2.7. Harness validation

The empirical linear harness is validated against a hand-computed case
at w=8 (r=1, α = {word0 bit2, word4 bit0}, β = word0 bit3, fixed key).
The linear approximation `x₀ ⊕ F(x)₂ = x₁x₆` has correlation exactly
±1/2 with fixed key.

- **Fixed key**: observed correlation **0.4993** (expected 0.5, within
  sampling noise).
- **Random keys per sample**: observed |corr| **0.0022** (expected ≈0,
  because the sign averages out).

This confirms the harness is correct when used with fixed keys. It also
confirms that "random keys per sample" (used in an earlier version of
`misc/mini_trail.js`) washes out genuine linear signals and must not be
used for linear cryptanalysis. See `misc/validate_lineal_harness.js`.

### 2.8. Beam search over the exact model: 128 rounds, both directions, all offsets

Tool: `misc/mysx_linear_beam.py`. Parameters of the reported runs:
all 31 rotation offsets, up to 128 rounds, 256 single-bit starts,
beam 2000 (ranked by weight, then Hamming weight; deduplicated by mask),
`h(b) ≤ 16` per cell, `b = 0xFFFFFFFF` excluded, the 3 sparsest valid `g`
per cell (`--g-keep 3`), reported value = suffix minimum over R. Every
truncation only restricts the search, so the values are achievable
single-trail weights (upper bounds).

- Forward run (`--direction forward`, offsets are the first round mod 31):
  8 processes, 1972 s, output `misc/beam_full.json` / `beam_full.log`.
- Backward run (`--direction backward`, offsets are the last round mod 31):
  8 processes, 1512 s, output `misc/beam_bwd.json` / `beam_bwd.log`.
- Combined by `merge` over `beam_full.json`, `beam_pairs47.json`,
  `beam_bwd.json` (68 result sets from 3 files).

Validation before the runs: `selftest` passes in both directions. The
new backward checks are: (i) every forward edge is a backward edge with
the same cost (325 edges); (ii) the 9-round weight-0 chains are found
backward at end residues 20 and 4, with `|corr|=1` on the real cipher;
(iii) a backward R=14 trail with weight 21 is a valid forward trail with
equal weight. `reproduce` returns the §2.6 table exactly.

Best achievable weight per R, **combined forward + backward**
(minimum over offsets and directions, subject to `r0 + R ≤ 128` for
forward and to the backward end round fitting in the cipher):

| R | best weight | offset | direction | ≈ texts 2^{2w} |
|---|---|---|---|---|
| 9 | 0 | 4 | backward | 2⁰ |
| 10 | 1 | 4 | backward | 2² |
| 12 | 2 | 20 | backward | 2⁴ |
| 14 | 5 | 20 | backward | 2¹⁰ |
| 16 | 8 † | 23 | forward | 2¹⁶ † |
| 18 | 24 | 20 | backward | 2⁴⁸ |
| 20 | 38 | 20 | backward | 2⁷⁶ |
| 22 | 63 | 23 | forward | 2¹²⁶ |
| 24 | 88 | 3 | backward | 2¹⁷⁶ |
| 32 | 204 | 3 | backward | 2⁴⁰⁸ |
| 40 | 361 | 20 | backward | 2⁷²² |
| 48 | 485 | 20 | backward | 2⁹⁷⁰ |
| 56 | 630 | 27 | forward | 2¹²⁶⁰ |
| 64 | 786 | 27 | forward | 2¹⁵⁷² |
| 80 | 1081 | 9 | forward | 2²¹⁶² |
| 96 | 1336 | 21 | backward | 2²⁶⁷² |
| 112 | 1671 | 21 | backward | 2³³⁴² |
| 128 | 2248 | 3 | backward | 2⁴⁴⁹⁶ |

† The weight-8 trail of this row cancels once its hull is computed
(§2.9.1), so 2¹⁶ texts is not a distinguisher cost. The best certified
correlation at R=16 is the offset-20 backward hull, |corr| = 2⁻¹¹
(≈2²² texts).

- Largest R with an achievable trail of weight < 32 (≈2⁶⁴ texts): **19**.
- Largest R with weight < 64 (≈2¹²⁸ texts): **22**, with weight 63
  (forward offset 23). This is a **tie with the threshold**: at beam
  1000 the same cell gives 64/71, so the defensible statement is
  "≈20–22 rounds", not "22".
- Between R=22 and R=112 the best weight grows by roughly 12–21 per
  round (≈22 on average between R=48 and R=128, because the last step,
  112→128, is ≈36 per round: only offset 3 backward fits a full
  128-round trail).
- The cheapest trails alternate direction. Among the tabulated R values:
  backward at R=9, 10, 12, 14 (tied with offset 23 forward), 18, 20, 24,
  32, 40, 48, 96, 112, 128; forward at R=16, 22, 56, 64, 80. Each
  direction aligns best with a different set of rotation windows.
- The R=128 best (offset 3 backward) covers exactly rounds 0..127
  (`end_round(3) = 127`, `realizable_R = 128`). It is a real trail
  inside the cipher, not a virtual extension. Offsets whose
  `realizable_R < R` are excluded from the minimum.

### 2.9. Hull check: single-trail weight is not universally a correlation

The saved trails were checked against the real cipher prefix by prefix
(fixed key, final whitening disabled, 2¹⁷–2¹⁸ states). Script:
`misc/verify_beam_trail.py`; trail counting: `misc/hull_count.py`.

**Offset 20 backward, R=14, w=5** (covers rounds 100..113). This trail
is **isolated in its hull** and its empirical correlation matches the
prediction:

| R | weight w | predicted 2^{−w} | empirical | σ |
|---|---|---|---|---|
| 1 | 1 | 0.5000 | −0.4947 | 0.0028 |
| 2 | 3 | 0.1250 | −0.1206 | 0.0028 |
| 3 | 4 | 0.0625 | −0.0601 | 0.0028 |
| 4 | 4 | 0.0625 | +0.0601 | 0.0028 |
| 5–14 | 5 | 0.0312 | ±0.0279 | 0.0028 |

`hull_count` on the saved end mask returns **exactly one trail** at the
minimum weight for every R from 1 to 14 (layer sizes 4, 64, 84, 10, 4,
2, 1, 1, …, 1; the layer collapses to a single trail from R=7). The
predicted and empirical magnitudes agree within σ at every R. There is
**no cancellation** for this end mask. The weight is flat from R=5 to
R=14: the trail is five cheap rounds followed by a 9-round weight-0
chain, so the rows R=5–14 are the same signal, not independent
confirmations.

**Offset 23 forward, R=14, w=5** (start bit 197 of `s[23]`). This
trail is **not** isolated and cancels from R=8:

| R | weight w | predicted 2^{−w} | empirical |
|---|---|---|---|
| 1–4 | 0 | 1 | ±1.0000 |
| 5–7 | 1 | 0.5000 | −0.5014 |
| 8–10 | 2 | 0.2500 | ±0.0010 |
| 11–13 | 3 | 0.1250 | ±0.0012 |
| 14 | 5 | 0.0313 | −0.0001 (2 keys: also +0.00001) |

The model is exact up to R=7. From R=8 the empirical correlation is zero
because **two distinct trails of weight 2 share the same end masks** and
cancel (confirmed by exact enumeration with `hull_count.py`).

**Other offsets** (one key, 2¹⁶ states, σ=0.0039): r0=12 forward matches
the single trail (R=10: 0.497 vs 0.5; R=12: −0.116 vs 0.125); r0=27 and
r0=26 forward are ≈2× larger than predicted (R=10: 0.25 and 0.24 vs
0.125; R=12: 0.037 and 0.122 vs 0.016 and 0.0625); r0=24 forward is
cancelled (R=10: 0.005 vs 0.125). At R=14 the predicted values are
below this test's resolution.

Across the trails checked, the real correlation was exact (offset 20
backward at R=14, and r0=12 forward up to R=12), ≈2× larger (r0=26,
r0=27 forward), or exactly zero (r0=23 forward from R=8, r0=24 forward).
Hull effects are not a uniform correction, and they are not always
destructive: some trails survive intact.

**The offset-20 backward trail at R=14 (weight 5) is therefore a
verified linear distinguisher on a 14-round window (rounds 100–113)**:
it is isolated in its hull and its empirical correlation matches the
prediction on the real cipher. It is a property of that window of the
cipher, not a distinguisher for a 14-round version starting at round 0
and not an attack on the 128-round cipher. §2.9.1 extends it to 16
rounds.

### 2.9.1. Exact hull at R=15–17 (budgeted, meet-in-the-middle)

Tools: `misc/hull_bidir.py` (forward and backward frontiers joined in the
middle; complete for all trails of weight ≤ `wmax`; optional exact signs
for random keys), `misc/scan_endpairs.py`, `misc/test_signed_dp.py`,
`misc/emp_check.py`. Inputs: `misc/beam_paths_bwd20.json`,
`misc/beam_paths_fwd23.json`. Full description: PAPER.md §4.10.5 and
`misc/HULL_R15_R17.md`. Validation: `selftest` passes; the signed hull
equals `propagate()` on 40 of 40 end masks (forward windows r0=12 and
27, R ≤ 12, two keys); at R=14 it reproduces `hull_count.py`.

| trail | R | rounds | w1 | trails u→v found | budget | exact hull |
|---|---|---|---|---|---|---|
| offset 20 bwd | 14 | 100–113 | 5 | 1 × w5 | 7 | ±2⁻⁵ (isolated) |
| offset 20 bwd | 15 | 99–113 | 8 | 2 × w8 | 10 | +2⁻⁷ (two trails add) |
| offset 20 bwd | 16 | 98–113 | 12 | 2 × w12 | 14 | +2⁻¹¹ (two trails add) |
| offset 20 bwd | 17 | 97–113 | 16 | 2 × w16 | 18 | 0 (cancellation) |
| offset 23 fwd | 15 | 23–37 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 16 | 23–38 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 17 | 23–39 | 14 | 4 × w14 | 16 | 0 |

Empirical check (key `rand_key(1000)`): offset 20 backward, R=16,
N = 2²⁸: corr = +6.06×10⁻⁴ ± 6.1×10⁻⁵ against a hull prediction of
4.88×10⁻⁴ (+1.9σ), a single-trail value of 2.44×10⁻⁴ (+5.9σ) and zero
(+9.9σ); the sign matches. Offset 23 forward, R=16, N = 2²⁴:
+3.7×10⁻⁴ ± 2.4×10⁻⁴, 16σ from the single-trail value ±3.9×10⁻³.

R=17 scan (`scan_R17.log`): the top 8 end pairs of offset 20 backward (7
computed, 1 over the state cap) and of offset 23 forward all cancel
exactly within a budget equal to their own weight, for both keys.
Offsets 19 backward, 24 forward, 3 backward and 2 backward (weights
23–26) exceeded the cap: undecided.

Limits: a hull of 0 means "no net contribution up to the budget", not a
correlation of exactly 0; heavier trails (weight ≥ 15 at R=16, ≥ 19 at
R=17) are not summed; the empirical value at R=16 is 1.9σ above the
hull; one key only; R≥18 (weights ≥ 24) exceeds the enumeration caps and
is undecided, including the weight-63 trail at R=22.

### 2.10. Conclusion

**No linear bound is established over 128 rounds.** What is established
is an exact model of `F` and of the round, verified short-range linear
structure, a **verified distinguisher on a 16-round window** (offset 20
backward, exact hull 2⁻¹¹ at R=16), and an empirical picture of where
cheap single trails end (≈20 rounds in the family searched). What is
not:

1. **A distinguisher length beyond R=16.** R=16 is established for the
   offset-20 backward trail (exact hull over trails of weight ≤ 14 plus
   a one-key measurement). At R=17 the best pairs cancel within the
   budget, which does not exclude a smaller correlation from heavier
   trails or other end pairs. R≥18 is undecided; the trails of §2.8 at
   R=18–22, including the weight-63 trail at R=22, were not checked.
2. **A certified lower bound** on the best trail weight over 128
   rounds. Beam search only gives upper bounds; the truncations
   (`g-keep 3`, beam, single-bit starts, exclusion of `b=0xFFFFFFFF`)
   may hide cheaper trails. The MILP/SAT encoding is proposed in
   `LINEAR_MODEL.md` §7 but not implemented (the cost is
   `h(b) = Σ ⌈k/2⌉` over runs of `k` consecutive edges of `G_b`).
3. **Multi-bit starts.** `--starts pairs47` (pairs inside words 4..7)
   and `--starts rand:5000:4` (5000 random 4-bit masks) were explored
   and did **not** improve on single-bit starts at any R. `pairs47`
   covers a small structured subset; `rand:5000:4` covers 5000 masks
   out of 2²⁵⁶, so it is not conclusive for structured multi-bit
   masks. The honest statement is "the multi-bit starts tested do not
   improve on single-bit", not "multi-bit starts do not help".
4. **Key recovery from any hull.** A distinguisher is not an attack; no
   partial-key hypothesis in the outer rounds has been tried.

The 9-round free chain is a structural property of the rotation
schedule. It is not an attack: beyond it, the best single-trail weight
grows by roughly 12–21 per round, so the count of "free" rounds is not
a reduction of the 128 by 9 in any useful sense.

The most likely attack surface remains linear, by analogy with Simon
(linear-hull key-recovery attacks reach 49 of Simon128/128's 68 rounds;
Chen–Wang, FSE 2016). **MYSX's linear security over 128 rounds is
unknown.**

---

## 3. Integral cryptanalysis (division property, preliminary)

Tools: `misc/mysx_division_property_v2.py`, `misc/verify_division.py`.

**Model.** Standard bit-based division property (Todo–Morii FSE 2016
formulation): COPY is modelled as `k_a = Σ k_copies` (each copy may
carry the trace or not); XOR is modelled as `k_c = k_a + k_b` with
`(1,1)` invalid; AND is modelled as `k_c = k_a OR k_b`. The naive
`k_c = k_a ⊕ k_b` rule that appears in some references is **not
sound** when the XOR operands share input variables; MYSX's
`F = C ⊕ D` has both `C` and `D` depending on `R`, so the naive rule
overestimates balanced bits via spurious cancellations (oscillating,
non-converging counts in our experiments — those numbers are an
artifact and are not reported here). The `(1,1)`-invalid rule and the
OR-conservative rule were checked to agree on the tested input
patterns.

**Results** (r0 = 0 only).

| Input | Active bits | Integral size | Rounds with balanced bits | Saturation |
|---|---|---|---|---|
| bit 0 of word 0 | 1 | 2 | 10 | R = 11 |
| word 0 | 32 | 2³² | 6 | R = 7 |
| words 0 and 4 | 64 | 2⁶⁴ | 5 | R = 6 |

The **integral distinguishers** are the last two rows: 6 rounds with
a 2³²-text integral, and 5 rounds with a 2⁶⁴-text integral. They
cover 4.7% and 3.9% of the 128 rounds.

The first row (1 active bit, 2-text integral) is **not** a
meaningful integral distinguisher: with 2 texts, "balanced output
bit" means "output bit independent of the input bit". It is a
**single-bit dependency propagation** result — 10 rounds for the
active bit to reach all 256 output bits — and no integral security
conclusion is drawn from it.

**Empirical verification.** The 6-round distinguisher (word 0
active) and the 10-round single-bit dependency were verified against
the real cipher (fixed random key, all non-active input bits random,
20,000 samples): the predicted balanced bits never flipped, while
control bits (predicted not balanced) flipped with probabilities
6.5%–87%. The 5-round distinguisher (words 0,4 active) was not
verified empirically, because a 2⁶⁴-text integral cannot be
approximated by 20,000 random samples.

**Comparison with Simon (normalized).** Simon32/64 has a 14-round
integral distinguisher with 31 active bits under the conventional
bit-based division property, and a 15-round one using three subsets
(Todo–Morii FSE 2016): 44% of its 32 rounds. MYSX's 6-round /
2³²-text distinguisher covers 4.7% of its 128 rounds. In relative
coverage MYSX is stronger; in absolute rounds Simon reaches further
(14 vs 6) even though MYSX has 4× more rounds. The two are not directly
comparable without normalizing by total rounds.

**What this does not establish.** Integral distinguishers beyond 6
rounds for multi-bit inputs; behaviour for r0 ≠ 0 (rotation has
period 31; windows 12 and 27 are where linear chains are longest);
full-block inputs (255 active bits); three-subset division property
(Todo–Morii FSE 2016; variant without unknown subset: Hao et al.,
EUROCRYPT 2020) and traceability-enhanced variants (Wang et al., 2023;
citation to be verified), which may extend the distinguishers; and any
key-recovery attack based on these distinguishers.

---

## 4. Related-key cryptanalysis

Tools: `misc/keyschedule_test.js` + `misc/keyschedule_test_extended.js`
(22 tests).

Coverage: exhaustive weight-1 (512 bits), exhaustive weight-2
(130,816 pairs), weight-3 "same Δ" (1,680 trials), beam search up to
weight-6 (beam 50), 5 base keys, structured patterns, cycles, weak
keys, influence matrix.

| Metric | Result |
|---|---|
| Persistent `Δrk[r]=0` (r≥1) | 0 in all tests |
| Beam search worst `max_r weight` | 139 (ideal 128) |
| Minimum weight at r≥8 | 103 |
| Maximum low-weight window (<20) | 3–4 rounds |
| Worst bit (weight-1) | bit 160 (word 5, bit 0), 1-bit diff at r=1 |
| Weak keys / cycles / fixed points | None |
| Influence at r=64 | mean 0.498, min 0.406, max 0.590 |

**Limitations.** Heuristic, not a proof. No targeted MILP/SAT
related-key model (~650k variables). Adaptive related keys, biclique,
and algebraic attacks on the key schedule not covered. **Related-key
security is unknown.**

**Round-key recovery.** The only non-linear operation of the key
schedule is the 8 modular additions per step, and the schedule is
bijective. How many consecutive round keys a SAT solver needs to
recover the master key (about three by counting) has not been measured;
that number bounds what a partial key-recovery attack can lead to.

---

## 5. Diffusion / avalanche ladder

Tool: `misc/avalanche.js`. N=2000 keys, r=1..24. Matrix: 256 input bits
× 256 output bits per round.

| Metric | Value | Interpretation |
|---|---|---|
| `r_dif` (worst bit reaches all 256 output bits) | **15** | 12% of total rounds; slower than AES (~2), comparable ratio to ChaCha20 |
| `r_sac` (SAC matrix indistinguishable from uniform) | **≈22** | With N=2000, `maxAbsZ` converges to 4–10 (expected ~4.5), `zChi` ∈ ±4 |
| Worst input bit | **33** (word 1, bit 1) | Structural, consistent from r=5 |
| Fastest diffusion | bit 0 (word 0, bit 0) | Reaches 256 output bits at r=15 |

The worst bit is structural, not noise. The diffusion is slower than
AES but the ratio to total rounds (12%) is in line with established
ciphers. With 128 rounds, 15 of "warm-up" are acceptable.

---

## 6. Mini-MYSX validation and non-degeneracy

Tool: `misc/mini.js`, `misc/check_mini.js`,
`misc/check_mini_nondegenerate.js`.

**w=32 reproduces `mysx.prod.js` exactly**: F and MYZ_PERM are
bit-identical (tested against 16 fixed inputs, all OK).

**Keyword / w compatibility:**

| w | Keyword | Permutation length | Status |
|---|---|---|---|
| 32 | `MYSZKOWS` | 32 | OK (real MYSX) |
| 16 | `MYSZKOWS` | 16 | OK (L→R→L cycle at word 0, non-degenerate) |
| 16 | `MYSZ` | 16 | OK (no L→R→L cycle at word 0) |
| 8 | `MYSZKOWS` | 8 | **DEGENERATE** (L→R→L cycle at word 0; differential probability 1 at all rounds) |
| 8 | `MYSZ` | 8 | OK (non-degenerate from r=3) |

The w=8 + `MYSZKOWS` degeneracy is a design artifact of the 1-row
Myszkowski grid at w=8, not a property of MYSX. Use `kw='MYSZ'` for
w=8, or w=32 directly.

---

## 7. Generic attacks

| Attack | Complexity | Verdict |
|---|---|---|
| Classical brute force | 2⁵¹² operations (uniformly random 512-bit key) | Infeasible |
| Grover (quantum) | 2²⁵⁶ iterations (uniformly random 512-bit key) | Infeasible with foreseeable technology |
| Block collisions (birthday) | 2¹²⁸ blocks | Infeasible |

**Note on Grover.** With a uniformly random 512-bit key, Grover leaves
256 bits of effective security. Theoretical estimate only; no other
post-quantum analysis has been done.

**Note on the 512-bit key.** The API's key-derivation functions start
from HKDF-Extract (a 256-bit pseudorandom key). HKDF-Expand can output
64 bytes, but they are a deterministic function of that 256-bit value,
so a derived `encKey` carries at most 256 bits of entropy. If the master
secret has 256 bits of entropy, the effective classical security is 256
bits (not 512) and the Grover figure is 2¹²⁸ (not 2²⁵⁶). The 2⁵¹² and
2²⁵⁶ figures apply only to a uniformly random 64-byte key supplied
directly to `aeadEncrypt`.

---

## 8. Structural / Simon attacks

MYSX uses Simon's `F`. It is not Simon. Differences:

- Block size / branch organization: MYSX is an SPN-like structure with
  four parallel Feistel cells over 32-bit word pairs. Simon is a
  classical 2-branch Feistel over `n`-bit halves.
- Four parallel `F` per round (Simon uses 1).
- Myszkowski byte transposition (Simon has none).
- Round-dependent word rotations (Simon has none).
- Non-linear ARX key schedule (Simon's is linear).
- 128 rounds vs 68.

**What transfers.** The exact LAT of `F` — its closed form
`|corr| = 2^{−h(b)}`, its validity condition `l ∈ colspace(A_b)`, and
its sign structure — is a property of the function and therefore
applies to MYSX regardless of the surrounding structure (Section 2.2
is the transfer). That is the correct starting point for MYSX-specific
linear cryptanalysis; the failed models of the previous draft used a
different (incorrect) F model.

**What does not transfer.** Key recovery from Simon's linear key
schedule does not apply to MYSX's non-linear schedule. Linear hull
attacks against Simon are highly structured around Simon's
Feistel-branch and its round-reduced behaviour; the MYSX hull is a
different object and must be computed from the MYSX round model.
Integral distinguishers against Simon rely on its 2-branch Feistel
structure and its key schedule; the preliminary MYSX results in
Section 3 are considerably shorter, and their relationship to Simon's
is one of normalized coverage, not direct transfer.

**Published Simon results** (context only; figures checked against the
papers' abstracts, unverified round counts from earlier drafts were
removed):

- Linear-hull key-recovery attacks with dynamic key-guessing reaching
  49 rounds of Simon128/128 (Chen–Wang, FSE 2016, ePrint 2015/666).
- A 34-round linear characteristic with correlation 2⁻⁶¹ for Simon128
  and improved linear hulls (Shi et al., ePrint 2014/973).
- Differential analysis of Simon and Speck (Biryukov–Roy–Velichkov,
  FSE 2014).
- Integral distinguishers: 14 rounds for Simon32 (conventional
  bit-based division property) and 15 with three subsets (Todo–Morii,
  FSE 2016); 14/16/18/22/26 rounds for Simon32/48/64/96/128
  (Xiang–Zhang–Bao–Lin, ASIACRYPT 2016).
- Structural observations on the SIMON family
  (Kölbl–Leander–Tiessen, CRYPTO 2015).

**None of these results is transferred to MYSX in this paper.** The
MYSX-specific analysis (Sections 1–4 above, plus
`cryptanalysis/models/linear/`) is what provides the evidence.

---

## 9. Functional tests

`MYSX_ENABLE_TEST=1 node mysx.test.js` → **GLOBAL RESULT: PASS**.

The suite covers:

- KAT regression (16 blocks with `key[i]=i`).
- Block round-trip via CTR (8 lengths).
- AEAD round-trip with AAD.
- AEAD negative tests (altered nonce, ct, tag, AAD).
- NonceGuard policy (without guard rejected, `unsafeNoGuard` accepted,
  operational limit enforced, stats coherent, LRU eviction).
- HKDF correct lengths and context separation.
- PBKDF2 without salt rejected; deterministic with same salt;
  different salts → different keys.
- Avalanche (indicator only; 126.93/256, ideal 128).

**These tests do not prove cryptographic security.** They verify
functional correctness and negative-case handling. The test suite
explicitly reports `CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`.

---

## 10. Analysis limitations

- **Differential**: upper bounds on single-trail for one input at
  r=12–14, rotation offset not varied; one trail verified at r=4
  (clustering factor 2.00×); no lower bounds; no full clustering
  analysis; no inputs in the free windows.
- **Linear**: exact model of F established and verified against the
  real cipher at small round counts (|corr|=1 chains at 5 and 9
  rounds; exact signed hulls at r=10,11,12). Beam search over the
  model, **in both directions and merged over all 31 offsets**, up to
  128 rounds, gives achievable single-trail weights: 2 at R=12, 5 at
  R=14, 38 at R=20, below 64 up to R=22 (63, a tie with the
  threshold), 2248 at R=128 (offset 3 backward). The offset-20
  backward trail at R=14 (rounds 100–113) is **isolated in its hull**
  (`hull_count` = 1) and its empirical correlation matches 2⁻⁵; an exact
  budgeted hull extends it to R=16 (|corr| = 2⁻¹¹): that is a verified
  linear distinguisher on a 16-round window. Other trails cancel or are
  ≈2× larger (the best R=17 pairs cancel within the budget), so these
  are not universally distinguisher lengths. **No lower bound over 128
  rounds; no hull-aware bound beyond R=17; hulls are exact only up to a
  weight budget; no key-recovery cost estimate. Multi-bit starts (pairs47,
  rand:5000:4) were explored and did not improve on single-bit starts,
  but the random sample is too small to be conclusive for structured
  multi-bit masks.**
- **Integral**: preliminary. 6-round distinguisher with 2³² texts
  (word 0 active) and 5-round distinguisher with 2⁶⁴ texts (words 0,4
  active), using the sound `(1,1)`-invalid division-property rule.
  A 10-round single-bit dependency propagation is reported for context
  but is not an integral distinguisher. Only r0 = 0 tested; other
  round windows, full-block inputs, and three-subset / traceability-
  enhanced DP are not explored. No key-recovery attack was attempted.
- **Related-key**: heuristic up to weight-6; no targeted MILP; number
  of round keys needed to recover the master key not measured.
- **Impossible differential, boomerang, algebraic**: not analyzed.
- **No independent public cryptanalysis.**
- **No post-quantum analysis** beyond the trivial Grover bound.
- **No side-channel analysis.** JavaScript execution is not
  constant-time; cache-timing attacks on `crypto.subtle` HMAC are out
  of scope here but may matter in some deployments.

---

## 11. Verdict

**MYSX-256/512 v0.1-draft2 is an experimental proposal, not a secure
cipher.** The differential analysis reports upper bounds on
single-trail weights (one input, rotation offset not varied) with one
trail verified at r=4 (clustering factor 2.00×), not a security proof.
The linear side has an exact model of `F` and of the round; it
reproduces the real cipher's linear behaviour on the small round counts
where it has been checked, and it establishes `|corr|=1` chains at 5 and
9 rounds plus exact signed hulls at r=10–12. A beam search over that
model, run in **both directions** across all 31 rotation offsets and
merged, finds that cheap single trails end at roughly 20 rounds (weight
38 at R=20, below 64 only up to R=22 with 63 — a tie with the threshold
— then roughly 12–21 more per round up to R=112; 2248 at R=128, offset 3
backward). The offset-20 backward trail at R=14 (weight 5, rounds
100–113) is isolated in its hull and its empirical correlation matches
the prediction, and an exact budgeted hull extends it to R=16 (rounds
98–113, |corr| = 2⁻¹¹): **that is a verified linear distinguisher on a
16-round window**; at R=17 the best pairs cancel within the budget. For other trails, a check against the real cipher shows that a
single-trail weight can be exact, ≈2× too low, or exactly cancelled, so
these numbers say where cheap trails end, not universally how long a
distinguisher is. No lower bound over 128 rounds has been established,
no key-recovery attack has been attempted, and hull-aware bounds beyond
R≈14 are unexplored. Multi-bit starts (pairs47, rand:5000:4) did not
improve on single-bit starts, but the random sample is too small to be
conclusive. The integral analysis is preliminary: it establishes 5–6
round distinguishers with multi-bit inputs (2³² and 2⁶⁴ texts) and a
10-round single-bit dependency propagation, but only for the first round
window (r0 = 0). The related-key analysis is heuristic. No
impossible-differential, boomerang, or algebraic analysis has been done.
The cipher has not been externally audited.

### What to do

- **Do not use MYSX in production.** For real data use AES-256-GCM or
  XChaCha20-Poly1305.
- **If reviewing**, focus on: the exact signed hull for the best
  end-mask pairs of §2.8 at R=18–22 (R=15–17 are done, §2.9.1; this is
  the step that turns a weight into a distinguisher length beyond
  R=16), differential analysis over all
  rotation offsets and with inputs in the free windows, multi-bit starts
  with larger structured samples, a certified lower bound on the linear
  single-trail weight (the MILP/SAT encoding in `LINEAR_MODEL.md` §7),
  related-key MILP, and integral distinguishers beyond the preliminary
  5–6 round results in Section 3 (r0 ≠ 0, full-block inputs, and
  three-subset DP). The verified 9-round `|corr|=1` chains, the exact
  signed hulls at r=10–12, the isolation of the offset-20 backward trail
  at R=14 and its hull 2⁻¹¹ at R=16, the R=17 cancellations, and the
  cancellation of the r0=23 trail from R=8 are concrete
  points the new analysis must reproduce.
- **If extending**, the priorities are documented in PAPER.md §4.7,
  §4.9, §4.10 and §8.

### What **not** to do

- Do not add rounds on intuition: it does not eliminate short trails,
  only lengthens them.
- Do not declare MYSX "secure": differential, linear, integral,
  related-key, and others are attack families, not all of them.
- Do not present as "post-quantum": the key size is large, but the
  post-quantum analysis has not been done beyond Grover (and HKDF-derived
  keys carry at most 256 bits of entropy).
- Do not use the old approximate linear MILP (`misc/mysx_linear_milp.py`)
  as evidence: it is superseded and its trails do not verify.
- Do not report the 10-round single-bit dependency propagation as an
  "integral distinguisher": with 2 texts it is not one. Use the
  6-round / 2³²-text or 5-round / 2⁶⁴-text results instead.
- Do not read a beam-search weight as a distinguisher length or as a
  correlation in general: "an achievable trail of weight < 64 up to
  R=22" does not mean "a 22-round linear distinguisher exists", nor
  that none exists beyond it. The R=14 offset-20 backward trail is an
  exception where the hull check was completed and the weight *is* the
  correlation, on that window only.
- Do not compare a differential weight with a linear weight directly
  (differential: 2^w pairs; linear: 2^{2w} texts), and do not compare
  the differential figure (one input, one offset) with the linear
  figure (minimum over all offsets) as if they were the same kind of
  number.
- Do not treat the "≈20–22 rounds" threshold as exact: at beam 1000
  the same cell gives 64/71, so it is a tie with the 64 threshold, not
  a strict bound.

---

## 12. Reproducibility

| File | Purpose |
|---|---|
| `PAPER.md` | Full paper (spec + analysis + mini-MYSX) |
| `SPEC.md` | Formal specification |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `MYSX-paper.pdf` | Rendered paper (must be regenerated from the current `PAPER.md`) |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Public API |
| `mysx.test.js` | Functional tests (17 tests) |
| `cryptanalysis/models/linear/mysx_linear_model.py` | Exact linear model of F + round; `selftest` / `report` commands |
| `cryptanalysis/models/linear/LINEAR_MODEL.md` | Detailed documentation of the exact linear model |
| `cryptanalysis/models/linear/linear_model_data.json` | All numbers in Sections 2.1–2.7 as JSON |
| `misc/mysx_linear_beam.py` | Beam search over the exact model, all offsets, up to 128 rounds, forward and backward (`selftest`, `reproduce`, `run`, `merge`) |
| `misc/beam_full.log`, `misc/beam_full.json` | Output of the forward §2.8 run (`run --beam 2000 --jobs 8`) |
| `misc/beam_bwd.log`, `misc/beam_bwd.json` | Output of the backward §2.8 run (`run --direction backward --beam 2000 --jobs 8`) |
| `misc/beam_pairs47.json` | Output of the pairs47 multi-bit run (merged; not an improvement) |
| `misc/verify_beam_trail.py` | Prefix-by-prefix check of a saved beam trail against the real cipher, both directions (§2.9) |
| `misc/hull_count.py` | Counts trails sharing the end masks of a saved beam trail (§2.9) |
| `misc/hull_bidir.py` | Budgeted exact hull between two end masks, meet-in-the-middle, optional exact signs (§2.9.1) |
| `misc/scan_endpairs.py` | Exact budgeted hull of the top-K end-mask pairs of a beam (§2.9.1) |
| `misc/test_signed_dp.py` | Validation of `hull_bidir.py` signs against `propagate()` (§2.9.1) |
| `misc/emp_check.py` | Empirical correlation of a saved beam trail against the real cipher (§2.9.1) |
| `misc/beam_paths_bwd20.json`, `misc/beam_paths_fwd23.json` | Beam re-runs (`--paths 15..22`), input of §2.9.1 |
| `misc/scan_R17.log`, `misc/HULL_R15_R17.md` | R=17 scan output; summary and reproduction of §2.9.1 |
| `misc/mysx_milp.py` | Differential MILP |
| `misc/mysx_linear_milp.py` | Previous approximate linear MILPs (historical, superseded) |
| `misc/mysx_division_property.py` | Bit-based division-property MILP (v1; `--xor-rule` selects XOR or OR) |
| `misc/mysx_division_property_v2.py` | Bit-based division-property MILP (standard `(1,1)`-invalid XOR rule) |
| `misc/verify_division.py` | Empirical verification of integral distinguishers |
| `misc/keyschedule_test.js` | Basic key schedule audit |
| `misc/keyschedule_test_extended.js` | Exhaustive audit (22 tests) |
| `misc/check_trail.js` | Empirical differential trail at r=4 |
| `misc/check_linear_trail.js` | Empirical linear trail (superseded model) |
| `misc/check_linear_trail2.js` | Empirical linear trail (superseded model) |
| `misc/validate_diff_w32.js` | Differential verification at w=32 |
| `misc/validate_lineal_harness.js` | Hand-computed linear harness check |
| `misc/verify_trail_w32.js` | Per-trail verification at w=32 |
| `misc/avalanche.js` | Diffusion / avalanche ladder |
| `misc/avalanche.csv` | Raw avalanche data |
| `misc/ddt_lat.js` | DDT / LAT dumps |
| `misc/mini.js` | Mini-MYSX (w=8, w=16, w=32) |
| `misc/check_mini.js` | Mini-MYSX validation vs `mysx.prod.js` |
| `misc/check_mini_nondegenerate.js` | Keyword/w compatibility |
| `misc/mini_linear_fast.js` | Linear sampling at w=8, `kw='MYSZ'` |
| `misc/mini_linear_fixed.js` | Linear sampling with fixed keys |
| `misc/mini_trail.js` | Trail sampler (historical) |
| `misc/lab.js` | Scratch / experiments |

Fixed seed in tests (`0xC0FFEE`). MILPs are deterministic given the
solver and `gapRel`. The exact linear model's `selftest` verifies the
Python port of the cipher against `KNOWN_KAT_DIGEST` of `mysx.prod.js`,
so the linear results are stated relative to the reference
implementation. The beam search is deterministic given its parameters,
and `cmp` confirms that two independent forward runs
(`beam_full.json` and `beam_full_1.json`) are byte-identical.

**Public KAT.json digest**:
`5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`

**Internal regression digest**:
`3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`

A third-party implementation should target the **public digest**.

---

## 13. References

- Simon (NSA, 2013): `F` function used in the round.
- Myszkowski (1902): transposition with repeated-letter keyword.
- Blowfish (Schneier, 1993): π constants.
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104), AES-GCM
  (NIST SP 800-38D).
- König's theorem (bipartite matching / vertex cover) for the
  rank/matching identity in §2.2.
- Todo–Morii (FSE 2016, ePrint 2016/285): bit-based division property
  and integral distinguishers on Simon32, including the standard
  `(1,1)`-invalid XOR rule and the COPY / AND rules used in Section 3,
  and the three-subset variant.
- Hao–Leander–Meier–Todo–Wang (EUROCRYPT 2020): three-subset division
  property without unknown subset (not implemented here; may extend the
  integral distinguishers).
- Wang et al. (2023): traceability-enhanced division property (not
  implemented here; citation to be verified).
- Xiang–Zhang–Bao–Lin (ASIACRYPT 2016, ePrint 2016/857): MILP search of
  integral distinguishers by division property, including Simon32/48/
  64/96/128.
- Chen–Wang (FSE 2016, ePrint 2015/666): improved linear hull attack on
  round-reduced Simon with dynamic key-guessing.
- Shi–Hu–Sun–Song–Qiao–Ma (ePrint 2014/973): improved linear (hull)
  cryptanalysis of round-reduced versions of SIMON.
- Biryukov–Roy–Velichkov (FSE 2014): differential analysis of Simon and
  Speck.
- Kölbl–Leander–Tiessen (CRYPTO 2015): observations on the SIMON
  block cipher family.

---

## 14. Final warning

**MYSX has not been externally audited.** This document is a summary
of the author's self-analysis; the full analysis with methodology is
in [PAPER.md](PAPER.md). No result here replaces an independent
cryptographic review.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.
