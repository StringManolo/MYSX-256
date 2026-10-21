# MYSX-256/512 — Security Status (v0.1-draft)

**Proprietary cipher. NOT externally audited. DO NOT use for sensitive data.**
For production: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: `v0.1-draft` (2026)
This document is a standalone summary. The full analysis (with
methodology and data) is in [PAPER.md](PAPER.md) §3–§5.

`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`

## Summary

| Attack family | Status | What this means |
|---|---|---|
| Differential (MILP) | **Upper bounds observed + r=4 trail verified** | Weight 114 at r=14, extrapolating to 128 at r≈15. r=4 trail verified at w=32: observed 2⁻⁷ vs MILP 2⁻⁸, clustering factor **2.00×**. Not a proof: single-trail, one input, `gapRel=0.2`, Markov-independence not satisfied. |
| Linear (exact model) | **Exact F model established; short-range relations verified; no 128-round bound** | LAT of F in closed form (`|corr|=2^{-h}`, `h=rank(A_b)/2`). `|corr|=1` chains verified up to 9 rounds (3 keys). Exact signed hulls match the real cipher at r=10,11,12 (|z|<0.4). Beam search gives upper bounds on single-trail weight up to r=14 (weight 12). **No lower bound over 128 rounds.** |
| Related-key | **Heuristic coverage** | 22 tests up to weight-6 with no persistent `Δrk=0`. No targeted MILP; security unknown. |
| Integral | **Not analyzed** | — |
| Impossible differential | **Not analyzed** | — |
| Boomerang | **Not analyzed** | — |
| Algebraic (SAT) | **Not analyzed** | — |
| Grover (quantum) | **Infeasible (trivial estimate)** | 2²⁵⁶ iterations for a 512-bit key. No post-quantum analysis beyond Grover. |
| Classical brute force | **Infeasible** | 2⁵¹² operations. |
| Block collisions | **Infeasible** | 2¹²⁸ blocks (256-bit block). |

**Short verdict.** Differential resistance is reported as an *observed
upper bound* with **one trail verified at r=4** (clustering factor 2×),
not a proof. The linear side has moved from *"three models, no signal"*
to an **exact model of F**: the LAT has a closed form, mask propagation
is bit-exact, every trail carries an exact key-dependent sign, `|corr|=1`
chains are verified up to 9 rounds, and exact signed hulls match the real
cipher at r=10–12. That is real cryptanalytic structure, not noise. It is
**not** an attack on the 128-round cipher: no lower bound over 128
rounds, no key-recovery estimate, multi-bit starts unexplored. Related-key
security is *unknown* (heuristic only). The cipher is a `v0.1-draft`
awaiting external review. Do not use in production.

---

## 1. Differential cryptanalysis

### 1.1. Model

Tool: `misc/mysx_milp.py` (PuLP + CBC/HiGHS), `a = Δx ∨ Δy`, `gapRel=0.2`,
`timeLimit=300`. Single-bit input at r=12–14 (w2b30).

### 1.2. Observed upper bounds

| Rounds | Input | Weight (upper bound) | Single-trail prob. |
|---|---|---|---|
| 5 | w1b24 | 2 | 2⁻² |
| 6 | w1b24 | 6 | 2⁻⁶ |
| 7 | w2b30 | 10 | 2⁻¹⁰ |
| 8 | w2b30 | 18 | 2⁻¹⁸ |
| 12 | w2b30 | 68 | 2⁻⁶⁸ |
| 14 | w2b30 | 114 | 2⁻¹¹⁴ |

Extrapolation: the 128-bit threshold is reached at r≈15.

### 1.3. Direct verification of the r=4 trail at w=32

Trail: Δin = {w0b0}, Δout = {w0b4, w1b10, w1b16, w1b30, w6b4},
MILP weight 8 (8 active ANDs; Hamming weight of Δout is 5).

- **Sample size**: 8 fixed keys × 2¹⁷ pairs each = 1,048,576 pairs.
- **Observed hit rate**: 7.802×10⁻³ (8181 hits).
- **Expected from MILP**: 2⁻⁸ = 3.906×10⁻³.
- **Ratio**: **2.00×**.

The trail exists. The single-trail probability is a factor 2 higher
than the MILP predicts, consistent with **differential clustering**
(multiple trails with the same Δout contributing to the effective
probability). The MILP model is correct within a factor of 2 at r=4.

**If this factor holds at higher round counts**, the "128-bit
threshold at r≈15" becomes "at r≈17–18". The margin remains very
large, but the extrapolation should be read as approximate.

### 1.4. What this does not establish

- No lower bounds (requires gap=0 and multi-bit input search).
- No full clustering analysis (sum over all trails with the same
  Δin, Δout).
- No related-key differentials.

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

### 2.6. Beam-search upper bounds on single-trail weight

Layered beam search with the exact rules, starts = all 256 single-bit
masks, beam 1200, cells with `h ≤ 2` expanded. Each reported weight is
an **achievable single-trail weight**, i.e. an upper bound on the best
weight, not a minimum.

| rounds R | 1–9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|
| best weight, window r0=12 | 0 | 1 | 2 | 3 | 7 | 12 |
| best weight, window r0=27 | 0 | 1 | 3 | 3 | 6 | 11 |

At the 9-round mark the best trail still has weight 0 (`|corr| = 1`).
Beyond that, the weight grows. This is a structural feature of the
rotation schedule, not a key-dependent artifact.

### 2.7. Harness validation

The empirical linear harness is validated against a hand-computed case
at w=8 (r=1, α = {word0 bit2, word4 bit0}, β = word0 bit3, fixed key).
The linear approximation `x₀ ⊕ F(x)₂ = x₁x₆` has correlation exactly
±1/2 with fixed key.

- **Fixed key**: observed correlation **0.4993** (expected 0.5, within
  sampling noise).
- **Random keys per sample**: observed |corr| **0.0022** (expected ≈ 0,
  because the sign averages out).

This confirms the harness is correct when used with fixed keys. It also
confirms that "random keys per sample" (used in an earlier version of
`misc/mini_trail.js`) washes out genuine linear signals and must not be
used for linear cryptanalysis. See `misc/validate_lineal_harness.js`.

### 2.8. Conclusion

**No linear bound is established over 128 rounds.** What is now
established is an exact model of `F` and of the round, plus verified
short-range linear structure. The three things that *would* close the
question and that have not been done:

1. **A certified lower bound on the best trail weight over 128
   rounds.** Beam search only gives upper bounds from single-bit
   starts. The MILP/SAT encoding is proposed in
   `LINEAR_MODEL.md` §7 but not implemented.
2. **Multi-bit starts at high round counts.** Only single-bit starts
   were used in the beam search. In Simon, the best trails often start
   multi-bit.
3. **Key recovery from any hull.** A distinguisher is not an attack;
   no partial-key hypothesis in the last round has been tried.

The *effective* hard-round count in the best window is ~119 (128 − 9),
because the 9-round free chain costs nothing. That is a structural
property of the rotation schedule. It is not an attack on the full
cipher, but it is real, and it must be read into the security picture.

The most likely attack surface remains linear, by analogy with Simon
(hull attacks covering ~49/68 rounds, complexity ~2¹²⁷). **MYSX's
linear security over 128 rounds is unknown.**

---

## 3. Related-key cryptanalysis

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

---

## 4. Diffusion / avalanche ladder

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

## 5. Mini-MYSX validation and non-degeneracy

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

## 6. Generic attacks

| Attack | Complexity | Verdict |
|---|---|---|
| Classical brute force | 2⁵¹² operations | Infeasible |
| Grover (quantum) | 2²⁵⁶ iterations | Infeasible with foreseeable technology |
| Block collisions (birthday) | 2¹²⁸ blocks | Infeasible |

**Note on Grover.** With a 512-bit key, Grover leaves 256 bits of
effective security. Theoretical estimate only; no other post-quantum
analysis has been done.

**Note on the 512-bit key.** HKDF-SHA256 produces at most a 256-bit
pseudorandom key. If the master secret has 256 bits of entropy, the
effective security is 256 bits, not 512.

---

## 7. Structural / Simon attacks

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

**Published Simon128/128 attacks** (68 rounds):

- Linear-hull distinguishers covering ~49 rounds, complexity ~2¹²⁷
  (Chen–Wang, ePrint 2014/973).
- Differential distinguishers covering ~46–50 rounds, complexity
  ~2¹²⁵·⁷ (Biryukov–Roy–Velichkov, CRYPTO 2015).
- SAT-based algebraic distinguishers covering ~12–14 rounds.
- Integral distinguishers covering ~26 rounds.
- Structural observations on the SIMON family
  (Kölbl–Leander–Tiessen, CRYPTO 2015).

**None of these results is transferred to MYSX in this paper.** The
MYSX-specific analysis (Sections 1–3 above, plus
`cryptanalysis/models/linear/`) is what provides the evidence.

---

## 8. Functional tests

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

## 9. Analysis limitations

- **Differential**: upper bounds on single-trail for one input at
  r=12–14; one trail verified at r=4 (clustering factor 2.00×); no
  lower bounds; no full clustering analysis.
- **Linear**: exact model of F established and verified against the
  real cipher at small round counts (|corr|=1 chains at 5 and 9
  rounds; exact signed hulls at r=10,11,12). **No lower bound over
  128 rounds; only upper bounds from single-bit starts in the beam
  search; multi-bit starts unexplored; no key-recovery cost estimate.**
- **Related-key**: heuristic up to weight-6; no targeted MILP.
- **Integral, impossible, boomerang, algebraic**: not analyzed.
- **No independent public cryptanalysis.**
- **No post-quantum analysis** beyond the trivial Grover bound.
- **No side-channel analysis.** JavaScript execution is not
  constant-time; cache-timing attacks on `crypto.subtle` HMAC are out
  of scope here but may matter in some deployments.

---

## 10. Verdict

**MYSX-256/512 v0.1-draft is an experimental proposal, not a secure
cipher.** The differential analysis reports upper bounds on
single-trail weights with one trail verified at r=4 (clustering factor
2.00×), not a security proof. The linear side now has an exact model
of `F` and of the round; it reproduces the real cipher's linear
behaviour on the small round counts where it has been checked, and it
establishes `|corr|=1` chains at 5 and 9 rounds plus exact signed
hulls at r=10–12. That is an input to cryptanalysis, not a bound. No
lower bound over 128 rounds has been established, no key-recovery
attack has been attempted, and multi-bit starts at high round counts
are unexplored. The related-key analysis is heuristic. No integral,
impossible-differential, boomerang, or algebraic analysis has been
done. The cipher has not been externally audited.

### What to do

- **Do not use MYSX in production.** For real data use AES-256-GCM or
  XChaCha20-Poly1305.
- **If reviewing**, focus on: a certified lower bound on the linear
  single-trail weight over 128 rounds (the MILP/SAT encoding in
  `LINEAR_MODEL.md` §7 is the natural starting point), multi-bit
  starts, related-key MILP, and integral distinguishers. The verified
  9-round `|corr|=1` chains and the exact signed hulls at r=10–12 are
  concrete points the new analysis must reproduce.
- **If extending**, the priorities are documented in PAPER.md §4.7
  and §8.

### What **not** to do

- Do not add rounds on intuition: it does not eliminate short trails,
  only lengthens them.
- Do not declare MYSX "secure": differential, linear, related-key, and
  integral are attack families, not all of them.
- Do not present as "post-quantum": the key size is large, but the
  post-quantum analysis has not been done beyond Grover.
- Do not use the old approximate linear MILP (`misc/mysx_linear_milp.py`)
  as evidence: it is superseded and its trails do not verify.

---

## 11. Reproducibility

| File | Purpose |
|---|---|
| `PAPER.md` | Full paper (spec + analysis + mini-MYSX) |
| `SPEC.md` | Formal specification |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `MYSX-paper.pdf` | Rendered paper |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Public API |
| `mysx.test.js` | Functional tests (17 tests) |
| `cryptanalysis/models/linear/mysx_linear_model.py` | Exact linear model of F + round; `selftest` / `report` commands |
| `cryptanalysis/models/linear/LINEAR_MODEL.md` | Detailed documentation of the exact linear model |
| `cryptanalysis/models/linear/linear_model_data.json` | All numbers in Section 2 as JSON |
| `misc/mysx_milp.py` | Differential MILP |
| `misc/mysx_linear_milp.py` | Previous approximate linear MILPs (historical, superseded) |
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
implementation.

**Public KAT.json digest**:
`5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`

**Internal regression digest**:
`3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`

A third-party implementation should target the **public digest**.

---

## 12. References

- Simon (NSA, 2013): `F` function used in the round.
- Myszkowski (1902): transposition with repeated-letter keyword.
- Blowfish (Schneier, 1993): π constants.
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104), AES-GCM
  (NIST SP 800-38D).
- König's theorem (bipartite matching / vertex cover) for the
  rank/matching identity in §2.2.
- Chen–Wang (ePrint 2014/973): linear hull cryptanalysis of
  round-reduced Simon.
- Biryukov–Roy–Velichkov (CRYPTO 2015): differential analysis of
  Simon and Speck.
- Kölbl–Leander–Tiessen (CRYPTO 2015): observations on the SIMON
  block cipher family.

---

## 13. Final warning

**MYSX has not been externally audited.** This document is a summary
of the author's self-analysis; the full analysis with methodology is
in [PAPER.md](PAPER.md). No result here replaces an independent
cryptographic review.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.
