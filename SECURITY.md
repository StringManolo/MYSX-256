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
| Linear (MILP) | **No bound established** | Three models tried; none produced trails that verified empirically. Harness validated (0.5 fixed key, 0.0022 random key). w=8 mini experiment with `kw='MYSZ'` confirms no signal for α=word0 bit0 up to r=5. Linear security is unknown. |
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
not a proof. Linear security is *unknown* (all three models produced
trails that failed empirical verification; the harness is now
validated, and no signal was detected in the w=8 mini with
`kw='MYSZ'`). Related-key security is *unknown* (heuristic only). The
cipher is a `v0.1-draft` awaiting external review. Do not use in
production.

---

## 1. Differential cryptanalysis

### 1.1. Model

Tool: `mysx_milp.py` (PuLP + CBC/HiGHS), `a = Δx ∨ Δy`, `gapRel=0.2`,
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

### 2.1. Three models tried, none verified

| Model | Observed weights (r=1..10) | Empirical check |
|---|---|---|
| Hybrid (`α ∨ β ∨ γ`, no `γ ≥ α`) | 0, 2, 6, 8, 10, 18, 32, 48, 72, 109 | r=4, weight 8, 8 runs × N=2M, mean corr −4×10⁻⁴ (0.57σ). Trail does not exist at w=32. |
| Strict (`x = y = z = w` in XOR) | INFEASIBLE in r=1..10 | Model too restrictive. |
| Relaxed + correct AND | 0, 2, 8, 18, 35, 86, 157, 244, 338, 434 | r=3, weight 8, N=5M, corr −2.38×10⁻⁴ (0.53σ). Trail does not exist at w=32. |

**Diagnosis**: the models have false positives. The likely cause is
the AND model: `act = α ∨ β ∨ γ` does not capture the shared-variable
structure of F, where the two rotated inputs come from the same `x`.
A correct linear model of F's correlation requires modeling the rank
of the `i-1` to `i-8` connectivity graph, not the per-bit AND
activity. We did not implement this model in v0.1.

### 2.2. Harness validation

The linear sampling harness was validated against a hand-computed case
at w=8 (r=1, α = {word0 bit2, word4 bit0}, β = word0 bit3, fixed key).
The linear approximation `x₀ ⊕ F(x)₂ = x₁x₆` has correlation exactly
±1/2 with fixed key.

- **Fixed key**: observed correlation **0.4993** (expected 0.5, within
  sampling noise).
- **Random keys per sample**: observed |corr| **0.0022** (expected ≈ 0,
  because the sign averages out).

This confirms the harness is correct when used with fixed keys. It
also confirms that "random keys per sample" (used in an earlier
version of `mini_trail.js`) washes out genuine linear signals and must
not be used for linear cryptanalysis.

See `validate_linear_harness.js`.

### 2.3. Mini-MYSX at w=8

The mini-MYSX (`mini.js`) at w=8 with keyword `'MYSZ'` (non-degenerate;
see Section 5) was used to sample linear correlations for
α = word 0 bit 0 against 74 single- and multi-bit β masks, over 4
independent keys × 2¹⁹ samples each.

- **σ (per-key)**: 1.38×10⁻³.
- **Expected max |corr|** under H₀ (296 estimates): 4.66×10⁻³.
- **Observed max |corr|**: 4.87×10⁻³ (max/σ = 3.53) at r=1.
- **Observed max/σ** across r=1..5 and α ∈ {bit0, bit5}: **3.83** at
  r=2, consistent with H₀ (expected max/σ ≈ 3.38).

**No linear signal detected** for these α masks up to r=5.

Note: the mini-MYSX with `w=8, kw='MYSZKOWS'` is **degenerate** (L→R→L
cycle at word 0, differential probability 1 at all rounds) and must
not be used for analysis. Use `w=8, kw='MYSZ'` or w=32 directly. See
`check_mini_nondegenerate.js`.

### 2.4. Conclusion

**No linear bound is established.** The linear security of MYSX is
*unknown*. This is the most important open question, because the best
published attacks against Simon128/128 are linear (hull attacks
covering ~49/68 rounds, complexity ~2¹²⁷).

---

## 3. Related-key cryptanalysis

Tool: `keyschedule_test.js` + `keyschedule_test_extended.js` (22 tests).

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

Tool: `avalanche.js`. N=2000 keys, r=1..24. Matrix: 256 input bits ×
256 output bits per round.

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

Tool: `mini.js`, `check_mini.js`, `check_mini_nondegenerate.js`.

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

**What transfers.** F-level distinguishers (linear and differential
biases of Simon's `F` as a function) are properties of the function,
not of the key schedule. Any such bias may in principle be embedded in
MYSX's structure.

**What does not transfer.** Key recovery from Simon's linear key
schedule does not apply to MYSX's non-linear schedule.

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
MYSX-specific MILP analysis (Sections 1–3 above) is what provides the
evidence.

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
- **Linear**: no verified trail in three models; no bound. Harness
  validated; w=8 mini experiment confirms no signal for low-weight α.
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
2.00×), not a security proof. The linear analysis is a negative result
on three models, not a bound; the harness is now validated and a w=8
mini experiment confirms no signal for low-weight α. The related-key
analysis is heuristic. No integral, impossible-differential, boomerang,
or algebraic analysis has been done. The cipher has not been externally
audited.

### What to do

- **Do not use MYSX in production.** For real data use AES-256-GCM or
  XChaCha20-Poly1305.
- **If reviewing**, focus on: linear hull analysis (the most likely
  attack surface, by analogy with Simon), related-key MILP, and
  integral distinguishers. The r=4 differential trail with clustering
  factor 2× is a concrete starting point for a full clustering
  analysis.
- **If extending**, the priorities are documented in PAPER.md §1.1
  and §8.

### What **not** to do

- Do not add rounds on intuition: it does not eliminate short trails,
  only lengthens them.
- Do not declare MYSX "secure": differential, linear, related-key, and
  integral are attack families, not all of them.
- Do not present as "post-quantum": the key size is large, but the
  post-quantum analysis has not been done beyond Grover.

---

## 11. Reproducibility

| File | Purpose |
|---|---|
| `PAPER.md` | Full paper (spec + analysis + mini-MYSX) |
| `SPEC.md` | Formal specification |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Public API |
| `mysx.test.js` | Functional tests (17 tests) |
| `mysx_milp.py` | Differential MILP |
| `mysx_linear_milp.py` | Linear MILP |
| `keyschedule_test.js` | Basic key schedule audit |
| `keyschedule_test_extended.js` | Exhaustive audit (22 tests) |
| `check_trail.js` | Empirical differential trail at r=4 |
| `check_linear_trail2.js` | Empirical linear trail at r=3 |
| `avalanche.js` | Diffusion / avalanche ladder |
| `mini.js` | Mini-MYSX (w=8, w=16, w=32) |
| `check_mini.js` | Mini-MYSX validation vs `mysx.prod.js` |
| `check_mini_nondegenerate.js` | Keyword/w compatibility |
| `validate_linear_harness.js` | Hand-computed linear harness check |
| `mini_linear_fast.js` | Linear sampling at w=8, `kw='MYSZ'` |
| `verify_trail_w32.js` | Per-trail verification at w=32 |

Fixed seed in tests (`0xC0FFEE`). MILPs are deterministic given the
solver and `gapRel`.

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
