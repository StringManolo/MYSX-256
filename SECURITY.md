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
| Differential (MILP) | **Upper bounds observed** | Weight 114 at r=14, extrapolating to 128 at r≈15. Not a proof: single-trail, one input, `gapRel=0.2`, Markov-independence not satisfied. |
| Linear (MILP) | **No bound established** | Three models tried; none produced trails that verified empirically. Linear security is unknown. |
| Related-key | **Heuristic coverage** | 22 tests up to weight-6 with no persistent `Δrk=0`. No targeted MILP; security unknown. |
| Integral | **Not analyzed** | — |
| Impossible differential | **Not analyzed** | — |
| Boomerang | **Not analyzed** | — |
| Algebraic (SAT) | **Not analyzed** | — |
| Grover (quantum) | **Infeasible (trivial estimate)** | 2²⁵⁶ iterations for a 512-bit key. No post-quantum analysis beyond Grover. |
| Classical brute force | **Infeasible** | 2⁵¹² operations. |
| Block collisions | **Infeasible** | 2¹²⁸ blocks (256-bit block). |

**Short verdict.** Differential resistance is reported as an *observed
upper bound*, not a proof. Linear security is *unknown* (all three
models produced trails that failed empirical verification). Related-key
security is *unknown* (heuristic only). The cipher is a
`v0.1-draft` awaiting external review. Do not use in production.

---

## 1. Differential cryptanalysis (summary)

Model: `mysx_milp.py` (PuLP + CBC/HiGHS), `a = Δx ∨ Δy`, `gapRel=0.2`,
`timeLimit=300`. Single-bit input at r=12–14 (w2b30).

| Rounds | Input | Weight (upper bound) | Single-trail prob. |
|---|---|---|---|
| 5 | w1b24 | 2 | 2⁻² |
| 6 | w1b24 | 6 | 2⁻⁶ |
| 7 | w2b30 | 10 | 2⁻¹⁰ |
| 8 | w2b30 | 18 | 2⁻¹⁸ |
| 12 | w2b30 | 68 | 2⁻⁶⁸ |
| 14 | w2b30 | 114 | 2⁻¹¹⁴ |

Empirical check at r=4, w0b0, N=2,000: match rate 0.5–1.15%
(prob ≈ 2⁻⁷). Consistent with the model and differential clustering.

**What this does not establish**: no lower bounds, no multi-bit input
search, no differential clustering analysis, no related-key
differentials. See PAPER.md §3.4.

---

## 2. Linear cryptanalysis (summary)

Three models tried. **None produced trails that verified empirically.**

| Model | Observed weights (r=1..10) | Empirical check |
|---|---|---|
| Hybrid (`α ∨ β ∨ γ`, no `γ ≥ α`) | 0, 2, 6, 8, 10, 18, 32, 48, 72, 109 | r=4, weight 8, 8 runs × N=2M, mean corr −4×10⁻⁴ (0.57σ). Trail does not exist. |
| Strict (`x = y = z = w` in XOR) | INFEASIBLE in r=1..10 | Model too restrictive. |
| Relaxed + correct AND | 0, 2, 8, 18, 35, 86, 157, 244, 338, 434 | r=3, weight 8, N=5M, corr −2.38×10⁻⁴ (0.53σ). Trail does not exist. |

**Conclusion.** No linear bound is established. The linear security of
MYSX is *unknown*. This is the most important open question, because
the best published attacks against Simon128/128 are linear (hull
attacks covering ~49/68 rounds). See PAPER.md §4.

---

## 3. Related-key cryptanalysis (summary)

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
security is unknown.** See PAPER.md §5.

---

## 4. Generic attacks

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

## 5. Structural / Simon attacks

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

**None of these results is transferred to MYSX in this paper.** The
MYSX-specific MILP analysis (Sections 1–3 above) is what provides the
evidence.

---

## 6. Functional tests

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

## 7. Analysis limitations

- **Differential**: upper bounds on single-trail for one input at
  r=12–14; no lower bounds; no clustering.
- **Linear**: no verified trail in three models; no bound.
- **Related-key**: heuristic up to weight-6; no targeted MILP.
- **Integral, impossible, boomerang, algebraic**: not analyzed.
- **No independent public cryptanalysis.**
- **No post-quantum analysis** beyond the trivial Grover bound.
- **No side-channel analysis.** JavaScript execution is not
  constant-time; cache-timing attacks on `crypto.subtle` HMAC are out
  of scope here but may matter in some deployments.

---

## 8. Verdict

**MYSX-256/512 v0.1-draft is an experimental proposal, not a secure
cipher.** The differential analysis reports upper bounds on
single-trail weights, not a security proof. The linear analysis is a
negative result on three models, not a bound. The related-key analysis
is heuristic. No integral, impossible-differential, boomerang, or
algebraic analysis has been done. The cipher has not been externally
audited.

### What to do

- **Do not use MYSX in production.** For real data use AES-256-GCM or
  XChaCha20-Poly1305.
- **If reviewing**, focus on: linear hull analysis (the most likely
  attack surface, by analogy with Simon), related-key MILP, and
  integral distinguishers.
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

## 9. Reproducibility

| File | Purpose |
|---|---|
| `PAPER.md` | Full paper (spec + analysis) |
| `SPEC.md` | Formal specification |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Public API |
| `mysx.test.js` | Functional tests |
| `mysx_milp.py` | Differential MILP |
| `mysx_linear_milp.py` | Linear MILP |
| `keyschedule_test.js` | Basic key schedule audit |
| `keyschedule_test_extended.js` | Exhaustive audit (22 tests) |
| `check_trail.js` | Empirical differential trail at r=4 |
| `check_linear_trail2.js` | Empirical linear trail at r=3 |

Fixed seed in tests (`0xC0FFEE`). MILPs are deterministic given the
solver and `gapRel`.

**Public KAT.json digest**:
`5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`

**Internal regression digest**:
`3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`

A third-party implementation should target the **public digest**.

---

## 10. References

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

## 11. Final warning

**MYSX has not been externally audited.** This document is a summary
of the author's self-analysis; the full analysis with methodology is
in [PAPER.md](PAPER.md). No result here replaces an independent
cryptographic review.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.
