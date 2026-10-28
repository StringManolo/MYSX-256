# MYSX-256/512 v0.2-draft: A 256-bit Block Cipher with 512-bit Keys

**StringManolo**

**2026**

---

## Abstract

We present MYSX-256/512 v0.2-draft, an experimental 256-bit block cipher with 512-bit keys and 128 rounds, combining Feistel cells with Simon's F function, a Myszkowski byte transposition, word rotations, and an ARX key schedule. The cipher core (round function, F, transposition, key schedule) is unchanged from v0.1-draft2. The v0.2 revision changes two things: the rotation schedule and the AEAD packet format.

**Rotation schedule.** The consecutive schedule `(r mod 31)+1` of v0.1 is replaced by `rand_s9_45430` (31 explicit values in §2.8), selected by systematic search over 1M random 31-period schedules. On the 9 core metrics measured for v0.2 — integral at R=5/6, linear at R=10/14 both directions, exact DMITM, weight-0 chain, MILP differential at R=5 — the new schedule improves 6, ties 3, and regresses 0. The main weakness of v0.1, a differential trail of weight 2 at R=14 for offset r0=10 giving a distinguisher at 4 chosen pairs, is eliminated in v0.2 (best MILP weight at R=14 is 94 over 31 offsets, with r0=30 unresolved).

**AEAD v2.** The new namespace v2 (VERSION=0x02) adds: 512-bit secrets processed through HKDF-SHA512 (eliminating the 256-bit HKDF-SHA256 bottleneck of v1), 512-bit MAC keys, HMAC-SHA512 with 64-byte tags, one key per message (32-byte salt), authenticated header, rotation-calendar selected by a header byte, and Argon2id for password paths. The v1 API (consecutive calendar, HKDF-SHA256, PBKDF2-SHA256, 32-byte tag) is kept for reading legacy packets and is marked deprecated for new data. A cross-language KAT (Python reference vs JavaScript implementation) confirms 6/6 packets byte-identical; a 58-test security suite verifies the API.

The v0.2 analysis is partial by design. No lower bound over 128 rounds is established. No key-recovery attack has been attempted. No NIST SP 800-22 measurement for v0.2 exists (v0.1 passed). No external audit. MYSX is released for public review and must not be used to protect real data.

**Measured results for v0.2 (v0.1 values in parentheses):**

| Metric | v0.1 | v0.2 |
|---|---|---|
| Exact DMITM | 17 rounds | 9 rounds |
| Weight-0 chain | 13 rounds | 5 rounds |
| Truncated impossible | 39 rounds | 28 rounds |
| Integral dp5 (r0=0, word0) | 21/256 | 9/256 |
| Integral dp6 (r0=0, word0) | 4/256 | 4/256 |
| MILP differential R=5 | 4 | 4 |
| Linear single-trail R=10 fwd / bwd | 1 / 1 | 1 / 3 |
| Linear single-trail R=14 fwd / bwd | 5 / 5 | 8 / 11 |
| Linear single-trail R=128 forward | 2248 (backward) | 2294 (forward) |
| Linear single-trail R=128 backward | 2248 (backward) | 2161 (backward) |
| v2 cross-language KAT | — | 6/6 packets byte-identical |
| v2 security tests | — | 58/58 pass |

**PENDING for v0.2** (measured for v0.1, not re-measured for v0.2): beam differential (MILP only for v0.2); linear hull empirical verification for v0.2 (`lin_hull_v02` computes predictions but does not compare against the real cipher); full 31-offset integral sweep (only 6 offsets measured at R=5–6); NIST SP 800-22 (`nist_v02` skipped because `sts-2.1.2/assess` is not present). The full 31-offset differential sweep, the v0.2 backward beam to R=128, and the related-key re-validation are now measured and are no longer pending.

---

## Executive summary

We present MYSX-256/512 v0.2-draft, a 256-bit block cipher with 512-bit keys and 128 rounds. The design combines Feistel cells with Simon's round function, a Myszkowski byte transposition, word rotations, and an ARX key schedule. The cipher core is unchanged from v0.1-draft2. The v0.2 revision changes the rotation schedule and adds an AEAD v2 packet format. We provide the full specification, test vectors, and a self-analysis covering differential, linear, integral, impossible-differential, and related-key cryptanalysis, together with a functional and security validation of the v2 API.

**Rotation schedule.** The consecutive schedule `(r mod 31)+1` of v0.1 gives a differential trail of weight 2 at R=14 for offset r0=10, a 13-round probability-1 weight-0 chain, and a 17-round exact DMITM. These are not "tight margins"; they are structural alignments between the transposition and the consecutive step. The v0.2 calendar `rand_s9_45430` was selected by a systematic search over 1M random 31-period schedules followed by an 8-candidate evaluation on 9 metrics. It gives a 5-round weight-0 chain, 9-round exact DMITM, 28-round truncated impossible, a best MILP differential weight at R=14 of 94 (upper bound; r0=30 unresolved), and 9 balanced bits at R=5 (versus 21 for v0.1). The v0.1 offset r0=10 that was catastrophic for the differential analysis is eliminated in v0.2.

**AEAD v2.** HKDF-SHA512 with a 64-byte secret restores the 2^256 Grover bound; 512-bit MAC keys and HMAC-SHA512 tags replace the 256-bit HMAC of v1; the rotation calendar is selected by header byte CAL instead of hard-coded or environment variable; one key per message (32-byte salt) eliminates nonce reuse; Argon2id is used for password paths with explicit bounds. A 58-test security suite verifies the API; a cross-language KAT (Python reference vs JavaScript implementation) confirms 6/6 packets byte-identical.

**Differential.** The differential analysis reports upper bounds on the best single-trail weight over all 31 rotation offsets. For v0.1 at R=14, the best MILP weight is 2 (r0=10) and the worst observed non-None value is 211 (r0=21); the 128-bit threshold is reached at R≈24 for r0=10. For v0.2 at R=14, the best MILP weight over 31 offsets is 94 (r0=29), the worst is 335 (r0=2), and only r0=30 is unresolved; the 128-bit threshold has not been established for v0.2 by the offset sweep (all measured weights are far below 128 at R=14). The v0.1 r=4 trail at r0=0 has been directly verified with a clustering factor of 2.00× (observed 2^-7 vs MILP 2^-8); the v0.2 r=4 trail is not directly transferable and an informal re-run gives 16/2000 trail matches (0.80%) with average output difference weight 12.84.

**Linear.** The linear analysis is built on an exact, machine-checked model of F: its LAT admits the closed form |corr(b,g)| = 2^{-h(b)}, h(b) = rank(A_b)/2 on a 32-cycle, mask propagation is bit-exact, and every trail carries an exact key-dependent sign. Within this model we verify |corr|=1 chains over up to 9 consecutive rounds (three independent keys), and exact linear hulls at r=10,11,12 match the real cipher within sampling error (|z|<0.4). A beam search over the exact model, run in both directions for all 31 rotation offsets and up to 128 rounds, gives for v0.1 achievable single-trail weights of 2 at R=12, 5 at R=14, 38 at R=20, 2248 at R=128 (offset 3 backward); for v0.2 forward, 3 at R=12, 8 at R=14, 71 at R=20, 2294 at R=128 (offset 0 forward); for v0.2 backward, 6 at R=12, 11 at R=14, 69 at R=20, 2161 at R=128 (offset 3 backward). For v0.2 the largest R with an achievable trail of weight <32 is 17, and <64 is 19; for v0.1 merged, <64 is up to R=22 (weight 63 at offset 23 forward, a tie).

**Integral.** Standard division-property rules, extended to all 31 rotation offsets for v0.1 and to 6 offsets for v0.2. At r0=0, v0.1 has a 6-round (2^32-text) and a 5-round (2^64-text) distinguisher; v0.2 has 9/256 and 4/256 balanced bits at R=5/6 at r0=0. At r0=15 v0.1 extends to 10 rounds for both patterns with a thin tail (1 balanced bit at R=10). The r0=15 peak for v0.2 is PENDING.

**Impossible differentials.** v0.1 exact DMITM = 17, truncated = 39 (verified with `dmitm_trunc_v3.py --cal k1`). v0.2 exact DMITM = 9, truncated = 28 (verified with `dmitm_trunc_v3.py --cal v02 --verify 500`; conflict at w4b17). The truncated figure is a distinguisher, not a key-recovery cost.

**Related-key.** Inherited from v0.1 (key schedule unchanged). The v0.2 re-validation runs 22/22 PASS on the extended audit; no persistent Δrk[r]=0 for r≥1, no weak keys, no cycles, no fixed points. Slow diffusion at r=1–4 (expected: one Feistel round per cipher iteration). Worst bit: bit 160 (word 5, bit 0), 1-bit difference at r=1, consistent across base keys (structural, not noise). Beam-search score 139 (ideal 128). Heuristic, not a proof.

**The three geographies.** The differential, linear and integral analyses peak at different rotation offsets: differential r0=10 (v0.1) and r0=29 (v0.2); linear free chain r0=12 and r0=27; linear hull at offset 20 backward (≈r0=5–6 in first-round convention); integral r0=15 (v0.1). No single-offset bound describes the cipher as a whole. This is the main structural finding of the offset sweeps: the three analysis directions must be reported offset by offset, not by a single representative offset.

**Not established.** No lower bound over 128 rounds. No exact 128-round hull. No key-recovery attack. No NIST SP 800-22 for v0.2. No external audit. The v0.2 analysis is partial by design; PENDING items are listed in §4.14 and §8.

---

## 1. Introduction

MYSX-256/512 is an experimental block cipher. It is offered as a public proposal for cryptanalysis, not as a production primitive. The author makes no claim of security beyond the observed results reported here, and explicitly welcomes external review.

### 1.1. Security objectives (and non-objectives)

**Model.** MYSX is analyzed in the single-key, chosen-plaintext model for confidentiality, combined with an encrypt-then-MAC AEAD wrapper for integrity (Section 2.9). The design does not claim security under related-key, chosen-ciphertext, or side-channel models; see Section 5 for related-key coverage and Section 9 for engineering notes.

**Claimed security level.** None formally. The paper reports observed upper bounds on single-trail weights (Section 3), a verified exact linear model up to a small number of rounds (Section 4), a full-length beam search over that model in both directions (§4.10), and integral distinguishers at 6 rounds for multi-bit inputs at r0=0, extended to 10 rounds at r0=15 for v0.1 (§4.9). These are inputs to cryptanalysis, not proofs.

**Reading thresholds.** A differential trail of weight w needs about 2^w chosen pairs; a linear trail of weight w has |corr| = 2^{-w} and needs about 2^{2w} known texts. Therefore a 2^128-text budget corresponds to a differential weight threshold of ≈128 but to a linear weight threshold of ≈64. Differential and linear weights in this paper must not be compared directly; compare w_diff with 2·w_lin.

**Non-objectives.** MYSX v0.2 does not claim:

- post-quantum security beyond the trivial Grover bound (2^256 quantum iterations for a uniformly random 512-bit key; keys produced by the HKDF-SHA512 API of Section 2.9 from a 256-bit secret give 2^128; the v1 API's HKDF-SHA256 bottleneck gives 2^128 even for a 512-bit secret, see Section 6);
- resistance to related-key attacks beyond the heuristic coverage in Section 5 (key schedule unchanged from v0.1);
- resistance to integral attacks beyond the 6–10 round distinguishers of §4.9 for v0.1 and the 6-offset R=5–6 sweep for v0.2;
- resistance to impossible-differential, boomerang, or algebraic attacks beyond what §4.12 reports;
- resistance to linear-hull effects beyond the single-trail weights of §4.10 (no hull-aware bound beyond R=17);
- constant-time execution in JavaScript (side channels out of scope).

### 1.2. Design rationale

MYSX combines four building blocks, unchanged from v0.1:

1. **Simon's F** `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`. Chosen for its studied diffusion/linear/differential properties in Simon and its simplicity (no S-boxes, only AND/XOR/rotl). It does not inherit Simon's security proofs; the surrounding structure is different. See Section 7 for what transfers and what does not.
2. **Feistel cells over 32-bit word pairs.** Four parallel cells per round, then a byte transposition over the full 32-byte state, then word rotations. The result is classified as an SPN-like structure with Feistel cells, not as a "2-branch Feistel". See Section 2.1.
3. **Myszkowski transposition** (Section 2.3.1). A fixed byte permutation derived from the keyword MYSZKOWS. The choice is didactic; it provides byte-level diffusion but no cryptographic argument beyond that. An optimized permutation would provide strictly better diffusion per round; see Section 9.
4. **ARX key schedule** (Section 2.4). A bijective Feistel 8+8 update with modular addition, XOR, and rotations. Chosen for simplicity and to avoid S-boxes; analyzed in Section 5.

**Rotation schedule (v0.2).** The consecutive schedule `(r mod 31)+1` of v0.1 is replaced by `rand_s9_45430` (31 values in §2.8). The selection is systematic (§4.13). The consecutive schedule is not "moderately weak": at 3000 random schedules sampled without filtering, it is in the worst ~2% by exact DMITM and worst ~0.2% by weight-0 chain. The cause is the step of 1 aligning with the transposition period; the permutation is not the cause (40 random byte permutations with the consecutive schedule give mean exact DMITM 21.4).

**Parameter choices.** The parameter choices (256-bit block, 512-bit key, 128 rounds) are not derived from a formal argument. They were chosen to: provide a large block (avoid birthday-bound issues of 64-bit blocks); provide a large key (Grover leaves 256-bit security for a random 512-bit key); provide a large round count relative to Simon128/128 (68 rounds) as a precaution against unknown trails. No claim is made that 128 rounds is sufficient. The round count is a parameter, not a security level.

### 1.3. Comparison with related designs

| Design | Block | Key | Rounds | Structure | S-boxes |
|---|---|---|---|---|---|
| Simon128/128 | 128 | 128 | 68 | Feistel | No |
| Speck128/256 | 128 | 256 | 34 | ARX | No |
| ChaCha20 | 512 | 256 | 20 | ARX | No |
| MYSX-256/512 | 256 | 512 | 128 | SPN-like with Feistel cells | No |

MYSX's closest sibling is Simon. The differences (block size, branch organization, transposition, word rotations, non-linear key schedule) are substantial enough that Simon cryptanalysis does not transfer directly (see Section 7).

**Performance.** MYSX is estimated to run at a few MB/s in JavaScript, versus hundreds of MB/s for AES-GCM via WebCrypto (AES-NI). MYSX is not competitive on performance; it is a research primitive.

### 1.4. Versioning and revision notes

**Versioning.** The reference implementation (`mysx.prod.js`) is labelled v0.2-experimental. This document is the v0.2-draft of the design. The v0.1-draft2 paper (tag `v0.1-draft2` in the repository) is the previous design; its full analysis is preserved in `LEGACY_V1/`.

**Changes in v0.2.** The v0.2 revision changes two things relative to v0.1-draft2:

1. **Rotation schedule.** The consecutive schedule `(r mod 31)+1` is replaced by `rand_s9_45430` (Section 2.8). The selection is systematic; §4.13 documents the 9-metric evaluation, the false positive, and the control experiment showing that the permutation is not the cause.
2. **AEAD packet v2 (VERSION=0x02).** A new namespace v2 adds 512-bit secrets through HKDF-SHA512, 512-bit MAC keys, HMAC-SHA512 with 64-byte tags, one key per message, authenticated header, calendar selected by a header byte, and Argon2id for password paths. The v1 API is kept for reading legacy packets and is marked deprecated for new data.

**Revision notes for this v0.2-draft.** The following numerical corrections were made during this revision; they reflect the current `paper_results.json` (55 tests, 53 pass, 0 fail, 2 skip: `nist_v1`, `nist_v02`). No experimental result changed; only the transcription of results into the paper.

- **MILP differential R=5.** v0.1 is 4 (input w2b30, r0=0); v0.2 is 4 (min over r0 ∈ {0, 10, 20}). The metric is a **tie**, not an improvement. The "6 improvements, 3 ties, 0 regressions" count in the abstract is correct with this tie.
- **Truncated impossible for v0.2.** The conflict is at **w4b17** (first candidate, 28 rounds, R=74) and w4b20 (second candidate, 28 rounds, R=76). Earlier drafts reported w5b13; that was a transcription error.
- **Differential offset sweep for v0.2.** All 31 offsets are measured at R=14 in `diff_offset_sweep_v02`. The best is r0=29 with weight 94; the worst is r0=2 with weight 335; r0=19 is 275; r0=27 is 172; only r0=30 is `None`. Earlier drafts reported "6 offsets, r0=19 and r0=27 timed out"; that was stale.
- **Differential offset sweep for v0.1.** `diff_offset_sweep_full_v1` gives r0=10=2 (best), r0=21=211 (worst non-None), and `None` at r0 ∈ {0, 1, 2, 6, 18, 19, 20, 22, 23, 24, 25, 26, 27, 30}. The range of non-None values is 24–211. Earlier drafts cited "worst r0=30=266" and "121 vs 180 at r0=1"; neither is supported by the current sweep (`diff_offset_sweep_v1` gives r0=1=256; the 180/121 comparison is not reproducible from the committed JSON).
- **MILP differential R=6–14, v0.2.** The table for r0=0,10,20 gives R=10: 59/92/76; R=11: 62/92/76; R=12: 98/129/86; R=13: 120/**128**/104; R=14: **130/155/119**. Earlier drafts reported 139 at R=13 r0=10 and 129/164/132 at R=14; those are incorrect.
- **Differential growth at r0=10, v0.1.** `diff_growth_v1` gives R=23 MILP=110, R=24 MILP=134. Earlier drafts cited 107 and 131; those were from an older run.
- **Informal v0.2 r=4 trail.** `diff_r4_v1` with `MYSX_ROT_CAL` reports trail match 16/2000 (0.80%), average output difference weight 12.84 bits, and "probability ≈2^-7". Earlier drafts reported 12/2000 (0.60%) and 12.87; those are incorrect.
- **v0.2 backward beam to R=128.** `lin_beam_v02_R128_bwd` gives ub[R=128] = 2161 at offset 3 backward. Earlier drafts listed the v0.2 backward beam to R=128 as PENDING; it is now measured.
- **Related-key re-validation.** `rk_extended` runs 22/22 PASS on v0.2. Earlier drafts listed this as PENDING; it is now measured.
- **Test count.** `paper_results.json` has 55 tests: 53 pass, 0 fail, 2 skip (`nist_v1`, `nist_v02`, both `requires_file not present: sts-2.1.2/assess`). The item `diff_r16_r17_v1` is not in the current manifest; if it exists, it should be re-added to the manifest before being cited as a skip.
- **KAT v2 digest.** The `kat_v2` output shows `block_digest_cal1 = d1b3e268af1c7422` (truncated to 16 hex chars). The full 64-char value must be regenerated from `KAT_v2.json` before being published as a fixed string. The paper prints `d1b3e268...` and points to `KAT_v2.json`.
- **Linear v0.1 R=128 table.** The combined table (`lin_beam_full_table_v1`) gives R=56 actual min = 653 (backward offset 20) and R=64 actual min = 797 (backward offset 13); the paper values 630 and 786 are not reproducible from the committed JSON. The two checkpoints are documented (not asserted); the other 16 checkpoints match.
- **Largest R with weight <64.** This must be reported separately for v0.1 and v0.2. For v0.2 forward and backward, the largest R with an achievable trail of weight <64 is 19; the largest R with weight <32 is 17. For v0.1 merged (forward+backward), the largest R with weight <64 is 22 (weight 63 at offset 23 forward; 49 at R=21; a tie with the threshold). For v0.1 backward-only, the largest R with weight <64 is 21; R=22 backward gives 71.
- **Rand prefix.** The schedule name is `rand_s9_45430` (not `rand_59_45430`).
- **Typo fixes.** `scrypt` (not `script`); `mysx` (not `mysql`); `KNOWN_KAT_DIGEST` (all caps).

**Three geographies.** The three analysis directions peak at different rotation offsets: differential at r0=10 (v0.1) and r0=29 (v0.2); linear free chains at r0=12 and r0=27; linear hull at offset 20 backward (≈r0=5–6 in first-round convention); integral at r0=15 (v0.1). None of the single-offset bounds previously reported describes the cipher as a whole.

---

## 2. Specification

### 2.1. Parameters

| Parameter | Value |
|---|---|
| Block size | 256 bits (8 words of 32 bits) |
| Key size | 512 bits (16 words of 32 bits) |
| Rounds | 128 |
| Structure | SPN-like: 4 parallel Feistel cells + byte transposition |
| Non-linearity | `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` |
| Diffusion | Myszkowski transposition (keyword MYSZKOWS) |
| Rotation (v0.2) | `rotl(word, ROT_CAL[r mod 31])` per word and round |
| Final whitening | XOR with 8 words from the key schedule |

**Structural note.** MYSX is sometimes described as a "2-branch Feistel" by analogy with Simon. Strictly, each round applies four independent Feistel cells over 32-bit word pairs, then a byte transposition over the full 32-byte state, then word rotations. It is more accurately classified as an SPN with Feistel cells. The "Feistel" label is a convenience.

### 2.2. Notation

- `rotl(x, n)`: circular left rotation of x by n bits.
- `∧`: bitwise AND.
- `⊕`: bitwise XOR.
- `s[r]`: state at round r (`s[0]` = plaintext, `s[128]` = ciphertext).
- `s[r][i]`: word i (0..7) of the state at round r.
- `rk[r][i]`: subkey i (0..7) of round r.
- `rkFinal[i]`: word i (0..7) of the final whitening.
- `ROT_CAL[]`: the 31-value rotation schedule (Section 2.8).
- `CAL`, `KDF`: one-byte selectors in v2 packets (Section 2.9).

### 2.3. Constants

```
CONST[0..7] = [0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
               0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89]
```

These are the fractional digits of π (same as Blowfish).

#### 2.3.1. Myszkowski permutation

Keyword: `MYSZKOWS` (8 letters, S repeated at positions 3 and 8).

Alphabetical order: K(5), M(1), O(6), S(3,8), W(7), Y(2), Z(4).

The byte permutation `MYZ_PERM[0..31]` is constructed as:

```
MYZ_PERM = [4,12,20,28,   # K (column 4)
            0,8,16,24,    # M (column 0)
            5,13,21,29,   # O (column 5)
            2,7,10,15,18,23,26,31,  # S,S (columns 2 and 7, read row-wise)
            6,14,22,30,   # W (column 6)
            1,9,17,25,    # Y (column 1)
            3,11,19,27]   # Z (column 3)
```

The inverse permutation `MYZ_INV` satisfies `MYZ_INV[MYZ_PERM[i]] = i`.

**Design note.** The Myszkowski choice is didactic (classical transposition with a keyword) and adds no cryptographic argument. A byte permutation optimized for diffusion (e.g., a structured permutation over the 4×8 byte grid) would strictly dominate it. We keep Myszkowski in this draft because it is the design under review; a future version may replace it.

### 2.4. Key schedule

#### 2.4.1. Initialization

Input: key `K[0..63]` (64 bytes).

Initial state `s[0..15]` (16 words of 32 bits):

```
s[i] = big_endian_word(K[4i .. 4i+3])
```

#### 2.4.2. Expansion

For `r = 0..127`:

```
spread = (r+1) * 0x9E3779B9 (mod 2^32)

# Round subkeys
for i in 0..7:
    rk[r][i] = s[i] ⊕ s[(i+5) mod 16] ⊕ s[(i+11) mod 16]
              ⊕ CONST[(r+i) mod 8] ⊕ spread

# For i = 0..3: fold fk into rk
for i in 0..3:
    fk = s[(i+8) mod 16] ⊕ CONST[(r+i+3) mod 8]
    rk[r][i] = rk[r][i] ⊕ fk

# State update (Feistel 8+8, bijective)
L = s[0..7]
R = s[8..15]
for i in 0..7:
    a = R[i]
    b = R[(i+1) mod 8]
    c = R[(i+3) mod 8]
    F = (rotl((a+b) mod 2^32, 7) ⊕ rotl(c, 13) ⊕ CONST[i] ⊕ spread)
    s[i] = R[i]
    s[i+8] = L[i] ⊕ F
```

#### 2.4.3. Final whitening

After the 128 rounds:

```
for i in 0..7:
    rkFinal[i] = s[i] ⊕ s[(i+8) mod 16] ⊕ CONST[(128+i) mod 8]
```

### 2.5. Round function

Each round r transforms state `s[r]` into `s[r+1]` in four steps:

**Step 1. AddRoundKey.**

```
for i in 0..7:
    s[r][i] = s[r][i] ⊕ rk[r][i]
```

**Step 2. Feistel cells.** For `p = 0..3`:

```
L = s[r][p]
R = s[r][p+4]
s_mid[p] = R
s_mid[p+4] = L ⊕ F(R)
```

where `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.

**Step 3. Myszkowski transposition.** Convert `s_mid[0..7]` to bytes (big-endian per word):

```
bytes[4i .. 4i+3] = big_endian(s_mid[i])
permuted[j] = bytes[MYZ_PERM[j]] for j = 0..31
s_perm[i] = big_endian_word(permuted[4i .. 4i+3])
```

**Step 4. Word rotation.**

```
shift = ROT_CAL[r mod 31]
for i in 0..7:
    s[r+1][i] = rotl(s_perm[i], shift)
```

### 2.6. Encryption

```
s[0] = plaintext (as 8 big-endian words)
for r = 0..127:
    apply round r (Section 2.5)
for i in 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128] (as 32 big-endian bytes)
```

### 2.7. Decryption

Inverse of encryption:

```
s[128] = ciphertext
for i in 0..7:
    # Inverse rotation: rotl(word, 32 - shift)
    # Inverse transposition: bytes[MYZ_PERM[j]] = permuted[j]
    # Inverse Feistel: R = newL, L = newR ⊕ F(R)
    # XOR with rk[r][i]
```

### 2.8. Rotation schedule (v0.2)

The 31-value rotation schedule is:

```
ROT_CAL = [22, 5, 8, 7, 17, 10, 30, 1, 11, 26, 6, 3, 12, 23, 25,
           13, 28, 20, 21, 19, 24, 2, 18, 9, 4, 15, 29, 27, 16, 14, 31]
```

Round r uses `shift = ROT_CAL[r mod 31]`. The v0.1 schedule was `shift = (r mod 31) + 1` (i.e., `[1,2,...,31]`).

**Selection method.** 1M random permutations of 0..30 filtered by:

1. Maximum weight-0 chain at offset 10 ≤ 3
2. Global maximum weight-0 chain ≤ 5
3. Exact DMITM over the full left-half difference space.

8 candidates achieved exact DMITM = 9. The 8 finalists were ranked by a multidimensional score: integral at R=5/6, linear at R=10/14 (both directions), MILP differential at R=5, exact DMITM, weight-0 chain.

**Why the consecutive schedule was rejected.** Over 3000 random schedules without filtering, the consecutive schedule is in the worst ~2% by exact DMITM and worst ~0.2% by weight-0 chain. The cause is the step of 1: a consecutive sequence of shifts aligns with the transposition period in a way that lets the tracked bits remain in the "safe" half of the state for many rounds. The variable is the schedule step, not the Myszkowski permutation (a control with 40 random byte permutations and the consecutive schedule gives mean exact DMITM 21.4).

**The differential weakness closed by v0.2.** In v0.1, at offset r0=10 the best single-trail differential weight at R=14 is 2 (i.e., 4 chosen pairs distinguish 14 rounds of v0.1 from a random cipher). In v0.2, the best MILP weight at R=14 over 31 offsets is 94 (offset r0=29); the worst observed is 335 (r0=2); one offset (r0=30) timed out and is a candidate for a lower value. The structural alignment is gone.

**Reproducibility.** `CALENDAR_v02.txt` contains the schedule as `MYSX_ROT_CAL=22,5,8,...`; `search_mysx_deep.py --n 1000000 --seed 9` regenerates the search. `cryptanalysis/DMITM/wf2_deep_summary.json` contains the raw 8×9 table.

### 2.9. AEAD packet format (v2)

Two packet formats coexist. v1 (VERSION = 0x01) uses the consecutive calendar, HKDF-SHA256, HMAC-SHA256, 32-byte tag; deprecated for new data. v2 (VERSION = 0x02) is recommended.

**v2 packet layout.**

```
VERSION(1) = 0x02
CAL(1)
KDF(1)
KDF_PARAMS(var)
SALT(32)
NONCE(16)
CT(n)
TAG(64)
```

**Fields.**

- `CAL`: rotation calendar selector. `0` = consecutive (v0.1-compatible), `1` = `rand_s9_45430`. Unknown values rejected.
- `KDF`: `0` = RAW (64-byte or 32-byte secret, direct HKDF), `1` = Argon2id, `2` = PBKDF2-SHA512, `3` = scrypt.
- `KDF_PARAMS`: bounds checked on parse. Argon2id `memKiB ∈ [19456, 1048576]`, `passes ∈ [2, 16]`, `lanes ∈ [1, 16]`; PBKDF2-SHA512 `iterations ∈ [210000, 10000000]`; scrypt `logN ∈ [15, 20]`, `r ∈ [8, 16]`, `p ∈ [1, 16]`, memory ≤ 1 GiB.
- `SALT` (32 bytes), `NONCE` (16 bytes), fresh per packet.
- `TAG`: HMAC-SHA512 over `HEADER | u64(len(AAD)) | AAD | u64(len(CT)) | CT`, 64 bytes.

**Key derivation (v2).**

```
PRK      = HKDF-Extract-SHA512(salt=SALT, ikm)
info     = LP("MYSX-256/512 v2") | CAL | KDF | LP(context) | LP(label)
encKey   = HKDF-Expand(PRK, info(label="enc"), 64)
macKey   = HKDF-Expand(PRK, info(label="mac"), 64)
```

where `LP(x) = u16_be(len(x)) || x`.

**v2 API.** `v2.seal(plaintext, creds, opts)`, `v2.open(packet, creds, opts)`, `v2.generateSecret()`, `v2.securityLevel(cred)`, `v2.setArgon2Provider(fn)`, `v2.argon2FromNoble(argon2idAsync)`, `v2.CAL`, `v2.KDF`, `v2.DEFAULTS`, `v2.LIMITS`. The `_salt` and `_nonce` options are internal (KAT only) and must not be used in production.

**Cross-language validation (v0.2).** The v2 packet format has been implemented independently in Python (`tests/gen_v2_kat.py`, stdlib only) and in JavaScript (`mysx.prod.js`). Six complete packets (header + CT + tag) are byte-identical between the two implementations across: CAL=0 and CAL=1; KDF=RAW (64-byte and 32-byte secrets), PBKDF2-SHA512, scrypt; empty, 1-byte, 100-byte, 33-byte and 70-byte plaintexts. A 58-test suite (`tests/mysx_v2.test.js`) verifies KAT regression, cross-language KAT, per-byte bit-flip rejection, AAD/context/secret binding, KDF bounds, anti-downgrade on the KDF byte, password+keyfile separation, Argon2id RFC 9106 vector, and v1/v2 packet separation. All 58 tests pass.

**Smoke test.** `v2_smoke` reports: `calendar_injected = true`, `v2_api_complete = true`, `argon2 = "noble"`, `roundtrip_raw = true`, `packet_version = 2`, `packet_cal = 1`, `roundtrip_password = true`, `packet_kdf = 1`, `security_raw64 = {classicalBits: 512, groverBits: 256}`, `security_raw32 = {classicalBits: 256, groverBits: 128}`, `v1_compat = true`.

### 2.10. Key derivation (v1, deprecated)

HKDF-SHA256 with 32-byte MAC key (or PBKDF2-SHA256 for passwords). The HKDF-SHA256 bottleneck caps the effective quantum security at 2^128. Do not use v1 for new data.

### 2.11. Test vectors

See `KAT.json` (v0.1) and `KAT_v2.json` (v0.2). Two digests are documented:

- `KAT.json` public digest (v0.1): `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee` (SHA-256 over the full JSON: block + AEAD + KDF). This is the artifact a third-party implementation should reproduce.
- `KNOWN_KAT_DIGEST` (internal fast regression): `3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3` (SHA-256 over 16 blocks with `key[i]=i`). Strictly a subset of the public KAT, not a different KAT.
- `KAT_v2.json` (v0.2): `block_v02` (8 blocks with CAL=1), `v2_raw`, `v2_password_argon2`, `v2_password_scrypt`, `v2_kdf`, `v2_parse`, `security_level`, `block_digest_cal0 = KNOWN_KAT_DIGEST`, `block_digest_cal1 = d1b3e268...` (full 64-char value must be regenerated from `KAT_v2.json`; the `kat_v2` stdout shows `d1b3e268af1c7422`).
- `tests/_v2_kat_cross.json`: 6 cross-language v2 packets (Python reference → JS must reproduce byte-identical).

A third-party implementation should target the public v0.1 digest, `block_digest_cal1` for v0.2, and the 6 cross-language v2 packets.

---

## 3. Differential cryptanalysis

### 3.1. Model

Tool: `misc/mysx_milp2.py` (PuLP + CBC/HiGHS, with `--r0` rotation offset). AND model: `a = Δx ∨ Δy`, which counts a cost-1 event whenever at least one input is active. For an AND with independent inputs, this is the exact per-bit cost. The real approximations in the model are:

- The Markov-independence assumption does not hold: the two rotated inputs of F come from the same word x. The reported runs use a single input difference per offset (the one predicted by the free chain table of §3.5 as maximizing the free chain, or w2b30 for the §3.2 table); multi-bit input differences may yield lower weights.
- `gapRel = 0.2` and `timeLimit = 300–900` return feasible solutions (upper bounds), not certified optima. The MILP is therefore used as a lower-cost exploration tool.
- The model captures single trails, not differentials (clusters of trails with the same output difference).

The offsets were varied for the first time in the v0.1-draft2 paper (§3.5) and are now reported for v0.1 and v0.2. The §3.2 table, measured at r0=0 only for v0.1 and at r0 ∈ {0, 10, 20} for v0.2, is a valid upper bound for those offsets but is not representative of all 31 rotation offsets.

### 3.2. Observed upper bounds

**At r0=0, v0.1 (input w2b30).** The §3.2 table of v0.1-draft2 remains valid as an upper bound for that offset:

| Rounds | Input | Weight (upper bound) | Single-trail probability |
|---|---|---|---|
| 5 | w2b30 | 4 | 2^-4 |
| 6 | w2b30 | 6 | 2^-6 |
| 7 | w2b30 | 10 | 2^-10 |
| 8 | w2b30 | 18 | 2^-18 |
| 9 | w2b30 | 26 | 2^-26 |
| 10 | w2b30 | 42 | 2^-42 |
| 11 | w2b30 | 58 | 2^-58 |
| 12 | w2b30 | 68 | 2^-68 |
| 13 | w2b30 | 88 | 2^-88 |
| 14 | w2b30 | 106 | 2^-106 |

**At r0 ∈ {0, 10, 20}, v0.2 (input w1b31).** From `diff_milp_v02_R6_R14` (27/27 solves):

| Rounds | r0=0 | r0=10 | r0=20 |
|---|---|---|---|
| 10 | 59 | 92 | 76 |
| 11 | 62 | 92 | 76 |
| 12 | 98 | 129 | 86 |
| 13 | 120 | 128 | 104 |
| 14 | 130 | 155 | 119 |

(The complete R=6..9 values are in the full `diff_milp_v02_R6_R14` log; the visible `stdout_tail` begins at R=10. The paper reports only the R=10–14 rows it can verify from the JSON.)

**Offset sweep, R=14, v0.1 (MILP, single-bit input w1b31).** `diff_offset_sweep_full_v1`:

| r0 | weight | r0 | weight | r0 | weight |
|---|---|---|---|---|---|
| 0 | None | 11 | 84 | 22 | None |
| 1 | None | 12 | 24 | 23 | None |
| 2 | None | 13 | 50 | 24 | None |
| 3 | 154 | 14 | 52 | 25 | None |
| 4 | 166 | 15 | 186 | 26 | None |
| 5 | 80 | 16 | 167 | 27 | None |
| 6 | None | 17 | 173 | 28 | 118 |
| 7 | 96 | 18 | None | 29 | 173 |
| 8 | 174 | 19 | None | 30 | None |
| 9 | 50 | 20 | None | | |
| 10 | **2** | 21 | **211** | | |

Best: r0=10 with weight 2. Worst non-None: r0=21 with weight 211. Range of non-None values: 24 (r0=12) to 211 (r0=21). None at r0 ∈ {0,1,2,6,18,19,20,22,23,24,25,26,27,30}. The `diff_offset_sweep_v1` spot check gives r0=0=236, r0=1=256, r0=10=2, r0=15=166, r0=30=187; the 121/180 comparison cited in earlier drafts is not reproducible from the committed JSON and is not used here.

**Offset sweep, R=14, v0.2 (MILP, single-bit input w1b31).** `diff_offset_sweep_v02`:

| r0 | weight | r0 | weight | r0 | weight |
|---|---|---|---|---|---|
| 0 | 135 | 11 | 202 | 22 | 178 |
| 1 | 244 | 12 | 112 | 23 | 127 |
| 2 | **335** | 13 | 134 | 24 | 144 |
| 3 | 177 | 14 | 252 | 25 | 127 |
| 4 | 160 | 15 | 107 | 26 | 143 |
| 5 | 125 | 16 | 174 | 27 | 172 |
| 6 | 151 | 17 | 163 | 28 | 98 |
| 7 | 214 | 18 | 124 | 29 | **94** |
| 8 | 110 | 19 | 275 | 30 | None |
| 9 | 174 | 20 | 134 | | |
| 10 | 184 | 21 | 131 | | |

Best: r0=29 with weight 94. Worst: r0=2 with weight 335. Only r0=30 is unresolved. The range of measured values is 94 (r0=29) to 335 (r0=2). r0=19 is 275; r0=27 is 172.

**Comparison.** v0.1 has a catastrophic offset r0=10, weight 2 at R=14 (4 chosen pairs). v0.2 eliminates it: the best MILP weight across 31 offsets is 94 (upper bound), and the worst is 335 at r0=2. This is the main differential improvement of v0.2. The v0.1 R=14 distribution is bimodal (r0=10 is 2; most other non-None offsets are 50–211); the v0.2 R=14 distribution is unimodal in the 94–335 range (one outlier at 335, most values 94–252).

**Growth at r0=10, v0.1 (input w1b31, beam, multi-input).** Beam values at R=14..24: 2, 4, 6, 10, 15, 22, 34, 49, 78, 100, 133. MILP verification (`diff_growth_v1`): R=14→2, 15→4, 16→6, 17→10, 18→16, 19→24, 20→38, 21→56, 22→79, 23→**110**, 24→**134**. Linear interpolation puts the 128-bit threshold at R≈24. The paper's beam values differ from the MILP by −1 to +10 in R=18–24; both are upper bounds; neither is a minimum. The MILP is slightly above the beam at every round; the beam values are the tighter measurements for these offsets.

**Extrapolation at r0=0, v0.1.** The 128-bit threshold is reached at r≈15 by extrapolation from the R=5–14 MILP table. This is an extrapolation, not a proof. It tells us what the model produces for that input at that offset. The r0=0 value is one point in a distribution that runs from r≈24 (r0=10) to r≈15 (r0=0) and above; it is not the cipher-wide threshold.

### 3.3. Empirical check (r=4, w0b0)

The r=4 trail (it is not a row of the table above: `Δin = {w0b0}`, MILP weight 8, `Δout = {w0b4, w1b10, w1b16, w1b30, w6b4}`) was verified with 8 fixed keys × 2^17 pairs each, using the full 128-round cipher with the final whitening disabled (to isolate the round function).

- Observed hit rate: 7.802×10^-3 over 1,048,576 pairs.
- Expected from MILP: 2^-8 = 3.906×10^-3.
- Ratio: 2.00×.

The trail exists at r=4. The single-trail probability is a factor 2 higher than the MILP predicts, consistent with the clustering factor documented in §3.3. The MILP model is correct within a factor of 2 at this round count. This measurement was made at r0=0.

Two interpretations are consistent with the data:

- **Differential clustering (more likely).** Multiple trails with the same output difference `Δout` contribute to the observed probability, so the effective probability is higher than the single-trail probability.
- **Model systematic overestimate of the cost (less likely).** The AND model `a = Δx ∨ Δy` charges one bit too much at r=4. This would imply the true weight is 7, not 8. (Because the observed probability is higher than predicted, the model cannot be underestimating the cost; an underestimate would give a probability lower than predicted and a true weight of 9.)

Without a full clustering analysis (summing over all trails with the same Δin → Δout), we cannot distinguish these two. The practical implication is the same: the effective weight of the r=4 trail at r0=0 is 7, not 8, so the MILP weight is the pessimistic side by one bit. A constant factor 2 is one bit of weight; at the observed 8–23 bits of weight per round it moves the 128-bit threshold by a small fraction of a round, not by 2–3 rounds.

**v0.2 verification (informal).** `diff_r4_v1` on v0.2 (with `MYSX_ROT_CAL` set) reports trail match 16/2000 (0.80%) at R=4 with average output difference weight 12.84 bits, and "probability ≈2^-7". The specific r=4 trail is not directly transferable to v0.2 (the schedule change perturbs the alignment at R=4). No new trail at R=4 has been identified for v0.2.

### 3.4. What this section does not establish

- A lower bound on the best single-trail weight for any offset. The beam values of §3.5 are upper bounds from a specific start distribution; the MILP values are upper bounds with `gapRel=0.2`.
- An exact clustering analysis (requires modeling all trails with the same Δout and in particular the clustering factor at r0≠0).
- Resistance to related-key differentials.
- That the factor-2 clustering is constant across all round counts.
- That the beam, with single-bit starts and 3 candidates per cell, is exhaustive.
- The exact maximum chain length of 13 rounds for weight-0 chains is proven by linear algebra; the non-zero-weight tables are not.

### 3.5. Differential weight-0 chains

The differential model of §3.2 has the same structure as the linear model of §4.3: a round has weight 0 iff the difference does not touch the right half (words 4..7) of the state, in which case the round acts as a pure bit permutation on the left half. The free chain length depends on the rotation offset.

**Free chain table, v0.1 (verified, exact).** The maximum number of consecutive weight-0 rounds as a function of the offset r0 (first round mod 31), for a single-bit difference in words 0..3 of the state:

| r0 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| max | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 4 | 4 | 5 | **13** | 12 | 11 | 10 | 9 | 8 | 7 | 6 | 5 | 5 | 5 | 4 | 4 | 4 | 4 | 4 | 4 | 3 | 3 | 3 | 4 |

The worst offsets are r0 ∈ {0,1,2,3,4,5,6,27,28,29} (3 rounds); the best is r0=10 (13 rounds). The §3.2 table was measured at r0=0, one of the 3-round offsets.

**Maximum exact, v0.1.** By exhaustive linear algebra over the 2^128 left-half differences, no weight-0 differential chain longer than 13 rounds exists for any offset, and not even for multi-bit differences. The 13-round chain at r0=10 is therefore the exact maximum, not a search artifact.

**Verified deterministic chains, v0.1.** Two independent chains were verified against the real cipher with fixed keys, 2^15 pairs per key, 8 keys each (262,144 pairs total), full 128-round cipher, final whitening disabled:

| Offset | Input | Output | Rounds | Propagation |
|---|---|---|---|---|
| r0=10 | w1b31 | w4b12 | 13 | 100.0000% |
| r0=15 | w2b30 | w4b5 | 6 | 100.0000% |

The 13-round chain at r0=10 covers rounds 10–22, 41–53, 72–84 and 103–115 of the cipher (period 31). It is the same chain at every occurrence. The chains of 11 and 8 rounds reported during the sweep are not independent: they are the same 13-round chain started at a later point (w1b22 is the mask at round 12 of the 13-round chain; w2b24 is the mask at round 15). The independent chains are the 13-round chain and the 6-round chain.

**Free chain table, v0.2 (verified, exact).** The maximum number of consecutive weight-0 rounds as a function of r0 for v0.2:

- 5 rounds at r0 ∈ {3, 4, 13, 16, 17, 20, 24, 27, 28}.
- 4 rounds at r0 ∈ {0, 5, 6, 8, 9, 12, 14, 15, 18, 19, 21, 22, 25, 29, 30}.
- 3 rounds at r0 ∈ {1, 2, 7, 10, 11, 23, 26}.

No chain of length 6+ exists in v0.2. The full 31-offset table is printed by `diff_free_chain_v02`.

**Comparison.** v0.1: 13-round exact chain. v0.2: 5-round exact chain. The reduction is 8 rounds, consistent with the exact DMITM reduction (17→9).

**The catastrophic v0.1 offset.** r0=10 in v0.1 gives both the 13-round weight-0 chain and the weight-2 trail at R=14 (§3.2). The two are the same alignment; eliminating one eliminates the other.

**Three geographies.** The differential, linear and integral analyses peak at different rotation offsets (first-round convention):

| Direction | Peak offset (r0) | Longest verified | Data cost |
|---|---|---|---|
| Differential v0.1 | r0=10 | 13 rounds (weight 0) | 1 pair |
| Differential v0.2 | r0=29 | 5 rounds (weight 0) | 1 pair |
| Linear free chain | r0=12, r0=27 | 9 rounds (weight 0) | 2^0 |
| Linear hull | offset 20 backward ≈ r0=5–6 | 16 rounds (hull) | 2^22 texts |
| Integral v0.1 | r0=15 | 10 rounds | 2^32 / 2^64 texts |
| Integral v0.2 | (PENDING) | 6 rounds at r0=0 | 2^32 texts |

No single offset dominates all three. This is the main structural finding of the offset sweep: the three analysis directions must be reported offset by offset, not by a single representative offset.

---

## 4. Linear cryptanalysis

### 4.1. Overview

An earlier version of the v0.1 paper (§4 of the v0.0 draft) reported only negative results: three approximate linear MILP models (`misc/mysx_linear_milp.py`) all produced trails that failed empirical verification at w=32. That negative result has now been explained. The models used per-cell AND activity (`act = α ∨ β ∨ γ`) as a proxy for correlation, which is not the correct structure of F's LAT. A correct model exists in closed form and is implemented in `cryptanalysis/models/linear/mysx_linear_model.py` (with detailed documentation in `cryptanalysis/models/linear/LINEAR_MODEL.md` and raw data in `cryptanalysis/models/linear/linear_model_data.json`). The model is machine-checked against the real cipher by `python3 mysx_linear_model.py selftest`.

**Result in one line.** The LAT of F is exactly `corr(b,g) = ± 2^{-h(b)}`, where `h(b)` is half the GF(2)-rank of a 32-cycle subgraph determined by b; there is a free choice of g among `4^{h(b)}` values with sign determined by a quadratic form. Mask propagation is bit-exact; every trail carries an exact key-dependent sign. Verified consequences: `|corr| = 1` chains over up to 9 consecutive rounds (three keys), and exact linear-hull predictions at r=10,11,12 that match the real cipher within sampling error (`|z| < 0.4`). §4.10 extends the search for cheap trails to 128 rounds, all rotation offsets, and both directions (forward and backward), and shows that single-trail weights must be read together with hull effects. For the offset-20 backward trail at R=14 (weight 5, covering rounds 100–113), the hull check is complete: the trail is isolated and its empirical correlation matches 2^-5 (§4.10.3). An exact budgeted hull (§4.10.5) extends the verified window to R=16 (rounds 98–113, `|corr| = 2^-11`). This is a verified linear distinguisher on a 16-round window of the cipher.

### 4.2. Exact LAT of F

For output mask b and input mask g,

```
b·F(x) ⊕ g·x = Q_b(x) ⊕ l·x,   l = rotr(b,2) ⊕ g,
Q_b(x) = ⊕_j b_j (j+1) x_j x_{j-7}
```

`Q_b` is a quadratic form whose graph `G_b` is a subgraph of the 32-cycle `j → j-7` (edge (j, j-7) present iff `b_{j+1} = 1`; a single cycle because gcd(7,32)=1). Let `A_b` be the GF(2) adjacency matrix of `G_b`. Then:

```
corr(b,g) ≠ 0  iff  l = A_b y for some y.
There are exactly 2^{rank(A_b)} = 4^{h(b)} valid g.
For each valid g, corr(b,g) = (-1)^{Q_b(y)} · c_0(b)
with |c_0(b)| = 2^{-h(b)}, where h(b) = rank(A_b)/2.
```

`h(b)` equals the maximum matching = minimum vertex cover of `G_b` (König). The only graph that is not a forest is b = 0xFFFFFFFF (full cycle), where rank = 30 and h = 15. Parseval holds: `Σ_g corr(b,g)^2 = 1`.

This is exact and machine-checked against brute-force LAT of F for random b of Hamming weight up to 8 (selftest).

**Cost data.**

- Single-bit b: h=1, four valid g, |corr| = 1/2.
- Two-bit b (496 masks): histogram {2: 464, 1: 32} (the 32 pairs at bit distance 7 are adjacent edges).
- Uniform random 32-bit b (16384 samples): histogram of h peaks at h=11 (4130 samples); full histogram in `linear_model_data.json`.
- Densest masks per unit of weight (bits (1-7t) mod 32, t < 2m): every extra 2 consecutive edges costs 1; cost per active mask bit approaches 1/2 in the best case, never below 15/32.

### 4.3. Exact mask propagation (forward and backward)

**Forward step.** For a round r, with input mask m on `s[r]` and cells p = 0..3 (L = s[r][p], R = s[r][p+4]):

```
b_p = m[p]                         (only words 0..3 decide the cost)
g_p ∈ valid_gammas(b_p)            (4^{h(b_p)} choices, each |corr| = 2^{-h(b_p)})
n[p+4] = m[p]
n[p]   = m[p+4] ⊕ g_p
m_next = lin_fwd(n, r)             (byte transposition, then rotl by ROT_CAL[r mod 31])
w_r    = Σ_p h(m[p])
sign   = (∏_p sign_p) · (-1)^{m·rk[r]}
```

**Backward step.** For a round r, given `m_next` on `s[r+1]`:

```
n     = lin_inv(m_next, r)         (inverse rotation, then inverse transposition)
b_p   = n[p+4]                     (this is the output mask of F at cell p)
m[p]  = n[p+4]                     (cost h(n[p+4]) at this round)
m[p+4]= n[p] ⊕ g_p,  g_p ∈ valid_gammas(b_p)
```

The selftest verifies that every forward edge is a backward edge with the same cost (325 edges checked), so the two searches enumerate the same set of trails. Trails are always stored in forward order (mask on s[first] ... mask on s[last+1]).

**Correlation of a trail:** `∏_r 2^{-w_r} · (-1)^{Σ_r m_r · rk[r]} · ∏_p sign_p`. The linear hull at fixed key is the exact sum over all trails with the same `(m_0, m_R)`; `propagate()` computes it by correlation-vector propagation (pruned by weight). ELP mode (`propagate(..., elp=True)`) gives the key-independent potential under the (incorrect for a deterministic schedule) independent-round-key assumption.

**Free-chain structure.** A round has weight 0 iff words 0..3 of its input mask are zero; the round then acts as a pure bit permutation and the tracked bit never meets F. Since the rotation schedule has period 31, there are only 31 distinct windows. The exact free-chain table (all 128 single-bit masks in words 4..7, 31 windows) is in `LINEAR_MODEL.md` §4 and `linear_model_data.json`. Headline: the longest weight-0 chain is 9 consecutive rounds, at windows r=12 (mod 31) and r=27 (mod 31).

### 4.4. Verified |corr|=1 chains (v0.1)

Each of the 9-round chains has been checked against the real cipher (fixed random keys, 2^21 plaintexts, reduced rounds, final whitening disabled to isolate the round function). Representative results:

| Window | r0 | Rounds | Start bit | End bit | Key seed | Predicted sign | corr | σ |
|---|---|---|---|---|---|---|---|---|
| 12 | 9 | s[12].17 | s[21].79 | 1 | +1 | +1.00000 | 6.9e-04 |
| 12 | 9 | s[12].17 | s[21].79 | 2 | -1 | -1.00000 | 6.9e-04 |
| 12 | 9 | s[12].17 | s[21].79 | 3 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].14 | s[36].55 | 1 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].14 | s[36].55 | 2 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].14 | s[36].55 | 3 | +1 | +1.00000 | 6.9e-04 |
| 0 | 5 | s[0].20 | s[5].55 | 1 | -1 | -1.00000 | 6.9e-04 |
| 0 | 5 | s[0].20 | s[5].55 | 2 | -1 | -1.00000 | 6.9e-04 |
| 0 | 5 | s[0].20 | s[5].55 | 3 | -1 | -1.00000 | 6.9e-04 |

The magnitude is 1 for every key. Only the sign depends on the key, through `Σ_r m_r · rk[r]`. The model predicts that sign exactly. Per-round masks and complete details are in `linear_model_data.json` (`verified_chains`).

The backward search finds the same 9-round weight-0 chains at the corresponding end residues (20 and 4 mod 31). The selftest verifies `|corr|=1` on the real cipher for both, and that the forward and backward chains are the same trails (stored in forward order).

### 4.5. Best single trails beyond the free chain (upper bounds)

Layered beam search with the exact rules, starts = all 256 single-bit masks, beam 1200, cells with h ≤ 2 expanded. Each reported weight is an achievable single-trail weight, i.e. an upper bound on the best weight, not a minimum.

| Rounds R | 1-9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|
| best weight, window r0=12 | 0 | 1 | 2 | 3 | 7 | 12 |
| best weight, window r0=27 | 0 | 1 | 3 | 3 | 6 | 11 |

This table covers only the two windows with the longest free chain. §4.10 searches all 31 offsets in both directions and shows that the windows 12 and 27 are the best only up to R=12; from R=13 on, other offsets (notably r0=23 forward and r0=20 backward) give lower single-trail weights.

Note that this is the opposite of a linear-distinguisher risk at low rounds: at the 9-round mark we still have weight 0 (correlation ±1 in absolute value). The reader should not confuse this with an attack on the full cipher — see §4.7.

### 4.6. Hull verification (r0=12, exact signed hulls)

The single-trail numbers above are inputs to a hull computation. For three trails at r0=12 with weights 1, 2, 3, the model produces an exact signed prediction (fixed key, sum over all trails of weight ≤ w+4 with the same end masks) and the real cipher produces an empirical correlation over 2^22 plaintexts.

| Window | R | Best-trail w | Hull masks kept | Predicted corr | Empirical corr | σ | z |
|---|---|---|---|---|---|---|---|
| 12 | 10 | 1 | 4 | +0.500000 | +0.499997 | 4.9e-04 | -0.01 |
| 12 | 11 | 2 | 40 | -0.250000 | -0.250008 | 4.9e-04 | -0.02 |
| 12 | 12 | 3 | 3152 | -0.125000 | -0.124813 | 4.9e-04 | +0.38 |

Three independent predictions, three matches, |z| < 0.4 in every case. The hull sum is not an approximation here; it is the exact polynomial expansion of the trail system in the model, and it is what the real cipher produces within sampling error.

§4.10.3 extends this check to the saved R=14 trails from the beam search. The r0=23 forward trail cancels from R=8; the r0=24 forward trail cancels from R=8; the r0=12 forward trail is exact up to R=12; the offset-20 backward trail is exact from R=1 to R=14. Hull effects are not a uniform correction.

**v0.2 hull predictions (predictions only, no empirical).** `lin_hull_v02` computes exact signed hulls for v0.2 with r0=12:

| R | Hull size | Predicted corr |
|---|---|---|
| 10 | 4104 | -0.250000 |
| 11 | 200 | -0.125000 |
| 12 | 10576 | +0.031250 |

Empirical verification (comparing predicted vs real cipher) for v0.2 is PENDING — the hulls are computed but not compared against `round_enc`.

### 4.7. What this establishes and what it does not

**Established (machine-checked by selftest):**

- Exact LAT of F (valid set, magnitude, sign) against brute force.
- Exact per-round mask rule and key-sign tracking, in both directions (forward and backward edges match, 325 edges checked).
- Existence of key-independent-magnitude |corr|=1 single-bit relations over up to 9 consecutive rounds; found by both forward and backward searches at the corresponding residues.
- Exact signed linear-hull predictions (not approximations) at r=10, 11, 12 against the real cipher.
- The `mysx.prod.js` Python port reproduces `KNOWN_KAT_DIGEST`, so all claims are made against the actual reference implementation.
- (§4.10) The beam-search tool reproduces the §4.5 table exactly, its per-round masks agree with the real cipher wherever a trail is its own hull, and the selftest runs in both directions.
- (§4.10.3, §4.10.5) The offset-20 backward trail at R=14 (weight 5, rounds 100–113) is isolated in its hull (`hull_count = 1` trail) and its empirical correlation matches 2^-5 on the real cipher; the exact budgeted hull extends it to R=16 (rounds 98–113, `|corr| = 2^-11`, confirmed within 1.9σ on one key). This is a verified linear distinguisher on a 16-round window. It is seven weighted rounds followed by the 9-round weight-0 chain of this section, so it is the free chain plus a short weighted prefix, not new evidence about long trails.

**Not established:**

- A lower bound on the best trail weight over 128 rounds. Beam search gives upper bounds from a specific start distribution.
- An exact 128-round hull. Even the pruned `propagate()` will not scale; a certified bound would need a SAT/MILP encoding.
- A hull-aware correlation for the trails found in §4.10 beyond R=14. §4.10.3 shows that single-trail weight can over- or under-estimate the real correlation (cancellation was observed for some trails and isolation for others).
- The cost of a key-recovery attack.
- Behaviour of multi-bit starts at larger R beyond the pairs47 and `rand:5000:4` runs (which did not improve on single-bit; `rand:5000:4` is too small to be conclusive for structured multi-bit masks).
- Anything about the last-round/whitening structure, related-key linear behaviour, or side channels.

**The weight-0 chains are not an attack.** A 9-round `|corr|=1` relation sits in a 128-round cipher. Standard linear cryptanalysis extrapolates a weight over the full length; here the trail weight over rounds 0..8 is 0 and the weight over rounds 9..127 is unknown. The result is best read as: the exact machinery is in place and it agrees with the real cipher on small round counts, not as MYSX is broken. The 128-round picture remains open, although §4.10 shows that the cheap region ends at roughly 20 rounds in the single-trail model.

### 4.8. Previous incorrect models and why they failed

For the record, the v0.0 draft reported three approximate models, all with negative empirical verification. They used per-cell AND activity as a proxy for correlation, which is not the correct structure of F. The correct structure is the rank of the graph `A_b` above. The previous models produced trails with predicted `|corr| = 2^-8` at r=4 but no detectable signal — consistent with the fact that those trails have zero true correlation in the exact model.

An instructive detail from the old work remains relevant to any future linear work on MYSX: the empirical verification harness must use fixed keys per sample. With random keys per plaintext, the sign of every linear trail is key-dependent and the observed correlation of a genuinely nonzero trail collapses to zero. See `misc/validate_lineal_harness.js`, which validates the harness against a hand-computed w=8 case (observed correlation 0.4993 vs 0.5).

### 4.9. Integral / division property (preliminary, limited)

Tool: `misc/mysx_division_property_v2.py` with standard division-property rules (COPY: `k_a = Σ k_copies`; XOR: `k_c = k_a + k_b` with (1,1) invalid; AND: `k_c = k_a OR k_b`). The XOR and OR variants were found to be equivalent for all input patterns tested (the (1,1) constraint never fired), so the reported results do not depend on the choice between them.

**Results at r0=0, v0.1:**

| Input | Active bits | Integral size | Rounds with balanced bits | Saturation |
|---|---|---|---|---|
| bit 0 of word 0 | 1 | 2 | 10 | R=11 |
| word 0 | 32 | 2^32 | 6 | R=7 |
| words 0 and 4 | 64 | 2^64 | 5 | R=6 |

The integral distinguishers are the last two rows: 6 rounds with a 2^32-text integral, 5 rounds with a 2^64-text integral. These cover 4.7% and 3.9% of the 128 rounds at r0=0, leaving 122 and 123 rounds without an integral distinguisher in the tested pattern.

The first row (1 active bit, 2-text integral) is not a meaningful integral distinguisher: with 2 texts, "balanced output bit" is equivalent to "output bit independent of the input bit". It is reported as a single-bit dependency propagation result — it measures how many rounds are needed for the active bit to reach all 256 output bits (10) — but no integral security conclusion is drawn from it.

**Empirical verification at r0=0, v0.1.** The 6-round distinguisher (word 0 active) and the 10-round single-bit dependency were verified against the real cipher (fixed random key, all non-active input bits random) over 20,000 samples each. The balanced bits predicted by the model never flipped; control bits (predicted not balanced) flipped with probabilities 6.5%–87%. The 5-round distinguisher (words 0,4 active) was not verified empirically (its integral has 2^64 texts; a random-sample approximation with 20,000 samples is not meaningful).

**Offset sweep, v0.1.** All 31 rotation offsets were tested at the saturation rounds of r0=0 (word0: R=6; word0,word4: R=5). The number of balanced output bits varies 8–9× across offsets (3–28 at R=5 for word0,word4; 3–26 at R=6 for word0). The offsets r0=12 and r0=27, which maximize the weight-0 linear chains, are not special for DP (values near the mean). The peak block is r0 ∈ [12,17], with a maximum at r0=15 (shift 16).

**At r0=15, v0.1.** The distinguishers extend by four to five rounds over r0=0. The DP trace decays by roughly a factor of two per round:

| R | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|
| word0, balanced bits | 26 | 12 | 6 | 3 | 1 | 0 |
| word0,word4, balanced bits | 15 | 9 | 4 | 2 | 1 | 0 |

Both patterns saturate at R=11. The distinguisher covers 10 rounds for both patterns. The tail at R=10 is a single balanced bit; the practical strength is in the 7–8 round range.

**Verification at r0=15, v0.1.** The 12 word0 bits at R=7 and 13 of the 15 word0,word4 bits at R=6 were verified against the real cipher (20,000 samples, fixed key) as consistent with bit-0 toggle (and, for the two remaining bits word5 bit6 and word7 bit9, with simultaneous toggle of word0[0] and word4[0]). This is a necessary condition for the DP prediction, not a verification of the full 2^32/2^64 integral. The bits at R=8–10 were not individually verified; they remain model predictions.

**v0.2 integral results.**

| Input | R | Balanced bits |
|---|---|---|
| word 0 | 5 | 9/256 |
| word 0 | 6 | 4/256 |

`integral_sweep_v02` measures 6 offsets (0, 5, 10, 15, 20, 27) at R=5 and R=6. All six give the same 9/256 at R=5 and 4/256 at R=6. This is a strong indication that the v0.2 calendar is not offset-sensitive for DP at the saturation rounds of r0=0. The full 31-offset sweep and the r0=15 peak for v0.2 are PENDING.

**Comparison with Simon (with care).** For Simon32/64, Todo and Morii (FSE 2016) prove a 14-round integral distinguisher with the conventional bit-based division property (31 active input bits), and a 15-round one using three subsets. 14 rounds is 44% of Simon32's 32 rounds (47% for 15 rounds). In relative terms MYSX resists integral distinguishers better (7.8% at the maximum round count at r0=15, 6.25% at R=8, vs 44% for Simon32), which is consistent with MYSX's more aggressive diffusion (4 parallel Feistel cells + transposition). In absolute terms Simon's distinguisher reaches further (14 vs 10 rounds) even though MYSX has 4× more rounds. The two are not directly comparable without normalizing by total rounds, and the MYSX analysis used only the conventional bit-based rules.

**What this establishes and what it does not.**

Established:

- MYSX v0.1 has integral distinguishers covering 6–10 rounds depending on the rotation offset: 6 rounds (2^32) / 5 rounds (2^64) at r0=0; 10 rounds (2^32 and 2^64) at r0=15, with a thin tail (1 balanced bit at R=10, 0 at R=11).
- MYSX v0.2 has 9/256 and 4/256 balanced bits at R=5/6 at all six measured offsets.
- A single active input bit stops influencing all 256 output bits after 10 rounds at r0=0 (v0.1).
- The standard division-property rules with the (1,1)-invalid XOR constraint produce the same results as the OR-conservative rule for the tested inputs.

Not established:

- Full 2^32/2^64 integral verification at r0=15 (v0.1). The toggle test is a necessary condition only.
- Behaviour of the R=8–10 tail at r0=15 (v0.1) under a stronger verification method.
- Whether the peak at r0=15 (shift 16) reflects a structural weakness of shift-16 rounds or a property of the specific window. This is a hypothesis, not established.
- Behaviour for offsets outside the peak block [12,17] at extended round counts.
- Full-block inputs (255 active bits).
- The three-subset division property (introduced by Todo-Morii, FSE 2016; variant without unknown subset: Hao et al., EUROCRYPT 2020) and traceability-enhanced variants (Wang et al., 2023), which may extend the distinguishers.
- Any key-recovery attack based on these distinguishers.
- v0.2 offset sweep at r0=15, v0.2 r0=15 peak, v0.2 full 31-offset sweep.

**Historical note.** The XOR rule of Todo-Morii as commonly written in the literature (`k_c = k_a XOR k_b`) is not sound when the two XOR operands share variables. In MYSX's `F = C ⊕ D`, both C and D depend on R, so that rule overestimates balanced bits via spurious cancellations. The first implementation of this analysis used that rule and produced oscillating, non-converging numbers (127→117→152→...). Those numbers are an artifact and are not reported here. The results above use the standard (1,1)-invalid rule, which is sound.

### 4.10. Beam search over the exact linear model, 128 rounds, both directions, all offsets

#### 4.10.1. Method

Tool: `misc/mysx_linear_beam.py` (self-contained: it re-implements the exact LAT of F, the exact mask propagation of §4.3 in both directions and, for its selftest, the real cipher). It searches for achievable single-trail weights with `w = Σ_r Σ_p h(m_r[p])`.

**Two directions.**

- **Forward** (`--direction forward`, default): the offset o is the index of the first round mod 31. Starts are masks on `s[o]`, the trail covers rounds o .. o+R-1, and the trail must fit inside the cipher (o+R ≤ 128).
- **Backward** (`--direction backward`): the offset o is the index of the last round mod 31. Starts are masks on `s[e+1]` with `e = o + 31·⌊(127-o)/31⌋`, the trail covers rounds e-R+1 .. e, and the trail must fit inside the cipher (e+1 ≥ R, i.e. `realizable_R = e+1 ≥ R`). The propagation uses the inverse round rule of §4.3.

**Merge.** `python3 mysx_linear_beam.py merge a.json b.json c.json` combines any number of result files (from either direction) and reports the minimum weight per R across all offsets and both directions. The combined table of §4.10.2 is the output of `merge beam_full.json beam_pairs47.json beam_bwd.json`.

**Parameters of the reported runs:**

| Parameter | Value |
|---|---|
| Rotation offsets | all 31 (0..30) |
| Rounds | up to 128 |
| Start masks | the 256 single-bit masks of the relevant state |
| Beam width | 2000 states per layer, ranked by (weight, Hamming weight), deduplicated by mask |
| Per-cell limit | h(b) ≤ 16; b = 0xFFFFFFFF (full cycle, special case of §4.2) is excluded |
| Valid g per cell | the 3 sparsest elements of the valid set (`--g-keep 3`) |
| Reported value | suffix minimum `ub(R) = min_{R' ≥ R} best(R')`, valid because the best weight is non-decreasing in R |
| Forward run | `beam_full.json`, `beam_full.log`: 8 processes, 1972 s |
| Backward run | `beam_bwd.json`, `beam_bwd.log`: 8 processes, 1512 s |
| Multi-bit run | `beam_pairs47.json`: `--starts pairs47`, did not improve on single-bit |
| v0.2 forward run | `lin_beam_v02_R128`: 2 processes, 1242 s |
| v0.2 backward run | `lin_beam_v02_R128_bwd`: 2 processes, 1071 s |

Every exclusion or truncation above only restricts the search, so all reported weights remain achievable single-trail weights (upper bounds on the best weight). A larger beam, `--g-keep 0` and multi-bit starts can only lower them.

**Validation of the tool, before the runs:**

- selftest passes in both directions: (1) the closed-form LAT of F against sampling, (2) one round of the model against the real round function with random keys, (3) the 9-round weight-0 chains at r0=12 and r0=27 found by the forward search and confirmed with `|corr|=1` on the real cipher (256 random states per chain), (4) every forward edge is a backward edge with the same cost (325 edges checked), (5) the 9-round weight-0 chains are found backward at end residues 20 and 4 with `|corr|=1` on the real cipher, (6) a backward R=14 trail with weight 21 is a valid forward trail with equal weight.
- `reproduce` returns exactly the §4.5 table for r0=12 and r0=27 (R ≤ 14, beam 1200, h ≤ 2).

#### 4.10.2. Results

**Best achievable single-trail weight per number of rounds, v0.1, minimum over offsets and both directions, subject to the trail fitting inside the 128-round cipher** (forward: r0+R ≤ 128; backward: realizable_R = e+1 ≥ R):

| R | Best weight | Offset | Direction | ≈ texts 2^{2w} |
|---|---|---|---|---|
| 9 | 0 | 4 | backward | 2^0 |
| 10 | 1 | 4 | backward | 2^2 |
| 12 | 2 | 20 | backward | 2^4 |
| 14 | 5 | 20 | backward | 2^10 |
| 16 | 8 | 23 | forward | 2^16 |
| 18 | 24 | 20 | backward | 2^48 |
| 20 | 38 | 20 | backward | 2^76 |
| 22 | 63 | 23 | forward | 2^126 |
| 24 | 88 | 3 | backward | 2^176 |
| 32 | 204 | 3 | backward | 2^408 |
| 40 | 361 | 20 | backward | 2^722 |
| 48 | 485 | 20 | backward | 2^970 |
| 56 | 653 | 20 | backward | 2^1306 |
| 64 | 797 | 13 | backward | 2^1594 |
| 80 | 1081 | 21 | backward | 2^2162 |
| 96 | 1336 | 21 | backward | 2^2672 |
| 112 | 1671 | 21 | backward | 2^3342 |
| 128 | 2248 | 3 | backward | 2^4496 |

The R=16 row (weight 8) cancels once its hull is computed (four trails of weight 8 with the same end masks sum to zero, §4.10.5), so 2^16 texts is not a distinguisher cost. The best certified correlation at R=16 is the offset-20 backward hull, `|corr| = 2^-11` (≈2^22 texts). The same caveat applies to every row: a row is an achievable single-trail weight, not a correlation.

The two documented discrepancies against the older v0.1 paper are R=56 and R=64: the paper values 630 and 786 are not reproducible from the committed JSON; the actual minima are 653 (backward offset 20) and 797 (backward offset 13). The other 16 checkpoints match and are asserted in `lin_beam_full_table_v1`.

**Best achievable single-trail weight per number of rounds, v0.2 forward** (`lin_beam_v02_R128`, all 31 offsets):

| R | Best weight | Offset | Direction | ≈ texts 2^{2w} |
|---|---|---|---|---|
| 9 | 1 | 12 | forward | 2^2 |
| 10 | 1 | 14 | forward | 2^2 |
| 12 | 3 | 14 | forward | 2^6 |
| 14 | 8 | 14 | forward | 2^16 |
| 16 | 18 | 14 | forward | 2^36 |
| 18 | 39 | 14 | forward | 2^78 |
| 20 | 71 | 14 | forward | 2^142 |
| 22 | 95 | 14 | forward | 2^190 |
| 24 | 124 | 14 | forward | 2^248 |
| 32 | 256 | 14 | forward | 2^512 |
| 40 | 396 | 14 | forward | 2^792 |
| 48 | 541 | 14 | forward | 2^1082 |
| 56 | 701 | 13 | forward | 2^1402 |
| 64 | 839 | 13 | forward | 2^1678 |
| 80 | 1127 | 7 | forward | 2^2254 |
| 96 | 1439 | 7 | forward | 2^2878 |
| 112 | 1790 | 7 | forward | 2^3580 |
| 128 | 2294 | 0 | forward | 2^4588 |

**Best achievable single-trail weight per number of rounds, v0.2 backward** (`lin_beam_v02_R128_bwd`, all 31 offsets):

| R | Best weight | Offset | Direction | ≈ texts 2^{2w} |
|---|---|---|---|---|
| 9 | 1 | 11 | backward | 2^2 |
| 10 | 3 | 2 | backward | 2^6 |
| 12 | 6 | 25 | backward | 2^12 |
| 14 | 11 | 11 | backward | 2^22 |
| 16 | 22 | 11 | backward | 2^44 |
| 18 | 43 | 11 | backward | 2^86 |
| 20 | 69 | 4 | backward | 2^138 |
| 22 | 94 | 30 | backward | 2^188 |
| 24 | 122 | 4 | backward | 2^244 |
| 32 | 246 | 11 | backward | 2^492 |
| 40 | 372 | 25 | backward | 2^744 |
| 48 | 506 | 17 | backward | 2^1012 |
| 56 | 638 | 17 | backward | 2^1276 |
| 64 | 771 | 17 | backward | 2^1542 |
| 80 | 1066 | 17 | backward | 2^2132 |
| 96 | 1325 | 17 | backward | 2^2650 |
| 112 | 1675 | 20 | backward | 2^3350 |
| 128 | 2161 | 3 | backward | 2^4322 |

**Combined v0.2 table (min forward/backward):**

| R | weight | R | weight | R | weight |
|---|---|---|---|---|---|
| 9 | 1 | 22 | 94 | 80 | 1066 |
| 10 | 1 | 24 | 122 | 96 | 1325 |
| 12 | 3 | 32 | 246 | 112 | 1675 |
| 14 | 8 | 40 | 372 | 128 | 2161 |
| 16 | 18 | 48 | 506 | | |
| 18 | 39 | 56 | 638 | | |
| 20 | 69 | 64 | 771 | | |

**Largest R with an achievable single trail:**

- **v0.1 backward-only:** weight < 32 up to R=19; weight < 64 up to R=21.
- **v0.1 merged:** weight < 64 up to R=22 (weight 63 at offset 23 forward; a tie with the threshold).
- **v0.2 forward:** weight < 32 up to R=17; weight < 64 up to R=19.
- **v0.2 backward:** weight < 32 up to R=17; weight < 64 up to R=19.

The v0.2 backward beam and the v0.1 backward beam at R=128 are real trails inside the cipher; the fitting rule excludes offsets with realizable_R < R.

**Direction alternates with R.** Among the tabulated round counts, v0.1's minimum is reached by a backward trail at R=9, 10, 12, 14 (tied with offset 23 forward), 18, 20, 24, 32, 40, 48, 96, 112 and 128, and by a forward trail at R=16, 22, 56, 64 and 80. For v0.2, the forward and backward tables are both reported; the combined table is the right object. Do not compare the forward-only and backward-only tables row by row.

**R=128 is a real trail.** In forward mode for v0.1, only r0=0 fits a 128-round trail (o+R=128). In backward mode, offset 3 has e = 3 + 31·⌊124/31⌋ = 127, realizable_R = 128, and the trail covers rounds 0..127. The combined R=128 = 2248 at offset 3 backward is a real trail inside the cipher, not a virtual extension. The same is true for v0.2's R=128 = 2294 at offset 0 forward and R=128 = 2161 at offset 3 backward.

**Per-offset detail at R=14 (v0.1, backward, single-bit starts, beam 2000, merged).** For compactness, the backward values are shown (they include the best cell of the whole table, offset 20 = 5); the forward values are in `beam_full.json` and the merged per-offset arrays are in the output of `merge`.

| offset (backward, last round mod 31) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| weight | 17 | 11 | 11 | 8 | 11 | 36 | 61 | 46 | 34 | 47 | 43 |

| offset | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| weight | 24 | 53 | 42 | 38 | 31 | 24 | 16 | 12 | 8 | 5 | 21 |

| offset | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 |
|---|---|---|---|---|---|---|---|---|---|
| weight | 25 | 21 | 13 | 19 | 41 | 36 | 36 | 28 | 26 |

The best cell at R=14 is offset 20 backward (weight 5). The next best are offsets 3 and 19 backward (weight 8). The forward per-offset table is available in `beam_full.json`; the best forward cell at R=14 is offset 23 (weight 5), tied with offset 20 backward. The spread (5 to 61 across offsets for the same R) is the evidence that the rotation offset matters a great deal, which is also why the differential analysis of §3 needs to be repeated over offsets.

**Growth.** Between R=22 and R=112 the best weight grows by roughly 12–21 per round (12.5 for 22–24, 14.5 for 24–32, 19.6 for 32–40, 15.5 for 40–48, 18.1 for 48–56, 19.5 for 56–64, 18.4 for 64–80, 15.9 for 80–96, 20.9 for 96–112). The last step, 112–128, is ≈36 per round (1671→2248 for v0.1, 1790→2294 for v0.2 forward, 1675→2161 for v0.2 backward). That step is inflated by the fitting rule: only one offset fits a full 128-round trail per direction, so the R=128 value is not a minimum over all 31 offsets as the others are. The average between R=48 and R=128 is ≈22 per round. The weight never settles at a low per-round cost. Note also that single-trail weights above ≈256 say nothing about the cipher: with a 256-bit block the sum over the many trails of a hull is what matters there, and no hull-aware statement is made beyond R=14.

#### 4.10.3. Hull check of the trails found

A single-trail weight w predicts `|corr| = 2^{-w}` only when the trail is alone in its hull. The beam trails were therefore checked against the real cipher (fixed key, final whitening disabled, 2^17–2^18 random states), prefix by prefix, using the stored per-round masks. Script: `misc/verify_beam_trail.py`; trail counting: `misc/hull_count.py`.

**Trail of offset 20 backward, R=14, w=5 (covers rounds 100–113; first_round[14] = 100).** Key seed 1, 2^17 states (σ = 0.0028):

| R | trail weight w | predicted 2^{-w} | empirical corr |
|---|---|---|---|
| 1 | 1 | 0.5000 | -0.4947 |
| 2 | 3 | 0.1250 | -0.1206 |
| 3 | 4 | 0.0625 | -0.0601 |
| 4 | 4 | 0.0625 | +0.0601 |
| 5 | 5 | 0.0312 | +0.0279 |
| 6 | 5 | 0.0312 | -0.0279 |
| 7 | 5 | 0.0312 | -0.0279 |
| 8 | 5 | 0.0312 | -0.0279 |
| 9 | 5 | 0.0312 | -0.0279 |
| 10 | 5 | 0.0312 | +0.0279 |
| 11 | 5 | 0.0312 | +0.0279 |
| 12 | 5 | 0.0312 | -0.0279 |
| 13 | 5 | 0.0312 | +0.0279 |
| 14 | 5 | 0.0312 | -0.0279 |

`hull_count` on the saved end mask returns exactly one trail at the minimum weight for every R from 1 to 14 (layer sizes 4, 64, 84, 10, 4, 2, 1, 1, ..., 1; the layer collapses to a single trail from R=7). The predicted and empirical magnitudes agree within σ at every R. There is no cancellation for this end mask. This is a verified linear distinguisher on a 14-round window (rounds 100–113).

**How to read it.** The weight reaches 5 at R=5 and stays there up to R=14: the trail is five cheap rounds followed by a 9-round weight-0 chain (the free chain of §4.3). The rows R=5..14 are therefore the same signal observed after more free rounds, not ten independent confirmations. The trail lies at rounds 100–113, so it is a property of that window of the cipher; it is not a distinguisher for a 14-round version of the cipher starting at round 0, and it is not an attack on the 128-round cipher. Section 4.10.5 extends the same trail to R=16 by two more weighted rounds (R=15: weight 8, R=16: weight 12).

**Trail of r0=23 forward, R=14, w=5 (start bit 197 of s[23]; end masks bits {46, 66, 84, 196} of s[37]), key seed 1, 2^17 states (σ = 0.0028):**

| R | trail weight w | predicted 2^{-w} | empirical corr |
|---|---|---|---|
| 1-4 | 0 | 1 | ±1.0000 |
| 5-7 | 1 | 0.5000 | -0.5014 |
| 8-10 | 2 | 0.2500 | ±0.0010 |
| 11-13 | 3 | 0.1250 | ±0.0012 |
| 14 | 5 | 0.0313 | -0.0001 |

The model is exact up to R=7. At R=8 the empirical correlation is zero instead of ±1/4. An exact enumeration of all trails with weight ≤4 from the same start mask shows why: two distinct trails of weight 2 reach the same end masks at R=8, 9 and 10 (and one at R=7), so their contributions cancel. Two independent keys at R=14 (2^18 states each, σ=0.002) give -0.0004 and +0.00001 against a single-trail prediction of 0.031. For this trail the single-trail weight is therefore not a usable estimate of the correlation.

**Other offsets, R=14 trails, one key (seed 1), 2^16 states (σ = 0.0039):**

| r0 | direction | R | single-trail 2^{-w} | empirical corr | relation |
|---|---|---|---|---|---|
| 12 | forward | 10 | 0.5000 | +0.4969 | equal |
| 12 | forward | 12 | 0.1250 | -0.1161 | equal (sign key-dependent) |
| 27 | forward | 10 | 0.1250 | +0.2503 | ×2 |
| 27 | forward | 12 | 0.0156 | +0.0369 | ×2.4 |
| 26 | forward | 10 | 0.1250 | +0.2412 | ×2 |
| 26 | forward | 12 | 0.0625 | +0.1218 | ×2 |
| 24 | forward | 10 | 0.1250 | +0.0049 | cancelled |
| 24 | forward | 12 | 0.1250 | -0.0049 | cancelled |

At R=14 the predicted correlations (2^-7 to 2^-12) are below the resolution of this test (σ=0.0039) for these four forward trails, so no statement is made at R=14 for them. The offset-20 backward trail (previous table) is measurable at R=14 because its weight stays at 5 from R=5 to R=14, so the test at R=14 is the same signal as at R=5 (where σ is adequate).

**Reading.** Across the trails checked, the real correlation equals the single-trail value (offset 20 backward at R=14; r0=12 forward up to R=12), is about twice as large (r0=26, r0=27 forward; a second trail adds constructively), or is exactly cancelled (r0=23 forward from R=8; r0=24 forward). The observed gain is at most ≈2.4× (about 1.3 bits); the observed loss can be total. Hull effects are therefore not a uniform correction, and they are not always destructive: some trails survive intact and are genuine distinguishers of their window.

#### 4.10.4. What §4.10 establishes and what it does not

**Established:**

- In the single-trail model, and within the searched family (single-bit starts, beam 2000, 3 sparsest g per cell, both directions), no trail with weight <64 (≈2^128 texts) was found for more than 22 rounds (v0.1 merged) or 19 rounds (v0.2 forward and backward), and none with weight <32 for more than 19 rounds (v0.1 backward) or 17 rounds (v0.2 forward and backward). The 22-round threshold for v0.1 is a tie (weight 63): ≈20–22 is the defensible reading.
- The best weight grows by roughly 12–21 per round from R=22 to R=112 (≈22 on average from R=48 to R=128, inflated by the last step).
- The cheapest trails alternate direction (see §4.10.2 for the exact R values).
- The best cell at R=14 for v0.1 is offset-20 backward (weight 5), tied with offset-23 forward. The best cell at R=14 for v0.2 is offset 14 forward (weight 8), offset 11 backward (weight 11); the combined minimum is 8.
- The tool agrees with the real cipher wherever a trail is alone in its hull (offset-20 backward up to R=14; r0=12 forward up to R=12; r0=23 forward up to R=7).
- Single-trail weight is not a reliable proxy for correlation in general: exact cancellation was observed (r0=23 and r0=24 forward).
- The offset-20 backward trail at R=14 is isolated in its hull (`hull_count = 1` trail) and its empirical correlation matches 2^-5 on the real cipher.
- The exact budgeted hull of §4.10.5 extends it to R=16 (rounds 98–113, `|corr| = 2^-11`, two trails of weight 12 adding, empirical 6.1×10^-4 ± 6.1×10^-5 against a hull prediction of 4.9×10^-4). This is a verified linear distinguisher on a 16-round window (rounds 98–113).
- At R=17 the best end pairs of offset 20 backward (7 of 8 computed) and offset 23 forward (8 of 8) cancel exactly within the enumerated budget, for both keys tested (§4.10.5).
- Multi-bit starts (pairs47, `rand:5000:4`) did not improve on single-bit starts at any R. pairs47 is a small structured subset; `rand:5000:4` covers 5000 masks out of 2^256 and is not conclusive for structured multi-bit masks.
- The v0.2 backward beam to R=128 gives ub[R=128] = 2161 at offset 3 backward. The v0.2 forward beam gives ub[R=128] = 2294 at offset 0 forward. The v0.1 backward beam gives ub[R=128] = 2248 at offset 3 backward.

**Not established:**

- A distinguisher length beyond R=16 for v0.1. R=16 is established for the offset-20 backward trail (exact hull over trails of weight ≤14 plus a one-key measurement). At R=17 the best pairs cancel within the budget, which does not exclude a smaller non-zero correlation from heavier trails or a distinguisher from other end pairs. R ≥ 18 is undecided: the weights are ≥24 and the frontiers of the enumeration exceed the state caps (§4.10.5). The trails of §4.10.2 at R=18–22, including the weight-63 trail at R=22 that sits at the 2^128 threshold, have not been checked.
- A lower bound. The beam gives achievable weights only. The truncations (`g-keep 3`, beam, single-bit starts, exclusion of b = 0xFFFFFFFF) may hide cheaper trails.
- That hull gain stays small at larger R. At R=24 (w=88) a gain of ≈2^24 in correlation (88−64) would be needed to bring the data cost down to the 2^128 budget; the gains observed so far are ≤2.4× (exactly 2× at R=15 and R=16) and were measured only up to R=16.
- That multi-bit starts do not help at all. The tested samples (pairs47, `rand:5000:4`) do not improve on single-bit, but the random sample is too small to rule out structured multi-bit masks that might. The honest statement is "the multi-bit starts tested do not improve on single-bit".
- Key recovery from any hull, differential analogues, and the effect of the final whitening and of key-recovery rounds around a distinguisher.
- v0.2 hull empirical verification, v0.2 multi-bit starts, v0.2 exact 128-round hull, v0.2 hull-aware bound beyond R=14.

#### 4.10.5. Exact hull at R=15–17 (budgeted, meet-in-the-middle)

§4.10.4 named the exact signed hull of the best end-mask pairs at R ≥ 16 as the next step. This section does it for R=15–17 and reports where it stops. Tools: `misc/hull_bidir.py`, `misc/scan_endpairs.py`, `misc/test_signed_dp.py`, `misc/emp_check.py`. Inputs: `misc/beam_paths_bwd20.json` and `misc/beam_paths_fwd23.json`, re-runs of `mysx_linear_beam.py run` for offset 20 backward and offset 23 forward with `--paths 15..22` (their ub values and the R=14/20/24 paths are identical to `beam_bwd.json`/`beam_full.json`). A summary with the reproduction commands is in `misc/HULL_R15_R17.md`.

**Method.** `hull_count.py` expands only forward from the start mask, so its layers explode when heavy rounds sit at the start of the trail (backward trails). `hull_bidir.py` grows a forward frontier from the start mask u and a backward frontier from the end mask v (always extending the smaller one), prunes each state with the minimum weight already paid by the opposite frontier, and streams the last round into the join. Any trail u→v of total weight ≤ wmax has prefix and suffix weight ≤ wmax, so the result is complete for weight ≤ wmax (cells with b = 0xFFFFFFFF are skipped, which matters only from weight 15 per cell). With `--keys K` it also sums the exact signed contributions (cell sign from the LAT, key sign `(-1)^{m·rk}`) for K random keys.

**Validation.** `mysx_linear_beam.py selftest` passes; the signed hull equals `propagate()` of `mysx_linear_model.py` on 40 of 40 end masks (windows r0=12 with R=10, 11, 12 and r0=27 with R=10, two keys; `test_signed_dp.py`); at R=14 offset 20 backward, it reproduces `hull_count.py` (one trail of weight 5). These validation windows are forward and R ≤ 12; the signs of the backward step are validated indirectly by the empirical measurements below.

**Results.** w1 is the single-trail weight of the beam trail; "budget" is wmax (all trails up to it are enumerated). The hull value is the same for keys `rand_key(1000)` and `rand_key(1001)`.

| Trail | R | Rounds | w1 | Trails u→v found | Budget | Exact hull |
|---|---|---|---|---|---|---|
| offset 20 bwd | 14 | 100–113 | 5 | 1 × w5 | 7 | ±2^-5 (isolated) |
| offset 20 bwd | 15 | 99–113 | 8 | 2 × w8 | 10 | ±2^-7 (two trails add) |
| offset 20 bwd | 16 | 98–113 | 12 | ≥1 × w12 | 14 | ±2^-11 (two trails of weight 12 add; empirical 6.1×10^-4 ± 6.1×10^-5, +1.9σ) |
| offset 23 fwd | 16 | 23–38 | 8 | several w8, w9, w10 | 10 | 0 (cancellation within budget) |
| offset 23 fwd | 17 | 23–39 | 14 | several w14 | 14 | 0 (cancellation within budget) |
| offset 20 bwd | 17 | 97–113 | 16 | 2 × w16 | 18 | 0 (cancellation within budget) |

A hull of 0 means "no net contribution from trails up to the budget", not a correlation of exactly 0. Trails above the budget are not summed (weight ≥15 at R=16, ≥19 at R=17 in the main runs; the R=17 scan used a budget equal to the pair's own weight). The measured correlation at R=16 is 1.9σ above the hull prediction, which is compatible with noise and also with a few trails of weight 15 (each adds 2^-15); a run at R=16 with `--wmax 18` and more keys has not been done.

R ≥ 18 is undecided: the weights are ≥24 and the frontiers exceed 2.5 million states. Only end pairs returned by the beam were tried; other pairs at R=17–22 may not cancel. Covering them needs a different method (the SAT/MILP hull encoding of `LINEAR_MODEL.md` §7) or a much larger scan. In particular the weight-63 trail of the R=22 row of the §4.10.2 table, which decides the position of the 2^128 threshold for v0.1, is untouched.

The sign was checked empirically for one key only. None of this is a key-recovery cost, a lower bound, or an attack on the 128-round cipher.

#### 4.11. Statistical randomness of the CTR keystream

**v0.1.** Tool: NIST Statistical Test Suite (STS) 2.1.2, plus the generator script `misc/gen_nist_input.js`. This section reports the first statistical randomness test of the MYSX keystream; it was absent from v0.1-draft.

**Method.** One hundred independent sequences of 1,000,000 bits each were produced as follows: for each sequence, a fresh uniformly random 512-bit key and a fresh uniformly random 128-bit nonce were drawn, an all-zero plaintext of 125,000 bytes was encrypted with the CTR mode of §2.8 (with `FinalWhiten = true`, i.e. the full 128-round cipher), and the resulting keystream was written as a raw binary file. The 100 files (12,500,000 bytes in total, exactly 100,000,000 bits) were concatenated and fed to STS 2.1.2 with `./assess 1000000`, all 15 tests enabled, default parameters (block frequency M=128, template m=9, approximate entropy m=10, serial m=16, linear complexity M=500), binary input mode, and 100 bitstreams.

**Results, v0.1.** No test failed. No row is flagged with `*` or FAIL, no uniformity p-value is below the 0.0001 threshold, and no proportion is below the NIST minimum for its sample size.

| Test | Proportion | Uniformity p-value | Verdict |
|---|---|---|---|
| Frequency | 97/100 | 0.851383 | pass |
| Block Frequency | 97/100 | 0.289667 | pass |
| Cumulative Sums (fwd/rev) | 97/100 | 0.350485 / 0.637119 | pass |
| Runs | 100/100 | 0.834308 | pass |
| Longest Run of Ones | 100/100 | 0.096578 | pass |
| Rank | 100/100 | 0.574903 | pass |
| Discrete Fourier Transform | 96/100 | 0.779188 | pass |
| Non-Overlapping Template (148 sub-tests) | 96–100/100 | min 0.017912 | pass |
| Overlapping Template | 99/100 | 0.978072 | pass |
| Universal | 99/100 | 0.051942 | pass |
| Approximate Entropy | 99/100 | 0.051942 | pass |
| Random Excursions (8 states, n=65) | 64–65/65 | min 0.041438 | pass |
| Random Excursions Variant (18 states, n=65) | 63–65/65 | min 0.063482 | pass |
| Serial (two sub-tests) | 100/100 | 0.798139 / 0.366918 | pass |
| Linear Complexity | 100/100 | 0.224821 | pass |

The NIST minimum pass rate for a sample of 100 sequences is approximately 96/100 (61/65 for the random-excursion tests, which use 65 sequences because of cycle counts). The tightest margins in this run are the Discrete Fourier Transform test and two Non-Overlapping Template sub-tests, all at exactly 96/100; every other 100-sequence test is at 97/100 or above. The smallest uniformity p-value in the whole report is 0.017912, roughly 180× the 0.0001 rejection threshold.

**v0.2.** PENDING. `nist_v02` is skipped in `paper_results.json` with `requires_file not present: sts-2.1.2/assess`. The `nist.yml` workflow fails at "Download and build NIST STS 2.1.2" (build error not yet diagnosed). The v0.2 block cipher uses the same core as v0.1 with a different calendar; the NIST battery is expected to pass by analogy, but has not been measured. The v0.1 pass is preserved in `LEGACY_V1/NIST_SP_800-22_report.txt`.

**What this establishes and what it does not.**

Established:

- The CTR keystream of the full 128-round MYSX v0.1 passes the complete NIST SP 800-22 battery on 100 independent sequences of 10^6 bits, with fresh keys and nonces per sequence, no failures, and margins inside the NIST acceptance region for every test.

Not established:

- Any statement about cryptographic security. SP 800-22 detects gross statistical biases (non-uniformity, short-period artefacts, linear structure at the bit level, excess runs); it does not detect differential, linear-hull, or algebraic weaknesses, and a primitive can pass it and still be trivially broken.
- Any statement about reduced-round versions of the cipher. The test covers the full 128 rounds with the final whitening enabled, exactly as the public API uses it.
- Any statement about the AEAD construction as a whole (HMAC-SHA256 tag, packet format, nonce policy); only the raw keystream was tested.
- Independence between the 100 sequences beyond the fact that each uses a fresh random key and nonce. The sequences were drawn independently; no pairwise statistical test was run.
- Resistance to TestU01 (Crush/BigCrush) or dieharder, which were not run. TestU01 BigCrush is strictly stronger than SP 800-22 and would be the natural next step; it is left for future work.
- Any NIST result for v0.2.

The purpose of this section is narrow and negative: it rules out the trivial failure mode of a keystream with detectable statistical structure. It is not evidence of security, and it does not change the verdict of §10.

### 4.12. Impossible differentials

**Weight-0 chains.** Verified table in §3.5. v0.1: max 13 rounds at r0=10. v0.2: max 5 rounds at several offsets.

**Exact DMITM.**

| Version | Max weight-0 chain | Exact DMITM |
|---|---|---|
| v0.1 | 13 rounds | 17 rounds |
| v0.2 | 5 rounds | 9 rounds |

**v0.1 verification.** `dmitm_v1` confirms max=13, total=17 with 0 offsets where multi-bit improves over single-bit. The best witness is `Δs[23] = w1b31 -13 rounds-> w4b12`, `Dout = w7b6 <-4 rounds- w3b16`, incompatibility at s[23]. Verifiable in 0.3s. The full `(R, a, b)` table has 44 entries at total=12, 34 at 13, 22 at 14, 12 at 15, 5 at 16, 1 at 17.

**v0.2 verification.** `dmitm_v02` confirms max=5, total=9 with 0 offsets where multi-bit improves over single-bit. The best witness is `Δs[3] = w3b16 -4 rounds-> w6b18`, `Dout = w7b7 <-5 rounds- w0b30`, incompatibility at s[3]. The full `(R, a, b)` table has 93 entries at total=4, 110 at 5, 97 at 6, 66 at 7, 36 at 8, 15 at 9. The 9-round candidates are listed at R=3, 4, 8, 9, 13, 16, 17, 18, 20, 21, 22, 24.

**Truncated impossible (v0.1).** `Δs[44] = w2b29 -18 rounds-> s[62] <-21 rounds- Δs[83] = w7b24`, conflict at w6b16. This is 39 rounds. Verified with `dmitm_trunc_v3.py --cal k1`: premises 100% over 2000 pairs × 4 keys per side (0x00, 0xFF, and 2 random); propagation of the witness is exact and the conflict at w6b16 is confirmed. Top 1 of 1 distinct candidate at the maximum length.

**Truncated impossible (v0.2).** Top 2 of 2 distinct candidates at the maximum length 28:

| len | R | rs | bi | f | re | bo | g | conflict |
|---|---|---|---|---|---|---|---|---|
| 28 | 74 | 66 | w2b25 | 8 | 94 | w4b14 | 20 | w4b17 (1 bit) |
| 28 | 76 | 67 | w3b19 | 9 | 95 | w7b18 | 19 | w4b20 (1 bit) |

The best witness is `Δs[66] = w2b25 -8 rounds-> s[74] <-20 rounds- s[94] = w4b14`, conflict at **w4b17**. This is 28 rounds. Verified with `dmitm_trunc_v3.py --cal v02 --verify 500`: premises 2000/2000 per side against the real cipher (`VERIFY: fwd 2000/2000 bwd 2000/2000 OK`). The calibration is `v02 (rand_s9_45430) max_fwd=24 max_bwd=24 n_bits=256`.

**Reduction.** 39→28 (11 rounds). Consistent with the reduction in exact DMITM (17→9, -8) and weight-0 chain (13→5, -8). The truncated figure is the exact figure plus a short weighted prefix, so both shrank by approximately the same amount.

**Not established.** The search covers single-bit starting masks on all 31 rotation offsets. Multi-bit starts, weight-1 rounds, and narrower propagation are PENDING. The `--verify` check confirms the premises but is not a key-recovery cost. The truncated witness is a distinguisher, not an attack.

### 4.13. Rotation schedule selection

The 9-metric comparison (v0.1 vs v0.2, from `wf2_deep_summary.json`):

| Metric | v0.1 | v0.2 | Result |
|---|---|---|---|
| dp5 (integral R=5) | 21 | 9 | improvement |
| dp6 (integral R=6) | 4 | 4 | tie |
| lin_fwd10 | 10 | 11 | tie |
| lin_bwd10 | 10 | 13 | improvement |
| lin_fwd14 | 5 | 8 | improvement |
| lin_bwd14 | 5 | 11 | improvement |
| DMITM exact | 17 | 9 | improvement |
| Weight-0 chain | 13 | 5 | improvement |
| MILP R=5 | 4 | 4 | tie |
| Truncated impossible | 39 | 28 | improvement (-11) |

Directions. Lower is better for dp5, dp6, DMITM, chain, truncated. Higher is better for lin_fwd10/14, lin_bwd10/14, MILP.

**6 improvements, 3 ties, 0 regressions** on the 9 core metrics (dp5, dp6, lin_fwd10, lin_bwd10, lin_fwd14, lin_bwd14, DMITM, chain, MILP). Truncated is an additional improvement outside the 9-metric count.

**A false positive documented.** `rand_s9_33719` was top-ranked by R=4 screening (with dp4=42, mlp5=10). At R=6 its integral is worse than v0.1 (dp6=12 vs 4) and its linear weight at R=14 is 13 vs 5. Screening at R ≤ 4 is not sufficient.

**Why Myszkowski is not the cause.** A control with 40 random byte permutations and the same consecutive schedule gives mean exact DMITM 21.4 (range 10–34). MYSX v0.1 is at ~22nd percentile. Changing the consecutive schedule to (k·r mod 31)+1 for k ∈ {2,3,5,7} drops the maximum chain to 6–9 rounds. The variable is the schedule step, not the permutation.

**Reproducibility.** `MYSX_ROT_CAL=22,5,8,...` (see §2.8) reproduces the v0.2 schedule. `search_mysx_deep.py --n 1000000 --seed 9` regenerates the search. `cryptanalysis/DMITM/wf2_deep_summary.json` contains the raw 8×9 table.

### 4.14. What is PENDING for v0.2

The following are measured for v0.1 and not re-measured for v0.2, or only partially measured:

**Differential:**

- Beam differential (only MILP for v0.2; the beam-differential tables are v0.1 only).
- Cluster analysis at v0.2 offsets.
- The full 31-offset differential sweep is now measured for v0.2 (`diff_offset_sweep_v02`): best r0=29=94, worst r0=2=335, r0=19=275, r0=27=172, r0=30=None. This item is no longer PENDING.

**Linear:**

- Hull empirical verification for v0.2 (`lin_hull_v02` computes predictions at r0=12 but does not compare against the real cipher).
- v0.2 hull-aware bound beyond R=14.
- v0.2 exact 128-round hull.
- Multi-bit starts for v0.2.
- v0.2 backward beam to R=128 is now measured (`lin_beam_v02_R128_bwd`: ub[R=128]=2161 at offset 3 backward). This item is no longer PENDING.

**Integral:**

- Full 31-offset sweep for v0.2 (only 6 offsets measured at R=5–6).
- r0=15 peak for v0.2 (the v0.1 peak has not been checked for v0.2).
- R=7–10 tail for v0.2.
- Full 2^32/2^64 integral verification for v0.1 (the toggle test is a necessary condition only).

**Impossible:**

- Multi-bit starts.
- Weight-1 rounds.
- Narrower propagation.

**NIST:**

- Full NIST SP 800-22 battery for v0.2. `nist_v02` is skipped because `sts-2.1.2/assess` is not present. The v0.1 pass is preserved in `LEGACY_V1/NIST_SP_800-22_report.txt`.

**Related-key:**

- The 22-test re-validation is done (`rk_extended` 22/22 PASS; key schedule unchanged from v0.1; same structural limitation, worst bit 160). This item is no longer PENDING.

**Simon normalized coverage comparison:**

- v0.1's comparison was against the consecutive schedule for MYSX; v0.2 has different figures.

**Differential R=16, R=17 empirical trails:**

- The item `diff_r16_r17_v1` is not in the current `paper_results.json`. If it exists in the repository, it should be added to the manifest and re-run; if it was removed, this bullet should be removed from the paper.

**Other:**

- Boomerang, algebraic, side-channel: not analyzed.
- No external audit.

---

## 5. Related-key cryptanalysis

Inherited from v0.1 (key schedule unchanged). Tools: `misc/keyschedule_test.js` (basic) and `misc/keyschedule_test_extended.js` (22 tests). Coverage: exhaustive weight-1 (512 bits), exhaustive weight-2 (130,816 pairs), weight-3 "same Δ" (1,680 trials), beam search up to weight-6 (beam 50), 5 base keys, structured patterns, cycles, weak keys.

**Results (summary):**

- No persistent Δrk[r]=0 for r ≥ 1 in any test.
- Beam search score: 139 (ideal 128).
- No weak keys, cycles, or fixed points.
- Slow diffusion at r=1–4 (expected: one Feistel round per cipher iteration).
- Worst bit (minimum weight at r=1): bit 160 (word 5, bit 0), 1-bit difference. Consistent across 5 base keys (structural, not noise).

**v0.2 re-validation.** `rk_extended` runs 22/22 PASS on v0.2 (key schedule unchanged). The PASS list is:

- Verificación vs prod: PASS
- Biyectividad: PASS
- Espacio nulo rk[0] (255 patrones × 3 modos): PASS
- Propagación exhaustiva (persistencia): PASS
- Peso-1 exhaustivo (512): PASS
- Peso-2 exhaustivo: PASS
- Patrones estructurados: PASS
- Beam search: PASS
- Avalancha por bit: PASS
- Ciclos / puntos fijos: PASS
- Weak-key scan: PASS
- Matriz de influencia: PASS
- Mínimos locales conocidos: PASS
- Ventanas de bajo peso (FIX): PASS
- Multi-base consistencia (FIX): PASS
- Peso-3 misma Δ: PASS
- Coste distinguidor (FIX): PASS
- Multi-base bit consistencia (FIX): PASS
- Ventanas espacio nulo (FIX): PASS
- Identificar peor ΔK: PASS
- Extensión de ventana (umbral 40): PASS
- Peso mínimo por ronda: PASS

**Interpretation (from the test output):**

- key schedule sin Δrk[r]=0 persistente en ninguna prueba.
- Difusión lenta en r=1–4 (esperada por diseño: 1 ronda Feistel por iteración).
- Bit 160 (word 5, bit 0, mitad L) es el peor bit: Δrk[1] con 1 bit.
- Es una debilidad ESTRUCTURAL (consistente entre bases), no ruido.
- No explotable con las técnicas actuales (beam search score=139).
- Para eliminar: rediseñar key schedule en v0.2 (2 rondas Feistel por iteración). La v0.2 mantiene el key schedule de v0.1; esta recomendación es para una versión futura.

**Limitations.** These are heuristic tests, not a proof. We did not run a targeted MILP/SAT related-key model (~650k variables); adaptive related keys, biclique attacks, and algebraic attacks on the key schedule are not covered. MYSX's related-key security is unknown.

**Round-key recovery.** The only non-linear operation of the key schedule is the 8 modular additions per step; everything else is XOR and rotation. The schedule is bijective, so any 16 consecutive state words determine the master key. How many round keys must be known for a SAT solver to recover the master key (an estimate by counting: about three consecutive rk[r]) has not been measured. This number bounds what a partial key-recovery attack on a few rounds can lead to.

---

## 6. Generic attacks

| Attack | Complexity (uniformly random 512-bit secret) | Verdict |
|---|---|---|
| Classical brute force | 2^512 operations | Infeasible |
| Grover (quantum) | 2^256 iterations | Infeasible with foreseeable technology |
| Block collisions | 2^128 blocks | Infeasible |

**Note on Grover.** With a uniformly random 512-bit key, Grover leaves 256 bits of effective security. With 1,000,000 logical qubits at 1 ns/iteration, the time would be ~10^60 years. This is a theoretical estimate; no post-quantum analysis of the cipher beyond Grover has been done.

**Note on the 512-bit key.** The v2 API (Section 2.9) processes a uniformly random 64-byte secret through HKDF-SHA512, so Grover leaves 256 bits of effective security (2^256 quantum iterations). The v1 API's HKDF-Extract with HMAC-SHA256 produces a 256-bit PRK, so the effective quantum security for v1 is 2^128, not 2^256, even for a 512-bit input. The `v2_smoke` output confirms this: `security_raw64 = {classicalBits: 512, groverBits: 256}` and `security_raw32 = {classicalBits: 256, groverBits: 128}`.

**Note on password paths.** Security is limited by password entropy, not by the nominal key size. `v2.securityLevel` returns `null` for `classicalBits`/`groverBits` when the password is not accompanied by a ≥64-byte keyfile. A keyfile is strongly recommended. The `v2_smoke` output confirms that a password alone does not declare 2^256; with a 64-byte keyfile it does.

---

## 7. Simon cryptanalysis: what transfers and what does not

MYSX uses Simon's F. It is not Simon. The differences:

- Block size and branch organization: MYSX is an SPN-like structure with four parallel Feistel cells over 32-bit word pairs (Section 2.1). Simon is a classical 2-branch Feistel over n-bit halves. Four parallel F per round (Simon uses 1).
- Myszkowski byte transposition (Simon has none).
- Round-dependent word rotations (Simon has none).
- Non-linear ARX key schedule (Simon's is linear).
- 128 rounds vs 68.

**What transfers.** The exact LAT of F — its closed form `|corr| = 2^{-h(b)}`, its validity condition `l ∈ colspace(A_b)`, and its sign structure — is a property of the function and therefore applies to MYSX regardless of the surrounding structure (Section 4.2 is the transfer). That is the correct starting point for MYSX-specific linear cryptanalysis; the failed models of the v0.0 draft used a different (incorrect) F model.

**What does not transfer.** Key recovery from Simon's linear key schedule does not transfer: MYSX's key schedule is non-linear. Linear hull attacks against Simon are highly structured around Simon's Feistel-branch and its round-reduced behaviour; the MYSX hull is a different object and must be computed from the MYSX round model (Section 4.6). Integral distinguishers against Simon rely on Simon's particular 2-branch Feistel structure and its key schedule; the MYSX integral distinguishers in §4.9 are considerably shorter, and their relationship to Simon's is one of normalized coverage, not direct transfer.

**Relevant literature on Simon (cited for context; the figures below were checked against the papers' abstracts, other figures quoted in earlier drafts were not verified and have been removed):**

- Linear-hull key-recovery attacks with dynamic key-guessing reaching 49 rounds of Simon128/128 (Chen-Wang, "Improved Linear Hull Attack on Round-Reduced Simon with Dynamic Key-guessing Techniques", FSE 2016, ePrint 2015/666).
- Improved linear characteristics and hulls, including a 34-round linear characteristic with correlation 2^-61 for Simon128 (Shi-Hu-Sun-Song-Qiao-Ma, "Improved Linear (hull) Cryptanalysis of Round-reduced Versions of SIMON", ePrint 2014/973).
- Differential analysis of Simon and Speck (Biryukov-Roy-Velichkov, "Differential Analysis of Block Ciphers SIMON and SPECK", FSE 2014).
- Integral distinguishers: 14 rounds for Simon32 with the conventional bit-based division property, and 15 rounds with three subsets (Todo-Morii, "Bit-Based Division Property and Application to Simon Family", FSE 2016); 14-, 16-, 18-, 22- and 26-round distinguishers for Simon32/48/64/96/128 (Xiang-Zhang-Bao-Lin, ASIACRYPT 2016).
- Structural observations on the SIMON family (Kölbl-Leander-Tiessen, "Observations on the SIMON block cipher family", CRYPTO 2015).

None of these results is transferred to MYSX in this paper. The MYSX-specific analysis (Sections 3, 4, 5) is what provides the evidence; Simon attacks are context, not direct transfer.

---

## 8. Analysis limitations

**Differential:** single-trail upper bounds over 31 rotation offsets (inputs chosen by the free chain table at r0=10 or w2b30 for r0=0); two independent deterministic chains verified empirically for v0.1 (13 rounds at r0=10, 6 rounds at r0=15); no lower bounds; no full clustering analysis at r0≠0; the exact maximum of weight-0 chains (13 for v0.1, 5 for v0.2) is proven, but the non-zero-weight tables are upper bounds from a beam or time-limited MILP. The full 31-offset differential sweep is measured for v0.1 (`diff_offset_sweep_full_v1`: best r0=10=2, worst r0=21=211, r0=30=None) and for v0.2 (`diff_offset_sweep_v02`: best r0=29=94, worst r0=2=335, r0=30=None). The v0.1 R=14 offset sweep has 14 unresolved offsets; the v0.2 R=14 offset sweep has 1 unresolved offset (r0=30).

**Linear:** an exact model of F is established and matches the real cipher on small round counts, including exact signed hulls at r=10, 11, 12 (v0.1). A beam search over the exact model, in both directions and merged over all 31 offsets, up to 128 rounds (§4.10), gives achievable single-trail weights only:

- v0.1: 2 at R=12, 5 at R=14, 38 at R=20, 2248 at R=128 (offset 3 backward). The largest R with weight <64 is 22 (weight 63, a tie with the threshold; backward-only is 21).
- v0.2 forward: 3 at R=12, 8 at R=14, 71 at R=20, 2294 at R=128 (offset 0 forward). The largest R with weight <64 is 19; <32 is 17.
- v0.2 backward: 6 at R=12, 11 at R=14, 69 at R=20, 2161 at R=128 (offset 3 backward). The largest R with weight <64 is 19; <32 is 17.

The offset-20 backward trail at R=14 (rounds 100–113) is isolated in its hull (`hull_count = 1`) and its empirical correlation matches 2^-5; an exact budgeted hull extends it to R=16 (rounds 98–113, `|corr| = 2^-11`): that is a verified linear distinguisher on a 16-round window. Other trails cancel or are ≈2× larger (at R=17 the best pairs cancel within the budget), so single-trail weights are not universally distinguisher lengths. No lower bound over 128 rounds; no hull-aware bound beyond R=17; hulls are exact only up to a weight budget; g choices truncated to the 3 sparsest per cell; no key-recovery cost estimate. Multi-bit starts (pairs47, `rand:5000:4`) were explored and did not improve on single-bit starts, but the random sample is too small to be conclusive for structured multi-bit masks. v0.2 hull empirical verification is PENDING. v0.2 exact 128-round hull is PENDING.

**Integral:** v0.1 has 6–10 round distinguishers depending on the rotation offset: 6 rounds (2^32) / 5 rounds (2^64) at r0=0; 10 rounds (2^32 and 2^64) at r0=15, with a thin tail (1 balanced bit at R=10, 0 at R=11). The offset sweep shows the round count is offset-dependent. Verification covers the R=7/R=6 bits at r0=15 (consistent with bit-0 or double toggle; not full 2^32/2^64 integrals); the R=8–10 tail is a model prediction. Only r0=0 was tested for three-subset and traceability-enhanced DP; full-block inputs and key-recovery attacks were not explored. v0.2 has 9/256 and 4/256 balanced bits at R=5/6 at all six measured offsets (0, 5, 10, 15, 20, 27). Full 31-offset sweep and r0=15 peak for v0.2 are PENDING.

**Impossible:** v0.1 exact=17, truncated=39 (verified); v0.2 exact=9, truncated=28 (verified, conflict w4b17). Multi-bit starts and weight-1 rounds PENDING.

**Related-key:** heuristic tests up to weight-6; no targeted MILP; number of round keys needed to recover the master key not measured. v0.2 re-validation 22/22 PASS (`rk_extended`).

**NIST:** v0.1 pass (table in §4.11); v0.2 skipped (`nist_v02` `requires_file not present: sts-2.1.2/assess`).

**Other:** boomerang, algebraic, side-channel not analyzed. No independent public cryptanalysis. No post-quantum analysis beyond the trivial Grover bound. No side-channel analysis. Functional tests (`mysx.test.js`, 17 tests) cover round-trip, AEAD negatives, nonce policy, PBKDF2, avalanche. They do not prove security. The v2 security suite (`tests/mysx_v2.test.js`, 58 tests) covers KAT regression, cross-language KAT, per-byte bit-flip rejection, AAD/context/secret binding, KDF bounds, anti-downgrade, password+keyfile separation, Argon2id RFC 9106 vector, and v1/v2 packet separation. It does not prove security either.

---

## 9. Engineering notes

### 9.1. API surface

**Public (v2):** `v2.seal`, `v2.open`, `v2.generateSecret`, `v2.securityLevel`, `v2.setArgon2Provider`, `v2.argon2FromNoble`, `v2.CAL`, `v2.KDF`, `v2.DEFAULTS`, `v2.LIMITS`.

**Public (v1, deprecated):** `aeadEncrypt`, `aeadDecrypt`, `deriveAeadKeys`, `deriveAeadKeysFromPassword`, `NonceGuard`, `CONFIG`.

**Test API:** disabled by default. Enabled only when the environment variable `MYSX_ENABLE_TEST=1` is set in the process before requiring the module. There is no code-level toggle. CTR (`_ctrXor`) is not exported from the public API.

### 9.2. Migration v1 → v2

- v1 packets (0x01...) decryptable with `aeadDecrypt`.
- v2 packets (0x02...) created by `v2.seal`, not decryptable by `aeadDecrypt`.
- Do not use `aeadEncrypt` for new data (HKDF-SHA256 → 2^128).
- Do not pass `_salt`/`_nonce` to `v2.seal` in production (internal parameters for KAT generation).
- v2 is the recommended path for all new data.

### 9.3. NonceGuard (v1)

`NonceGuard` is a best-effort defense against nonce reuse in v1. It:

- counts messages per key (default 2^32);
- detects recent nonce reuse (window of 1024 per key);
- caps the number of tracked keys (default 1024, LRU eviction);
- identifies keys by a non-cryptographic 64-bit identifier made of two independent 32-bit lanes (a 32-bit FNV-1a lane and a multiplicative lane), not by the raw key bytes;
- on `onSave(state)` therefore does not leak the secret key;
- throttles `onSave` calls (default: once every 100 `check()` calls) to avoid per-message state copies;
- does not persist across restarts by itself;
- does not share state across processes or devices.

Persistence is provided by `onSave(state)` and `initialState` at construction, or by `save()` / `load(state)` for manual control.

It is not a substitute for key lifecycle management. If the application reuses (key, nonce) across restarts, CTR confidentiality is broken. When a key is evicted from the tracked set its counter and nonce window are lost. See `mysx.prod.js` for the exact contract.

**What it actually buys.** `aeadEncrypt` draws a fresh 16-byte random nonce for every message, so an accidental repeat of (key, nonce) has probability about 2^-65 even after 2^32 messages under one key (birthday bound on 128 bits). The nonce-window check therefore guards mainly against a faulty random-number generator; the part that matters in practice is the per-key message limit, which is also lost when a key is evicted or the process restarts. The option name `unsafeNoGuard` reflects that the guard is missing, not that nonces are imposed by the caller (they are not: there is no public path to impose a nonce).

The v2 API does not need `NonceGuard`: every message uses a fresh 32-byte salt and 16-byte nonce.

### 9.4. Type validation

All public functions validate that byte inputs are `Uint8Array` of the expected length (where applicable). Passing a string as `aad` or `plaintext` throws instead of silently coercing to array-like behavior.

### 9.5. KAT digests

Two digests are documented in `README.md`:

- `KAT.json` public digest: SHA-256 over the full JSON (block + AEAD + KDF). This is the artifact a third-party implementation should reproduce. Digest: `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`.
- `KNOWN_KAT_DIGEST` (internal): SHA-256 over 16 blocks with `key[i]=i`. Used as fast regression in `mysx.test.js`. It is strictly a subset of the public KAT, not a different KAT. Digest: `3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`.

`KAT_v2.json` (v0.2) adds:

- `block_v02`: 8 blocks with `CAL=1`.
- `v2_raw`, `v2_password_argon2`, `v2_password_scrypt`, `v2_kdf`, `v2_parse`, `security_level`.
- `block_digest_cal0 = KNOWN_KAT_DIGEST`.
- `block_digest_cal1 = d1b3e268...` (full 64-char value in `KAT_v2.json`; the `kat_v2` stdout shows `d1b3e268af1c7422`).
- `tests/_v2_kat_cross.json`: 6 cross-language v2 packets.

A third-party implementation should target the public v0.1 digest, `block_digest_cal1` for v0.2, and the 6 cross-language v2 packets.

### 9.6. Harness validation

**Linear sampling harness.** Validated against a hand-computed case at w=8, r=1, α={word0 bit2, word4 bit0}, β=word0 bit3, fixed key. The linear approximation `x_0 ⊕ F(x)_2 = x_1 x_6` has correlation exactly ±1/2 with fixed key. Observed correlation: 0.499296 (expected 0.5, within sampling noise). With random keys per sample, the sign of the correlation flips per sample and the observed |corr| drops to 0.002190 (expected ≈0). This confirms the harness is correct when used with fixed keys. It also confirms that the practice of "random keys per sample", used in an earlier version of `misc/mini_trail.js`, washes out genuine linear signals and must not be used for linear cryptanalysis. See `misc/validate_lineal_harness.js`.

**Mini-MYSX.** The mini-MYSX with w=32 reproduces `mysx.prod.js` exactly (F function and `MYZ_PERM` are bit-identical, verified in `misc/check_mini.js`). The keyword/w compatibility check (`mini_nondegenerate_v1`) reports: MYSZKOWS at w=32 (8-letter keyword, cols=8, rows=4) is degenerate at word 0 (`perm[0]=4`, L→R→L cycle); MYSZKOWS at w=16 is degenerate; MYSZ at w=16 (4-letter keyword, cols=4, rows=4) is non-degenerate (`perm[0]=0`); MYSZKOWS at w=8 (cols=8, rows=1) is degenerate; MYSZ at w=8 is non-degenerate. For analysis, use w=32 directly or w=8 with `MYSZ` (not `MYSZKOWS`). The F differential at w=8 with `MYSZKOWS` is 1.00 for r=1–4 (degenerate L→R→L cycle); with `MYSZ` it is 1.00 at r=1 and drops below 1 from r=2 (F activates).

**Beam-search tool.** `lin_beam_selftest` passes in both directions:

- [1] exact LAT of F vs sampling: OK
- [2] one-round trail vs real round function: OK
- [3] r0=12: 9-round weight-0 chain found=True, |corr|=1 on real cipher: OK
- [3] r0=27: 9-round weight-0 chain found=True, |corr|=1 on real cipher: OK
- [4] forward edges are backward edges (325 edges): OK
- [5] backward end-residue 20: 9-round weight-0 chain found=True, |corr|=1 on real cipher: OK
- [5] backward end-residue 4: 9-round weight-0 chain found=True, |corr|=1 on real cipher: OK
- [6] backward R=14 trail (weight 21) is a valid forward trail with equal weight: OK
- SELFTEST PASSED

**Exact LAT model.** `lin_model_selftest` passes (`ALL PASS`):

- Python port reproduces `KNOWN_KAT_DIGEST` of `mysx.prod.js` (skipped when `MYSX_ROT_CAL` is set, because the KAT digest is for k=1).
- `lin_bwd` inverts `lin_fwd` (rounds 0..61).
- `h(b)` (GF(2) rank/2) equals the run formula on the 32-cycle.
- F-LAT theorem (valid set, |corr|=2^-h, closed-form sign) vs brute force: mismatches=0.
- Parseval: sum over g of corr^2 = 1.
- Monte-Carlo with the real F agrees with the exact LAT worst |z|=1.70.
- |corr|=1 chains (5 and 9 rounds) incl. key sign match the real cipher.
- 2-round hull prediction (weight>0, signed, fixed key) vs real cipher top |corr|=0.25, 0.25, 0.25, 0.25, max|z|=0.50.
- ALL PASS.

**Differential verification.** `misc/verify_diff_trail.py` and `misc/verify_diff_13r.py` check the deterministic trails of §3.5 against the real cipher at 100% propagation over 262,144 pairs × 8 keys. Both pass (`100.0000%`).

**Division-property harness.** `misc/verify_division.py` validates the R=10 single-bit dependency: the two bits the model predicts as balanced (word 0 bit 31, word 3 bit 6) are confirmed balanced over 20,000 random samples, and the other 62 bits of words 0 and 3 are confirmed not balanced. See `misc/verify_division.py` and §4.9.

**Differential free chain table.** `misc/diff_free_chain_table.py` was verified against the MILP for the offsets tested; the maximum weight-0 chain length (13 rounds for v0.1, 5 for v0.2) was verified by exhaustive linear algebra over 2^128 left-half differences.

**Hull checks.** `lin_hull_check_v1` passes: offset-20 backward isolated at R=14 (hull_count=1); r0=23 forward cancels from R=8; r0=24 forward cancels from R=8; r0=12 forward is exact up to R=12; offset-20 backward is exact from R=1 to R=14; at R=17 the best end pairs of offsets 20 backward and 23 forward cancel exactly within the enumerated budget for both keys tested. `lin_hull_v1_r10_12` passes with |z|<0.4. `lin_hull_v02` computes three hulls for v0.2 (predictions only; no empirical).

**v2 security suite.** `tests/mysx_v2.test.js` runs 58 tests, 0 fail, 0 skipped. It covers KAT regression, cross-language KAT (6/6 packets byte-identical), per-byte bit-flip rejection, AAD/context/secret binding, KDF bounds, anti-downgrade on the KDF byte, password + keyfile separation, Argon2id RFC 9106 vector, v1/v2 packet separation, and Argon2id provider roundtrip. See `tests/gen_v2_kat.py` for the Python reference.

**v2 smoke test.** `v2_smoke` reports: `calendar_injected = true`, `v2_api_complete = true`, `argon2 = "noble"`, `roundtrip_raw = true`, `packet_version = 2`, `packet_cal = 1`, `roundtrip_password = true`, `packet_kdf = 1`, `security_raw64 = {classicalBits: 512, groverBits: 256}`, `security_raw32 = {classicalBits: 256, groverBits: 128}`, `v1_compat = true`.

**Functional tests.** `mysx.test.js` runs 17 tests: KAT regression, CTR round-trip (8 lengths), AEAD round-trip with AAD, AEAD negatives (nonce/ct/tag/AAD tamper), NonceGuard (4 cases), key derivation (HKDF, PBKDF2), avalanche indicator. All pass. `CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`; a PASS here only says the chosen tests did not detect failures.

### 9.7. Avalanche ladder

The avalanche ladder (`avalanche_v1`, `avalanche_v02`) measures diffusion per round: `minReach` (minimum number of output bits reached from any input bit), `minBit`, `maxAbsZ`, `maxCell`, and `zChi`. This is an engineering indicator, not a cryptographic claim.

**v0.1:**

| r | minReach | minBit | maxAbsZ | maxCell | zChi |
|---|---|---|---|---|---|
| 1 | 1 | 0 | 44.72 | [0,0] | 360444.17 |
| 2 | 1 | 0 | 44.72 | [0,0] | 356496.26 |
| 3 | 1 | 7 | 44.72 | [0,0] | 345666.12 |
| 4 | 4 | 5 | 44.72 | [0,0] | 323227.73 |
| 5 | 10 | 33 | 44.72 | [0,0] | 281845.32 |
| 6 | 23 | 33 | 44.72 | [0,0] | 220566.53 |
| 7 | 55 | 33 | 44.72 | [0,0] | 148511.24 |
| 8 | 111 | 33 | 44.72 | [0,0] | 83128.77 |
| 9 | 156 | 33 | 44.72 | [0,1] | 39431.82 |
| 10 | 213 | 33 | 44.72 | [0,30] | 14006.9 |
| 11 | 239 | 33 | 44.72 | [0,105] | 4219.15 |
| 12 | 249 | 33 | 44.72 | [1,166] | 1226.52 |
| 13 | 253 | 33 | 44.72 | [1,19] | 350.32 |
| 14 | 255 | 33 | 44.72 | [33,123] | 88.19 |
| 15 | 256 | -1 | 22.18 | [6,21] | 8.48 |
| 16 | 256 | -1 | 10.6 | [70,177] | 1.29 |
| 17 | 256 | -1 | 10.91 | [70,178] | 2.51 |
| 18 | 256 | -1 | 12.12 | [70,180] | 3.13 |
| 19 | 256 | -1 | 10.15 | [70,183] | 2.08 |
| 20 | 256 | -1 | 10.51 | [70,171] | 2.12 |
| 21 | 256 | -1 | 11.23 | [70,72] | -0.53 |
| 22 | 256 | -1 | 4.65 | [21,195] | -0.42 |
| 23 | 256 | -1 | 4.29 | [75,87] | 2.03 |
| 24 | 256 | -1 | 4.56 | [132,91] | -0.17 |

**v0.2:**

| r | minReach | minBit | maxAbsZ | maxCell | zChi |
|---|---|---|---|---|---|
| 1 | 1 | 0 | 44.72 | [0,0] | 360444.12 |
| 2 | 1 | 0 | 44.72 | [0,0] | 356493.1 |
| 3 | 1 | 7 | 44.72 | [0,0] | 345695.82 |
| 4 | 4 | 5 | 44.72 | [0,0] | 323248.18 |
| 5 | 10 | 33 | 44.72 | [0,0] | 281875.54 |
| 6 | 23 | 33 | 44.72 | [0,0] | 220567.58 |
| 7 | 55 | 33 | 44.72 | [0,0] | 148497.49 |
| 8 | 111 | 33 | 44.72 | [0,0] | 83000.03 |
| 9 | 156 | 33 | 44.72 | [0,1] | 39301.36 |
| 10 | 213 | 33 | 44.72 | [0,30] | 14055.62 |
| 11 | 239 | 33 | 44.72 | [0,105] | 4241.75 |
| 12 | 249 | 33 | 44.72 | [1,166] | 1229.53 |
| 13 | 253 | 33 | 44.72 | [1,19] | 349.32 |
| 14 | 255 | 33 | 44.72 | [33,123] | 87.58 |
| 15 | 256 | -1 | 21.47 | [6,21] | 7.96 |
| 16 | 256 | -1 | 11.54 | [70,177] | 1.78 |
| 17 | 256 | -1 | 10.38 | [70,178] | 0.49 |
| 18 | 256 | -1 | 9.66 | [70,180] | 1.11 |
| 19 | 256 | -1 | 10.73 | [70,183] | 1.71 |
| 20 | 256 | -1 | 8.9 | [70,171] | 1.13 |
| 21 | 256 | -1 | 10.73 | [70,72] | 1.19 |
| 22 | 256 | -1 | 4.61 | [249,192] | 1.92 |
| 23 | 256 | -1 | 4.43 | [183,31] | -1.91 |
| 24 | 256 | -1 | 4.2 | [244,135] | 0.26 |

Full reach of all 256 bits is achieved at r=15 in both versions, and the zChi statistic drops to <10 at r=15 and <3 at r=16. The avalanche ladder is a diffusion indicator; it does not establish resistance to differential, linear, or algebraic attacks.

---

## 10. Verdict

MYSX-256/512 v0.2-draft is an experimental proposal, not a secure cipher.

**Rotation schedule.** `rand_s9_45430` replaces the consecutive schedule `(r mod 31)+1`. On the 9 core metrics measured, the new schedule improves 6, ties 3, and regresses 0. Exact DMITM: 17→9. Weight-0 chain: 13→5. Truncated impossible: 39→28 (verified 2000/2000 against the real cipher; conflict at w4b17). Integral balanced bits at R=5: 21→9. MILP differential R=5: 4→4 (tie). The v0.1 catastrophic offset r0=10 (weight-2 trail at R=14, 4 chosen pairs to distinguish 14 rounds) is eliminated in v0.2 (best MILP weight at R=14 is 94; r0=30 unresolved; worst observed 335 at r0=2). The full 31-offset differential sweep is measured for both versions.

**AEAD v2.** HKDF-SHA512 with a 64-byte secret (2^256 Grover); 512-bit MAC keys; HMAC-SHA512; one key per message; authenticated header with rotation calendar; Argon2id for password paths. Cross-language KAT: 6/6 packets byte-identical to an independent Python reference. 58 security tests pass. `v2_smoke` confirms `calendar_injected`, `packet_version=2`, `packet_cal=1`, `v1_compat`, `security_raw64 = 512/256`, `security_raw32 = 256/128`.

**Differential.** v0.1: weight-0 chains up to 13 rounds at r0=10 (proven maximal by linear algebra, verified with 100% propagation over 262,144 pairs × 8 keys); weight-2 trail at R=14 for r0=10; offset sweep best r0=10=2, worst non-None r0=21=211, r0=30=None; growth at r0=10 from R=14=2 to R=24=134 (MILP). v0.2: weight-0 chains up to 5 rounds; best MILP weight at R=14 is 94 (r0=29), worst 335 (r0=2), r0=19=275, r0=27=172, r0=30=None; the r0=10 catastrophic offset is gone.

**Linear.** Exact model of F; exact signed hulls at r=10, 11, 12 (v0.1) matching the real cipher within |z|<0.4; verified |corr|=1 chains at 5 and 9 rounds (v0.1). Beam search over the model, both directions, all 31 offsets, up to 128 rounds:

- v0.1: 2 at R=12, 5 at R=14, 38 at R=20, 2248 at R=128 (offset 3 backward). Largest R with weight <64 is 22 (weight 63, a tie; backward-only is 21).
- v0.2 forward: 3 at R=12, 8 at R=14, 71 at R=20, 2294 at R=128 (offset 0 forward). Largest R with weight <64 is 19; <32 is 17.
- v0.2 backward: 6 at R=12, 11 at R=14, 69 at R=20, 2161 at R=128 (offset 3 backward). Largest R with weight <64 is 19; <32 is 17.

The offset-20 backward trail at R=14 (weight 5, rounds 100–113) is isolated in its hull (`hull_count=1`) and its empirical correlation matches 2^-5; an exact budgeted hull extends it to R=16 (rounds 98–113, `|corr| = 2^-11`): this is a verified linear distinguisher on a 16-round window. At R=17 the best end pairs cancel within the enumerated budget. For other trails, a check against the real cipher shows that a single-trail weight can be exact, ≈2× too low, or exactly cancelled, so these numbers are evidence about where cheap trails end, not universally how long a distinguisher is. No lower bound over 128 rounds has been established, no key-recovery attack has been attempted, and hull-aware bounds beyond R=17 are unexplored. Multi-bit starts (pairs47, `rand:5000:4`) did not improve on single-bit starts, but the random sample is too small to be conclusive. v0.2 hull empirical verification is PENDING. v0.2 exact 128-round hull is PENDING.

**Integral.** v0.1: 6-round (2^32 texts) and 5-round (2^64 texts) at r0=0; extended to 10 rounds (both patterns) at r0=15, with a thin tail (one balanced bit at R=10) and practical strength in the 7–8 round range. The R=7/R=6 bits are consistent with a 2-text or 4-text toggle; the full 2^32/2^64 integrals were not verified. The offsets r0=12 and r0=27 are not special for DP. v0.2: 9/256 and 4/256 at R=5/6 at all six measured offsets (0, 5, 10, 15, 20, 27). Full 31-offset sweep and r0=15 peak for v0.2 are PENDING.

**Three geographies.** The three analysis directions peak at different offsets (differential r0=10 for v0.1, r0=29 for v0.2; linear free chains r0=12/27; linear hull at offset 20 backward ≈r0=5–6; integral r0=15 for v0.1), so none of the single-offset bounds previously reported describes the cipher as a whole.

**NIST.** The CTR keystream of v0.1 passes the full NIST SP 800-22 battery (100 sequences × 10^6 bits, fresh key and nonce per sequence, no failures, §4.11), which rules out gross statistical biases but says nothing about differential, linear, algebraic, or key-recovery attacks. v0.2 NIST is skipped in the current suite (`nist_v02` requires `sts-2.1.2/assess`).

**Related-key.** Heuristic (v0.1 inherited). v0.2 re-validation 22/22 PASS; worst bit 160, slow diffusion r=1–4, beam score 139. Not exploitable with current techniques.

**PENDING for v0.2.**

- Differential: beam differential (MILP only for v0.2); cluster analysis at v0.2 offsets.
- Linear: hull empirical verification for v0.2; v0.2 hull-aware bound beyond R=14; v0.2 exact 128-round hull; v0.2 multi-bit starts.
- Integral: full 31-offset sweep for v0.2; r0=15 peak for v0.2; R=7–10 tail for v0.2; full 2^32/2^64 integral verification for v0.1.
- Impossible: multi-bit starts; weight-1 rounds; narrower propagation.
- NIST: full NIST SP 800-22 battery for v0.2.
- Differential R=16, R=17 empirical trails: the item `diff_r16_r17_v1` is not in the current manifest.

No lower bound over 128 rounds is established. No key-recovery attack has been attempted. No external audit. The truncated impossible for v0.2 is 28 rounds, not 39. The related-key security is unknown.

---

## 11. Reproducibility

All measured claims of §2–§5 are reproducible via `./run_all_gh_actions.sh --no-nist` in the repository. **53 tests pass, 0 fail, 2 skip** (`nist_v1`, `nist_v02`; both `requires_file not present: sts-2.1.2/assess`). The full per-test output is in `paper_results.json` (55 tests total).

### Files

| File | Purpose |
|---|---|
| `mysx.prod.js` | Reference implementation (v1 + v2) |
| `mysx.test.js` | 17 functional tests (v1) |
| `KAT.json` (in `LEGACY_V1/`) | v0.1 test vectors |
| `KAT_v2.json` | v0.2 test vectors |
| `calendar/CALENDAR_v02.txt` | `MYSX_ROT_CAL=22,5,8,...` |
| `calendar/wf2_deep_summary.json` | 8 candidates × 9 metrics (§4.13) |
| `cryptanalysis/DMITM/dmitm_verify.py` | Exact DMITM search |
| `cryptanalysis/DMITM/dmitm_trunc_v3.py` | Truncated impossible differentials (§4.12) |
| `cryptanalysis/DMITM/search_mysx_deep.py` | 1M random schedule search |
| `cryptanalysis/models/linear/mysx_linear_model.py` | Exact linear model of F + round |
| `cryptanalysis/models/linear/LINEAR_MODEL.md` | Model documentation |
| `cryptanalysis/models/linear/linear_model_data.json` | Data for §4.2–§4.6 |
| `misc/mysx_linear_beam.py` | Beam search over the exact linear model |
| `misc/beam_full.json`, `misc/beam_bwd.json` | v0.1 beam outputs |
| `misc/beam_paths_bwd20.json`, `misc/beam_paths_fwd23.json` | Hull inputs (§4.10.5) |
| `misc/verify_beam_trail.py`, `misc/hull_count.py`, `misc/hull_bidir.py`, `misc/scan_endpairs.py`, `misc/test_signed_dp.py`, `misc/emp_check.py` | Hull checks |
| `misc/HULL_R15_R17.md` | Summary and reproduction commands of §4.10.5 |
| `misc/mysx_milp2.py` | Differential MILP |
| `misc/mysx_division_property_v2.py` | Division property |
| `misc/diff_free_chain_table.py` | Differential free chain table (§3.5) |
| `misc/verify_diff_trail.py`, `misc/verify_diff_13r.py` | Differential trail verification |
| `misc/keyschedule_test.js`, `misc/keyschedule_test_extended.js` | Key schedule audit |
| `misc/gen_nist_input.js`, `misc/nist_input/` | NIST keystream generation (§4.11) |
| `tests/gen_v2_kat.py` | Independent Python reference for v2 packets |
| `tests/mysx_v2.test.js` | 58 security tests for v2 API |
| `tests/manifest.json` | Test manifest |
| `run_all_gh_actions.sh`, `run_all_local.sh` | Orchestrators |
| `github/workflows/paper.yml` | CI matrix for non-NIST tests |
| `github/workflows/nist.yml` | CI matrix for NIST (build broken) |

### Reproduction commands

**v0.1 claims:**

```bash
# KAT
python3 -c "import json; d=json.load(open('LEGACY_V1/KAT.json')); \
  assert d['digest']=='5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee'"

# Free chain table (r0=10 -> 13, r0=15 -> 8, r0=0 -> 3, r0=27 -> 3)
python3 misc/diff_free_chain_table.py

# 13-round chain verification
python3 misc/verify_diff_13r.py        # 100.0000%

# 6-round chain verification
python3 misc/verify_diff_trail.py      # 100.0000%

# MILP differential (R=5 -> 4, R=14 -> 106)
python3 misc/mysx_milp2.py --rounds 5-14 --input-bit 94 --r0 0 --solver cbc

# Beam reproduce (paper §4.5)
python3 misc/mysx_linear_beam.py reproduce

# Exact hulls (|z| < 0.4)
python3 tests/run_hull_v1.py

# Exact DMITM (17 rounds)
python3 cryptanalysis/DMITM/dmitm_verify.py exact

# Truncated impossible (39 rounds)
python3 cryptanalysis/DMITM/dmitm_trunc_v3.py --cal k1 --max_fwd 24 --max_bwd 24

# Beam to R=128 backward (2248)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 4 --direction backward

# Hull check (isolated at R=14, cancels at r0=23 forward)
python3 tests/run_hull_check_v1.py
```

**v0.2 claims:**

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31

# Exact DMITM (9 rounds)
python3 cryptanalysis/DMITM/dmitm_verify.py exact

# Free chain table (max 5 rounds, no 13)
python3 misc/diff_free_chain_table.py

# Truncated impossible (28 rounds with VERIFY, conflict w4b17)
python3 cryptanalysis/DMITM/dmitm_trunc_v3.py --cal v02 --max_fwd 24 --max_bwd 24 --verify 500

# Beam R=10 forward (1) and backward (3)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1 --direction backward

# Beam R=14 forward (8) and backward (11)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1 --direction backward

# Beam R=128 forward (2294) and backward (2161)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 2
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 2 --direction backward

# Integral R=5 (9/256), R=6 (4/256)
python3 misc/mysx_division_property_v2.py --rounds 5 --active word0 --r0 0 --solver highs
python3 misc/mysx_division_property_v2.py --rounds 6 --active word0 --r0 0 --solver highs

# MILP R=5 (4, min over r0 in {0,10,20})
python3 tests/run_diff_milp_v02_R5.py

# Hull predictions (r=10,11,12)
python3 tests/run_hull_v02.py

# Cross-language v2 KAT + security suite
python3 tests/gen_v2_kat.py
MYSX_ENABLE_TEST=1 node tests/mysx_v2.test.js

# v2 smoke test
MYSX_ENABLE_TEST=1 node tests/v2_smoke.js

# Exact LAT model selftest
python3 cryptanalysis/models/linear/mysx_linear_model.py selftest

# Beam selftest
python3 misc/mysx_linear_beam.py selftest

# Linear harness validation
node misc/validate_lineal_harness.js

# Mini non-degeneracy check
node misc/check_mini_nondegenerate.js

# Avalanche ladder
node misc/avalanche.js
```

**Division-property results (§4.9).** At r0=0, all three input patterns (single bit, word 0, words 0+4) were run with `--r0 0`. The (1,1)-invalid XOR rule and the OR-conservative rule were checked to agree on the tested patterns. Per-round balanced-bit counts are in the terminal logs of the runs; the runtimes were 0.4 s to 4.8 ks with SCIP. The R=10 single-bit dependency was verified against the real cipher (20,000 random samples per bit). The R=6 word-0 integral was verified against the real cipher at the last round (R=6, balanced bits confirmed; R=7 saturated). The R=5 words-0,4 integral was not verified empirically because its 2^64-text integral cannot be approximated by 20,000 random samples. At r0=15, the offset sweep used `--r0 15` (all 31 offsets at the saturation rounds of r0=0). The R=7/R=6 bits at r0=15 were verified as consistent with bit-0 or double toggle; the full 2^32/2^64 integrals were not verified. v0.2 was measured at 6 offsets (0, 5, 10, 15, 20, 27) at R=5–6.

**Statistical tests (§4.11).** From `misc/`: `MYSX_ENABLE_TEST=1 node gen_nist_input.js` regenerates the 100 files (the TEST API is enabled only by that environment variable and is not part of the public surface). Concatenate with `cat nist_input/data* > nist_input/all_data.bin`, then run `./assess 1000000` in STS 2.1.2 with input choice 0, input file `.../nist_input/all_data.bin`, all tests, default parameters, 100 bitstreams, binary mode. Keys and nonces are drawn with `crypto.randomBytes` and are therefore not reproducible bit-for-bit; the result (no failures, all proportions inside the acceptance region) is stable across reruns, but a rerun produces different sequences. The report is deterministic given the input file.

**Fixed seed in tests (0xC0FFEE).** MILPs are deterministic given the solver and `gapRel`. The mini-MYSX with w=32 reproduces `mysx.prod.js` exactly (F function and `MYZ_PERM` are bit-identical, verified in `misc/check_mini.js`). The exact linear model's selftest additionally verifies the Python port against `KNOWN_KAT_DIGEST` of `mysx.prod.js`, so the linear results are stated relative to the reference implementation.

**Beam search (§4.10).** The forward run is reproduced with `python3 misc/mysx_linear_beam.py run --beam 2000 --jobs 8 --out beam_full.json`; the backward run with the same command plus `--direction backward --out beam_bwd.json`. The combined table is reproduced with `python3 misc/mysx_linear_beam.py merge beam_full.json beam_pairs47.json beam_bwd.json`. The search is deterministic given the parameters (no randomness except a fixed seed inside the coset sampler for cells with `rank(A_b) > 8`). `cmp` confirms that two independent forward runs (`beam_full.json` and `beam_full_1.json`) are byte-identical. The hull checks of §4.10.3 use the saved R=14 trails with fixed keys (`random.Random(seed)` over 64 bytes, seed 1 and 2) and are not part of the tool; their scripts are `misc/verify_beam_trail.py` and `misc/hull_count.py`.

**Exact hull (§4.10.5).** From `misc/`: `python3 test_signed_dp.py` (validation against `propagate()`); `python3 hull_bidir.py beam_paths_bwd20.json 20 --R 16 --wmax 14 --keys 2`; `python3 hull_bidir.py beam_paths_bwd20.json 20 --R 17 --wmax 18 --keys 2`; `python3 hull_bidir.py beam_paths_fwd23.json 23 --R 16 --wmax 10 --keys 2`; `python3 emp_check.py beam_paths_bwd20.json 20 16 28 1000` (about 12 min, one CPU); `python3 scan_endpairs.py --R 17 --cells 20:backward,23:forward --topk 8`. Keys are `rand_key(1000)`, `rand_key(1001)`, ....

**Differential chains (§3.5).** From `misc/`: `python3 diff_free_chain_table.py` (free chain table); `python3 verify_diff_trail.py` (6-round trail at r0=15); `python3 verify_diff_13r.py` (13-round trail at r0=10); `python3 mysx_milp2.py --rounds 13 --input-bit 63 --r0 10 --trail` (13-round trail).

**Test count.** `paper_results.json` has `n_tests=55`, `n_pass=53`, `n_fail=0`, `n_skipped=2` (`nist_v1`, `nist_v02`). The list of pass tests is in the companion `paper_results.json`; each has an `id`, `name`, `group`, `spec_status`, `status`, `returncode`, `elapsed_s`, `assertions`, `setup`, `stdout_tail`, `stderr_tail`. The two skips are due to a missing external dependency (`sts-2.1.2/assess`); they are not failures.

---

## 12. Final warning

MYSX has not been externally audited. This paper is the author's self-analysis, not a certification. No result here replaces an independent cryptographic review.

Do not use MYSX to protect real data. For production: AES-256-GCM or XChaCha20-Poly1305.