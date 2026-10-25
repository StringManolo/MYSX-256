---
title: "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys (v0.1-draft2)"
author: "StringManolo"
date: "2026"
abstract: |
  We present MYSX-256/512, a 256-bit block cipher with 512-bit keys and
  128 rounds. The design combines Feistel cells with Simon's round
  function, a Myszkowski byte transposition, word rotations, and an ARX
  key schedule. We provide the full specification, test vectors, and a
  self-analysis covering differential, linear, integral, and related-key
  cryptanalysis. The differential analysis reports an observed upper
  bound on the best single-trail weight (114 at 14 rounds, extrapolating
  to the 128-bit threshold at r≈15; the runs do not vary the rotation
  offset, so this extrapolation is likely optimistic, see §3.1). The r=4
  trail has been directly verified at w=32 with a clustering factor of
  2.00× (observed 2⁻⁷ vs MILP 2⁻⁸). The linear analysis is built on an
  exact model of F: the LAT admits a closed form
  (`|corr(b,g)| = 2^{−h(b)}`, `h(b) = rank(A_b)/2` on a 32-cycle), mask
  propagation is bit-exact, and every trail carries an exact
  key-dependent sign. Within this model we verify `|corr|=1` chains over
  up to 9 consecutive rounds (three independent keys), and exact linear
  hulls at r=10,11,12 match the real cipher within sampling error
  (|z| < 0.4). A beam search over the exact model, run in both
  directions (forward and backward) for all 31 rotation offsets and up
  to 128 rounds, and merged (§4.10), gives achievable single-trail
  weights of 2 at 12 rounds, 5 at 14 rounds, 38 at 20 rounds, 786 at 64
  rounds and 2248 at 128 rounds; after round ~20 the best weight grows
  by roughly 12–21 per round up to R=112 (the last step, 112→128, is
  ≈36 per round because only one offset fits a full 128-round trail),
  and the largest round count with an achievable single trail of
  weight < 64 (≈2¹²⁸ texts) is 22 (weight 63, a tie with the
  threshold). Among the tabulated round counts, backward trails are the
  cheapest at R=9–14, 18, 20, 24–48 and 96–128, and forward trails at
  R=16, 22, 56, 64 and 80. A hull check against the real cipher shows
  that the offset-20 backward trail is isolated in its hull at R=14
  (weight 5, rounds 100–113, empirical correlation matching 2⁻⁵), and
  an exact budgeted hull (§4.10.5) extends it to R=16 (rounds 98–113):
  two trails of weight 12 add up to |corr| = 2⁻¹¹, which a 2²⁸-sample
  measurement on one key confirms within 1.9σ. This is a verified
  linear distinguisher on a 16-round window of the cipher (seven
  weighted rounds followed by a 9-round weight-0 chain), not an attack
  on the full cipher. At R=17 the best end pairs of offsets 20 backward
  and 23 forward cancel exactly within the enumerated budget. Other
  trails can be equal to their single-trail value, a factor ~2 larger,
  or exactly cancelled (§4.10.3, §4.10.5). No lower bound over 128 rounds is established;
  the weight-0 windows are a property of 5–9 round windows, not an
  attack on the full cipher. A preliminary integral analysis with
  standard division-property rules finds integral distinguishers
  covering 6 rounds with a 2³²-text integral (word 0 active) and 5
  rounds with a 2⁶⁴-text integral (words 0 and 4 active); a 10-round
  single-bit dependency propagation is also reported but is not an
  integral distinguisher (2 texts). Only r0=0 was tested. The key
  schedule was audited with 22 structural and empirical tests up to
  weight-6 with no persistent Δrk=0 pattern found. MYSX has not been
  externally audited. It is released as v0.1-draft2 for public review
  and must not be used to protect real data.
---

# 1. Introduction

MYSX-256/512 is an experimental block cipher. It is offered as a public
proposal for cryptanalysis, not as a production primitive. The author
makes no claim of security beyond the observed results reported here,
and explicitly welcomes external review.

## 1.1. Security objectives (and non-objectives)

**Model.** MYSX is analyzed in the single-key, chosen-plaintext model
for confidentiality, combined with an encrypt-then-MAC AEAD wrapper for
integrity (Section 2.9). The design does not claim security under
related-key, chosen-ciphertext, or side-channel models; see Section 5
for related-key coverage and Section 9 for engineering notes.

**Claimed security level.** None formally. The paper reports observed
upper bounds on single-trail weights (Section 3), a verified exact
linear model up to a small number of rounds (Section 4), a full-length
beam search over that model in both directions (§4.10), and preliminary
integral distinguishers at 5–6 rounds for multi-bit inputs (§4.9).
These are inputs to cryptanalysis, not proofs.

**Reading thresholds.** A differential trail of weight `w` needs about
2^w chosen pairs; a linear trail of weight `w` has `|corr| = 2^{−w}` and
needs about 2^{2w} known texts. Therefore a 2¹²⁸-text budget corresponds
to a differential weight threshold of ≈128 but to a *linear* weight
threshold of ≈64. Differential and linear weights in this paper must
not be compared directly; compare `w_diff` with `2·w_lin`.

**Non-objectives.** MYSX does not claim:

- post-quantum security beyond the trivial Grover bound (2²⁵⁶ quantum
  iterations for a *uniformly random* 512-bit key; keys produced by the
  HKDF-based API of Section 2.10 from a 256-bit secret give 2¹²⁸, see
  Section 6);
- resistance to related-key attacks beyond the heuristic coverage in
  Section 5;
- resistance to integral attacks beyond the preliminary 5–6 round
  distinguishers reported in §4.9, nor resistance to impossible-
  differential, boomerang, or algebraic attacks (none analyzed);
- resistance to linear-hull effects beyond the sampled checks of §4.6
  and §4.10.3–§4.10.5 (no hull-aware bound beyond R=17);
- constant-time execution in JavaScript (side channels out of scope).

## 1.2. Design rationale

MYSX combines four building blocks:

- **Simon's F** `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`. Chosen
  for its **studied** diffusion/linear/differential properties in Simon
  and its simplicity (no S-boxes, only AND/XOR/rotl). It does **not**
  inherit Simon's security proofs; the surrounding structure is
  different. See Section 7 for what transfers and what does not.
- **Feistel cells over 32-bit word pairs.** Four parallel cells per
  round, then a byte transposition over the full 32-byte state, then
  word rotations. The result is classified as an SPN-like structure
  with Feistel cells, not as a "2-branch Feistel". See Section 2.1.
- **Myszkowski transposition** (Section 2.3.1). A fixed byte
  permutation derived from the keyword `MYSZKOWS`. The choice is
  didactic; it provides byte-level diffusion but no cryptographic
  argument beyond that. An optimized permutation would provide
  strictly better diffusion per round; see Section 9.
- **ARX key schedule** (Section 2.4). A bijective Feistel 8+8 update
  with modular addition, XOR, and rotations. Chosen for simplicity and
  to avoid S-boxes; analyzed in Section 5.

The parameter choices (256-bit block, 512-bit key, 128 rounds) are not
derived from a formal argument. They were chosen to:

- provide a large block (avoid birthday-bound issues of 64-bit blocks);
- provide a large key (Grover leaves 256-bit security for a random
  512-bit key);
- provide a large round count relative to Simon128/128 (68 rounds) as
  a precaution against unknown trails.

No claim is made that 128 rounds is sufficient. The round count is a
parameter, not a security level.

## 1.3. Comparison with related designs

| Design | Block | Key | Rounds | Structure | S-boxes |
|---|---|---|---|---|---|
| Simon128/128 | 128 | 128 | 68 | Feistel | No |
| Speck128/256 | 128 | 256 | 34 | ARX | No |
| ChaCha20 | 512 | 256 | 20 | ARX | No |
| MYSX-256/512 | 256 | 512 | 128 | SPN-like with Feistel cells | No |

MYSX's closest sibling is Simon. The differences (block size, branch
organization, transposition, word rotations, non-linear key schedule)
are substantial enough that Simon cryptanalysis does not transfer
directly (see Section 7).

**Performance.** MYSX is estimated to run at a few MB/s in JavaScript,
versus hundreds of MB/s for AES-GCM via WebCrypto (AES-NI). MYSX is not
competitive on performance; it is a research primitive.

## 1.4. Versioning and revision notes

**Versioning.** The reference implementation (`mysx.prod.js`) is
labelled `v0.1-draft` and has not changed since. This document is the
second documentation draft of that same design and is therefore labelled
`v0.1-draft2`. An earlier revision of this text carried the label
`v0.2-draft`; that label is withdrawn because it suggested a change of
the cipher or of the code, and there is none.

**Changes since the previous draft (`v0.1-draft`).**

- **New direction:** the beam search (§4.10) now supports
  `--direction backward` (the offset is the index of the *last* round
  of the trail, mod 31) and a `merge` command that combines results
  from both directions. The table of §4.10.2 is now the minimum over
  forward and backward and over all offsets; a few `v0.1-draft`
  checkpoint values (R=12, R=48, R=112, R=128, and in general those
  where backward wins) are superseded.
- **New verified distinguisher (on a 16-round window):** the offset-20
  backward trail is isolated in its hull at R=14 (weight 5,
  `hull_count` = 1 trail, empirical correlation 2⁻⁵ on the real cipher,
  §4.10.3) and, by the exact budgeted hull of §4.10.5, extends to R=16
  (rounds 98–113, |corr| = 2⁻¹¹). This is the first non-trivial linear
  distinguisher the analysis certifies. It consists of seven weighted
  rounds (98–104, total weight 12) followed by a 9-round weight-0
  chain (105–113).
- **New exact hull at R=15–17 (§4.10.5):** new tools `hull_bidir.py`
  (budgeted meet-in-the-middle enumeration of all trails between two
  end masks, with exact signs), `scan_endpairs.py`, `test_signed_dp.py`
  and `emp_check.py`. The R=16 row of the §4.10.2 table (weight 8,
  offset 23 forward) is a trail that cancels; the best certified
  correlation at R=16 is 2⁻¹¹.
- **Correction on R=128:** in forward mode only r0=0 fits a 128-round
  trail. In backward mode, offset 3 gives `end_round(3) = 127`,
  `realizable_R = 128`, so the combined R=128 = 2248 at offset 3
  backward **is a real trail inside the cipher**, not a virtual
  extension. The `v0.1-draft` statement that "for r0>0 the value at
  R=128 is a virtual extension" is forward-specific; §4.10.2
  clarifies.
- **Hull check (§4.10.3)** extended: the r0=23 forward trail continues
  to cancel from R=8; the r0=24 forward trail cancels from R=8; the r0=12
  forward trail is exact up to R=12; the offset-20 backward trail is
  exact from R=1 to R=14. Hull effects are not uniform.
- **Multi-bit starts:** explored (`pairs47`, `rand:5000:4`) and do not
  improve on single-bit starts at any R. `pairs47` is a small structured
  subset; `rand:5000:4` covers 5000 masks out of 2²⁵⁶ and is not
  conclusive for structured multi-bit masks. The honest statement is
  "the multi-bit starts tested do not improve on single-bit".
- Added §4.10.1 backward-step rule and its `selftest` (every forward
  edge is a backward edge with the same cost, 325 edges checked).
- Abstract: numbers updated to the combined forward+backward values;
  added the verified distinguisher at R=14.

**Corrections made in `v0.1-draft2`** (errors found while reviewing the
previous text; no experimental result changed):

- §3.3: the direction of the "systematic model error" argument was
  inverted. An observed probability *higher* than predicted means the
  model *over*estimates the cost (true weight 7, not 9). Fixed.
- §3.2: the r=4 trail is not a row of the table; the text now says so.
  §3.1/§3.2/§3.4 now state that the rotation offset was not varied in
  the differential runs, which makes the r≈15 extrapolation optimistic.
- §4.10.2 and the abstract: the statement on which direction is cheapest
  contradicted the table; rewritten from the table. The "15–25 per
  round" growth figure did not match the table (12.5–20.9 per round up
  to R=112, ≈36 for 112→128); replaced.
- §4.10.3, abstract, §4.7, §10: "distinguisher at 14 rounds" now says
  "on a 14-round window (rounds 100–113)" and explains that the weight
  is flat from R=5 to R=14 (§4.10.5 later extends the window to 16
  rounds).
- §4.9, §7: Simon integral figures and the Simon literature list
  corrected against the sources (Simon32: 14 rounds with conventional
  bit-based division property, 15 with three subsets; the Simon128
  26-round integral is Xiang et al.; ePrint 2014/973 is Shi et al.; the
  49-round Simon128/128 result is a key-recovery attack by Chen–Wang;
  Biryukov–Roy–Velichkov is FSE 2014).
- §4.10.4: the hull gain needed at R=24 (w=88) to reach the 2¹²⁸ budget
  is 2²⁴ in correlation (w − 64), not 2⁴⁰.
- §1.1, §6: the Grover 2²⁵⁶ figure holds for a uniformly random 512-bit
  key only; HKDF-derived keys give 2¹²⁸. The HKDF sentence in §6 was
  imprecise and is fixed.
- §8: functional test count aligned with `README.md` and `SECURITY.md`
  (17 tests).
- §9.2: note that 128-bit random nonces make accidental reuse
  negligible, so `NonceGuard` mainly enforces the per-key message limit.

# 2. Specification

## 2.1. Parameters

| Parameter | Value |
|---|---|
| Block size | 256 bits (8 words of 32 bits) |
| Key size | 512 bits (16 words of 32 bits) |
| Rounds | 128 |
| Structure | SPN-like: 4 parallel Feistel cells + byte transposition |
| Non-linearity | `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` |
| Diffusion | Myszkowski transposition (keyword `MYSZKOWS`) |
| Rotation | `rotl(word, (r mod 31) + 1)` per word and round |
| Final whitening | XOR with 8 words from the key schedule |

**Structural note.** MYSX is sometimes described as a "2-branch Feistel"
by analogy with Simon. Strictly, each round applies four independent
Feistel cells over 32-bit word pairs, then a byte transposition over
the full 32-byte state, then word rotations. It is more accurately
classified as an SPN with Feistel cells. The "Feistel" label is a
convenience.

## 2.2. Notation

- `rotl(x, n)`: circular left rotation of `x` by `n` bits.
- `∧`: bitwise AND.
- `⊕`: bitwise XOR.
- `s[r]`: state at round `r` (`s[0]` = plaintext, `s[128]` = ciphertext).
- `s[r][i]`: word `i` (0..7) of the state at round `r`.
- `rk[r][i]`: subkey `i` (0..7) of round `r`.
- `rkFinal[i]`: word `i` (0..7) of the final whitening.

## 2.3. Constants

```
CONST[0..7] = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]
```

These are the fractional digits of π (same as Blowfish).

### 2.3.1. Myszkowski permutation

Keyword: `MYSZKOWS` (8 letters, S repeated at positions 3 and 8).

Alphabetical order: K(5), M(1), O(6), S(3,8), W(7), Y(2), Z(4).

The byte permutation `MYZ_PERM[0..31]` is constructed as:

```
MYZ_PERM = [
   4,12,20,28,                 # K (column 4)
   0, 8,16,24,                 # M (column 0)
   5,13,21,29,                 # O (column 5)
   2, 7,10,15,18,23,26,31,     # S,S (columns 2 and 7, read row-wise)
   6,14,22,30,                 # W (column 6)
   1, 9,17,25,                 # Y (column 1)
   3,11,19,27                  # Z (column 3)
]
```

The inverse permutation `MYZ_INV` satisfies `MYZ_INV[MYZ_PERM[i]] = i`.

**Design note.** The Myszkowski choice is didactic (classical
transposition with a keyword) and adds no cryptographic argument.
A byte permutation optimized for diffusion (e.g., a structured
permutation over the 4×8 byte grid) would strictly dominate it.
We keep Myszkowski in this draft because it is the design under review; a
future version may replace it.

## 2.4. Key schedule

### 2.4.1. Initialization

Input: key `K[0..63]` (64 bytes).

Initial state `s[0..15]` (16 words of 32 bits):

```
s[i] = big_endian_word(K[4i .. 4i+3])
```

### 2.4.2. Expansion

For `r = 0 .. 127`:

```
spread = (r + 1) * 0x9E3779B9  (mod 2^32)

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
    F = (rotl((a + b) mod 2^32, 7) ⊕ rotl(c, 13) ⊕ CONST[i] ⊕ spread)
    s[i]     = R[i]
    s[i + 8] = L[i] ⊕ F
```

### 2.4.3. Final whitening

After the 128 rounds:

```
for i in 0..7:
    rkFinal[i] = s[i] ⊕ s[(i+8) mod 16] ⊕ CONST[(128+i) mod 8]
```

## 2.5. Round function

Each round `r` transforms state `s[r]` into `s[r+1]` in four steps:

**Step 1. AddRoundKey.**

```
for i in 0..7:
    s[r][i] = s[r][i] ⊕ rk[r][i]
```

**Step 2. Feistel cells.** For `p = 0..3`:

```
L = s[r][p]
R = s[r][p + 4]
s_mid[p]     = R
s_mid[p + 4] = L ⊕ F(R)
```

where `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.

**Step 3. Myszkowski transposition.** Convert `s_mid[0..7]` to bytes
(big-endian per word):

```
bytes[4i .. 4i+3] = big_endian(s_mid[i])
permuted[j] = bytes[MYZ_PERM[j]]  for j = 0..31
s_perm[i] = big_endian_word(permuted[4i .. 4i+3])
```

**Step 4. Word rotation.**

```
shift = (r mod 31) + 1
for i in 0..7:
    s[r+1][i] = rotl(s_perm[i], shift)
```

## 2.6. Encryption

```
s[0] = plaintext  (as 8 big-endian words)
for r = 0..127:
    apply round r (Section 2.5)
for i in 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128]  (as 32 big-endian bytes)
```

## 2.7. Decryption

Inverse of encryption:

```
s[128] = ciphertext
for i in 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
for r = 127..0:
    apply inverse round r (inverse of Section 2.5, reverse order)
plaintext = s[0]
```

The inverse round consists of:

1. Inverse rotation: `rotl(word, 32 - shift)`.
2. Inverse transposition: `bytes[MYZ_PERM[j]] = permuted[j]`.
3. Inverse Feistel: `R = newL`, `L = newR ⊕ F(R)`.
4. XOR with `rk[r][i]`.

## 2.8. Mode of operation (CTR)

32-byte counter:

```
counter[0..15]  = nonce (16 bytes)
counter[16..31] = 0  (128 bits, big-endian)
```

For each 32-byte plaintext block:

```
keystream = MYSX_encrypt(counter)
ciphertext_block = plaintext_block ⊕ keystream
counter[16..31] += 1  (big-endian)
```

## 2.9. AEAD (encrypt-then-MAC)

Packet: `VERSION(1) ‖ NONCE(16) ‖ CT(n) ‖ TAG(32)`

MAC input: `VERSION ‖ NONCE ‖ AAD_LEN(4 BE) ‖ AAD ‖ CT_LEN(4 BE) ‖ CT`

TAG: `HMAC-SHA256(macKey, MAC input)`

Verification: the decryptor verifies the TAG before decrypting.

## 2.10. Key derivation

**From a random secret (HKDF-SHA256).**

```
encKey = HKDF-SHA256(secret, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(secret, salt, info = context ‖ ":mac", L = 32)
```

**From a password (PBKDF2-SHA256 + HKDF).**

```
prk    = PBKDF2-SHA256(password, salt, iterations = 600000, L = 32)
encKey = HKDF-SHA256(prk, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(prk, salt, info = context ‖ ":mac", L = 32)
```

## 2.11. Test vectors

See `KAT.json` (public). Two digests are documented in `README.md`:

- `KAT.json` public digest: SHA-256 over the full JSON (block + AEAD +
  KDF). This is the artifact a third-party implementation should
  reproduce.
- `KNOWN_KAT_DIGEST` (internal): SHA-256 over 16 blocks with
  `key[i] = i`. Used as fast regression in `mysx.test.js`. It is
  strictly a subset of the public KAT, not a different KAT.

A third-party implementation should target the **public digest**.

# 3. Differential cryptanalysis

## 3.1. Model

Tool: `misc/mysx_milp.py` (PuLP + CBC/HiGHS). AND model: `a = Δx ∨ Δy`,
which counts a cost-1 event whenever at least one input is active.
For an AND with independent inputs, this is the exact per-bit cost.
The real approximations in the model are:

- The Markov-independence assumption does not hold: the two rotated
  inputs of F come from the same word `x`.
- We ran a single input difference at r=12–14 (w2b30). Multi-bit input
  differences may yield lower weights.
- No run varying the rotation offset (index of the first round mod 31)
  is reported. The linear analysis of §4.10 shows that this offset
  changes the best achievable weight by an order of magnitude (at R=14,
  backward: 5 at offset 20 vs 61 at offset 6). The differential bounds
  below are therefore not known to be representative, and the
  extrapolation to r≈15 is likely optimistic until the offset is varied.
- `gapRel=0.2` and `timeLimit=300` return feasible solutions (upper
  bounds), not certified optima.
- The model captures single trails, not differentials (clusters of
  trails with the same output difference).

## 3.2. Observed upper bounds

| Rounds | Input | Weight (upper bound) | Single-trail prob. |
|---|---|---|---|
| 5 | w1b24 | 2 | 2⁻² |
| 6 | w1b24 | 6 | 2⁻⁶ |
| 7 | w2b30 | 10 | 2⁻¹⁰ |
| 8 | w2b30 | 18 | 2⁻¹⁸ |
| 12 | w2b30 | 68 | 2⁻⁶⁸ |
| 14 | w2b30 | 114 | 2⁻¹¹⁴ |

Extrapolation: the 128-bit threshold is reached at r≈15. **This is an
extrapolation, not a proof.** It tells us what the model produces for
the input we tried; it does not establish the best trail over all
inputs or offsets, nor that clustering does not lower the effective
security.

**Comparison with the linear direction.** At 14 rounds the differential
upper bound is 114 (≈2¹¹⁴ pairs), whereas the linear side now has a
**verified distinguisher on a 14-round window** (offset-20 backward
trail covering rounds 100–113, weight 5, ≈2¹⁰ texts, isolated hull;
§4.10.3). Even allowing for the different thresholds (§1.1) and for the
fact that the differential run used a single input difference with a
20% solver gap, the linear direction is the weaker one by a wide margin
and is where analysis effort should concentrate. Part of that gap is
probably not intrinsic: the linear figure is the minimum over all 31
rotation offsets, the differential figure is for one input at one
position. A differential analysis with inputs placed in the free windows
and over all offsets (the analogue of the weight-0 linear chains and of
§4.10) has not been done.

**Direct verification at r=4 (w=32).** The r=4 trail (it is not a row of
the table above: Δin = {w0b0}, MILP weight 8, Δout = {w0b4, w1b10,
w1b16, w1b30, w6b4}) was verified with 8 fixed keys × 2¹⁷ pairs each,
using the full 128-round cipher with the final whitening disabled (to
isolate the round function). Observed hit rate: 7.802×10⁻³ over
1,048,576 pairs. Expected from MILP: 2⁻⁸ = 3.906×10⁻³.
**Ratio: 2.00×.**

The trail exists at r=4. The single-trail probability is a factor 2
higher than the MILP predicts, consistent with the clustering factor
documented in §3.3. **The MILP model is correct within a factor of 2
at this round count.**

## 3.3. Empirical check (r=4, w0b0)

As described above, the direct verification gives a ratio of 2.00×
between the observed probability and the MILP single-trail prediction.
Two interpretations are consistent with the data:

- **Differential clustering** (more likely): multiple trails with the
  same output difference Δout contribute to the observed probability,
  so the effective probability is higher than the single-trail
  probability.
- **Model systematic overestimate of the cost** (less likely): the AND
  model `a = Δx ∨ Δy` charges one bit too much at r=4. This would imply
  the true weight is 7, not 8. (Because the observed probability is
  *higher* than predicted, the model cannot be *under*estimating the
  cost; an underestimate would give a probability lower than predicted
  and a true weight of 9.)

Without a full clustering analysis (summing over all trails with the
same Δin, Δout), we cannot distinguish these two. The practical
implication is the same: the effective weight of the r=4 trail is 7,
not 8, so the MILP weight is the pessimistic side by one bit.

**What this does to the extrapolation.** A *constant* factor 2 is one
bit of weight; at the observed 8–23 bits of weight per round it moves
the "128-bit threshold at r≈15" by a small fraction of a round, not by
2–3 rounds. Only a factor that grows with the weight (for example the
ratio 7/8 applied to the whole trail) would matter: it would move the
crossing to roughly r≈16–17. Either way the margin on this input is
large, and the extrapolation should be read as approximate and, see
§3.1, as specific to the input and offset tried.

## 3.4. What this section does **not** establish

- A lower bound on the best single-trail weight (requires gap=0 and
  multi-bit inputs).
- An exact clustering analysis (requires modeling all trails with the
  same Δout).
- Resistance to related-key differentials.
- That the factor-2 clustering is constant across all round counts.
- The effect of the rotation offset (first round mod 31) on the best
  differential weight, nor any differential inputs placed in the free
  windows.

# 4. Linear cryptanalysis

## 4.1. Overview

An earlier version of this paper (§4 of the v0.0 draft) reported only
negative results: three approximate linear MILP models
(`misc/mysx_linear_milp.py`) all produced trails that failed empirical
verification at w=32. That negative result has now been explained. The
models used per-cell AND activity (`act = α ∨ β ∨ γ`) as a proxy for
correlation, which is not the correct structure of F's LAT. A correct
model exists in closed form and is implemented in
`cryptanalysis/models/linear/mysx_linear_model.py` (with detailed
documentation in `cryptanalysis/models/linear/LINEAR_MODEL.md` and raw
data in `cryptanalysis/models/linear/linear_model_data.json`). The
model is machine-checked against the real cipher by
`python3 mysx_linear_model.py selftest`.

**Result in one line.** The LAT of F is exactly
`corr(b,g) = ±2^{−h(b)}`, where `h(b)` is half the GF(2)-rank of a
32-cycle subgraph determined by `b`; there is a free choice of
`g` among `4^{h(b)}` values with sign determined by a quadratic form.
Mask propagation is bit-exact; every trail carries an exact
key-dependent sign. Verified consequences: `|corr|=1` chains over up to
9 consecutive rounds (three keys), and exact linear-hull predictions
at r=10,11,12 that match the real cipher within sampling error
(|z| < 0.4). §4.10 extends the search for cheap trails to 128 rounds,
all rotation offsets, and **both directions** (forward and backward),
and shows that single-trail weights must be read together with hull
effects. For the offset-20 backward trail at R=14 (weight 5, covering
rounds 100–113), the hull check is complete: the trail is isolated and
its empirical correlation matches 2⁻⁵ (§4.10.3). An exact budgeted hull
(§4.10.5) extends the verified window to R=16 (rounds 98–113,
|corr| = 2⁻¹¹). This is a verified linear distinguisher on a 16-round
window of the cipher.

## 4.2. Exact LAT of F

For output mask `b` and input mask `g`,

```
b.F(x) ⊕ g.x  =  Q_b(x) ⊕ l.x ,   l = rotr(b,2) ⊕ g ,
Q_b(x) = ⊕_j b_{j+1} x_j x_{j−7} .
```

`Q_b` is a quadratic form whose graph `G_b` is a subgraph of the
32-cycle `j —— j−7` (edge `(j, j−7)` present iff `b_{j+1}=1`; a single
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

This is **exact** and **machine-checked** against brute-force LAT of F
for random `b` of Hamming weight up to 8 (`selftest`).

**Cost data.**

- Single-bit `b`: `h = 1`, four valid `g`, `|corr| = 1/2`.
- Two-bit `b` (496 masks): histogram `{2: 464, 1: 32}` (the 32 pairs
  at bit distance 7 are adjacent edges).
- Uniform random 32-bit `b` (16384 samples): histogram of `h` peaks at
  `h = 11` (4130 samples); full histogram in
  `linear_model_data.json`.
- Densest masks per unit of weight (bits `(1−7t) mod 32`, `t < 2m`):
  every extra 2 consecutive edges costs 1; cost per active mask bit
  approaches 1/2 in the best case, never below 15/32.

## 4.3. Exact mask propagation (forward and backward)

**Forward step.** For a round `r`, with input mask `m` on `s[r]` and
cells `p = 0..3` (`L = s[r][p]`, `R = s[r][p+4]`):

```
b_p     = m[p]                          (only words 0..3 decide the cost)
g_p     ∈ valid_gammas(b_p)             (4^{h(b_p)} choices, each |corr| = 2^{−h(b_p)})
n[p+4]  = m[p] ;  n[p]  = m[p+4] ⊕ g_p
m_next  = lin_fwd(n, r)                 (byte transposition, then rotl by (r mod 31)+1)
w_r     = Σ_p h(m[p])
sign    = (Π_p sign_p) · (−1)^{m · rk[r]}
```

**Backward step.** For a round `r`, given `m_next` on `s[r+1]`:

```
n       = lin_inv(m_next, r)            (inverse rotation, then inverse transposition)
b_p     = n[p+4]                        (this is the output mask of F at cell p)
m[p]    = n[p+4]                        (cost h(n[p+4]) at this round)
m[p+4]  = n[p] ⊕ g_p ,  g_p ∈ valid_gammas(b_p)
```

The `selftest` verifies that every forward edge is a backward edge with
the same cost (325 edges checked), so the two searches enumerate the
same set of trails. Trails are always stored in forward order
(mask on `s[first]` … mask on `s[last+1]`).

Correlation of a trail: `Π_r 2^{−w_r} · (−1)^{Σ_r m_r·rk[r]} · Π_p sign_p`.
The linear hull at fixed key is the exact sum over all trails with the
same `(m_0, m_R)`; `propagate()` computes it by correlation-vector
propagation (pruned by weight). ELP mode
(`propagate(..., elp=True)`) gives the key-independent potential under
the (incorrect for a deterministic schedule) independent-round-key
assumption.

**Free-chain structure.** A round has weight 0 iff words 0..3 of its
input mask are zero; the round then acts as a pure bit permutation and
the tracked bit never meets `F`. Since the rotation schedule has
period 31, there are only 31 distinct windows. The exact free-chain
table (all 128 single-bit masks in words 4..7, 31 windows) is in
`LINEAR_MODEL.md` §4 and `linear_model_data.json`. Headline: the
longest weight-0 chain is **9 consecutive rounds**, at windows
`r ≡ 12 (mod 31)` and `r ≡ 27 (mod 31)`.

## 4.4. Verified `|corr| = 1` chains

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
through `Σ_r m_r · rk[r]`. The model predicts that sign exactly. Per-
round masks and complete details are in `linear_model_data.json`
(`verified_chains`).

The backward search finds the same 9-round weight-0 chains at the
corresponding end residues (20 and 4 mod 31). The `selftest` verifies
`|corr|=1` on the real cipher for both, and that the forward and
backward chains are the same trails (stored in forward order).

## 4.5. Best single trails beyond the free chain (upper bounds)

Layered beam search with the exact rules, starts = all 256 single-bit
masks, beam 1200, cells with `h ≤ 2` expanded. Each reported weight is
an **achievable single-trail weight**, i.e. an upper bound on the best
weight, not a minimum.

| rounds R | 1–9 | 10 | 11 | 12 | 13 | 14 |
|---|---|---|---|---|---|---|
| best weight, window r0=12 | 0 | 1 | 2 | 3 | 7 | 12 |
| best weight, window r0=27 | 0 | 1 | 3 | 3 | 6 | 11 |

This table covers only the two windows with the longest free chain.
§4.10 searches all 31 offsets in both directions and shows that the
windows 12 and 27 are the best only up to R=12; from R=13 on, other
offsets (notably r0=23 forward and r0=20 backward) give lower
single-trail weights.

Note that this is *the opposite* of a linear-distinguisher risk at low
rounds: at the 9-round mark we still have weight 0 (correlation ±1 in
absolute value). The reader should not confuse this with an attack on
the full cipher — see §4.7.

## 4.6. Hull verification (r0=12, exact signed hulls)

The single-trail numbers above are inputs to a hull computation. For
three trails at r0 = 12 with weights 1, 2, 3, the model produces an
exact signed prediction (fixed key, sum over all trails of weight ≤
w+4 with the same end masks) and the real cipher produces an empirical
correlation over 2²² plaintexts.

| window r0 | R | best-trail w | hull masks kept | predicted corr | empirical corr | σ | z |
|---|---|---|---|---|---|---|---|
| 12 | 10 | 1 | 4 | +0.500000 | +0.499997 | 4.9e-04 | −0.01 |
| 12 | 11 | 2 | 40 | −0.250000 | −0.250008 | 4.9e-04 | −0.02 |
| 12 | 12 | 3 | 3152 | −0.125000 | −0.124813 | 4.9e-04 | +0.38 |

Three independent predictions, three matches, |z| < 0.4 in every case.
The hull sum is not an approximation here; it is the exact polynomial
expansion of the trail system in the model, and it is what the real
cipher produces within sampling error.

§4.10.3 extends this check to the saved R=14 trails from the beam
search. The r0=23 forward trail cancels from R=8; the r0=24 forward
trail cancels from R=8; the r0=12 forward trail is exact up to R=12;
the offset-20 backward trail is exact from R=1 to R=14. Hull effects
are not a uniform correction.

## 4.7. What this establishes and what it does not

**Established (machine-checked by `selftest`):**

- Exact LAT of F (valid set, magnitude, sign) against brute force.
- Exact per-round mask rule and key-sign tracking, in both directions
  (forward and backward edges match, 325 edges checked).
- Existence of key-independent-magnitude `|corr| = 1` single-bit
  relations over up to 9 consecutive rounds; found by both forward and
  backward searches at the corresponding residues.
- Exact signed linear-hull predictions (not approximations) at r=10,
  11, 12 against the real cipher.
- The `mysx.prod.js` Python port reproduces `KNOWN_KAT_DIGEST`, so all
  claims are made against the actual reference implementation.
- (§4.10) The beam-search tool reproduces the §4.5 table exactly, its
  per-round masks agree with the real cipher wherever a trail is its
  own hull, and the `selftest` runs in both directions.
- (§4.10.3, §4.10.5) The offset-20 backward trail at R=14 (weight 5,
  rounds 100–113) is isolated in its hull (`hull_count` = 1 trail) and
  its empirical correlation matches 2⁻⁵ on the real cipher; the exact
  budgeted hull extends it to R=16 (rounds 98–113, |corr| = 2⁻¹¹,
  confirmed within 1.9σ on one key). This is a **verified linear
  distinguisher on a 16-round window**. It is seven weighted rounds
  followed by the 9-round weight-0 chain of this section, so it is the
  free chain plus a short weighted prefix, not new evidence about long
  trails.

**Not established:**

- A **lower bound** on the best trail weight over 128 rounds. Beam
  search gives upper bounds from a specific start distribution.
- An exact 128-round hull. Even the pruned `propagate()` will not
  scale; a certified bound would need a SAT/MILP encoding.
- A hull-aware correlation for the trails found in §4.10 beyond
  R=14. §4.10.3 shows that single-trail weight can over- or
  under-estimate the real correlation (cancellation was observed for
  some trails and isolation for others).
- The cost of a key-recovery attack.
- Behaviour of multi-bit starts at larger R beyond the pairs47 and
  rand:5000:4 runs (which did not improve on single-bit; rand:5000:4
  is too small to be conclusive for structured multi-bit masks).
- Anything about the last-round / whitening structure, related-key
  linear behaviour, or side channels.

**The weight-0 chains are not an attack.** A 9-round `|corr| = 1`
relation sits in a 128-round cipher. Standard linear cryptanalysis
extrapolates a weight over the full length; here the trail weight over
rounds 0..8 is 0 and the weight over rounds 9..127 is unknown. The
result is best read as: *the exact machinery is in place and it agrees
with the real cipher on small round counts*, not as *MYSX is broken*.
The 128-round picture remains open, although §4.10 shows that the
cheap region ends at roughly 20 rounds in the single-trail model.

## 4.8. Previous incorrect models and why they failed

For the record, the v0.0 draft reported three approximate models, all
with negative empirical verification. They used per-cell AND activity
as a proxy for correlation, which is not the correct structure of F.
The correct structure is the rank of the graph `A_b` above. The
previous models produced trails with predicted `|corr| ≈ 2^{−8}` at r=4
but no detectable signal — consistent with the fact that those trails
have zero true correlation in the exact model.

An instructive detail from the old work remains relevant to *any*
future linear work on MYSX: the empirical verification harness must
use **fixed keys** per sample. With random keys per plaintext, the
sign of every linear trail is key-dependent and the observed
correlation of a genuinely nonzero trail collapses to zero. See
`misc/validate_lineal_harness.js`, which validates the harness against
a hand-computed `w=8` case (observed correlation 0.4993 vs 0.5).

## 4.9. Integral / division property (preliminary, limited)

Tool: `misc/mysx_division_property_v2.py` with standard division-
property rules (COPY: `k_a = Σ k_copies`; XOR: `k_c = k_a + k_b` with
`(1,1)` invalid; AND: `k_c = k_a OR k_b`). The XOR and OR variants
were found to be equivalent for all input patterns tested (the `(1,1)`
constraint never fired), so the reported results do not depend on the
choice between them.

**Results.**

| Input | Active bits | Integral size | Rounds with balanced bits | Saturation |
|---|---|---|---|---|
| bit 0 of word 0 | 1 | 2 | 10 | R = 11 |
| word 0 | 32 | 2³² | 6 | R = 7 |
| words 0 and 4 | 64 | 2⁶⁴ | 5 | R = 6 |

The **integral distinguishers** are the last two rows: 6 rounds with a
2³²-text integral, 5 rounds with a 2⁶⁴-text integral. These cover 4.7%
and 3.9% of the 128 rounds, leaving 122 and 123 rounds without an
integral distinguisher in the tested pattern.

The first row (1 active bit, 2-text integral) is **not** a meaningful
integral distinguisher: with 2 texts, "balanced output bit" is
equivalent to "output bit independent of the input bit". It is
reported as a **single-bit dependency propagation** result — it
measures how many rounds are needed for the active bit to reach all
256 output bits (10) — but no integral security conclusion is drawn
from it.

**Empirical verification.** The 6-round distinguisher (word 0 active)
and the 10-round single-bit dependency were verified against the real
cipher (fixed random key, all non-active input bits random) over
20,000 samples each. The balanced bits predicted by the model never
flipped; control bits (predicted not balanced) flipped with
probabilities 6.5%–87%. The 5-round distinguisher (words 0,4 active)
was not verified empirically (its integral has 2⁶⁴ texts; a random-
sample approximation with 20,000 samples is not meaningful).

**Comparison with Simon (with care).** For Simon32/64, Todo and Morii
(FSE 2016) prove a 14-round integral distinguisher with the
conventional bit-based division property (31 active input bits), and a
15-round one using three subsets. 14 rounds is 44% of Simon32's 32
rounds (47% for 15 rounds). In **relative terms** MYSX resists integral
distinguishers better (4.7% vs 44%), which is consistent with MYSX's
more aggressive diffusion (4 parallel Feistel cells + transposition).
In **absolute terms** Simon's distinguisher reaches further (14 vs 6
rounds) even though MYSX has 4× more rounds. The two are not directly
comparable without normalizing by total rounds, and the MYSX analysis
used only the conventional bit-based rules at r0=0. (The earlier text
of this paragraph quoted an 11-round Simon32 distinguisher, 34%; that
figure was wrong.)

**What this establishes and what it does not.**

Established:

- MYSX has integral distinguishers covering 5–6 rounds with multi-bit
  inputs (2³² and 2⁶⁴ texts).
- A single active input bit stops influencing all 256 output bits
  after 10 rounds.
- The standard division-property rules with the `(1,1)`-invalid XOR
  constraint produce the same results as the OR-conservative rule for
  the tested inputs.

Not established:

- Integral distinguishers beyond 6 rounds for multi-bit inputs.
- Behaviour for r0 ≠ 0. Only r0 = 0 (the first round window) was
  tested. The rotation schedule has period 31, and windows r0 = 12 and
  r0 = 27 are where the linear chains are longest; they may also give
  longer integral distinguishers, or shorter. Not explored.
- Full-block inputs (255 active bits).
- The three-subset division property (introduced by Todo–Morii,
  FSE 2016; variant without unknown subset: Hao et al., EUROCRYPT 2020)
  and traceability-enhanced variants (Wang et al., 2023; citation to be
  verified), which may extend the distinguishers.
- Any key-recovery attack based on these distinguishers.

**Historical note.** The XOR rule of Todo–Morii as commonly written
in the literature (`k_c = k_a XOR k_b`) is not sound when the two XOR
operands share variables. In MYSX's `F = C ⊕ D`, both `C` and `D`
depend on `R`, so that rule overestimates balanced bits via spurious
cancellations. The first implementation of this analysis used that
rule and produced oscillating, non-converging numbers (127 → 117 →
152 → …). Those numbers are an artifact and are not reported here.
The results above use the standard `(1,1)`-invalid rule, which is
sound.

## 4.10. Beam search over the exact linear model, 128 rounds, both directions, all offsets

### 4.10.1. Method

Tool: `misc/mysx_linear_beam.py` (self-contained: it re-implements the
exact LAT of F, the exact mask propagation of §4.3 in both directions
and, for its `selftest`, the real cipher). It searches for achievable
single-trail weights with `w = Σ_r Σ_p h(m_r[p])`.

**Two directions.**

- **Forward** (`--direction forward`, default): the offset `o` is the
  index of the *first* round mod 31. Starts are masks on `s[o]`, the
  trail covers rounds `o .. o+R-1`, and the trail must fit inside the
  cipher (`o + R ≤ 128`).
- **Backward** (`--direction backward`): the offset `o` is the index
  of the *last* round mod 31. Starts are masks on `s[e+1]` with
  `e = o + 31·⌊(127−o)/31⌋`, the trail covers rounds `e-R+1 .. e`,
  and the trail must fit inside the cipher (`e + 1 ≥ R`, i.e.
  `realizable_R = e + 1 ≥ R`). The propagation uses the inverse
  round rule of §4.3.

**Merge.** `python3 mysx_linear_beam.py merge a.json b.json c.json`
combines any number of result files (from either direction) and reports
the minimum weight per R across all offsets and both directions. The
combined table of §4.10.2 is the output of
`merge beam_full.json beam_pairs47.json beam_bwd.json`.

Parameters of the reported runs:

| Parameter | Value |
|---|---|
| Rotation offsets | all 31 (0..30) |
| Rounds | up to 128 |
| Start masks | the 256 single-bit masks of the relevant state |
| Beam width | 2000 states per layer, ranked by (weight, Hamming weight), deduplicated by mask |
| Per-cell limit | `h(b) ≤ 16`; `b = 0xFFFFFFFF` (full cycle, special case of §4.2) is excluded |
| Valid `g` per cell | the 3 sparsest elements of the valid set (`--g-keep 3`) |
| Reported value | suffix minimum `ub(R) = min_{R' ≥ R} best(R')`, valid because the best weight is non-decreasing in R |
| Forward run | `beam_full.json`, `beam_full.log`: 8 processes, 1972 s |
| Backward run | `beam_bwd.json`, `beam_bwd.log`: 8 processes, 1512 s |
| Multi-bit run | `beam_pairs47.json`: `--starts pairs47`, did not improve on single-bit |

Every exclusion or truncation above only *restricts* the search, so all
reported weights remain achievable single-trail weights (upper bounds
on the best weight). A larger beam, `--g-keep 0` and multi-bit starts
can only lower them.

Validation of the tool, before the runs:

- `selftest` passes in both directions: (1) the closed-form LAT of F
  against sampling, (2) one round of the model against the real round
  function with random keys, (3) the 9-round weight-0 chains at r0 = 12
  and r0 = 27 found by the forward search and confirmed with
  `|corr| = 1` on the real cipher (256 random states per chain), (4)
  every forward edge is a backward edge with the same cost (325 edges
  checked), (5) the 9-round weight-0 chains are found backward at end
  residues 20 and 4 with `|corr| = 1` on the real cipher, (6) a
  backward R=14 trail with weight 21 is a valid forward trail with
  equal weight.
- `reproduce` returns exactly the §4.5 table for r0 = 12 and r0 = 27
  (R ≤ 14, beam 1200, `h ≤ 2`).

### 4.10.2. Results

Best achievable single-trail weight per number of rounds, minimum over
offsets and both directions, subject to the trail fitting inside the
128-round cipher (forward: `r0 + R ≤ 128`; backward:
`realizable_R = e + 1 ≥ R`):

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

† The weight-8 trail of this row cancels once its hull is computed (four
trails of weight 8 with the same end masks sum to zero, §4.10.5), so 2¹⁶
texts is not a distinguisher cost. The best certified correlation at
R=16 is the offset-20 backward hull, |corr| = 2⁻¹¹ (≈2²² texts). The
same caveat applies to every row: a row is an achievable *single-trail*
weight, not a correlation.

Largest R with an achievable single trail of weight < 32 (≈2⁶⁴ texts):
**19**. Largest R with weight < 64 (≈2¹²⁸ texts): **22** (weight 63 at
R=22, offset 23 forward; 49 at R=21). This is a **tie with the
threshold**: at beam 1000 the same cell gives 64/71, so the defensible
statement is "≈20–22 rounds", not "22".

**Direction alternates with R.** Among the tabulated round counts the
minimum is reached by a backward trail at R=9, 10, 12, 14 (tied with
offset 23 forward), 18, 20, 24, 32, 40, 48, 96, 112 and 128, and by a
forward trail at R=16, 22, 56, 64 and 80. The two directions align with
different sets of rotation windows, so neither is uniformly better. The
combined table is the right object; do not compare the forward-only and
backward-only tables row by row.

**R=128 is a real trail.** In forward mode only r0=0 fits a 128-round
trail (`o + R = 128`). In backward mode, offset 3 has
`e = 3 + 31·⌊124/31⌋ = 127`, `realizable_R = 128`, and the trail covers
rounds 0..127. The combined R=128 = 2248 at offset 3 backward is a
**real trail inside the cipher**, not a virtual extension. Offsets with
`realizable_R < R` are excluded from the minimum (the tool checks this
explicitly). The `v0.1-draft` statement that "for r0>0 the value at
R=128 is a virtual extension" was forward-specific; it does not hold for
backward offset 3.

**Per-offset detail at R=14** (single-bit starts, beam 2000, merged).
For compactness, the backward values are shown (they include the best
cell of the whole table, offset 20 = 5); the forward values are in
`beam_full.json` and the merged per-offset arrays are in the output of
`merge`.

| offset (backward, last round mod 31) | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| weight | 17 | 11 | 11 | 8 | 11 | 36 | 61 | 46 | 34 | 47 | 43 |

| offset | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| weight | 24 | 53 | 42 | 38 | 31 | 24 | 16 | 12 | 8 | **5** | 21 |

| offset | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 30 |
|---|---|---|---|---|---|---|---|---|---|
| weight | 25 | 21 | 13 | 19 | 41 | 36 | 36 | 28 | 26 |

The best cell at R=14 is offset 20 backward (weight 5). The next best
are offsets 3 and 19 backward (weight 8). The forward per-offset table
is available in `beam_full.json`; the best forward cell at R=14 is
offset 23 (weight 5), tied with offset 20 backward. The spread (5 to 61
across offsets for the same R) is the evidence that the rotation offset
matters a great deal, which is also why the differential analysis of §3
needs to be repeated over offsets.

**Growth.** Between R=22 and R=112 the best weight grows by roughly
12–21 per round (12.5 for 22→24, 14.5 for 24→32, 19.6 for 32→40, 15.5
for 40→48, 18.1 for 48→56, 19.5 for 56→64, 18.4 for 64→80, 15.9 for
80→96, 20.9 for 96→112). The last step, 112→128, is ≈36 per round
(1671 → 2248). That step is inflated by the fitting rule: only offset 3
backward fits a full 128-round trail, so the R=128 value is not a
minimum over all 31 offsets as the others are. The average between R=48
and R=128 is ≈22 per round. The weight never settles at a low per-round
cost. Note also that single-trail weights above ≈256 say nothing about
the cipher: with a 256-bit block the sum over the many trails of a hull
is what matters there, and no hull-aware statement is made beyond
R≈14.

### 4.10.3. Hull check of the trails found

A single-trail weight `w` predicts `|corr| = 2^{−w}` only when the trail
is alone in its hull. The beam trails were therefore checked against the
real cipher (fixed key, final whitening disabled, 2¹⁷–2¹⁸ random
states), prefix by prefix, using the stored per-round masks. Script:
`misc/verify_beam_trail.py`; trail counting: `misc/hull_count.py`.

**Trail of offset 20 backward, R=14, w=5** (covers rounds 100..113;
`first_round[14] = 100`). Key seed 1, 2¹⁷ states (σ = 0.0028):

| R | trail weight w | predicted 2^{−w} | empirical corr |
|---|---|---|---|
| 1 | 1 | 0.5000 | −0.4947 |
| 2 | 3 | 0.1250 | −0.1206 |
| 3 | 4 | 0.0625 | −0.0601 |
| 4 | 4 | 0.0625 | +0.0601 |
| 5 | 5 | 0.0312 | +0.0279 |
| 6 | 5 | 0.0312 | −0.0279 |
| 7 | 5 | 0.0312 | −0.0279 |
| 8 | 5 | 0.0312 | −0.0279 |
| 9 | 5 | 0.0312 | −0.0279 |
| 10 | 5 | 0.0312 | +0.0279 |
| 11 | 5 | 0.0312 | +0.0279 |
| 12 | 5 | 0.0312 | −0.0279 |
| 13 | 5 | 0.0312 | +0.0279 |
| 14 | 5 | 0.0312 | −0.0279 |

`hull_count` on the saved end mask returns **exactly one trail** at the
minimum weight for every R from 1 to 14 (layer sizes 4, 64, 84, 10, 4,
2, 1, 1, …, 1; the layer collapses to a single trail from R=7). The
predicted and empirical magnitudes agree within σ at every R. There is
**no cancellation** for this end mask. **This is a verified linear
distinguisher on a 14-round window (rounds 100–113).**

**How to read it.** The weight reaches 5 at R=5 and stays there up to
R=14: the trail is five cheap rounds followed by a 9-round weight-0
chain (the free chain of §4.3). The rows R=5…14 are therefore the same
signal observed after more free rounds, not ten independent
confirmations. The trail lies at rounds 100–113, so it is a property of
that window of the cipher; it is not a distinguisher for a 14-round
version of the cipher starting at round 0, and it is not an attack on
the 128-round cipher. Section 4.10.5 extends the same trail to R=16 by
two more weighted rounds (R=15: weight 8, R=16: weight 12).

**Trail of r0=23 forward, R=14, w=5** (start bit 197 of `s[23]`; end
masks bits {46, 66, 84, 196} of `s[37]`), key seed 1, 2¹⁷ states
(σ = 0.0028):

| R | trail weight w | predicted 2^{−w} | empirical corr |
|---|---|---|---|
| 1–4 | 0 | 1 | ±1.0000 |
| 5–7 | 1 | 0.5000 | −0.5014 |
| 8–10 | 2 | 0.2500 | ±0.0010 |
| 11–13 | 3 | 0.1250 | ±0.0012 |
| 14 | 5 | 0.0313 | −0.0001 |

The model is exact up to R=7. At R=8 the empirical correlation is zero
instead of ±1/4. An exact enumeration of all trails with weight ≤ 4
from the same start mask shows why: **two distinct trails of weight 2
reach the same end masks at R=8, 9 and 10** (and one at R=7), so their
contributions cancel. Two independent keys at R=14 (2¹⁸ states each,
σ = 0.002) give −0.0004 and +0.00001 against a single-trail prediction
of 0.031. For this trail the single-trail weight is therefore not a
usable estimate of the correlation.

**Other offsets, R=14 trails, one key (seed 1), 2¹⁶ states
(σ = 0.0039):**

| r0 | direction | R | single-trail 2^{−w} | empirical corr | relation |
|---|---|---|---|---|---|
| 12 | forward | 10 | 0.5000 | +0.4969 | equal |
| 12 | forward | 12 | 0.1250 | −0.1161 | equal (sign key-dependent) |
| 27 | forward | 10 | 0.1250 | +0.2503 | ×2 |
| 27 | forward | 12 | 0.0156 | +0.0369 | ×2.4 |
| 26 | forward | 10 | 0.1250 | +0.2412 | ×2 |
| 26 | forward | 12 | 0.0625 | +0.1218 | ×2 |
| 24 | forward | 10 | 0.1250 | +0.0049 | cancelled |
| 24 | forward | 12 | 0.1250 | −0.0049 | cancelled |

At R=14 the predicted correlations (2⁻⁷ to 2⁻¹²) are below the
resolution of this test (σ = 0.0039) for these four forward trails, so
no statement is made at R=14 for them. The offset-20 backward trail
(previous table) is measurable at R=14 because its weight stays at 5
from R=5 to R=14, so the test at R=14 is the same signal as at R=5
(where σ is adequate).

**Reading.** Across the trails checked, the real correlation equals
the single-trail value (offset 20 backward at R=14; r0=12 forward up to
R=12), is about twice as large (r0=26, r0=27 forward; a second trail
adds constructively), or is exactly cancelled (r0=23 forward from R=8;
r0=24 forward). The observed gain is at most ≈2.4× (about 1.3 bits);
the observed loss can be total. Hull effects are therefore not a
uniform correction, and they are not always destructive: some trails
survive intact and are genuine distinguishers of their window.

### 4.10.4. What §4.10 establishes and what it does not

Established:

- In the single-trail model, and within the searched family (single-bit
  starts, beam 2000, 3 sparsest `g` per cell, both directions), no
  trail with weight < 64 (≈2¹²⁸ texts) was found for more than 22
  rounds, and none with weight < 32 for more than 19 rounds. The
  threshold at 22 is a tie (weight 63): "≈20–22" is the defensible
  reading.
- The best weight grows by roughly 12–21 per round from R≈22 to R=112
  (≈22 on average from R=48 to R=128, inflated by the last step).
- The cheapest trails alternate direction (see §4.10.2 for the exact
  R values). The best cell at R=14 is offset-20 backward (weight 5),
  tied with offset-23 forward.
- The tool agrees with the real cipher wherever a trail is alone in its
  hull (offset-20 backward up to R=14; r0=12 forward up to R=12;
  r0=23 forward up to R=7).
- Single-trail weight is not a reliable proxy for correlation in
  general: exact cancellation was observed (r0=23 and r0=24 forward).
- The offset-20 backward trail at R=14 is isolated in its hull
  (`hull_count` = 1 trail) and its empirical correlation matches 2⁻⁵
  on the real cipher. The exact budgeted hull of §4.10.5 extends it to
  R=16 (rounds 98–113, |corr| = 2⁻¹¹, two trails of weight 12 adding,
  empirical 6.1×10⁻⁴ ± 6.1×10⁻⁵ against a hull prediction of
  4.9×10⁻⁴). **This is a verified linear distinguisher on a 16-round
  window (rounds 98–113).**
- At R=17 the best end pairs of offset 20 backward (7 of 8 computed)
  and offset 23 forward (8 of 8) cancel exactly within the enumerated
  budget, for both keys tested (§4.10.5).
- Multi-bit starts (pairs47, rand:5000:4) did not improve on single-bit
  starts at any R. pairs47 is a small structured subset;
  rand:5000:4 covers 5000 masks out of 2²⁵⁶ and is not conclusive for
  structured multi-bit masks.

Not established:

- A **distinguisher length beyond R=16**. R=16 is established for the
  offset-20 backward trail (exact hull over trails of weight ≤ 14 plus
  a one-key measurement). At R=17 the best pairs cancel within the
  budget, which does not exclude a smaller non-zero correlation from
  heavier trails or a distinguisher from other end pairs. R≥18 is
  undecided: the weights are ≥ 24 and the frontiers of the enumeration
  exceed the state caps (§4.10.5). The trails of §4.10.2 at R=18–22,
  including the weight-63 trail at R=22 that sits at the 2¹²⁸
  threshold, have not been checked.
- A **lower bound**. The beam gives achievable weights only. The
  truncations (`g-keep 3`, beam, single-bit starts, exclusion of
  `b = 0xFFFFFFFF`) may hide cheaper trails.
- That hull gain stays small at larger R. At R=24 (w=88) a gain of
  ≈2²⁴ in correlation (88 − 64) would be needed to bring the data cost
  down to the 2¹²⁸ budget; the
  gains observed so far are ≤ 2.4× (exactly 2× at R=15 and R=16) and
  were measured only up to R=16.
- That multi-bit starts do not help at all. The tested samples
  (pairs47, rand:5000:4) do not improve on single-bit, but the random
  sample is too small to rule out structured multi-bit masks that
  might. The honest statement is "the multi-bit starts tested do not
  improve on single-bit".
- Key recovery from any hull, differential analogues, and the effect
  of the final whitening and of key-recovery rounds around a
  distinguisher.

### 4.10.5. Exact hull at R=15–17 (budgeted, meet-in-the-middle)

§4.10.4 named the exact signed hull of the best end-mask pairs at R≥16
as the next step. This section does it for R=15–17 and reports where it
stops. Tools: `misc/hull_bidir.py`, `misc/scan_endpairs.py`,
`misc/test_signed_dp.py`, `misc/emp_check.py`. Inputs:
`misc/beam_paths_bwd20.json` and `misc/beam_paths_fwd23.json`, re-runs of
`mysx_linear_beam.py run` for offset 20 backward and offset 23 forward
with `--paths 15..22` (their `ub` values and the R=14/20/24 paths are
identical to `beam_bwd.json` / `beam_full.json`). A summary with the
reproduction commands is in `misc/HULL_R15_R17.md`.

**Method.** `hull_count.py` expands only forward from the start mask, so
its layers explode when heavy rounds sit at the start of the trail
(backward trails). `hull_bidir.py` grows a forward frontier from the
start mask `u` and a backward frontier from the end mask `v` (always
extending the smaller one), prunes each state with the minimum weight
already paid by the opposite frontier, and streams the last round into
the join. Any trail `u → v` of total weight ≤ `wmax` has prefix and
suffix weight ≤ `wmax`, so the result is **complete for weight ≤ wmax**
(cells with `b = 0xFFFFFFFF` are skipped, which matters only from weight
15 per cell). With `--keys K` it also sums the exact signed
contributions (cell sign from the LAT, key sign `(−1)^{m·rk}`) for K
random keys.

**Validation.** `mysx_linear_beam.py selftest` passes; the signed hull
equals `propagate()` of `mysx_linear_model.py` on 40 of 40 end masks
(windows r0=12 with R=10, 11, 12 and r0=27 with R=10, two keys;
`test_signed_dp.py`); at R=14, offset 20 backward, it reproduces
`hull_count.py` (one trail of weight 5). These validation windows are
forward and R ≤ 12; the signs of the backward step are validated
indirectly by the empirical measurements below.

**Results.** `w1` is the single-trail weight of the beam trail; "budget"
is `wmax` (all trails up to it are enumerated). The hull value is the
same for keys `rand_key(1000)` and `rand_key(1001)`.

| trail | R | rounds | w1 | trails u→v found | budget | exact hull |
|---|---|---|---|---|---|---|
| offset 20 bwd | 14 | 100–113 | 5 | 1 × w5 | 7 | ±2⁻⁵ (isolated) |
| offset 20 bwd | 15 | 99–113 | 8 | 2 × w8 | 10 | +2⁻⁷ (two trails add) |
| offset 20 bwd | 16 | 98–113 | 12 | 2 × w12 | 14 | +2⁻¹¹ (two trails add) |
| offset 20 bwd | 17 | 97–113 | 16 | 2 × w16 | 18 | 0 (exact cancellation) |
| offset 23 fwd | 15 | 23–37 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 16 | 23–38 | 8 | 4 × w8 | 10 | 0 |
| offset 23 fwd | 17 | 23–39 | 14 | 4 × w14 | 16 | 0 |

**Empirical check** against the real cipher (fixed key `rand_key(1000)`):

- offset 20 backward, R=16, N = 2²⁸: corr = +6.06×10⁻⁴ ± 6.1×10⁻⁵. The
  hull predicts 4.88×10⁻⁴ (+1.9σ); the single-trail value would be
  2.44×10⁻⁴ (+5.9σ) and zero is +9.9σ away. The sign matches the model.
- offset 23 forward, R=16, N = 2²⁴: corr = +3.7×10⁻⁴ ± 2.4×10⁻⁴ (1.5σ
  from zero); the single-trail value would be ±3.9×10⁻³ (16σ away).
  Consistent with the cancellation.

**R=17 scan** (`scan_endpairs.py --R 17`, `scan_R17.log`): the top 8 end
pairs of offset 20 backward (weight 16; 7 computed, 1 exceeded the state
cap of 800,000) and of offset 23 forward (weight 14; 8 of 8) all give an
exact hull of 0, for both keys, within a budget equal to the pair's
single-trail weight. Offsets 19 backward, 24 forward, 3 backward and 2
backward have R=17 weights 23–26 and exceeded the state cap: undecided.

**Reading.**

- The verified window of the offset-20 backward trail grows from 14 to 16
  rounds (rounds 98–113). The weights at R=14, 15, 16, 17 are 5, 8, 12,
  16: the two added rounds cost 3 and 4, so the trail is seven weighted
  rounds (98–104, total weight 12) followed by the 9-round weight-0
  chain (105–113). At R=15 and R=16 the hull is a factor 2 above the
  single-trail value because two trails of equal weight add.
- The R=16 row of the §4.10.2 table (weight 8, offset 23 forward) is the
  trail that cancels; its "2¹⁶ texts" is not a distinguisher cost.
- At R=17 the best pairs of both offsets cancel exactly within the
  budget, for both keys, in all 14 (pair, key) cases of offset 20
  backward and all 16 of offset 23 forward, and at R=15–17 the two keys
  agree in every case.
  This suggests that the relative sign of the paired trails does not
  depend on the key, i.e. that the addition or cancellation is
  structural; two keys are too few to assert it.

**What this does not establish.**

- A hull of 0 means "no net contribution from trails up to the budget",
  not a correlation of exactly 0. Trails above the budget are not summed
  (weight ≥ 15 at R=16, ≥ 19 at R=17 in the main runs; the R=17 scan used
  a budget equal to the pair's own weight). The measured correlation at
  R=16 is 1.9σ above the hull prediction, which is compatible with noise
  and also with a few trails of weight 15 (each adds 2⁻¹⁵); a run at
  R=16 with `--wmax 18` and more keys has not been done.
- R≥18 is undecided: the weights are ≥ 24 and the frontiers exceed
  2.5 million states. Only end pairs returned by the beam were tried;
  other pairs at R=17–22 may not cancel. Covering them needs a different
  method (the SAT/MILP hull encoding of `LINEAR_MODEL.md` §7) or a much
  larger scan. In particular the weight-63 trail of the R=22 row of the
  §4.10.2 table, which decides the position of the 2¹²⁸ threshold, is
  untouched.
- The sign was checked empirically for one key only.
- None of this is a key-recovery cost, a lower bound, or an attack on
  the 128-round cipher.

# 5. Related-key cryptanalysis

Tools: `misc/keyschedule_test.js` (basic) +
`misc/keyschedule_test_extended.js` (22 tests). Coverage: exhaustive
weight-1 (512 bits), exhaustive weight-2 (130,816 pairs), weight-3
"same Δ" (1,680 trials), beam search up to weight-6 (beam 50), 5 base
keys, structured patterns, cycles, weak keys.

**Results (summary):**

- No persistent `Δrk[r]=0` for r≥1 in any test.
- Beam search score: 139 (ideal 128).
- No weak keys, cycles, or fixed points.
- Slow diffusion at r=1–4 (expected: one Feistel round per cipher
  iteration).
- Worst bit (minimum weight at r=1): bit 160 (word 5, bit 0), 1-bit
  difference. Consistent across 5 base keys (structural, not noise).

**Limitations.** These are heuristic tests, not a proof. We did not
run a targeted MILP/SAT related-key model (~650k variables); adaptive
related keys, biclique attacks, and algebraic attacks on the key
schedule are not covered. **MYSX's related-key security is unknown.**

**Round-key recovery.** The only non-linear operation of the key
schedule is the 8 modular additions per step; everything else is XOR
and rotation. The schedule is bijective, so any 16 consecutive state
words determine the master key. How many round keys must be known for a
SAT solver to recover the master key (an estimate by counting: about
three consecutive `rk[r]`) has not been measured. This number bounds
what a partial key-recovery attack on a few rounds can lead to.

# 6. Generic attacks

| Attack | Complexity | Verdict |
|---|---|---|
| Classical brute force | 2⁵¹² operations (uniformly random 512-bit key) | Infeasible |
| Grover (quantum) | 2²⁵⁶ iterations (uniformly random 512-bit key) | Infeasible with foreseeable technology |
| Block collisions (birthday) | 2¹²⁸ blocks | Infeasible |

**Note on Grover.** With a uniformly random 512-bit key, Grover leaves
256 bits of effective security. With 1,000,000 logical qubits at 1
ns/iteration, the time would be ~10⁶⁰ years. This is a theoretical
estimate; no post-quantum analysis of the cipher beyond Grover has been
done.

**Note on the 512-bit key.** The key-derivation functions of Section
2.10 (and therefore every key produced by `deriveAeadKeys` and
`deriveAeadKeysFromPassword`) start from HKDF-Extract, whose output is
a 256-bit pseudorandom key (HMAC-SHA256). HKDF-Expand can output 64
bytes, but they are a deterministic function of that 256-bit value, so
the entropy of a derived 512-bit `encKey` is at most 256 bits. If the
master secret has 256 bits of entropy, the effective classical security
is 256 bits (not 512) and the Grover figure is 2¹²⁸ iterations (not
2²⁵⁶). The "key size" of MYSX is not the security level of the system.
The 2⁵¹² and 2²⁵⁶ figures apply only if the caller supplies a
uniformly random 64-byte key directly to `aeadEncrypt`.

# 7. Simon cryptanalysis: what transfers and what does not

MYSX uses Simon's `F`. It is **not** Simon. The differences:

- Block size and branch organization: MYSX is an SPN-like structure
  with four parallel Feistel cells over 32-bit word pairs (Section 2.1).
  Simon is a classical 2-branch Feistel over `n`-bit halves.
- Four parallel `F` per round (Simon uses 1).
- Myszkowski byte transposition (Simon has none).
- Round-dependent word rotations (Simon has none).
- Non-linear ARX key schedule (Simon's is linear).
- 128 rounds vs 68.

**What transfers.** The exact LAT of `F` — its closed form
`|corr| = 2^{−h(b)}`, its validity condition `l ∈ colspace(A_b)`, and
its sign structure — is a property of the function and therefore
applies to MYSX regardless of the surrounding structure (Section 4.2
is the transfer). That is the correct starting point for MYSX-specific
linear cryptanalysis; the failed models of the v0.0 draft used a
different (incorrect) F model.

**What does not transfer.** Key recovery from Simon's linear key
schedule does not transfer: MYSX's key schedule is non-linear. Linear
hull attacks against Simon are highly structured around Simon's
Feistel-branch and its round-reduced behaviour; the MYSX hull is a
different object and must be computed from the MYSX round model
(Section 4.6). Integral distinguishers against Simon rely on Simon's
particular 2-branch Feistel structure and its key schedule; the
preliminary MYSX integral distinguishers in §4.9 are considerably
shorter, and their relationship to Simon's is one of normalized
coverage, not direct transfer.

**Relevant literature on Simon** (cited for context; the figures below
were checked against the papers' abstracts, other figures quoted in
earlier drafts were not verified and have been removed):

- Linear-hull key-recovery attacks with dynamic key-guessing reaching
  49 rounds of Simon128/128 (Chen–Wang, "Improved Linear Hull Attack on
  Round-Reduced Simon with Dynamic Key-guessing Techniques", FSE 2016,
  ePrint 2015/666).
- Improved linear characteristics and hulls, including a 34-round linear
  characteristic with correlation 2⁻⁶¹ for Simon128 (Shi–Hu–Sun–Song–
  Qiao–Ma, "Improved Linear (hull) Cryptanalysis of Round-reduced
  Versions of SIMON", ePrint 2014/973).
- Differential analysis of Simon and Speck (Biryukov–Roy–Velichkov,
  "Differential Analysis of Block Ciphers SIMON and SPECK", FSE 2014).
- Integral distinguishers: 14 rounds for Simon32 with the conventional
  bit-based division property, and 15 rounds with three subsets
  (Todo–Morii, "Bit-Based Division Property and Application to Simon
  Family", FSE 2016); 14-, 16-, 18-, 22- and 26-round distinguishers for
  Simon32/48/64/96/128 (Xiang–Zhang–Bao–Lin, ASIACRYPT 2016).
- Structural observations on the SIMON family
  (Kölbl–Leander–Tiessen, "Observations on the SIMON block cipher
  family", CRYPTO 2015).

None of these results is transferred to MYSX in this paper. The
MYSX-specific analysis (Sections 3, 4, 5) is what provides the
evidence; Simon attacks are context, not direct transfer.

# 8. Analysis limitations

- **Differential**: upper bounds on single-trail for one input at
  r=12–14, no variation of the rotation offset; one trail verified at
  r=4 (ratio 2.00×); no lower bounds; no full clustering analysis; no
  inputs placed in the free windows.
- **Linear**: an exact model of `F` is established and matches the
  real cipher on small round counts, including exact signed hulls at
  r=10, 11, 12. A beam search over the exact model, **in both
  directions and merged over all 31 offsets**, up to 128 rounds
  (§4.10), gives achievable single-trail weights only: 2 at R=12, 5 at
  R=14, 38 at R=20, weight < 64 up to R=22 (63, a tie) and 2248 at
  R=128 (offset 3 backward; a real trail inside the cipher). The
  offset-20 backward trail at R=14 (rounds 100–113) is **isolated in
  its hull** (`hull_count` = 1) and its empirical correlation matches
  2⁻⁵; an exact budgeted hull extends it to R=16 (rounds 98–113,
  |corr| = 2⁻¹¹): that is a verified linear distinguisher on a
  16-round window. Other trails cancel or are ≈2× larger (at R=17 the
  best pairs cancel within the budget), so single-trail weights are
  not universally distinguisher lengths. No lower bound over 128
  rounds; no hull-aware bound beyond R=17; hulls are exact only up to
  a weight budget; `g` choices truncated to the
  3 sparsest per cell; no key-recovery cost estimate. Multi-bit starts
  (pairs47, rand:5000:4) were explored and did not improve on
  single-bit starts, but the random sample is too small to be
  conclusive for structured multi-bit masks.
- **Integral**: preliminary. 6-round distinguisher with 2³² texts
  (word 0 active) and 5-round distinguisher with 2⁶⁴ texts (words 0,4
  active), both with the sound `(1,1)`-invalid division-property rule.
  A 10-round single-bit dependency propagation is reported for context
  but is not an integral distinguisher. Only r0 = 0 tested; other
  round windows, full-block inputs, and three-subset / traceability-
  enhanced DP are not explored. No key-recovery attack was attempted.
- **Related-key**: heuristic tests up to weight-6; no targeted MILP;
  number of round keys needed to recover the master key not measured.
- **Impossible differential, boomerang, algebraic**: not analyzed.
- **No independent public cryptanalysis.**
- **No post-quantum analysis** beyond the trivial Grover bound.
- **No side-channel analysis.**
- **Functional tests** (`mysx.test.js`, 17 tests) cover round-trip,
  AEAD negatives, nonce policy, PBKDF2, avalanche. They do not prove
  security.

# 9. Engineering notes

## 9.1. API surface

- Public API: `aeadEncrypt`, `aeadDecrypt`, `deriveAeadKeys`,
  `deriveAeadKeysFromPassword`, `NonceGuard`.
- Test API: **disabled by default**. Enabled only when the environment
  variable `MYSX_ENABLE_TEST=1` is set in the process before requiring
  the module. There is no code-level toggle.
- CTR (`_ctrXor`) is not exported from the public API.

## 9.2. NonceGuard

`NonceGuard` is a best-effort defense against nonce reuse. It:

- counts messages per key (default 2³²);
- detects recent nonce reuse (window of 1024 per key);
- caps the number of tracked keys (default 1024, LRU eviction);
- identifies keys by a non-cryptographic 64-bit identifier made of two
  independent 32-bit lanes (a 32-bit FNV-1a lane and a multiplicative
  lane), **not** by the raw key bytes; `onSave(state)` therefore does
  not leak the secret key;
- throttles `onSave` calls (default: once every 100 `check()` calls)
  to avoid per-message state copies;
- **does not persist across restarts by itself**;
- **does not share state across processes or devices**.

Persistence is provided by `onSave(state)` and `initialState` at
construction, or by `save()` / `load(state)` for manual control.

**It is not a substitute for key lifecycle management.** If the
application reuses `(key, nonce)` across restarts, CTR confidentiality
is broken. When a key is evicted from the tracked set its counter and
nonce window are lost. See `mysx.prod.js` for the exact contract.

**What it actually buys.** `aeadEncrypt` draws a fresh 16-byte random
nonce for every message, so an accidental repeat of `(key, nonce)` has
probability about 2⁻⁶⁵ even after 2³² messages under one key
(birthday bound on 128 bits). The nonce-window check therefore guards
mainly against a faulty random-number generator; the part that matters
in practice is the per-key message limit, which is also lost when a key
is evicted or the process restarts. The option name `unsafeNoGuard`
reflects that the guard is missing, not that nonces are imposed by the
caller (they are not: there is no public path to impose a nonce).

## 9.3. aeadEncrypt size validation

`aeadEncrypt` validates plaintext size **before** allocating the CTR
output buffer, and enforces a configurable `MAX_PLAINTEXT_BYTES` limit
(aligned with `MAX_CT_BYTES`, 2³¹−1). Applications that require larger
limits should raise both limits explicitly and manage memory
accordingly.

## 9.4. Type validation

All public functions validate that byte inputs are `Uint8Array` of the
expected length (where applicable). Passing a `string` as `aad` or
`plaintext` throws instead of silently coercing to array-like
behavior.

## 9.5. KAT digests

Two digests are documented in `README.md`:

- `KAT.json` public digest: SHA-256 over the full JSON (block + AEAD +
  KDF). This is the artifact a third-party implementation should
  reproduce.
- `KNOWN_KAT_DIGEST` (internal): SHA-256 over 16 blocks with
  `key[i] = i`. Used as fast regression in `mysx.test.js`. It is
  strictly a subset of the public KAT, not a different KAT.

A third-party implementation should target the **public digest**.

## 9.6. Harness validation

The linear sampling harness is validated against a hand-computed case
at w=8 (r=1, α = {word0 bit2, word4 bit0}, β = word0 bit3, fixed key).
The linear approximation `x₀ ⊕ F(x)₂ = x₁x₆` has correlation exactly
±1/2 with fixed key. Observed correlation: **0.4993** (expected 0.5,
within sampling noise). With random keys per sample, the sign of the
correlation flips per sample and the observed |corr| drops to **0.0022**
(expected ≈ 0).

This confirms the harness is correct when used with fixed keys. It
also confirms that the practice of "random keys per sample", used in
an earlier version of `misc/mini_trail.js`, washes out genuine linear
signals and must not be used for linear cryptanalysis.

See `misc/validate_lineal_harness.js`.

The mini-MYSX with `w=8, kw='MYSZKOWS'` is **degenerate**: the
permutation becomes `[4,0,5,2,7,6,1,3]`, the L→R→L cycle at word 0
means a single-bit difference never passes through F, and the
differential probability is 1 at all rounds. This is not
representative of MYSX. Use `w=8, kw='MYSZ'` (non-degenerate from
r=3) or w=32 directly. See `misc/check_mini_nondegenerate.js`.

The integral division-property harness (`misc/verify_division.py`) is
validated against the R=10 single-bit dependency: the two bits the
model predicts as balanced (word 0 bit 31, word 3 bit 6) are
confirmed balanced over 20,000 random samples, and the other 62 bits
of words 0 and 3 are confirmed not balanced. See `misc/verify_division.py`
and §4.9.

The beam-search tool (`misc/mysx_linear_beam.py`) has its own
`selftest` (LAT of F, one round against the real round function,
9-round weight-0 chains against the real cipher, forward/backward
edge duality, backward 9-round weight-0 chains, backward R=14 trail
is a valid forward trail) and a `reproduce` command that regenerates
the §4.5 table. See §4.10.1.

# 10. Verdict

**MYSX-256/512 v0.1-draft2 is an experimental proposal, not a secure
cipher.** The differential analysis reports upper bounds on single-trail
weights (one input, rotation offset not varied), not a security proof;
one trail at r=4 has been directly verified with clustering factor
2.00×. The linear analysis has a correct, exact model of `F` and of the
round; it reproduces the real cipher's linear behaviour on the small
round counts where it has been checked (verified `|corr| = 1` chains at
5 and 9 rounds; exact signed hulls at r = 10, 11, 12). A beam search
over that model, run in **both directions** for all rotation offsets, up
to 128 rounds, and merged, finds that the cheap region ends at roughly
20 rounds (single-trail weight 38 at R=20, below 64 only up to R=22
with weight 63 — a tie with the threshold — then growing by roughly
12–21 per round up to R=112; 2248 at R=128, offset 3 backward, which is
a real trail inside the cipher). The offset-20 backward trail at R=14
(weight 5, rounds 100–113) is **isolated in its hull** (`hull_count` =
1) and its empirical correlation matches the prediction, and an exact
budgeted hull extends it to R=16 (rounds 98–113, |corr| = 2⁻¹¹):
**this is a verified linear distinguisher on a 16-round window**, made
of seven weighted rounds and a 9-round weight-0 chain. At R=17 the best
end pairs cancel within the enumerated budget. For other trails, a check against
the real cipher shows that a single-trail weight can be exact, ≈2× too
low, or exactly cancelled, so these numbers are evidence about where
cheap trails end, not universally how long a distinguisher is. No lower
bound over 128 rounds has been established, no key-recovery attack has
been attempted, and hull-aware bounds beyond R=17 are unexplored.
Multi-bit starts (pairs47, rand:5000:4) did not improve on single-bit
starts, but the random sample is too small to be conclusive. The
integral analysis is preliminary: it establishes 5–6 round integral
distinguishers with multi-bit inputs (2³² and 2⁶⁴ texts) and a 10-round
single-bit dependency propagation, but only for the first round window
(r0 = 0). The related-key analysis is heuristic. No impossible-
differential, boomerang, or algebraic analysis has been done. The cipher
has not been externally audited.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.

# 11. Reproducibility

| File | Purpose |
|---|---|
| `SPEC.md` | Formal specification (identical content to Section 2) |
| `PAPER.md` | This document |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Implementation (public API) |
| `mysx.test.js` | Functional tests |
| `cryptanalysis/models/linear/mysx_linear_model.py` | Exact linear model of F + round; `selftest` / `report` commands |
| `cryptanalysis/models/linear/LINEAR_MODEL.md` | Detailed documentation of the exact linear model |
| `cryptanalysis/models/linear/linear_model_data.json` | All numbers in Section 4 (except §4.10) as JSON |
| `misc/mysx_linear_beam.py` | Beam search over the exact linear model, all offsets, up to 128 rounds, forward and backward (§4.10); `selftest`, `reproduce`, `run`, `merge` |
| `misc/beam_full.log`, `misc/beam_full.json` | Output of the forward §4.10 run (`run --beam 2000 --jobs 8`) |
| `misc/beam_bwd.log`, `misc/beam_bwd.json` | Output of the backward §4.10 run (`run --direction backward --beam 2000 --jobs 8`) |
| `misc/beam_pairs47.json` | Output of the pairs47 multi-bit run (merged; not an improvement) |
| `misc/verify_beam_trail.py` | Prefix-by-prefix check of a saved beam trail against the real cipher, both directions (§4.10.3) |
| `misc/hull_count.py` | Counts trails sharing the end masks of a saved beam trail (§4.10.3) |
| `misc/hull_bidir.py` | Budgeted exact linear-hull enumeration between two end masks (meet-in-the-middle; optional exact signs for random keys) (§4.10.5) |
| `misc/scan_endpairs.py` | Exact budgeted hull of the top-K end-mask pairs of a beam (§4.10.5) |
| `misc/test_signed_dp.py` | Validation of the signed hull of `hull_bidir.py` against `propagate()` (§4.10.5) |
| `misc/emp_check.py` | Empirical correlation of a saved beam trail against the real cipher, fixed key (§4.10.5) |
| `misc/beam_paths_bwd20.json`, `misc/beam_paths_fwd23.json` | Re-runs of the beam search (offset 20 backward, offset 23 forward, `--paths 15..22`), input of §4.10.5 |
| `misc/scan_R17.log` | Output of the R=17 end-pair scan (§4.10.5) |
| `misc/HULL_R15_R17.md` | Summary and reproduction commands of §4.10.5 |
| `misc/mysx_milp.py` | Differential MILP |
| `misc/mysx_linear_milp.py` | Previous approximate linear MILPs (historical, superseded by `mysx_linear_model.py`) |
| `misc/mysx_division_property.py` | Bit-based division-property MILP (v1; `--xor-rule` selects XOR or OR) |
| `misc/mysx_division_property_v2.py` | Bit-based division-property MILP (standard `(1,1)`-invalid XOR rule) |
| `misc/verify_division.py` | Empirical verification of integral distinguishers |
| `misc/keyschedule_test.js` | Basic key schedule audit |
| `misc/keyschedule_test_extended.js` | Exhaustive audit (22 tests) |
| `misc/check_trail.js` | Empirical differential trail at r=4 |
| `misc/check_linear_trail2.js` | Empirical check of the superseded linear model (negative result) |
| `misc/validate_lineal_harness.js` | Hand-computed linear harness check |
| `misc/mini.js` | Mini-MYSX (w=8, w=16, w=32) |
| `misc/check_mini.js` | Mini-MYSX validation vs `mysx.prod.js` |
| `misc/check_mini_nondegenerate.js` | Keyword/w compatibility check |
| `misc/mini_linear_fast.js` | Linear sampling at w=8, `kw='MYSZ'` |
| `misc/verify_trail_w32.js` | Per-trail verification at w=32 with MILP weight |
| `misc/avalanche.js` | Diffusion and avalanche ladder (r=1..24) |

Fixed seed in tests (`0xC0FFEE`). MILPs are deterministic given the
solver and `gapRel`. The mini-MYSX with `w=32` reproduces
`mysx.prod.js` exactly (F function and MYZ_PERM are bit-identical,
verified in `misc/check_mini.js`). The exact linear model's `selftest`
additionally verifies the Python port against `KNOWN_KAT_DIGEST` of
`mysx.prod.js`, so the linear results are stated relative to the
reference implementation.

**Beam search (§4.10).** The forward run is reproduced with
`python3 misc/mysx_linear_beam.py run --beam 2000 --jobs 8
--out beam_full.json`; the backward run with the same command plus
`--direction backward --out beam_bwd.json`. The combined table is
reproduced with
`python3 misc/mysx_linear_beam.py merge beam_full.json
beam_pairs47.json beam_bwd.json`. The search is deterministic given the
parameters (no randomness except a fixed seed inside the coset sampler
for cells with `rank(A_b) > 8`). `cmp` confirms that two independent
forward runs (`beam_full.json` and `beam_full_1.json`) are
byte-identical. The hull checks of §4.10.3 use the saved R=14 trails
with fixed keys (`random.Random(seed)` over 64 bytes, seed 1 and 2) and
are not part of the tool; their scripts are
`misc/verify_beam_trail.py` and `misc/hull_count.py`.

**Exact hull (§4.10.5).** From `misc/`:
`python3 test_signed_dp.py` (validation against `propagate()`);
`python3 hull_bidir.py beam_paths_bwd20.json 20 --R 16 --wmax 14 --keys 2`;
`python3 hull_bidir.py beam_paths_bwd20.json 20 --R 17 --wmax 18 --keys 2`;
`python3 hull_bidir.py beam_paths_fwd23.json 23 --R 16 --wmax 10 --keys 2`;
`python3 emp_check.py beam_paths_bwd20.json 20 16 28 1000` (about 12 min,
one CPU); `python3 scan_endpairs.py --R 17 --cells 20:backward,23:forward --topk 8`.
Keys are `rand_key(1000)`, `rand_key(1001)`, …

**Division-property results (`§4.9`).** All three input patterns
(single bit, word 0, words 0+4) were run with `--r0 0`. The
`(1,1)`-invalid XOR rule and the OR-conservative rule were checked to
agree on the tested patterns. Per-round balanced-bit counts are in
the terminal logs of the runs; the runtimes were 0.4 s to 4.8 ks with
SCIP. The R=10 single-bit dependency was verified against the real
cipher (20,000 random samples per bit). The R=6 word-0 integral was
verified against the real cipher at the last round (R=6, balanced
bits confirmed; R=7 saturated). The R=5 words-0,4 integral was not
verified empirically because its 2⁶⁴-text integral cannot be
approximated by 20,000 random samples.

# 12. Final warning

**MYSX has not been externally audited.** This paper is the author's
self-analysis, not a certification. No result here replaces an
independent cryptographic review.

**Do not use MYSX to protect real data.**
