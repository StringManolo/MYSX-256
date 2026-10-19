---
title: "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys (v0.1-draft)"
author: "StringManolo"
date: "2026"
abstract: |
  We present MYSX-256/512, a 256-bit block cipher with 512-bit keys and
  128 rounds. The design combines Feistel cells with Simon's round
  function, a Myszkowski byte transposition, word rotations, and an ARX
  key schedule. We provide the full specification, test vectors, and a
  self-analysis covering differential, linear, and related-key
  cryptanalysis. The differential analysis reports an observed upper
  bound on the best single-trail weight (114 at 14 rounds, extrapolating
  to the 128-round threshold at r≈15); this is not a proof of security
  and uses a Markov-independence assumption the design does not satisfy.
  The linear analysis attempted three models; none produced trails that
  verified empirically, so no linear bound is claimed. The key schedule
  was audited with 22 structural and empirical tests up to weight-6 with
  no persistent Δrk=0 pattern found. MYSX has not been externally
  audited. It is released as v0.1-draft for public review and must not
  be used to protect real data.
---

# 1. Introduction

MYSX-256/512 is an experimental block cipher. It is offered as a public
proposal for cryptanalysis, not as a production primitive. The author
makes no claim of security beyond the observed results reported here,
and explicitly welcomes external review.

## 1.1. Security objectives (and non-objectives)

**Model.** MYSX is analyzed in the single-key, chosen-plaintext model
for confidentiality, combined with an encrypt-then-MAC AEAD wrapper for
integrity. The design does not claim security under related-key,
chosen-ciphertext, or side-channel models; see Section 9.

**Claimed security level.** None formally. The paper reports observed
upper bounds on single-trail weights and negative results on three
linear-trail models. These are inputs to cryptanalysis, not proofs.

**Non-objectives.** MYSX does not claim:

- post-quantum security beyond the trivial Grover bound (2²⁵⁶ quantum
  iterations for a 512-bit key);
- resistance to related-key attacks beyond the heuristic coverage in
  Section 7;
- resistance to integral, impossible-differential, boomerang, or
  algebraic attacks (none analyzed);
- constant-time execution in JavaScript (side channels out of scope).

## 1.2. Design rationale

MYSX combines four building blocks:

- **Simon's F** `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`. Chosen
  for its proven diffusion/linear/ differential properties in Simon and
  its simplicity (no S-boxes, only AND/XOR/rotl). It does **not**
  inherit Simon's security proofs; the surrounding structure is
  different.
- **Feistel cells over 128-bit branches.** Four parallel Feistel cells
  per round, each acting on 32-bit word pairs.
- **Myszkowski transposition.** A fixed byte permutation derived from
  the keyword `MYSZKOWS`. The choice is aesthetic/didactic: it provides
  byte-level diffusion but no cryptographic argument beyond that. An
  optimized permutation would provide strictly better diffusion per
  round; see Section 9.
- **ARX key schedule.** A bijective Feistel 8+8 update with modular
  addition, XOR, and rotations. Chosen for simplicity and to avoid
  S-boxes; analyzed in Section 7.

The parameter choices (256-bit block, 512-bit key, 128 rounds) are not
derived from a formal argument. They were chosen to:

- provide a large block (avoid birthday-bound issues of 64-bit blocks);
- provide a large key (Grover leaves 256-bit security);
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
| MYSX-256/512 | 256 | 512 | 128 | Feistel cells + transposition | No |

MYSX's closest sibling is Simon. The differences (block size, branch
width, transposition, word rotations, non-linear key schedule) are
substantial enough that Simon cryptanalysis does not transfer directly
(see Section 8).

**Performance.** MYSX is estimated to run at a few MB/s in JavaScript,
versus hundreds of MB/s for AES-GCM via WebCrypto (AES-NI). MYSX is not
competitive on performance; it is a research primitive.

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

**Structural note.** MYSX is often described as a "2-branch Feistel" by
analogy with Simon. Strictly, each round applies four independent
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
We keep Myszkowski in v0.1 because it is frozen; a future version may
replace it.

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
for i = 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128]  (as 32 big-endian bytes)
```

## 2.7. Decryption

Inverse of encryption:

```
s[128] = ciphertext
for i = 0..7:
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

- `KAT.json` public digest: covers the full JSON (block + AEAD + KDF).
- `KNOWN_KAT_DIGEST` (internal): covers 16 blocks with `key[i] = i`,
  used as fast regression in `mysx.test.js`.

# 3. Differential cryptanalysis

## 3.1. Model

Tool: `mysx_milp.py` (PuLP + CBC/HiGHS). AND model: `a = Δx ∨ Δy`,
which **overestimates** the cost of an active AND (counts a cost-1
event whenever at least one input is active). This is a heuristic;
it is not a proof that the model represents all differential
transitions. Specifically:

- The Markov-independence assumption does not hold: the two rotated
  inputs of F come from the same word `x`.
- We ran a single input difference at r=12–14 (w2b30). Multi-bit input
  differences may yield lower weights.
- `gapRel=0.2` and `timeLimit=300` return feasible solutions (upper
  bounds), not certified optima.

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
inputs, nor that clustering does not lower the effective security.

## 3.3. Empirical check (r=4, w0b0)

N=2,000 samples; match rate 0.5–1.15% (prob ≈ 2⁻⁷). The model predicts
2⁻⁸ for this input; the factor-2 gap is consistent with differential
clustering. This is a sanity check, not a proof of the extrapolation.

## 3.4. What this section does **not** establish

- A lower bound on the best single-trail weight (requires gap=0 and
  multi-bit inputs).
- Resistance to differential clustering (requires modeling multiple
  trails with the same output difference).
- Resistance to related-key differentials.

# 4. Linear cryptanalysis

## 4.1. Three models, no bound

We tried three linear models. **None produced trails that verified
empirically.** The honest conclusion is that no linear bound is
established for MYSX.

### 4.1.1. Hybrid model (`act = α ∨ β ∨ γ`, no `γ ≥ α`)

This model produced growing weights (8 at r=3, 18 at r=4, 86 at r=6,
434 at r=10). Empirical verification at r=4 (weight 8, expected
correlation 2⁻⁸ = 0.0039) gave correlation −2.4×10⁻⁴ over 2,000,000
samples, at 0.53σ from zero. **The predicted trail does not exist.**

Diagnosis: the model allowed `(α,β,γ) = (1,0,0)`, which has correlation
0 in the real AND (not 1/2). The trails found were artifacts.

### 4.1.2. Strict model (`x = y = z = w` in XOR)

This model returned INFEASIBLE in all rounds 1–10 for mask w0b0. The
model is too restrictive: it forbids valid trails with correlation 1
(e.g., the trivial r=1 trail with weight 0).

### 4.1.3. Relaxed model with correct AND (`x+y+z-w=2u`, `γ = α OR β`)

Growing weights (8 at r=3, 18 at r=4, 86 at r=6, 434 at r=10).
Empirical verification at r=3 (weight 8) gave correlation −2.4×10⁻⁴
over 5,000,000 samples, at 0.53σ from zero. **The predicted trail does
not exist.**

Diagnosis: model artifact, or destructive clustering (multiple trails
with opposite signs cancelling). **We do not know which.** Either way,
the conclusion is the same: we have no verified linear trail, and
therefore no linear bound.

## 4.2. Why this matters

The best published attacks against Simon128/128 are linear (hull
attacks covering ~49/68 rounds, complexity ~2¹²⁷). The linear side is
therefore the most likely attack surface for MYSX. **A negative result
on three models is not a security claim.** It is an open question.

To establish a linear bound for MYSX, future work would need:

1. **Sign tracking** (±1/2 per active AND), which the current MILP does
   not model.
2. **Linear hull analysis** (clustering of many trails with the same
   mask).
3. **A SAT/MILP model with XOR correlations < 1**.

None of these is done here. **MYSX's linear security is unknown.**

# 5. Related-key cryptanalysis

Tool: `keyschedule_test.js` (basic) + `keyschedule_test_extended.js`
(22 tests). Coverage: exhaustive weight-1 (512 bits), exhaustive
weight-2 (130,816 pairs), weight-3 "same Δ" (1,680 trials), beam search
up to weight-6 (beam 50), 5 base keys, structured patterns, cycles,
weak keys.

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

# 6. Generic attacks

| Attack | Complexity | Verdict |
|---|---|---|
| Classical brute force | 2⁵¹² operations | Infeasible |
| Grover (quantum) | 2²⁵⁶ iterations | Infeasible with foreseeable technology |
| Block collisions (birthday) | 2¹²⁸ blocks | Infeasible |

**Note on Grover.** With a 512-bit key, Grover leaves 256 bits of
effective security. With 1,000,000 logical qubits at 1 ns/iteration,
the time would be ~10⁶⁰ years. This is a theoretical estimate; no
post-quantum analysis of the cipher beyond Grover has been done.

**Note on the 512-bit key.** HKDF-SHA256 produces at most a 256-bit
pseudorandom key. If the master secret has 256 bits of entropy, the
effective security is 256 bits, not 512. The "key size" of MYSX is not
the security level of the system.

# 7. Simon cryptanalysis: what transfers and what does not

MYSX uses Simon's `F`. It is **not** Simon. The differences:

- Block/branch size: 256-bit block with 128-bit branches (Simon uses
  `n`-bit branches).
- Four parallel `F` per round (Simon uses 1).
- Myszkowski byte transposition (Simon has none).
- Round-dependent word rotations (Simon has none).
- Non-linear ARX key schedule (Simon's is linear).
- 128 rounds vs 68.

**What transfers.** The linear and differential distinguishers on
Simon's `F` are properties of the function, not of the key schedule.
Any distinguisher on F may in principle be embedded in MYSX's structure.
The Simon-specific attacks on round-reduced Simon do not transfer
directly because the surrounding state, diffusion, and round count are
different, but the F-level biases are the natural starting point for
attacking MYSX.

**What does not transfer.** Key recovery from Simon's linear key
schedule does not transfer: MYSX's key schedule is non-linear.

**Relevant literature.**

- Kölbl, Leander, Tiessen, "Observations on the SIMON block cipher
  family", CRYPTO 2015.
- Biryukov, Roy, Velichkov, "Differential analysis of block ciphers
  SIMON and SPECK", CRYPTO 2015.
- Chen, Wang, "Improved linear hull cryptanalysis of round-reduced
  versions of SIMON", ePrint 2014/973.

None of these results is transferred to MYSX in this paper.

# 8. Analysis limitations

- **Differential**: upper bounds on single-trail for one input at
  r=12–14; no lower bounds; no clustering.
- **Linear**: no verified trail in three models; no bound.
- **Related-key**: heuristic tests up to weight-6; no targeted MILP.
- **Integral, impossible, boomerang, algebraic**: not analyzed.
- **No independent public cryptanalysis.**
- **Empirical verification**: consistent with the model at r=4
  (differential) and inconsistent at r=3–4 (linear).
- **Functional tests** (`mysx.test.js`, 16/16 PASS) cover round-trip,
  AEAD negatives, nonce policy, PBKDF2, avalanche. They do not prove
  security.

# 9. Engineering notes

## 9.1. API surface

- Production API: `aeadEncrypt`, `aeadDecrypt`, `deriveAeadKeys`,
  `deriveAeadKeysFromPassword`, `NonceGuard`.
- Test API: gated by environment variable `MYSX_ENABLE_TEST=1`. Not
  activatable from code (`globalThis`), only from the process
  environment.
- CTR (`_ctrXor`) is not exported from the production API.

## 9.2. NonceGuard

`NonceGuard` is a best-effort defense against nonce reuse. It:

- counts messages per key (default 2³²);
- detects recent nonce reuse (window of 1024 per key);
- **does not persist across restarts**;
- **does not share state across processes or devices**;
- caps the number of tracked keys (default 1024) to avoid unbounded
  memory growth;
- provides optional persistence callbacks (`onSave`, `onLoad`) for
  applications that need it.

**It is not a substitute for key lifecycle management.** If the
application reuses `(key, nonce)` across restarts, CTR confidentiality
is broken. See `mysx.prod.js` for the exact contract.

## 9.3. aeadEncrypt size validation

`aeadEncrypt` validates plaintext size **before** allocating the CTR
output buffer, and enforces a configurable `maxPlaintextBytes` limit
(default 2³²). Applications that require larger limits should raise
the limit explicitly and manage memory accordingly.

## 9.4. KAT digests

Two digests are documented in `README.md`:

- `KAT.json` public digest: SHA-256 over the full JSON (block + AEAD +
  KDF). This is the artifact that a third-party implementation should
  reproduce.
- `KNOWN_KAT_DIGEST` (internal): SHA-256 over 16 blocks with
  `key[i] = i`. Used as fast regression in `mysx.test.js`. It is
  strictly a subset of the public KAT, not a different KAT.

A third-party implementation should target the **public digest**; the
internal digest is only a self-check.

# 10. Verdict

**MYSX-256/512 v0.1-draft is an experimental proposal, not a secure
cipher.** The differential analysis reports upper bounds on single-trail
weights, not a security proof. The linear analysis is a negative result
on three models, not a bound. The related-key analysis is heuristic. No
integral, impossible-differential, boomerang, or algebraic analysis has
been done. The cipher has not been externally audited.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.

# 11. Reproducibility

| File | Purpose |
|---|---|
| `SPEC.md` | Formal specification |
| `PAPER.md` | This document |
| `KAT.json` | Test vectors (block, AEAD, KDF) |
| `generate_kat.py` | KAT generator |
| `mysx.prod.js` | Implementation (production API) |
| `mysx.test.js` | Functional tests |
| `mysx_milp.py` | Differential MILP |
| `mysx_linear_milp.py` | Linear MILP (three models) |
| `keyschedule_test.js` | Basic key schedule audit |
| `keyschedule_test_extended.js` | Exhaustive audit (22 tests) |
| `check_trail.js` | Empirical differential trail at r=4 |
| `check_linear_trail2.js` | Empirical linear trail at r=3 |

Fixed seed in tests (`0xC0FFEE`). MILPs are deterministic given the
solver and `gapRel`.

# 12. Final warning

**MYSX has not been externally audited.** This paper is the author's
self-analysis, not a certification. No result here replaces an
independent cryptographic review.

**Do not use MYSX to protect real data.**
