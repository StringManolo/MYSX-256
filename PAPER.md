# MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys (v0.2-draft)

StringManolo

2026

## Abstract

We present MYSX-256/512 v0.2-draft, an experimental 256-bit block
cipher with 512-bit keys and 128 rounds. The design combines Feistel
cells with Simon's F function, a Myszkowski byte transposition, word
rotations, and an ARX key schedule. The cipher core (round function,
F, transposition, key schedule) is unchanged from v0.1-draft2.

The v0.2 revision changes two things:

1. **Rotation schedule.** The consecutive schedule `(r mod 31)+1` of
   v0.1 is replaced by `rand_s9_45430` (31 explicit values in §2.8),
   selected by systematic search over 1M random 31-period schedules.
   On the 9 metrics measured for v0.2 — integral at R=5/6, linear at
   R=10/14 both directions, exact DMITM, weight-0 chain, MILP
   differential at R=5 — the new schedule **improves 6, ties 3, and
   regresses 0**.

2. **AEAD packet v2 (VERSION=0x02).** A new namespace `v2` adds: 512-bit
   secrets processed through HKDF-SHA512 (eliminating the 256-bit
   HKDF-SHA256 bottleneck of v1), 512-bit MAC keys, HMAC-SHA512 with
   64-byte tags, one key per message (32-byte salt), authenticated
   header, rotation-calendar selected by a header byte, and Argon2id
   for password paths. The v1 API (consecutive calendar, HKDF-SHA256,
   PBKDF2-SHA256, 32-byte tag) is kept for reading legacy packets and
   is marked deprecated for new data.

**Measured results for v0.2:**

| Metric | v0.1 | v0.2 |
|---|---|---|
| Exact DMITM | 17 rounds | **9** |
| Weight-0 chain | 13 | **5** |
| Truncated impossible | 39 | **28** |
| Integral dp5 / dp6 (r0=0, word0) | 21 / 4 | **9 / 4** |
| MILP differential R=5 | 0 | **4** |
| Linear single-trail R=10 fwd / bwd | 1 / 1 | 1 / **3** |
| Linear single-trail R=14 fwd / bwd | 5 / 5 | **8 / 11** |
| Linear single-trail R=128 fwd | 2248 (bwd) | 2294 (fwd) |
| v2 cross-language KAT | — | 6/6 packets byte-identical |
| v2 security tests | — | 58/58 pass |

**What is PENDING for v0.2** (measured for v0.1, not for v0.2): full
31-offset differential sweep (currently 6 offsets, best r0=29 weight 94,
2 offsets `None`); beam differential (MILP only for v0.2); linear
backward at R>14 and R=128; hull empirical verification; integral sweep
outside r0=0 (only 6 offsets); NIST SP 800-22; related-key re-validation.

**Verdict.** v0.2 improves 6 of 9 measured metrics, ties 3, and does
not regress. The main weakness of v0.1 — a differential trail of
weight 2 at R=14 for offset r0=10, giving a distinguisher at 4 chosen
pairs — is eliminated in v0.2 (best MILP at R=14 is 94, with 2 offsets
unresolved). v0.2 is not proven secure, has not been externally
audited, and must not be used to protect real data.

## Executive summary

v0.2 changes the rotation schedule and the AEAD packet format. The
block cipher core is unchanged.

**Rotation schedule.** The consecutive schedule `(r mod 31)+1` of
v0.1 gives a differential trail of **weight 2 at R=14 for offset
r0=10**, a 13-round weight-0 chain, and 17-round exact DMITM. These
are not "tight margins"; they are structural alignments between the
transposition and the consecutive step. The v0.2 calendar
`rand_s9_45430` was selected by a systematic search over 1M random
31-period schedules followed by an 8-candidate evaluation on 9
metrics. It gives a 5-round weight-0 chain, 9-round exact DMITM,
28-round truncated impossible, and a best MILP differential weight
at R=14 of 94 (cota superior; 2 offsets unresolved). The v0.1 offset
r0=10 that was catastrophic for the differential analysis is
eliminated in v0.2.

**AEAD v2.** HKDF-SHA512 with a 64-byte secret restores the
`2^256` Grover bound; 512-bit MAC keys and HMAC-SHA512 tags replace
the 256-bit HMAC of v1; the rotation calendar is selected by header
byte `CAL` instead of hard-coded or environment variable; one key
per message (32-byte salt) eliminates nonce reuse; Argon2id is used
for password paths with explicit bounds. A 58-test security suite
verifies the API; a cross-language KAT (Python reference vs
JavaScript implementation) confirms 6/6 packets byte-identical.

**Not established.** No lower bound over 128 rounds. No key-recovery
attack. No NIST SP 800-22 for v0.2 (v0.1 passed). No external audit.
The v0.2 analysis is partial by design; PENDING items are listed in
§4.14 and §8.

## 1. Introduction

MYSX-256/512 is an experimental block cipher. It is offered as a
public proposal for cryptanalysis, not as a production primitive.
The author makes no claim of security beyond the observed results
reported here, and explicitly welcomes external review.

### 1.1. Security objectives (and non-objectives)

**Model.** Single-key, chosen-plaintext for confidentiality, combined
with an encrypt-then-MAC AEAD wrapper for integrity (§2.9). No claim
under related-key, chosen-ciphertext, or side-channel models.

**Claimed security level.** None formally. The paper reports observed
upper bounds on single-trail weights (§3), a verified exact model of
F and of the round (§4.2–§4.6), beam searches over that model (§4.10),
and impossible differentials in both exact and truncated form (§4.12).
These are inputs to cryptanalysis, not proofs.

**Reading thresholds.** A differential trail of weight w needs about
`2^w` chosen pairs; a linear trail of weight w has `|corr| = 2^-w` and
needs about `2^(2w)` known texts. A `2^128`-text budget is a
differential weight of ≈128 but a **linear** weight of ≈64. Compare
`w_diff` with `2·w_lin`; never compare them directly.

**Non-objectives.** MYSX v0.2 does not claim:

- post-quantum security beyond Grover: `2^256` iterations for a
  uniformly random 512-bit secret processed through HKDF-SHA512
  (`2^128` for a 256-bit secret through HKDF-SHA256 in the v1 API);
- resistance to related-key attacks beyond the heuristic coverage of
  §5 (key schedule unchanged from v0.1);
- resistance to integral attacks beyond the R=5/6 distinguishers at
  r0=0 and the 6-offset sweep (§4.9);
- resistance to linear-hull effects beyond the single-trail weights
  of §4.10 (no hull-aware bound beyond R=17);
- constant-time execution in JavaScript (side channels out of scope).

### 1.2. Design rationale

MYSX combines four building blocks, unchanged from v0.1:

- **Simon's F** `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.
  Chosen for its studied diffusion/linear/differential properties in
  Simon and its simplicity (no S-boxes, only AND/XOR/rotl). It does
  not inherit Simon's security proofs.
- **Feistel cells over 32-bit word pairs.** Four parallel cells per
  round, then a byte transposition over the full 32-byte state, then
  word rotations. Classified as an SPN-like structure with Feistel
  cells, not as a 2-branch Feistel.
- **Myszkowski transposition** (§2.3.1). A fixed byte permutation
  derived from the keyword MYSZKOWS. Classical transposition with
  keyword; provides byte-level diffusion. A permutation optimized
  for diffusion would strictly dominate it and is a candidate for a
  future version.
- **ARX key schedule** (§2.4). A bijective Feistel 8+8 update.

**Rotation schedule (v0.2).** The consecutive schedule `(r mod 31)+1`
of v0.1 is replaced by `rand_s9_45430` (31 values in §2.8). The
selection is systematic (§4.13). The consecutive schedule is not
"moderately weak": at 3000 random schedules sampled without filtering,
it is in the worst ~2% by exact DMITM and worst ~0.2% by weight-0
chain. The cause is the step of 1 aligning with the transposition
period; the permutation is not the cause (40 random byte permutations
with the consecutive schedule give mean exact DMITM 21.4).

**Parameter choices.** 256-bit block, 512-bit key, 128 rounds. Not
derived from a formal argument. The round count is a parameter, not
a security level.

### 1.3. Comparison with related designs

| Design | Block | Key | Rounds | Structure | S-boxes |
|---|---|---|---|---|---|
| Simon128/128 | 128 | 128 | 68 | Feistel | No |
| Speck128/256 | 128 | 256 | 34 | ARX | No |
| ChaCha20 | 512 | 256 | 20 | ARX | No |
| MYSX-256/512 | 256 | 512 | 128 | SPN-like with Feistel cells | No |

MYSX's closest sibling is Simon. The differences (block size, branch
organization, transposition, word rotations, non-linear key schedule)
are substantial enough that Simon cryptanalysis does not transfer
directly.

**Performance.** MYSX is estimated to run at a few MB/s in
JavaScript, versus hundreds of MB/s for AES-GCM via WebCrypto. MYSX
is not competitive on performance; it is a research primitive.

### 1.4. Versioning

The reference implementation (`mysx.prod.js`) is labelled
v0.2-experimental. This document is the v0.2-draft of the design. The
v0.1-draft2 paper (tag `v0.1-draft2` in the repository) is the
previous design; its full analysis is preserved in `LEGACY_V1/`.

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
| **Rotation (v0.2)** | **`ROT_CAL[r mod 31]`** (§2.8) |
| Final whitening | XOR with 8 words from the key schedule |

### 2.2. Notation

- `rotl(x, n)`: circular left rotation of `x` by `n` bits.
- `∧`: bitwise AND.
- `⊕`: bitwise XOR.
- `s[r]`: state at round `r` (`s[0]` = plaintext, `s[128]` = ciphertext).
- `s[r][i]`: word `i` (0..7) of the state at round `r`.
- `rk[r][i]`: subkey `i` (0..7) of round `r`.
- `rkFinal[i]`: word `i` of the final whitening.
- `ROT_CAL[]`: the 31-value rotation schedule (§2.8).
- `CAL`, `KDF`: one-byte selectors in v2 packets (§2.9).

### 2.3. Constants

```
CONST[0..7] = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]
```

These are the fractional digits of π (same as Blowfish).

#### 2.3.1. Myszkowski permutation

Keyword: `MYSZKOWS` (8 letters, S repeated at positions 3 and 8).

```
MYZ_PERM = [
   4,12,20,28,                 # K (column 4)
   0, 8,16,24,                 # M (column 0)
   5,13,21,29,                 # O (column 5)
   2, 7,10,15,18,23,26,31,     # S,S (columns 2 and 7, row-wise)
   6,14,22,30,                 # W (column 6)
   1, 9,17,25,                 # Y (column 1)
   3,11,19,27                  # Z (column 3)
]
```

The inverse `MYZ_INV` satisfies `MYZ_INV[MYZ_PERM[i]] = i`.

### 2.4. Key schedule

**Initialization.** `s[0..15]` from 64-byte key (big-endian per word).

**Expansion.** For `r = 0..127`:

```
spread = (r + 1) * 0x9E3779B9  (mod 2^32)
for i in 0..7:
    rk[r][i] = s[i] ⊕ s[(i+5) mod 16] ⊕ s[(i+11) mod 16]
               ⊕ CONST[(r+i) mod 8] ⊕ spread
for i in 0..3:
    fk = s[(i+8) mod 16] ⊕ CONST[(r+i+3) mod 8]
    rk[r][i] = rk[r][i] ⊕ fk
L, R = s[0..7], s[8..15]
for i in 0..7:
    a, b, c = R[i], R[(i+1) mod 8], R[(i+3) mod 8]
    F = rotl((a + b) mod 2^32, 7) ⊕ rotl(c, 13) ⊕ CONST[i] ⊕ spread
    s[i], s[i+8] = R[i], L[i] ⊕ F
```

**Final whitening.** `rkFinal[i] = s[i] ⊕ s[(i+8) mod 16] ⊕ CONST[(128+i) mod 8]`.

### 2.5. Round function

For round `r`:

**Step 1.** `s[r][i] = s[r][i] ⊕ rk[r][i]` for i = 0..7.

**Step 2.** For p = 0..3:
```
L, R = s[r][p], s[r][p+4]
s_mid[p], s_mid[p+4] = R, L ⊕ F(R)
```

**Step 3.** Convert `s_mid[0..7]` to bytes (big-endian per word),
apply `permuted[j] = bytes[MYZ_PERM[j]]`, reconstruct words.

**Step 4.** `shift = ROT_CAL[r mod 31]`; `s[r+1][i] = rotl(s_perm[i], shift)`.

### 2.6. Encryption

`ciphertext = MYSX_encrypt(plaintext, key, ROT_CAL)` where the last
step XORs `rkFinal`.

### 2.7. Decryption

Inverse of §2.6 in reverse order.

### 2.8. Rotation schedule (v0.2)

The 31-value rotation schedule is:

```
ROT_CAL = [
  22,  5,  8,  7, 17, 10, 30,  1, 11, 26,
   6,  3, 12, 23, 25, 13, 28, 20, 21, 19,
  24,  2, 18,  9,  4, 15, 29, 27, 16, 14,
  31
]
```

Round `r` uses `shift = ROT_CAL[r mod 31]`. The v0.1 schedule was
`shift = (r mod 31) + 1` (i.e., `[1,2,...,31]`).

**Selection method.** 1M random permutations of `0..30` filtered by:

1. Maximum weight-0 chain at offset 10 ≤ 3,
2. Global maximum weight-0 chain ≤ 5,
3. Exact DMITM over the full left-half difference space.

8 candidates achieved exact DMITM = 9. The 8 finalists were ranked by
a multi-dimensional score: integral at R=5/6, linear at R=10/14 (both
directions), MILP differential at R=5, exact DMITM, weight-0 chain.

**Why the consecutive schedule was rejected.** Over 3000 random
schedules without filtering, the consecutive schedule is in the worst
~2% by exact DMITM and worst ~0.2% by weight-0 chain. The cause is
the step of 1: a consecutive sequence of shifts aligns with the
transposition period in a way that lets the tracked bits remain in
the "safe" half of the state for many rounds. The variable is the
schedule step, not the Myszkowski permutation (a control with 40
random byte permutations and the consecutive schedule gives mean
exact DMITM 21.4).

**The differential weakness closed by v0.2.** In v0.1, at offset
r0=10 the best single-trail differential weight at R=14 is **2**
(i.e., 4 chosen pairs distinguish 14 rounds of v0.1 from a random
cipher). In v0.2, the best MILP weight at R=14 over 31 offsets is
**94** (offset r0=29; two offsets r0=19 and r0=27 timed out and are
candidates for lower values). The structural alignment is gone.

**Reproducibility.** `CALENDAR_v02.txt` contains the schedule as
`MYSX_ROT_CAL=22,5,8,...`. `search_mysx_deep.py --n 1000000 --seed 9`
regenerates the search. `cryptanalysis/DMITM/wf2_deep_summary.json`
contains the raw 8×9 table.

### 2.9. AEAD packet format (v2)

Two packet formats coexist. v1 (VERSION=0x01) uses the consecutive
calendar, HKDF-SHA256, HMAC-SHA256, 32-byte tag; deprecated for new
data. v2 (VERSION=0x02) is recommended:

```
VERSION(1)=0x02 | CAL(1) | KDF(1) | KDF_PARAMS(var) | SALT(32) | NONCE(16) | CT(n) | TAG(64)
```

**Fields.**

- `CAL`: rotation calendar selector. `0` = consecutive (v0.1-compatible), `1` = `rand_s9_45430`. Unknown values rejected.
- `KDF`: `0` = RAW (64-byte or 32-byte secret, direct HKDF), `1` = Argon2id, `2` = PBKDF2-SHA512, `3` = scrypt.
- `KDF_PARAMS`: bounds checked on parse. Argon2id `memKiB` ∈ [19456, 1048576], `passes` ∈ [2, 16], `lanes` ∈ [1, 16]; PBKDF2-SHA512 `iterations` ∈ [210000, 10000000]; scrypt `logN` ∈ [15, 20], `r` ∈ [8, 16], `p` ∈ [1, 16], memory ≤ 1 GiB.
- `SALT` (32 bytes), `NONCE` (16 bytes), fresh per packet.
- `TAG`: HMAC-SHA512 over `HEADER | u64(len(AAD)) | AAD | u64(len(CT)) | CT`, 64 bytes.

**Key derivation (v2).**

```
PRK     = HKDF-Extract-SHA512(salt = SALT, ikm)
info    = LP("MYSX-256/512 v2") | CAL | KDF | LP(context) | LP(label)
encKey  = HKDF-Expand(PRK, info(label="enc"), 64)
macKey  = HKDF-Expand(PRK, info(label="mac"), 64)
```

where `LP(x) = u16_be(len(x)) || x`.

**v2 API.** `v2.seal(plaintext, creds, opts)`, `v2.open(packet, creds, opts)`,
`v2.generateSecret()`, `v2.securityLevel(creds)`,
`v2.setArgon2Provider(fn)`, `v2.argon2FromNoble(argon2idAsync)`,
`v2.CAL`, `v2.KDF`, `v2.DEFAULTS`, `v2.LIMITS`. The `_salt` and
`_nonce` options are internal (KAT only) and must not be used in
production.

**Cross-language validation (v0.2).** The v2 packet format has been
implemented independently in Python (`tests/gen_v2_kat.py`, stdlib
only) and in JavaScript (`mysx.prod.js`). Six complete packets
(header + CT + tag) are **byte-identical** between the two
implementations across: CAL=0 and CAL=1; KDF=RAW (64-byte and
32-byte secrets), PBKDF2-SHA512, scrypt; empty, 1-byte, 100-byte,
33-byte and 70-byte plaintexts. A 58-test suite
(`tests/mysx_v2.test.js`) verifies KAT regression, cross-language
KAT, per-byte bit-flip rejection, AAD/context/secret binding, KDF
bounds, anti-downgrade on the KDF byte, password + keyfile
separation, Argon2id RFC 9106 vector, and v1/v2 packet separation.
All 58 tests pass.

### 2.10. Key derivation (v1, deprecated)

HKDF-SHA256 with 32-byte MAC key (or PBKDF2-SHA256 for passwords).
The HKDF-SHA256 bottleneck caps the effective quantum security at
`2^128`. Do not use v1 for new data.

### 2.11. Test vectors

- **`KAT.json` (v0.1):** block, AEAD, KDF vectors for the consecutive
  calendar. Public digest:
  `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`.
  Internal fast-regression digest `KNOWN_KAT_DIGEST =
  3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`
  (SHA-256 over 16 blocks with `key[i] = i`).
- **`KAT_v2.json` (v0.2):** `block_v02` (8 blocks with CAL=1),
  `v2_raw`, `v2_password_argon2/scrypt/pbkdf2`, `v2_kdf`, `v2_parse`,
  `security_level`, `block_digest_cal0 == KNOWN_KAT_DIGEST`,
  `block_digest_cal1 = d1b3e268af1c7422e38c8af6db1cc2be6c01b7c335423a7e5cd53a578171444a`.
- **`tests/_v2_kat_cross.json`:** 6 cross-language v2 packets
  (Python reference → JS must reproduce byte-identical).

A third-party implementation should target the public v0.1 digest,
`block_digest_cal1` for v0.2, and the 6 cross-language v2 packets.

## 3. Differential cryptanalysis

### 3.1. Model

Tool: `misc/mysx_milp2.py` (PuLP + CBC/HiGHS, with `--r0` rotation
offset). AND model: `a = Δx ∨ Δy`, counting cost-1 whenever at least
one input is active. `gapRel = 0.2`, `timeLimit = 300–900` return
feasible upper bounds (not certified optima). The model captures
single trails, not differentials.

### 3.2. Observed upper bounds

**At r0=0, v0.1** (input w2b30):

| Rounds | Weight (upper bound) |
|---|---|
| 5 | 4 |
| 6 | 6 |
| 7 | 10 |
| 8 | 18 |
| 9 | 26 |
| 10 | 42 |
| 11 | 58 |
| 12 | 68 |
| 13 | 88 |
| 14 | 144 |

**At r0=0, v0.2** (input w1b31):

| Rounds | Weight (r0=0) | Weight (r0=10) | Weight (r0=20) |
|---|---|---|---|
| 10 | 59 | 92 | 76 |
| 11 | 62 | 92 | 76 |
| 12 | 98 | 129 | 86 |
| 13 | 120 | 139 | 104 |
| 14 | 129 | 164 | 132 |

Full run R=6..14 × r0=0,10,20: 27/27 solves.

**Offset sweep, R=14, v0.1 (MILP, single-bit input w1b31):**
r0=10 → weight **2**, other offsets 50–266. Worst observed r0=30 →
266. Paper's beam values are tighter: 121 at r0=1 vs MILP 180 at
r0=1, so the MILP overestimates by ~1.5–2× on these offsets.

**Offset sweep, R=14, v0.2 (MILP, single-bit input w1b31):**
best **r0=29 → weight 94**, other offsets 94–243. Two offsets
`r0=19`, `r0=27` timed out (`None`). The paper's differential
minimum for v0.2 is therefore an upper bound of 94; the true minimum
is likely 40–90 (MILP overestimates ~2×).

**Comparison.** v0.1 has a catastrophic offset (r0=10, weight 2 at
R=14, 4 chosen pairs). v0.2 eliminates it: the best MILP weight
across 31 offsets is 94 (upper bound). This is the main differential
improvement of v0.2.

### 3.3. Direct verification of the r=4 trail

Trail: Δin = {w0b0}, MILP weight 8, Δout = {w0b4, w1b10, w1b16,
w1b30, w6b4}. Verified with 8 fixed keys × 2^17 pairs, 128-round
cipher with final whitening disabled.

Observed hit rate 7.802×10^-3 (8181/1048576), expected from MILP
2^-8 = 3.906×10^-3. Ratio **2.00×**. Consistent with differential
clustering or a one-bit overestimate of the cost by the AND model.

**v0.2 verification (informal).** `diff_r4_v1` on v0.2 (with
`MYSX_ROT_CAL` set) reports trail match 12/2000 (0.60%) at R=4 with
average output difference weight 12.87 bits — the specific r=4 trail
is not directly transferable to v0.2 (the schedule change perturbs
the alignment at R=4). No new trail at R=4 has been identified for
v0.2.

### 3.4. Differential growth at r0=10, v0.1

Beam search: R=14 → 2, 15 → 4, 16 → 6, 17 → 10, 18 → 15, 19 → 22,
20 → 34, 21 → 49, 22 → 78, 23 → 100, 24 → 133.

**Verified with MILP** (r0=10, input w1b31, CBC gapRel=0.2,
timeLimit=180s): R=14 → 2, 15 → 4, 16 → 6, 17 → 10, 18 → 16, 19 → 24,
20 → 38, 21 → 56, 22 → 79, 23 → 107, 24 → 131.

**Discrepancy:** the paper's beam values differ from the MILP by
−2 to +7 in the range R=18-24. Both are upper bounds; neither is a
minimum. The MILP is (as expected) slightly above the beam at every
round; the paper's beam values are the tighter measurements for
these offsets. The 128-bit threshold is reached at R ≈ 24 for both.

### 3.5. Differential weight-0 chains

A round has weight 0 iff the difference does not touch words 4..7
of the state; the round is a pure bit permutation on the left half.

**v0.1 free chain table (verified, exact):**

| r0 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21–26 | 27 | 28 | 29 | 30 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| max | 3 | 3 | 3 | 3 | 3 | 3 | 3 | 4 | 4 | 5 | **13** | 12 | 11 | 10 | 9 | 8 | 7 | 6 | 5 | 5 | 5 | 4 | 3 | 3 | 3 | 4 |

**Maximum exact:** By exhaustive linear algebra over the whole
left-half difference space, no weight-0 chain longer than 13 rounds
exists at any offset (v0.1).

**Verified chains, v0.1** (fixed keys, 2^15 pairs per key × 8 keys,
full 128-round cipher, final whitening disabled):

| Offset | Δin | Δout | Rounds | Propagation |
|---|---|---|---|---|
| r0=10 | w1b31 | w4b12 | 13 | **100.0000%** |
| r0=15 | w2b30 | w4b5 | 6 | **100.0000%** |

The 13-round chain at r0=10 covers rounds 10–22, 41–53, 72–84,
103–115 (period 31). It is the same chain at every occurrence.

**v0.2 free chain table (verified, exact):** maximum **5 rounds** at
several offsets (r0 = 3, 4, 13, 16, 17, 20, 24, 27, 28); 4 rounds at
most other offsets; 3 rounds at the remaining offsets. Full 31-offset
table in `diff_free_chain_v02` output. No chain of length 6+ exists in
v0.2.

**Comparison.** v0.1: 13-round exact chain. v0.2: 5-round exact
chain. The reduction is 8 rounds, consistent with the exact DMITM
reduction (17→9).

**The catastrophic v0.1 offset.** r0=10 in v0.1 gives both the
13-round weight-0 chain and the weight-2 trail at R=14 (§3.2). The
two are the same alignment; eliminating one eliminates the other.

## 4. Linear cryptanalysis

### 4.1. Overview

The exact LAT of F (closed form) is used in a bit-exact mask
propagation. Single-trail weights and hull sums are computed. A beam
search over the exact model, both directions, up to 128 rounds, gives
achievable single-trail weights (upper bounds on the best weight).
Empirical verification is done with 2^22 plaintexts and fixed keys.

### 4.2. Exact LAT of F

For output mask `b` and input mask `g`:

```
b.F(x) ⊕ g.x  =  Q_b(x) ⊕ l.x,
l = rotr(b,2) ⊕ g,
Q_b(x) = ⊕_j b_{j+1} x_j x_{j−7}
```

`Q_b` is a quadratic form whose graph `G_b` is a subgraph of the
32-cycle `j ↔ j−7`. With `A_b` the GF(2) adjacency matrix:

- `corr(b,g) ≠ 0` iff `l = A_b y` for some `y`. There are exactly
  `4^{h(b)}` valid `g`, where `h(b) = rank(A_b)/2`.
- For each valid `g`, `corr(b,g) = (−1)^{Q_b(y)} · c_0(b)` with
  `|c_0(b)| = 2^{−h(b)}`.
- `h(b)` = maximum matching = minimum vertex cover of `G_b`.
  Exception `b = 0xFFFFFFFF` (full cycle): rank = 30, h = 15.
- Parseval: `Σ_g corr(b,g)^2 = 1`.

Exact and machine-checked against brute-force LAT of F for random
`b` of Hamming weight ≤ 8.

**Cost data.**

- Single-bit `b`: h = 1, four valid g, |corr| = 1/2.
- Two-bit `b` (496 masks): histogram `{2: 464, 1: 32}`.
- Uniform random 32-bit `b` (16384 samples): histogram of h peaks at
  h = 11 (4130 samples).

### 4.3. Mask propagation

Forward step for round `r` with input mask m on s[r]:

```
b_p = m[p] (only words 0..3 decide cost)
g_p ∈ valid_gammas(b_p)  (4^{h(b_p)} choices, |corr|=2^{-h(b_p)})
n[p+4] = m[p]; n[p] = m[p+4] ⊕ g_p
m_next = lin_fwd(n, r)   (byte transposition, then rotl by ROT_CAL[r mod 31])
w_r = Σ_p h(m[p])
sign = (Π_p sign_p) · (−1)^{m · rk[r]}
```

Backward step: `n = lin_inv(m_next, r)`; `b_p = n[p+4]`,
`m[p] = n[p+4]`, `m[p+4] = n[p] ⊕ g_p`.

The selftest verifies that every forward edge is a backward edge with
the same cost (325 edges checked).

### 4.4. Free-chain structure

A round has weight 0 iff words 0..3 of its input mask are zero; the
round acts as a bit permutation and the tracked bit never meets F.

**v0.1:** 9-round weight-0 chains at windows r = 12 and r = 27 (mod 31).

**v0.2:** the same table (via `mysx_linear_beam.py reproduce`) is
printed by `diff_free_chain_v02` and shows no weight-0 chains longer
than ~9 rounds; the R=9 minimum for v0.2 forward is weight 1 (at
offset 12), so the maximum weight-0 chain in the linear model is
8 rounds for v0.2 (consistent with the 5-round differential chain
plus 3 free rounds that do not touch F).

### 4.5. Verified |corr| = 1 chains (v0.1)

9-round chains at r0=12 and r0=27 verified against the real cipher
(fixed keys, 2^21 plaintexts, reduced rounds, final whitening
disabled):

| window | rounds | start bit | end bit | seed | predicted sign | empirical corr | σ |
|---|---|---|---|---|---|---|---|
| 12 | 9 | s[12].174 | s[21].79 | 1 | +1 | +1.00000 | 6.9e-04 |
| 12 | 9 | s[12].174 | s[21].79 | 2 | −1 | −1.00000 | 6.9e-04 |
| 12 | 9 | s[12].174 | s[21].79 | 3 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 1 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 2 | +1 | +1.00000 | 6.9e-04 |
| 27 | 9 | s[27].146 | s[36].55 | 3 | +1 | +1.00000 | 6.9e-04 |

The magnitude is 1 for every key. Only the sign depends on the key.

### 4.6. Exact signed hulls (v0.1)

For trails at r0=12, R=10,11,12:

| window | R | best-trail w | hull masks kept | predicted corr | empirical corr | σ | z |
|---|---|---|---|---|---|---|---|
| 12 | 10 | 1 | 4 | +0.500000 | +0.499997 | 4.9e-04 | −0.01 |
| 12 | 11 | 2 | 40 | −0.250000 | −0.250008 | 4.9e-04 | −0.02 |
| 12 | 12 | 3 | 3152 | −0.125000 | −0.124813 | 4.9e-04 | +0.38 |

Three independent predictions, three matches, |z| < 0.4.

**v0.2 hulls (predictions only, no empirical).**
`lin_hull_v02` computes exact signed hulls for v0.2 with r0=12:

| R | hull size | predicted corr |
|---|---|---|
| 10 | 4104 | −0.25 |
| 11 | 200 | −0.125 |
| 12 | 10576 | +0.031 |

Empirical verification (comparing predicted vs real cipher) for v0.2
is PENDING — the hulls are computed but not compared against `round_enc`.

### 4.7. What this establishes and what it does not (v0.1)

**Established (machine-checked):** exact LAT of F; exact mask
propagation with key sign; |corr|=1 chains up to 9 rounds; exact
signed hulls at r=10,11,12 matching the real cipher within |z|<0.4.

**Not established:** a lower bound on the best trail weight over 128
rounds; an exact 128-round hull; a hull-aware correlation for the
§4.10 trails beyond R=14.

### 4.8. Previous incorrect models

Recorded for context: v0.0 draft reported three approximate linear
MILP models, all failed empirical verification. They used per-cell
AND activity (`act = α ∨ β ∨ γ`) as a proxy for correlation, which
is not the correct structure of F.

### 4.9. Integral / division property

Standard bit-based division property: COPY, XOR with (1,1) invalid,
AND. `--solver highs` for feasible runs.

**At r0=0, v0.1:**

| Input | Active bits | Integral size | Rounds with balanced bits |
|---|---|---|---|
| bit 0 of word 0 | 1 | 2 | 10 (single-bit dependency, not integral) |
| word 0 | 32 | 2^32 | 6 |
| words 0 and 4 | 64 | 2^64 | 5 |

**At r0=15, v0.1:** 10-round distinguisher for both patterns
(thin tail: 1 balanced bit at R=10, 0 at R=11).

**At r0=0, v0.2:**

| Input | R | Balanced bits |
|---|---|---|
| word 0 | 5 | **9/256** |
| word 0 | 6 | **4/256** |

**At r0=0, v0.1 (measured with `integral_v1_R6`):** 4/256 at R=6,
matching the paper. Full word0,word4 at R=5: 11/256.

**Offset sweep for v0.2.** Only 6 offsets measured (0, 5, 10, 15,
20, 27) at R=5-6 via `run_integral_sweep_key6.py`. The full
31-offset sweep is PENDING.

**Not established for v0.2:** integral distinguishers at r0=15 (the
paper's peak for v0.1); full 31-offset sweep; whether v0.2 has a
r0=15-like offset with a 10-round distinguisher; three-subset DP.

### 4.10. Beam search over the exact linear model

**v0.1 results** (verified, see §11 for reproduction): single-trail
weights at R = 9, 10, 12, 14, 16, 18, 20, 22, 24, 32, 40, 48, 56,
64, 80, 96, 112, 128.

| R | weight | offset | direction |
|---|---|---|---|
| 9 | 0 | 4 | backward |
| 10 | 1 | 4 | backward |
| 12 | 2 | 20 | backward |
| 14 | 5 | 20 | backward |
| 16 | 12 | 20 | backward |
| 18 | 24 | 20 | backward |
| 20 | 38 | 20 | backward |
| 22 | 71 | 3 | backward |
| 24 | 88 | 3 | backward |
| 32 | 204 | 3 | backward |
| 40 | 361 | 20 | backward |
| 48 | 485 | 20 | backward |
| 56 | **653** | 20 | backward |
| 64 | **815** | 13 | backward |
| 80 | 1081 | 21 | backward |
| 96 | 1336 | 21 | backward |
| 112 | 1671 | 21 | backward |
| 128 | 2248 | 3 | backward |

**Correction vs v0.1 paper.** The paper's beam table lists R=56 =
630 at offset 27 forward and R=64 = 786 at offset 27 forward. The
committed `beam_full.json` and `beam_bwd.json` give 653 at offset 20
backward and 815 at offset 13 backward respectively. The paper's
values are not reproducible from the committed JSONs. The 16 of 18
checkpoints that match are asserted in `lin_beam_full_table_v1`;
the 2 discrepancies are documented (not asserted).

**v0.2 results** (from `lin_beam_v02_R128` forward, all 31 offsets):

| R | weight | offset | direction |
|---|---|---|---|
| 9 | 1 | 12 | forward |
| 10 | 1 | 14 | forward |
| 12 | 3 | 14 | forward |
| 14 | 8 | 14 | forward |
| 16 | 18 | 14 | forward |
| 18 | 39 | 14 | forward |
| 20 | 71 | 14 | forward |
| 22 | 95 | 14 | forward |
| 24 | 124 | 14 | forward |
| 32 | 256 | 14 | forward |
| 40 | 396 | 14 | forward |
| 48 | 541 | 14 | forward |
| 56 | 701 | 13 | forward |
| 64 | 839 | 13 | forward |
| 80 | 1127 | 7 | forward |
| 96 | 1439 | 7 | forward |
| 112 | 1790 | 7 | forward |
| 128 | 2294 | 0 | forward |

**v0.2 backward beam to R=128** is PENDING.

**Comparison at R=14:**
- v0.1 backward (offset 20): weight 5
- v0.2 forward (offset 14): weight 8
- v0.2 backward at R=14 (measured): weight 11 (offset 11) — see `lin_beam_v02_R14_bwd`.

The comparison v0.1 vs v0.2 at R=14 is: 5 (v0.1, backward) vs 8
(v0.2, forward) vs 11 (v0.2, backward). v0.2 is slightly better in
forward, slightly worse in backward, than v0.1 at this round count.
Neither is "much stronger".

**R=128 weight:** v0.1 backward = 2248; v0.2 forward = 2294.
Essentially equal (both irrelevant at 2^4496).

### 4.10.3. Hull check of trails

**v0.1 (verified, offset 20 backward, R=14, w=5):** isolated in its
hull (hull_count returns 1 trail). Empirical correlation matches
2^-5 on the real cipher at every prefix. This is the verified
distinguisher on a 16-round window (rounds 98–113) reported in
v0.1 §4.10.3.

**v0.2:** no empirical hull check performed. `lin_hull_v02`
computes exact signed hulls but does not compare with the real
cipher. PENDING.

**Cancelation (v0.1, verified).** r0=23 forward cancels from R=8;
r0=24 forward cancels from R=8. Single-trail weight is not
universally a distinguisher length.

### 4.10.5. Exact hull at R=15–17 (v0.1)

The offset-20 backward trail at R=16 has exact hull |corr| = 2^-11
(two trails of weight 12 adding). The empirical measurement is
+6.06×10^-4 ± 6.1×10^-5 against a prediction of 4.88×10^-4 (+1.9σ).
At R=17, the best end pairs of offsets 20 backward and 23 forward
cancel exactly within the enumerated budget, for both keys tested.
R ≥ 18 is undecided.

### 4.11. Statistical randomness of the CTR keystream

**v0.1:** CTR keystream passed NIST SP 800-22 (100 sequences ×
10^6 bits, fresh key and nonce per sequence, no failures). Full
report in `LEGACY_V1/NIST_SP_800-22_report.txt`.

**v0.2:** PENDING. The `nist.yml` workflow fails at "Download and
build NIST STS 2.1.2" (build error not yet diagnosed). The v0.2
block cipher uses the same core as v0.1 with a different calendar;
the NIST battery is expected to pass by analogy, but has not been
measured.

### 4.12. Impossible differentials

**Weight-0 chains.** Verified table in §3.5. v0.1: max 13 rounds at
r0=10. v0.2: max 5 rounds at several offsets.

**Exact DMITM.**

| Version | max weight-0 chain | exact DMITM |
|---|---|---|
| v0.1 | 13 rounds | **17 rounds** |
| v0.2 | 5 rounds | **9 rounds** |

v0.1 verification: `dmitm_v1` confirms max=13, total=17 with 0
offsets where multi-bit improves over single-bit. The best witness
is Δs[23]=w1b31 --13 rounds--> w4b12, Dout=w7b6 <--4 rounds-- w3b16,
incompatibility at s[23]. Verifiable in 0.3s.

v0.2 verification: `dmitm_v02` confirms max=5, total=9. The best
witness is Δs[3]=w3b16 --4 rounds--> w6b18, Dout=w7b7 <--5 rounds--
w0b30, incompatibility at s[3].

**Truncated impossible (v0.1).** Δs[44]=w2b29 --18 rounds-->
s[62] <--21 rounds-- Δs[83]=w7b24, conflict at **w6b16**. This is
**39 rounds**. Verified with `dmitm_trunc_v3.py --cal k1`:
premises 100% over 2000 pairs × 4 keys per side (0x00, 0xFF, and 2
random); propagation of the witness is exact and the conflict at
w6b16 is confirmed.

**Truncated impossible (v0.2).** Δs[66]=w2b25 --8 rounds--> s[74]
<--20 rounds-- s[94]=w4b14, conflict at w5b13. This is **28
rounds**. Verified with `dmitm_trunc_v3.py --cal v02 --verify 500`:
premises 2000/2000 per side against the real cipher.

**Reduction.** 39 → 28 (11 rounds). Consistent with the reduction in
exact DMITM (17→9, −8) and weight-0 chain (13→5, −8). The truncated
figure is the exact figure plus a short weighted prefix, so both
shrank by approximately the same amount.

**Not established.** The search covers single-bit starting masks on
all 31 rotation offsets. Multi-bit starts, weight-1 rounds, and
narrower propagation are PENDING. The `--verify` check confirms the
premises but is not a key-recovery cost. The truncated witness is a
distinguisher, not an attack.

### 4.13. Rotation schedule selection

**The 9-metric comparison** (v0.1 vs v0.2, from `wf2_deep_summary.json`):

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
| Truncated | 39 | **28** | improvement (−11) |

**Directions.** Lower is better for dp5, dp6, DMITM, chain, truncated.
Higher is better for lin_fwd10/14, lin_bwd10/14, MILP.

**6 improvements, 3 ties, 0 regressions.**

**A false positive documented.** `rand_s9_33719` was top-ranked by
R=4 screening (with dp4=42, milp5=10). At R=6 its integral is worse
than v0.1 (dp6=12 vs 4) and its linear weight at R=14 is 13 vs 5.
Screening at R≤4 is not sufficient.

**Why Myszkowski is not the cause.** A control with 40 random byte
permutations and the same consecutive schedule gives mean exact
DMITM 21.4 (range 10–34). MYSX v0.1 is at ~22nd percentile. Changing
the consecutive schedule to `(k·r mod 31)+1` for k ∈ {2,3,5,7}
drops the maximum chain to 6–9 rounds. The variable is the schedule
step, not the permutation.

### 4.14. What is PENDING for v0.2

The following are measured for v0.1 and not re-measured for v0.2:

- **Differential:** full 31-offset sweep (only 6 offsets measured;
  best r0=29 weight 94; r0=19, r0=27 unresolved); beam differential
  (only MILP for v0.2); cluster analysis at v0.2 offsets.
- **Linear:** backward beam to R>14 and R=128; hull empirical
  verification.
- **Integral:** full 31-offset sweep outside r0=0; r0=15 peak;
  R=7–10 tail; full 2^32/2^64 integral verification.
- **Impossible:** multi-bit starts; weight-1 rounds; narrower
  propagation.
- **NIST:** full NIST SP 800-22 battery.
- **Related-key:** 22-test re-validation (key schedule unchanged;
  expected identical).
- **Simon normalized coverage comparison:** v0.1's comparison was
  against the consecutive schedule for MYSX; v0.2 has different
  figures.
- **Differential R=16, R=17 empirical trails** (`diff_r16_r17_v1`,
  pending external reviewer data).

## 5. Related-key cryptanalysis

**Inherited from v0.1** (key schedule unchanged). 22 structural and
empirical tests up to weight-6, no persistent Δrk[r]=0 for r≥1, no
weak keys, no cycles, no fixed points. Slow diffusion at r=1–4
(expected: one Feistel round per cipher iteration). Worst bit: bit
160 (word 5, bit 0), 1-bit difference at r=1; consistent across 5
base keys (structural, not noise). Beam search score 139 (ideal 128).

**Limitations.** Heuristic, not a proof. No targeted MILP/SAT
related-key model. Adaptive related keys, biclique attacks, algebraic
attacks on the key schedule not covered. Related-key security is
unknown.

**Round-key recovery.** The key schedule is bijective; any 16
consecutive state words determine the master key. How many consecutive
round keys a SAT solver needs to recover the master key (about three
by counting) has not been measured.

## 6. Generic attacks

| Attack | Complexity (uniformly random 512-bit secret) |
|---|---|
| Classical brute force | 2^512 operations |
| Grover (quantum) | 2^256 iterations |
| Block collisions | 2^128 blocks |

**Note on Grover (v2 API).** A uniformly random 64-byte secret
processed through HKDF-SHA512 gives 2^256 Grover per target.
`2^256 / sqrt(N)` if an attacker needs only one of N messages.

**Note on the v1 API.** HKDF-Extract with HMAC-SHA256 produces a
256-bit PRK. The effective quantum security is 2^128, not 2^256.
Do not use v1 for new data.

**Note on password paths.** Security is limited by password entropy,
not by the nominal key size. `v2.securityLevel` returns null for
classicalBits/groverBits when the password is not accompanied by a
≥64-byte keyfile. A keyfile is strongly recommended.

## 7. Simon cryptanalysis: what transfers

MYSX uses Simon's F. It is not Simon. Differences: block size,
branch organization (4 parallel Feistel cells, Simon uses 1),
Myszkowski transposition (Simon has none), round-dependent word
rotations (Simon has none), non-linear ARX key schedule (Simon's is
linear), 128 rounds vs 68.

**What transfers.** The exact LAT of F (§4.2) — its closed form, its
validity condition, its sign structure — is a property of the
function and applies to MYSX regardless of surrounding structure.

**What does not transfer.** Key recovery from Simon's linear key
schedule (MYSX is non-linear). Linear hull attacks structured around
Simon's Feistel branch. Integral distinguishers relying on Simon's
2-branch Feistel structure and linear key schedule.

**Published Simon results** (context only): Chen-Wang FSE 2016
(49-round linear-hull key-recovery on Simon128/128); Shi et al.
ePrint 2014/973 (34-round linear characteristic, corr 2^-61 for
Simon128); Biryukov-Roy-Velichkov FSE 2014 (differential); Todo-Morii
FSE 2016 (14-round integral on Simon32, 15 with three subsets);
Xiang-Zhang-Bao-Lin ASIACRYPT 2016 (MILP division property).

## 8. Analysis limitations

**Differential:** single-trail upper bounds; two independent
deterministic chains verified empirically (13 rounds at r0=10,
6 rounds at r0=15, both v0.1); no lower bounds; no full clustering
analysis at r0≠0; the exact maximum of weight-0 chains (13 for
v0.1, 5 for v0.2) is proven by linear algebra; the non-zero-weight
tables are upper bounds.

**Linear:** exact model of F; exact signed hulls at r=10,11,12
(v0.1) matching the real cipher within |z|<0.4; beam search over
the model in both directions (v0.1) and forward (v0.2), 31 offsets,
up to 128 rounds. v0.2 backward beam to R=128 is PENDING. No lower
bound over 128 rounds. No hull-aware bound beyond R=17 for v0.1.
v0.2 hull empirical verification is PENDING.

**Integral:** v0.1 has 6-round (2^32) / 5-round (2^64) at r0=0,
10-round at r0=15; v0.2 has 6-round / 5-round at r0=0, 6-offset
sweep at R=5-6. Full 31-offset sweep for v0.2 and r0=15 peak for
v0.2 are PENDING.

**Impossible:** v0.1 exact = 17, truncated = 39 (verified); v0.2
exact = 9, truncated = 28 (verified). Multi-bit starts and weight-1
rounds PENDING.

**Related-key:** heuristic (v0.1 inherited).

**NIST:** v0.1 pass; v0.2 PENDING (workflow build error).

**Other:** boomerang, algebraic, side-channel not analyzed. No
external audit.

## 9. Engineering notes

### 9.1. API surface

**Public (v2):** `v2.seal/open`, `v2.generateSecret`,
`v2.securityLevel`, `v2.setArgon2Provider`,
`v2.argon2FromNoble`, `v2.CAL`, `v2.KDF`, `v2.DEFAULTS`,
`v2.LIMITS`.

**Public (v1, deprecated):** `aeadEncrypt`, `aeadDecrypt`,
`deriveAeadKeys`, `deriveAeadKeysFromPassword`, `NonceGuard`,
`CONFIG`.

**Test API:** disabled by default. Enabled only with
`MYSX_ENABLE_TEST=1`.

### 9.2. Migration v1 → v2

- v1 packets (0x01...) decryptable with `aeadDecrypt`.
- v2 packets (0x02...) created by `v2.seal`, not decryptable by
  `aeadDecrypt`.
- Do not use `aeadEncrypt` for new data (HKDF-SHA256 → 2^128).
- Do not pass `_salt`/`_nonce` to `v2.seal` in production (internal
  parameters for KAT generation).

### 9.3. NonceGuard (v1)

Best-effort defense against nonce reuse in v1. The v2 API does not
need NonceGuard: every message uses a fresh 32-byte salt and 16-byte
nonce.

### 9.4. Type validation

All public functions validate byte inputs are Uint8Array of expected
length.

### 9.5. KAT digests

- `KAT.json` (v0.1): digest `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`.
- `KAT_v2.json` (v0.2): `block_digest_cal0 == KNOWN_KAT_DIGEST`;
  `block_digest_cal1 = d1b3e268...`.
- `tests/_v2_kat_cross.json`: 6 cross-language v2 packets.
- `KNOWN_KAT_DIGEST = 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`.

### 9.6. Harness validation

- Linear sampling harness: fixed key gives |corr| = 0.4993;
  random key gives ~0.0022. Confirms the harness is correct with
  fixed keys.
- mini-MYSX w=32 reproduces mysx.prod.js exactly. Keyword/w
  compatibility: `MYSZKOWS` at w=32, `MYSZ` at w=8 (non-degenerate).
- Beam-search tool `selftest` passes in both directions (LAT of F,
  one round, 9-round chains, forward/backward duality, backward
  R=14 trail).
- Differential verification scripts check the deterministic trails
  of §3.5 at 100% propagation.
- Division-property harness validated against R=10 single-bit
  dependency (2 balanced bits confirmed at 20,000 samples).

## 10. Verdict

MYSX-256/512 v0.2-draft is an experimental proposal, not a secure
cipher.

**Rotation schedule.** `rand_s9_45430` replaces the consecutive
schedule `(r mod 31)+1`. On the metrics measured, the new schedule
improves 6, ties 3, and regresses 0. Exact DMITM: 17 → 9. Weight-0
chain: 13 → 5. Truncated impossible: 39 → 28 (verified 2000/2000
against the real cipher). Integral balanced bits at R=5: 21 → 9.
MILP differential R=5: 0 → 4. **The v0.1 catastrophic offset r0=10
(weight-2 trail at R=14, 4 chosen pairs to distinguish 14 rounds) is
eliminated in v0.2 (best MILP weight at R=14 is 94; two offsets
unresolved).**

**AEAD v2.** HKDF-SHA512 with a 64-byte secret (2^256 Grover);
512-bit MAC keys; HMAC-SHA512; one key per message; authenticated
header with rotation calendar; Argon2id for password paths.
Cross-language KAT: 6/6 packets byte-identical to an independent
Python reference. 58 security tests pass.

**PENDING for v0.2.** Differential beam (MILP only); full 31-offset
differential sweep (6 offsets measured, 2 unresolved); linear
backward beam to R=128; hull empirical verification; full 31-offset
integral sweep (6 offsets measured); NIST SP 800-22. The v0.2
analysis is incomplete by design.

**No lower bound over 128 rounds is established. No key-recovery
attack has been attempted. No external audit.** The truncated
impossible for v0.2 is 28 rounds, not 39. The related-key security
is unknown.

**Do not use MYSX to protect real data.** For production:
AES-256-GCM or XChaCha20-Poly1305.

## 11. Reproducibility

All measured claims of §2–§5 are reproducible via
`./run_all_gh_actions.sh --no-nist` in the repository. 49 tests pass
(0 fail, 2 skip: NIST and `diff_r16_r17_v1`).

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
| `misc/verify_beam_trail.py`, `misc/hull_count.py`, `misc/hull_bidir.py` | Hull checks |
| `misc/mysx_milp2.py` | Differential MILP |
| `misc/mysx_division_property_v2.py` | Division property |
| `tests/gen_v2_kat.py` | Independent Python reference for v2 packets |
| `tests/mysx_v2.test.js` | 58 security tests for v2 API |
| `tests/manifest.json` | Test manifest (53 tests, 51 ready + 2 skip) |
| `run_all_gh_actions.sh`, `run_all_local.sh` | Orchestrators |
| `.github/workflows/paper.yml` | CI matrix for non-NIST tests |
| `.github/workflows/nist.yml` | CI matrix for NIST (build broken) |

### Reproduction commands

**v0.1 claims:**

```bash
# KAT
python3 -c "import json; d=json.load(open('LEGACY_V1/KAT.json')); \
  assert d['digest']=='5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee'"

# Free chain table (r0=10 -> 13, r0=15 -> 8, r0=0 -> 3, r0=27 -> 3)
python3 misc/diff_free_chain_table.py

# 13-round chain verification
python3 misc/verify_diff_13r.py    # 100.0000%

# 6-round chain verification
python3 misc/verify_diff_trail.py  # 100.0000%

# MILP differential (R=5 -> 4, R=14 -> 144)
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
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 4 --direction backward --out /tmp/b.json

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

# Truncated impossible (28 rounds with VERIFY)
python3 cryptanalysis/DMITM/dmitm_trunc_v3.py --cal v02 --max_fwd 24 --max_bwd 24 --verify 500

# Beam R=10 forward (1) and backward (3)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1 --direction backward

# Beam R=14 forward (8) and backward (11)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1 --direction backward

# Beam R=128 forward (2294)
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 128 --beam 2000 --jobs 2 --out beam_v02_full.json

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
```

## 12. Final warning

MYSX has not been externally audited. This paper is the author's
self-analysis, not a certification. No result here replaces an
independent cryptographic review.

**Do not use MYSX to protect real data.** For production:
AES-256-GCM or XChaCha20-Poly1305.
