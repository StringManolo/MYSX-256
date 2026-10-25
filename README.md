# MYSX-256/512

Experimental block cipher with a 256-bit block and 512-bit key.
**Proprietary design, NOT externally audited, NOT for production use.**
For real data: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: `v0.1-draft2` (2026) — documentation draft 2. The reference
implementation (`mysx.prod.js`) is still `v0.1-draft`; the cipher and
the code did not change. (An earlier revision of this text was labelled
`v0.2-draft`; that label is withdrawn because it suggested a change of
the cipher.)

## Status

| Aspect | Status |
|---|---|
| Specification | [SPEC.md](SPEC.md), [PAPER.md](PAPER.md) §2 |
| Test vectors | [KAT.json](KAT.json) |
| Security analysis | [SECURITY.md](SECURITY.md), [PAPER.md](PAPER.md) §3–§5 |
| Differential cryptanalysis | Offset sweep over all 31 rotation offsets (PAPER.md §3.5): the 128-bit threshold is at R≈24 for r0=10 (the best offset) versus R≈15 for r0=0 (one of the worst). At R=14 the best single-trail weight ranges from 2 (r0=10) to about 120 across offsets. **Probability-1 differential weight-0 chains**: 13 rounds at r0=10 (the exact maximum, verified by linear algebra over the 2¹²⁸ left-half differences and empirically with 100% propagation over 262,144 pairs × 8 keys) and 6 rounds at r0=15. The r=4 trail at r0=0 is directly verified with clustering factor 2.00× |
| Linear cryptanalysis | Exact model of F established; `|corr|=1` chains verified up to 9 rounds; exact signed hulls match the real cipher at r=10–12; beam search over the exact model **in both directions (forward + backward)**, merged over all 31 offsets and up to 128 rounds (achievable single-trail weight 2 at R=12, 5 at R=14, 38 at R=20, below 64 only up to R=22 with 63, a tie with the threshold; 2248 at R=128, offset 3 backward, a real trail inside the cipher). **Verified linear distinguisher on a 16-round window (rounds 98–113)**: the offset-20 backward trail is isolated in its hull at R=14 (weight 5, empirical correlation 2⁻⁵) and an exact budgeted hull extends it to R=16 (|corr| = 2⁻¹¹, two trails of weight 12 adding; one-key measurement within 1.9σ); it is seven weighted rounds plus a 9-round weight-0 chain, not an attack on the full cipher. At R=17 the best end pairs cancel within the enumerated budget. Other trails cancel or are ≈2× larger. **No 128-round bound** |
| Integral cryptanalysis | Offset sweep over all 31 rotation offsets (PAPER.md §4.9): 6-round (2³² texts) / 5-round (2⁶⁴ texts) distinguishers at r0=0; **extended to 10 rounds for both patterns at r0=15 (shift 16)**. The offsets r0=12 and r0=27 are not special for DP. The R=7/R=6 bits at r0=15 (12 and 15 balanced bits) are verified as consistent with a 2-text / 4-text toggle; the full 2³²/2⁶⁴ integrals were not verified. The 10-round single-bit dependency propagation is not an integral distinguisher. Practical strength at r0=15 is in the 7–8 round range |
| Related-key cryptanalysis | Heuristic coverage; security unknown |
| Impossible differential / boomerang / algebraic | Not analyzed |
| External review | None |
| Downstream implementation | [`mysx-256-cli`](https://github.com/stringmanolo/mysx-256-cli) (Rust, file encryptor) — verified against this `KAT.json`, not audited |
| Frozen | No — awaiting external review |

**`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`**

## Warning

**Do not use MYSX to protect real data.** It is a public proposal for
cryptanalysis, not a production primitive. It has not been externally
audited, and the paper explicitly documents the analyses that were not
performed.

## What MYSX is

- 256-bit block (8 × 32-bit words), 512-bit key (16 × 32-bit words).
- 128 rounds.
- SPN-like structure with four parallel Feistel cells over 32-bit word
  pairs, a Myszkowski byte transposition, and round-dependent word
  rotations.
- Simon's `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` as the only
  non-linearity (no S-boxes, no tables).
- ARX key schedule (bijective Feistel 8+8 update).
- Final whitening with 8 words derived from the key schedule.

## Downstream implementations

Implementations of MYSX-256/512 that are **not** part of this repository,
are **not** audited, and do **not** change the `CRYPTANALYSIS_STATUS` of
the cipher:

- [`mysx-256-cli`](https://github.com/stringmanolo/mysx-256-cli) — Rust
  command-line file encryptor. Streams chunks, authenticates header and
  each chunk, uses Argon2id or PBKDF2 for password derivation. Verified
  against `KAT.json` (16/16 vector groups) and `KNOWN_KAT_DIGEST`. Defines
  its own on-disk container format; this repository does not specify a
  file format.

## Repository structure

```
.
├── README.md
├── PAPER.md                     # Full paper (spec + analysis + mini-MYSX)
├── SPEC.md                      # Specification (identical to §2 of PAPER.md)
├── SECURITY.md                  # Standalone security summary
├── TODO.md                      # Open items
├── KAT.json                     # Test vectors (block, AEAD, KDF)
├── MYSX-paper.pdf               # Rendered paper (regenerate from PAPER.md)
├── generate_kat.py              # KAT generator
├── mysx.prod.js                 # Public API (AEAD, KDF, NonceGuard)
├── mysx.test.js                 # Functional test suite (17 tests)
├── diffResults/                 # Raw logs of the differential offset sweep (PAPER.md §3.5)
├── dpResults/                   # Raw logs of the integral offset sweep (PAPER.md §4.9)
├── dpResults_v2/                # Raw logs of the r0=15 saturation runs (PAPER.md §4.9)
├── cryptanalysis/
│   └── models/
│       └── linear/
│           ├── mysx_linear_model.py   # EXACT linear model of F + round
│           ├── LINEAR_MODEL.md        # Detailed model documentation
│           └── linear_model_data.json # Numbers from PAPER.md §4.1–§4.9 as JSON
└── misc/
    ├── mysx_linear_beam.py            # Beam search over the exact linear model, all offsets, up to 128 rounds, both directions (selftest, reproduce, run, merge)
    ├── beam_full.log                  # Output of the forward PAPER.md §4.10 run
    ├── beam_full.json                 # Same run: weights per round/offset, saved trails
    ├── beam_bwd.log                   # Output of the backward PAPER.md §4.10 run
    ├── beam_bwd.json                  # Same run: weights per round/offset, saved trails
    ├── beam_pairs47.json              # Output of the pairs47 multi-bit run (merged; not an improvement)
    ├── verify_beam_trail.py           # Prefix-by-prefix check of a saved trail vs the real cipher, both directions
    ├── hull_count.py                  # Counts trails sharing the end masks of a saved trail
    ├── hull_bidir.py                  # Budgeted exact hull between two end masks (meet-in-the-middle, exact signs)
    ├── scan_endpairs.py               # Exact budgeted hull of the top-K end-mask pairs of a beam
    ├── test_signed_dp.py              # Validation of hull_bidir.py against propagate()
    ├── emp_check.py                   # Empirical correlation of a saved beam trail vs the real cipher
    ├── beam_paths_bwd20.json          # Beam re-run, offset 20 backward, --paths 15..22 (input of hull_bidir.py)
    ├── beam_paths_fwd23.json          # Beam re-run, offset 23 forward, --paths 15..22
    ├── scan_R17.log                   # Output of the R=17 end-pair scan
    ├── HULL_R15_R17.md                # Summary and reproduction of the R=15-17 exact hulls
    ├── mysx_milp.py                   # Differential MILP (original, --r0 fixed at 0)
    ├── mysx_milp2.py                  # Differential MILP with --r0 (PAPER.md §3.5)
    ├── verify_diff_trail.py           # Empirical check of the 6-round deterministic trail at r0=15 (PAPER.md §3.5)
    ├── verify_diff_13r.py             # Empirical check of the 13-round deterministic trail at r0=10 (PAPER.md §3.5)
    ├── diff_free_chain_table.py       # Differential free chain table by offset (PAPER.md §3.5)
    ├── mysx_linear_milp.py            # Previous approximate linear MILPs (superseded)
    ├── mysx_division_property.py      # Bit-based division property MILP (v1)
    ├── mysx_division_property_v2.py   # Bit-based DP MILP, standard (1,1)-invalid XOR rule
    ├── verify_division.py             # Empirical verification of integral distinguishers
    ├── verify_division_double_toggle.py # Double-toggle check for bits 5:6 and 7:9 at r0=15 (PAPER.md §4.9)
    ├── keyschedule_test.js            # Basic key schedule audit
    ├── keyschedule_test_extended.js   # Exhaustive key schedule audit (22 tests)
    ├── check_trail.js                 # Empirical differential trail at r=4
    ├── check_linear_trail.js          # Empirical linear trail (superseded model)
    ├── check_linear_trail2.js         # Empirical linear trail (superseded model)
    ├── validate_diff_w32.js           # Differential verification at w=32
    ├── validate_lineal_harness.js     # Hand-computed linear harness check
    ├── verify_trail_w32.js            # Per-trail verification at w=32
    ├── avalanche.js                   # Diffusion / avalanche ladder (r=1..24)
    ├── avalanche.csv                  # Raw avalanche data
    ├── ddt_lat.js                     # DDT / LAT dumps
    ├── mini.js                        # Mini-MYSX (w=8, w=16, w=32)
    ├── mini_linear_fast.js            # Linear sampling at w=8, kw='MYSZ'
    ├── mini_linear_fixed.js           # Linear sampling with fixed keys
    ├── mini_trail.js                  # Trail sampler (historical)
    ├── check_mini.js                  # Mini-MYSX validation vs mysx.prod.js
    ├── check_mini_nondegenerate.js    # Keyword/w compatibility check
    └── lab.js                         # Scratch / experiments
```

## Usage (research only)

```javascript
const nodeCrypto = require('node:crypto');
const {
  aeadEncrypt, aeadDecrypt, deriveAeadKeys, NonceGuard
} = require('./mysx.prod.js');

(async () => {
  const master = nodeCrypto.randomBytes(32);   // Buffer is a Uint8Array
  const { encKey, macKey } = await deriveAeadKeys(master, { context: 'demo' });
  const guard = new NonceGuard();

  const plaintext = new TextEncoder().encode('hola mundo');
  const packet = await aeadEncrypt(plaintext, encKey, macKey, { nonceGuard: guard });
  const recovered = await aeadDecrypt(packet, encKey, macKey);
  console.log(new TextDecoder().decode(recovered));
})();
```

Notes on the public API:

- `aeadEncrypt` requires a `NonceGuard` or `unsafeNoGuard: true`.
  The nonce is always generated internally (16 random bytes); there is
  no public path to impose it. Because nonces are 128-bit random, an
  accidental `(key, nonce)` repeat is negligible; the guard mainly
  enforces the per-key message limit and catches a faulty RNG.
- Keys produced by `deriveAeadKeys*` come from HKDF-SHA256 over a
  256-bit PRK, so they carry at most 256 bits of entropy (see
  PAPER.md §6).
- The test API is disabled by default. Set `MYSX_ENABLE_TEST=1` in the
  process environment before `require('./mysx.prod.js')` to enable it.
- All public inputs are type-checked (`Uint8Array` with exact lengths).
- `MAX_PLAINTEXT_BYTES` is validated **before** allocating the CTR
  output buffer (aligned with `MAX_CT_BYTES`, 2³¹−1).

## KAT digests

Two digests are documented:

- **Public KAT.json digest** (target for third-party implementations):
  `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`
  SHA-256 over the full `KAT.json` (block + AEAD + KDF).
- **Internal regression digest** (`KNOWN_KAT_DIGEST` in `mysx.prod.js`):
  `3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`
  SHA-256 over 16 blocks with `key[i] = i`. A strict subset of the
  public KAT.

A third-party implementation should target the **public KAT.json
digest**.

## Reproducing the results

### Functional and structural

```bash
# Functional tests (17 tests)
MYSX_ENABLE_TEST=1 node mysx.test.js

# Diffusion / avalanche ladder (r = 1..24)
node misc/avalanche.js

# Mini-MYSX validation (F and permutation identical to mysx.prod.js)
node misc/check_mini.js

# Keyword / w compatibility (which keyword works at which word size)
node misc/check_mini_nondegenerate.js
```

### Differential

```bash
# Differential MILP (observed upper bounds at r0=0)
python3 misc/mysx_milp.py --rounds 1-14 --input-bit 0

# Offset sweep: 31 offsets at R=14 with the free-chain-optimal input
# (see diffResults/ for the full sweep)
python3 misc/mysx_milp2.py --rounds 14 --input-bit 63 --r0 10   # r0=10, w1b31, weight 2 (best)
python3 misc/mysx_milp2.py --rounds 14 --input-bit 94 --r0 0    # r0=0, weight 114

# Differential free chain table by offset (PAPER.md §3.5)
python3 misc/diff_free_chain_table.py

# Deterministic trail verification (100% propagation expected)
python3 misc/verify_diff_13r.py         # 13-round chain at r0=10, w1b31 -> w4b12
python3 misc/verify_diff_trail.py       # 6-round chain at r0=15, w2b30 -> w4b5

# Empirical differential trail check at r0=0 (r=4, clustering factor 2.00×)
node misc/check_trail.js

# Differential verification at w=32
node misc/validate_diff_w32.js
```

### Linear

```bash
# Exact linear model: self-check against the real cipher
python3 cryptanalysis/models/linear/mysx_linear_model.py selftest

# Regenerate LINEAR_MODEL.md and linear_model_data.json
python3 cryptanalysis/models/linear/mysx_linear_model.py report

# Linear harness validation (hand-computed case, expected |corr| = 0.5)
node misc/validate_lineal_harness.js

# Linear sampling at w=8 (kw='MYSZ', non-degenerate)
node misc/mini_linear_fast.js

# Per-trail verification at w=32 (exact model trail vs observed probability)
node misc/verify_trail_w32.js
```

#### Beam search to 128 rounds, all offsets, both directions (PAPER.md §4.10)

```bash
cd misc

# Validate the tool against the real cipher. In both directions:
# LAT of F, one round, 9-round chains, forward/backward edge duality,
# backward 9-round chains, backward R=14 trail is a valid forward trail.
python3 mysx_linear_beam.py selftest

# Reproduce the PAPER.md §4.5 table (r0=12 and r0=27, R<=14)
python3 mysx_linear_beam.py reproduce

# Forward run reported in PAPER.md §4.10 (~33 min with 8 processes)
python3 mysx_linear_beam.py run --beam 2000 --jobs 8 --paths 12,14,20,24,32,64,128 --out beam_full.json | tee beam_full.log

# Backward run reported in PAPER.md §4.10 (~25 min with 8 processes)
python3 mysx_linear_beam.py run --direction backward --beam 2000 --jobs 8 --paths 12,14,20,24,32,64,128 --out beam_bwd.json | tee beam_bwd.log

# Combined table (forward + backward, minimum over offsets and directions)
python3 mysx_linear_beam.py merge beam_full.json beam_pairs47.json beam_bwd.json

# Verified distinguisher on the 14-round window (rounds 100-113): offset-20
# backward trail, hull = 1 trail, empirical correlation ≈ ±0.0279
# (σ = 0.0028) vs predicted 0.0312
python3 verify_beam_trail.py beam_bwd.json 20 --R 14 --n 17
python3 hull_count.py beam_bwd.json 20 --R 14 --wmax 5

# Cancellation example (for comparison): r0=23 forward trail cancels from R=8
python3 verify_beam_trail.py beam_full.json 23 --R 14 --n 17
python3 hull_count.py beam_full.json 23 --R 14

# Exact budgeted hull at R=15-17 (PAPER.md §4.10.5; summary in HULL_R15_R17.md)
python3 test_signed_dp.py
python3 hull_bidir.py beam_paths_bwd20.json 20 --R 16 --wmax 14 --keys 2
python3 hull_bidir.py beam_paths_bwd20.json 20 --R 17 --wmax 18 --keys 2
python3 hull_bidir.py beam_paths_fwd23.json 23 --R 16 --wmax 10 --keys 2
python3 emp_check.py beam_paths_bwd20.json 20 16 28 1000      # ~12 min, 1 CPU
python3 scan_endpairs.py --R 17 --cells 20:backward,23:forward --topk 8

# Multi-bit starts (explored; did not improve on single-bit; see TODO.md)
python3 mysx_linear_beam.py run --offsets 12,23,24,25,26,27 --starts pairs47 --beam 2000 --paths 14,20,24 --out beam_pairs47.json
python3 mysx_linear_beam.py run --offsets 12,23,24,25,26,27 --starts rand:5000:4 --beam 2000 --paths 14,20,24 --out beam_rand.json
```

The tool needs only Python 3 (no dependencies). Its output values are
**achievable single-trail weights** (upper bounds on the best weight),
not correlations: see PAPER.md §4.10.3 for why, and for the offset-20
backward trail at R=14 that *is* a verified distinguisher of its
window.

The old approximate linear MILPs (`misc/mysx_linear_milp.py`, three
variants) are kept for historical reference but are **superseded**.
Their trails do not verify empirically because they used a per-cell
AND-activity proxy for F's correlation, which is incorrect. The exact
model is `cryptanalysis/models/linear/mysx_linear_model.py`.

### Integral (division property, preliminary)

```bash
# 32-bit active input (word 0) at r0=0: 6-round distinguisher, saturates at R=7
python3 misc/mysx_division_property_v2.py \
  --rounds 1-10 --active word0 --solver scip --stop-when-zero

# 64-bit active input (words 0 and 4) at r0=0: 5-round distinguisher, saturates at R=6
python3 misc/mysx_division_property_v2.py \
  --rounds 1-10 --active word0,word4 --solver scip --stop-when-zero

# Single active bit (word 0, bit 0): 10-round dependency propagation
# NOTE: with 2 texts this is NOT an integral distinguisher.
python3 misc/mysx_division_property_v2.py \
  --rounds 1-15 --active bit0 --solver scip --stop-when-zero

# Offset sweep: all 31 offsets at the saturation round of r0=0
# (see dpResults/ for the full sweep)
for r0 in $(seq 0 30); do
  python3 misc/mysx_division_property_v2.py \
    --rounds 6 --active word0 --r0 $r0 --solver scip > dp_w0_R6_r0${r0}.log 2>&1
done

# r0=15 extends the distinguishers to 10 rounds (PAPER.md §4.9)
# (see dpResults_v2/ for the saturation runs)
python3 misc/mysx_division_property_v2.py --rounds 11 --active word0 --r0 15 --solver scip
python3 misc/mysx_division_property_v2.py --rounds 11 --active word0,word4 --r0 15 --solver scip

# Empirical verification of the 6-round distinguisher (word 0 active) at r0=0
python3 misc/verify_division.py --rounds 6 --balanced-bits "<w:b,...>" --samples 20000

# Empirical verification of the r0=15 bits at R=7 (word0) and R=6 (word0,word4)
# (see dpResults_v2/balanced_bits_r015.txt for the bit lists)
python3 misc/verify_division.py --rounds 7 --r0 15 --balanced-bits "<12 bits>" --samples 20000
python3 misc/verify_division.py --rounds 6 --r0 15 --balanced-bits "<13 bits>" --samples 20000
python3 misc/verify_division_double_toggle.py     # the two remaining bits (5:6, 7:9)
```

Requirements: `pip install pulp` and one of `pyscipopt` (recommended,
`--solver scip`), `highspy` (`--solver highs`), or the bundled CBC
(`--solver cbc`, slower for R ≥ 5). Gurobi (`--solver gurobi`) is
size-limited in the free trial and does **not** fit R ≥ 5 for this
cipher. The `(1,1)`-invalid XOR rule implemented in
`mysx_division_property_v2.py` is the sound one; the naive
`k_c = k_a ⊕ k_b` rule overestimates balanced bits when the XOR
operands share variables (which they do in `F = C ⊕ D`).

### Related-key

```bash
# Key schedule audit (basic)
node misc/keyschedule_test.js

# Key schedule audit (exhaustive, 22 tests)
node misc/keyschedule_test_extended.js --thorough
```

## What this paper establishes

- **Observed upper bounds** on the best single-trail differential
  weight, **over all 31 rotation offsets** (PAPER.md §3.5): at R=14 the
  best weight ranges from 2 (r0=10) to about 120 (r0=1) across offsets;
  the 128-bit threshold is reached at R≈24 for r0=10 versus R≈15 for
  r0=0. **Not a proof of security.**
- **Probability-1 differential weight-0 chains**: 13 rounds at r0=10
  (the exact maximum, verified by linear algebra over the 2¹²⁸ left-half
  differences and empirically with 100% propagation over 262,144 pairs
  × 8 keys; the chain covers rounds 10–22, 41–53, 72–84, 103–115 of the
  cipher), 6 rounds at r0=15, 3 rounds at r0∈{0–6, 27–29}. These are
  the differential analogue of the linear weight-0 chains of §4.3.
- **Direct verification of the r=4 differential trail at w=32** (r0=0):
  the trail exists with observed probability 2⁻⁷ vs MILP prediction
  2⁻⁸, giving a clustering factor of **2.00×**.
- **Diffusion / avalanche ladder**: `r_dif = 15` (worst bit reaches
  all 256 output bits at r=15), `r_sac ≈ 22` (SAC matrix is
  indistinguishable from random with N=2000 at r≈22). Slow diffusion
  by design (12% of total rounds), comparable to ChaCha20's ratio.
- **Mini-MYSX with w=32 reproduces `mysx.prod.js` exactly**: F and
  MYZ_PERM are bit-identical (verified in `misc/check_mini.js`).
- **Exact LAT of F**: for output mask `b` and input mask `g`,
  `corr(b,g) = ±2^{−h(b)}` where `h(b) = rank(A_b)/2` and `A_b` is the
  adjacency matrix of a subgraph of the 32-cycle `j ↔ j−7`; the valid
  set of `g` and the sign are given in closed form. Machine-checked
  against brute-force LAT in `selftest`.
- **Exact mask propagation with key-dependent sign tracking**, in both
  directions: every trail carries its exact `(−1)^{Σ m_r·rk[r]}` factor.
  The `selftest` verifies that every forward edge is a backward edge
  with the same cost (325 edges checked), so the two searches enumerate
  the same set of trails. Free-chain structure: a round has weight 0
  iff words 0..3 of its input mask are zero; the rotation schedule has
  period 31, so there are 31 distinct windows.
- **`|corr| = 1` single-bit linear relations over up to 9 consecutive
  rounds**, at windows `r ≡ 12 (mod 31)` and `r ≡ 27 (mod 31)`.
  Verified against the real cipher with three independent keys
  (magnitude = 1, sign predicted exactly by the model). Found by both
  the forward and backward searches at the corresponding residues
  (20 and 4 mod 31).
- **Exact signed linear hulls match the real cipher** at r=10, 11, 12
  (window r0=12) with |z| < 0.4 over 2²² plaintexts. Three independent
  predictions, three matches within sampling error.
- **Beam search over the exact model, both directions, all 31 offsets,
  up to 128 rounds** (single-bit starts, beam 2000, merged): achievable
  single-trail weight **2 at R=12, 5 at R=14, 38 at R=20, 88 at R=24,
  204 at R=32, 361 at R=40, 485 at R=48, 630 at R=56, 786 at R=64,
  1081 at R=80, 1336 at R=96, 1671 at R=112, 2248 at R=128** (offset 3
  backward; a real trail inside the cipher, not a virtual extension).
  Weight below 64 (≈2¹²⁸ texts) only up to R=22 (weight 63, a **tie**
  with the threshold; "≈20–22" is the defensible reading), below 32
  only up to R=19. Between R=22 and R=112 the best weight grows by
  roughly 12–21 per round (the last step, 112→128, is ≈36 per round
  because only one offset fits a full 128-round trail). The cheapest
  trails alternate direction: among the tabulated R values, backward at
  R=9, 10, 12, 14, 18, 20, 24, 32, 40, 48, 96, 112, 128 and forward at
  R=16, 22, 56, 64, 80. The tool reproduces the earlier r0=12/27 table
  exactly and passes its own `selftest` in both directions.
- **Verified linear distinguisher on a 16-round window.** The offset-20
  backward trail at R=14 (weight 5, covering rounds 100..113) is
  **isolated in its hull** (`hull_count` returns exactly one trail at
  the minimum weight for every R from 1 to 14) and its empirical
  correlation on the real cipher matches the predicted 2⁻⁵ at every
  prefix (measured ±0.0279 vs predicted 0.0312, σ = 0.0028, no
  cancellation). An exact budgeted hull (`hull_bidir.py`, PAPER.md
  §4.10.5) extends it to R=15 (+2⁻⁷) and R=16 (rounds 98–113,
  +2⁻¹¹, two trails of weight 12 adding); a 2²⁸-sample measurement on
  one key gives 6.06×10⁻⁴ ± 6.1×10⁻⁵ against a prediction of
  4.88×10⁻⁴ (+1.9σ) and a single-trail value of 2.44×10⁻⁴ (+5.9σ).
  The trail is seven weighted rounds followed by a 9-round weight-0
  chain. This is the first non-trivial linear distinguisher the analysis
  certifies; it is a property of that window, not an attack on the
  128-round cipher.
- **R=17 cancellations.** The best end pairs of offset 20 backward (7
  of 8 computed) and offset 23 forward (8 of 8) give a hull of exactly 0
  within the enumerated budget, for both keys tested. The R=16 row of
  the PAPER.md §4.10.2 table (weight 8, offset 23 forward) is such a
  cancelling trail.
- **Hull effects measured and non-uniform**: across the trails checked,
  the real correlation of a beam trail was equal to its single-trail
  value (offset-20 backward at R=14; r0=12 forward up to R=12), about
  twice as large (r0=26, r0=27 forward), or exactly cancelled by a
  second trail of the same weight (r0=23 forward from R=8, r0=24
  forward). Single-trail weight is therefore not a *universal*
  distinguisher length, but it is not universally cancelled either.
- **The linear sampling harness is validated**: the hand-computed
  `w=8` case gives |corr| = 0.5 with fixed key, drops to ~0 with
  random keys per sample. Confirms that the earlier "no signal"
  result was a model artifact, not a property of the cipher.
- **Integral distinguishers (division property), offset sweep**: with
  standard `(1,1)`-invalid rules, at r0=0: 6 rounds (2³² texts, word 0
  active) and 5 rounds (2⁶⁴ texts, words 0,4 active). An offset sweep
  over all 31 rotation offsets (PAPER.md §4.9) shows the round count is
  offset-dependent: at **r0=15 (shift 16) the distinguishers extend to
  10 rounds for both patterns** (thin tail: 1 balanced bit at R=10, 0
  at R=11). The offsets r0=12 and r0=27 are not special for DP. The
  R=7/R=6 bits at r0=15 (12 and 15 balanced bits) were verified as
  consistent with a 2-text / 4-text toggle; the full 2³²/2⁶⁴ integrals
  were not verified. The 10-round single-bit dependency propagation is
  **not** an integral distinguisher (2 texts). Practical strength at
  r0=15 is in the 7–8 round range.
- **Heuristic related-key coverage** up to weight-6: no persistent
  `Δrk[r]=0`, no weak keys, no cycles, no fixed points.
- A clean specification, reproducible test vectors, and a functional
  test suite (17 tests).

## What this paper does **not** establish

- No lower bound on differential trail weights (requires gap=0 and
  multi-bit input search), and no differential inputs in the free
  windows. The rotation offset **was** varied over all 31 values
  (PAPER.md §3.5); the reported weights are upper bounds from a beam
  (or time-limited MILP), not proven minima. The exact maximum of
  weight-0 chains (13 rounds) **is** proven by linear algebra; the
  non-zero-weight tables are not.
- No full differential clustering analysis (sum over all trails with
  the same Δin, Δout), and in particular the clustering factor at
  r0 ≠ 0 has not been measured.
- **No linear bound over 128 rounds.** Beam values are upper bounds
  from single-bit starts only, with the 3 sparsest valid `g` per cell;
  the exact hull at 128 rounds would need a SAT/MILP encoding
  (proposed in `cryptanalysis/models/linear/LINEAR_MODEL.md` §7, not
  implemented). No lower bound over 128 rounds; no hull-aware bound
  beyond R=17, and hulls are exact only up to a weight budget.
- **No linear distinguisher length beyond R=16.** R=16 is established
  for the offset-20 backward trail (exact hull over trails of weight
  ≤ 14, plus a one-key measurement 1.9σ above the prediction; a run
  with a larger budget and more keys has not been done). At R=17 the
  best pairs cancel within the budget, which does not exclude a smaller
  correlation from heavier trails or other end pairs. R≥18 (weights
  ≥ 24) exceeds the enumeration caps and is undecided, including the
  weight-63 trail at R=22 that sits at the 2¹²⁸ threshold.
- **Multi-bit starts are not conclusive.** `pairs47` and `rand:5000:4`
  were explored and did **not** improve on single-bit starts at any R.
  `pairs47` covers a small structured subset; `rand:5000:4` covers 5000
  masks out of 2²⁵⁶, so it is not conclusive for structured multi-bit
  masks. The honest statement is "the multi-bit starts tested do not
  improve on single-bit", not "multi-bit starts do not help".
- **No integral bound beyond R=10.** All 31 rotation offsets were
  tested at the saturation rounds of r0=0; at r0=15 the distinguishers
  extend to 10 rounds. Full 2³²/2⁶⁴ integral verification at r0=15 has
  not been done (the toggle test is a necessary condition only); the
  R=8–10 tail is a model prediction. Full-block inputs (255 active
  bits), the three-subset division property and traceability-enhanced
  variants are not explored. The 5-round / 2⁶⁴-text distinguisher at
  r0=0 was not verified empirically.
- No key-recovery cost estimate from any trail (differential, linear,
  or integral).
- No related-key bound (heuristic only); the number of consecutive
  round keys needed to recover the master key was not measured.
- No impossible-differential, boomerang, or algebraic analysis.
- No external review.
- No proof of post-quantum security beyond the trivial Grover bound
  (2²⁵⁶ for a uniformly random 512-bit key, 2¹²⁸ for HKDF-derived keys).

## Design weaknesses acknowledged

- **Slow diffusion**: 15 rounds until the worst input bit reaches all
  output bits. This is longer than AES (~2 rounds) or ChaCha20
  (~4–5 rounds), but the ratio to total rounds (12%) is in line with
  established ciphers.
- **Myszkowski permutation is not cryptographically optimized**: it
  is a didactic choice. A structured permutation over the byte grid
  would strictly improve diffusion per round. See PAPER.md §2.3.1.
- **Key schedule has structural asymmetries**: bit 160 of the key is
  the slowest to diffuse in the subkeys (1-bit difference at r=1).
  Not exploitable with current techniques but worth noting. See
  PAPER.md §5.
- **Linear structure at short range is exact and verified**: 9-round
  `|corr| = 1` chains exist at windows 12 and 27, and cheap single
  trails (weight < 64) extend to about 22 rounds in the best
  direction (forward at R=22, weight 63; backward at R=24, weight 88).
  Beyond R≈20 the best single-trail weight grows by roughly 12–21 per
  round, so this is a short-range property of the rotation schedule and
  the diffusion, not an attack on the 128-round cipher (no lower bound
  over 128 rounds, no hull-aware bound beyond R=17, no key recovery).
  **However, the offset-20 backward trail is a verified distinguisher
  of its 16-round window (rounds 98–113)**: isolated in its hull at
  R=14, and with exact hull 2⁻¹¹ at R=16 confirmed empirically. An
  external reviewer should look here first. See PAPER.md §4 and
  `cryptanalysis/models/linear/LINEAR_MODEL.md`.
- **Position inside the cipher matters, and it is a schedule
  artifact**: the cost of a 14-round trail depends strongly on where it
  sits in the period-31 rotation schedule (backward offsets at R=14:
  weight 5 at offset 20, 17 at offset 0, 61 at offset 6; PAPER.md
  §4.10.2). The differential offset sweep (PAPER.md §3.5) shows this
  directly: at R=14 the best weight ranges from 2 (r0=10) to about 120
  (r0=1) across offsets, and the 128-bit threshold moves from R≈15
  (r0=0) to R≈24 (r0=10). This is a property of the rotation schedule
  combined with the 128 round count, not of F. Changing the round count
  or the rotation schedule moves the alignment. This is documented as
  a design decision, not hidden.
- **Integral distinguishers are offset-dependent**: 6 rounds with 2³²
  texts and 5 rounds with 2⁶⁴ texts at r0=0, extended to **10 rounds
  (both patterns) at r0=15** (shift 16). In relative coverage at
  r0=15 (7.8% of 128 rounds; 6.25% at the strongest meaningful round
  count R=8) this is stronger than Simon32/64 (14 rounds, 44% of its
  32 rounds, 31 active bits, Todo–Morii FSE 2016; 15 with three
  subsets), but in absolute rounds Simon reaches further. The R=8–10
  tail at r0=15 is a model prediction; full 2³²/2⁶⁴ integrals were
  not verified. See PAPER.md §4.9.

## Citation

```
StringManolo. "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys
(v0.1-draft2)". 2026. https://github.com/stringmanolo/MYSX-256
```

## Final warning

**MYSX has not been externally audited.** Do not use it to protect real
data. For production: **AES-256-GCM** or **XChaCha20-Poly1305**.
