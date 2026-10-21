# MYSX-256/512

Experimental block cipher with a 256-bit block and 512-bit key.
**Proprietary design, NOT externally audited, NOT for production use.**
For real data: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: `v0.1-draft` (2026)

## Status

| Aspect | Status |
|---|---|
| Specification | [SPEC.md](SPEC.md), [PAPER.md](PAPER.md) §2 |
| Test vectors | [KAT.json](KAT.json) |
| Security analysis | [SECURITY.md](SECURITY.md), [PAPER.md](PAPER.md) §3–§5 |
| Differential cryptanalysis | Upper bounds observed; r=4 trail directly verified with clustering factor 2.00× |
| Linear cryptanalysis | Exact model of F established; `|corr|=1` chains verified up to 9 rounds; exact signed hulls match the real cipher at r=10–12; **no 128-round bound** |
| Related-key cryptanalysis | Heuristic coverage; security unknown |
| Integral / boomerang / algebraic | Not analyzed |
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
├── MYSX-paper.pdf               # Rendered paper
├── generate_kat.py              # KAT generator
├── mysx.prod.js                 # Public API (AEAD, KDF, NonceGuard)
├── mysx.test.js                 # Functional test suite (17 tests)
├── cryptanalysis/
│   └── models/
│       └── linear/
│           ├── mysx_linear_model.py   # EXACT linear model of F + round
│           ├── LINEAR_MODEL.md        # Detailed model documentation
│           └── linear_model_data.json # All numbers from PAPER.md §4 as JSON
└── misc/
    ├── mysx_milp.py                   # Differential MILP
    ├── mysx_linear_milp.py            # Previous approximate linear MILPs (superseded)
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
const {
  aeadEncrypt, aeadDecrypt, deriveAeadKeys, NonceGuard
} = require('./mysx.prod.js');

const master = crypto.getRandomValues(new Uint8Array(32));
const { encKey, macKey } = await deriveAeadKeys(master, { context: 'demo' });
const guard = new NonceGuard();

const plaintext = new TextEncoder().encode('hola mundo');
const packet = await aeadEncrypt(plaintext, encKey, macKey, { nonceGuard: guard });
const recovered = await aeadDecrypt(packet, encKey, macKey);
```

Notes on the public API:

- `aeadEncrypt` requires a `NonceGuard` or `unsafeNoGuard: true`.
  The nonce is always generated internally; there is no public path
  to impose it.
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
# Differential MILP (observed upper bounds)
python3 misc/mysx_milp.py --rounds 1-14 --input-bit 0

# Empirical differential trail check (r=4, clustering factor 2.00×)
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

The old approximate linear MILPs (`misc/mysx_linear_milp.py`, three
variants) are kept for historical reference but are **superseded**.
Their trails do not verify empirically because they used a per-cell
AND-activity proxy for F's correlation, which is incorrect. The exact
model is `cryptanalysis/models/linear/mysx_linear_model.py`.

### Related-key

```bash
# Key schedule audit (basic)
node misc/keyschedule_test.js

# Key schedule audit (exhaustive, 22 tests)
node misc/keyschedule_test_extended.js --thorough
```

## What this paper establishes

- **Observed upper bounds** on the best single-trail differential
  weight for one input at r=12–14 (weight 114 at r=14, extrapolating
  to 128 at r≈15). **Not a proof of security.**
- **Direct verification of the r=4 differential trail at w=32**: the
  trail exists with observed probability 2⁻⁷ vs MILP prediction 2⁻⁸,
  giving a clustering factor of **2.00×**.
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
- **Exact mask propagation with key-dependent sign tracking**: every
  trail carries its exact `(−1)^{Σ m_r·rk[r]}` factor. Free-chain
  structure: a round has weight 0 iff words 0..3 of its input mask are
  zero; the rotation schedule has period 31, so there are 31 distinct
  windows.
- **`|corr| = 1` single-bit linear relations over up to 9 consecutive
  rounds**, at windows `r ≡ 12 (mod 31)` and `r ≡ 27 (mod 31)`.
  Verified against the real cipher with three independent keys
  (magnitude = 1, sign predicted exactly by the model).
- **Exact signed linear hulls match the real cipher** at r=10, 11, 12
  (window r0=12) with |z| < 0.4 over 2²² plaintexts. Three independent
  predictions, three matches within sampling error.
- **Beam-search upper bounds on single-trail weight** from single-bit
  starts, up to r=14: weight 12 (window r0=12) and 11 (window r0=27)
  at r=14. Each value is an achievable weight, i.e. an upper bound on
  the best weight, not a minimum.
- **The linear sampling harness is validated**: the hand-computed
  `w=8` case gives |corr| = 0.5 with fixed key, drops to ~0 with
  random keys per sample. Confirms that the earlier "no signal"
  result was a model artifact, not a property of the cipher.
- **Heuristic related-key coverage** up to weight-6: no persistent
  `Δrk[r]=0`, no weak keys, no cycles, no fixed points.
- A clean specification, reproducible test vectors, and a functional
  test suite (17 tests).

## What this paper does **not** establish

- No lower bound on differential trail weights (requires gap=0 and
  multi-bit input search).
- No full differential clustering analysis (sum over all trails with
  the same Δin, Δout).
- **No linear bound over 128 rounds.** Beam values are upper bounds
  from single-bit starts only; multi-bit starts are unexplored; the
  exact hull at 128 rounds would need a SAT/MILP encoding (proposed in
  `cryptanalysis/models/linear/LINEAR_MODEL.md` §7, not implemented).
- No key-recovery cost estimate from any trail (differential or
  linear).
- No related-key bound (heuristic only).
- No integral, impossible-differential, boomerang, or algebraic
  analysis.
- No external review.
- No proof of post-quantum security beyond the trivial Grover bound.

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
  `|corr| = 1` chains reduce the effective "hard" round count to
  ~119 in the best window. This is a structural property of the
  rotation schedule, not a key-dependent artifact. It is **not** an
  attack on the full cipher (no lower bound over 128 rounds, no key
  recovery), but it is real cryptanalytic material. See PAPER.md §4
  and `cryptanalysis/models/linear/LINEAR_MODEL.md`.

## Citation

```
StringManolo. "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys
(v0.1-draft)". 2026. https://github.com/stringmanolo/MYSX-256
```

## Final warning

**MYSX has not been externally audited.** Do not use it to protect real
data. For production: **AES-256-GCM** or **XChaCha20-Poly1305**.
