# MYSX-256/512

Experimental block cipher with a 256-bit block and 512-bit key.
**Proprietary design, NOT externally audited, NOT for production use.**
For real data: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: `v0.1-draft` (2026)
License: MIT (see [LICENSE](LICENSE))

## Status

| Aspect | Status |
|---|---|
| Specification | [SPEC.md](SPEC.md), [PAPER.md](PAPER.md) §2 |
| Test vectors | [KAT.json](KAT.json) |
| Security analysis | [SECURITY.md](SECURITY.md), [PAPER.md](PAPER.md) §3–§5 |
| Differential cryptanalysis | Upper bounds observed (not a proof) |
| Linear cryptanalysis | No bound established |
| Related-key cryptanalysis | Heuristic coverage; security unknown |
| Integral / boomerang / algebraic | Not analyzed |
| External review | None |
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

## Repository structure

```
.
├── README.md
├── PAPER.md                     # Full paper (spec + analysis)
├── SPEC.md                      # Specification (identical to §2 of PAPER.md)
├── SECURITY.md                  # Standalone security summary
├── CHANGELOG.md                 # Changes between versions
├── LICENSE                      # MIT
├── KAT.json                     # Test vectors (block, AEAD, KDF)
├── generate_kat.py              # KAT generator
├── mysx.prod.js                 # Public API (AEAD, KDF, NonceGuard)
├── mysx.test.js                 # Functional test suite (16 tests)
├── mysx_milp.py                 # Differential MILP model
├── mysx_linear_milp.py          # Linear MILP model (three variants)
├── keyschedule_test.js          # Basic key schedule audit
├── keyschedule_test_extended.js # Exhaustive key schedule audit (22 tests)
├── check_trail.js               # Empirical differential trail at r=4
└── check_linear_trail2.js       # Empirical linear trail at r=3
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

```bash
# Functional tests (16 tests)
MYSX_ENABLE_TEST=1 node mysx.test.js

# Differential MILP (observed upper bounds)
python3 mysx_milp.py --rounds 1-14 --input-bit 0

# Linear MILP (three models; none verify empirically)
python3 mysx_linear_milp.py --rounds 1-10

# Key schedule audit (basic)
node keyschedule_test.js

# Key schedule audit (exhaustive, 22 tests)
node keyschedule_test_extended.js --thorough

# Empirical differential trail check
node check_trail.js

# Empirical linear trail check
node check_linear_trail2.js
```

## What this paper establishes

- An observed upper bound on the best single-trail differential weight
  for one input at r=12–14 (weight 114 at r=14, extrapolating to 128 at
  r≈15). **Not a proof of security.**
- A negative result on three linear-trail models. **No linear bound.**
- Heuristic related-key coverage up to weight-6. **No proof.**
- A clean specification, reproducible test vectors, and a functional
  test suite.

## What this paper does **not** establish

- No lower bounds on differential trail weights.
- No linear bound.
- No related-key bound.
- No integral, impossible-differential, boomerang, or algebraic
  analysis.
- No external review.
- No proof of post-quantum security beyond the trivial Grover bound.

## Citation

```
StringManolo. "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys
(v0.1-draft)". 2026. https://github.com/[user]/MYSX-256
```

## Final warning

**MYSX has not been externally audited.** Do not use it to protect real
data. For production: **AES-256-GCM** or **XChaCha20-Poly1305**.
