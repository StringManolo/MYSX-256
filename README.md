# MYSX-256/512

Experimental block cipher with a 256-bit block and a 512-bit key.
**Proprietary design, NOT externally audited, NOT for production use.**
For real data: AES-256-GCM or XChaCha20-Poly1305.

Author: StringManolo
Version: **`v0.2-draft`** (2026) — current draft.
The previous version `v0.1-draft2` is preserved in
[`LEGACY_V1/`](LEGACY_V1/) as a frozen reference. See
[`LEGACY_V1/README.md`](LEGACY_V1/README.md) for the v0.1 documentation
and the full v0.1 analysis.

## Status

**`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`**

| Aspect | Status |
|---|---|
| Specification | [`PAPER.md`](PAPER.md) §2 |
| Test vectors (v0.2) | [`KAT_v2.json`](KAT_v2.json) |
| Test vectors (v0.1, reference) | [`LEGACY_V1/KAT.json`](LEGACY_V1/KAT.json) |
| Paper (v0.2-draft) | [`PAPER.md`](PAPER.md) |
| Paper (v0.1-draft2, reference) | [`LEGACY_V1/PAPER.md`](LEGACY_V1/PAPER.md) |
| Calendar selection | [`calendar/CALENDAR_v02.txt`](calendar/CALENDAR_v02.txt), PAPER.md §2.8, §4.13 |
| Rotation schedule (v0.2) | `rand_s9_45430`, 31 explicit values in PAPER.md §2.8 |
| Rotation schedule (v0.1) | Consecutive `(r mod 31)+1` (deprecated) |
| Differential (v0.2) | **PENDING** beyond R=5. Only MILP R=5 = 4 measured (vs 0 for v0.1) |
| Linear (v0.2) | Partial. Beam R=10, R=14 both directions measured (§4.12); R>14 **PENDING** |
| Integral (v0.2) | Partial. DP R=5 = 9, R=6 = 4 at r0=0 (vs 21, 4 for v0.1). 31-offset sweep **PENDING** |
| Impossible differential (v0.2) | Exact DMITM = 9 rounds (vs 17 for v0.1). Truncated figure **PENDING** |
| Differential, linear, integral (v0.1) | Fully analyzed in [`LEGACY_V1/PAPER.md`](LEGACY_V1/PAPER.md) §3–§5 |
| Related-key | Heuristic (v0.1 inherited, key schedule unchanged); security unknown |
| Boomerang / algebraic | Not analyzed |
| External review | None |
| Downstream implementation | [`mysx-256-cli`](https://github.com/stringmanolo/mysx-256-cli) (Rust) — verified against **v0.1** `KAT.json`, not audited, not v0.2 |
| Frozen | No — awaiting external review |

## What's new in v0.2

Two changes from v0.1-draft2. Everything else (round function, F,
Myszkowski transposition, ARX key schedule) is identical.

### 1. Rotation schedule

The consecutive schedule `(r mod 31)+1` of v0.1 is replaced by
`rand_s9_45430`, a 31-value permutation:

```
22, 5, 8, 7, 17, 10, 30, 1, 11, 26, 6, 3, 12, 23, 25,
13, 28, 20, 21, 19, 24, 2, 18, 9, 4, 15, 29, 27, 16, 14, 31
```

The schedule was selected by systematic search over 1M random 31-period
schedules. On 9 measured metrics (integral R=5/6, linear R=10/14 both
directions, exact DMITM, weight-0 chain, MILP R=5), the new schedule
**improves 6, ties 3, and regresses 0**:

| Metric | v0.1 | v0.2 | Δ |
|---|---|---|---|
| Exact DMITM | 17 | **9** | −8 |
| Weight-0 chain | 13 | **5** | −8 |
| Integral R=5 | 21 | **9** | −12 |
| Integral R=6 | 4 | 4 | 0 |
| Linear forward R=10 | 1 | 1 | 0 |
| Linear backward R=10 | 1 | **3** | +2 |
| Linear forward R=14 | 5 | **8** | +3 |
| Linear backward R=14 | 5 | **11** | +6 |
| MILP R=5 | 0 | **4** | +4 |

(Higher is better for linear weight and MILP weight: higher weight = lower
correlation = more secure. Lower is better for dp5/dp6/DMITM/chain.)

The consecutive schedule of v0.1 was in the worst ~2% of 3000 random
schedules by exact DMITM and in the worst ~0.2% by weight-0 chain.
The improvement is a property of the **schedule step regularity**, not
of the Myszkowski permutation. See PAPER.md §2.8 and §4.13.

**How to reproduce.** [`calendar/CALENDAR_v02.txt`](calendar/CALENDAR_v02.txt)
contains the schedule as `MYSX_ROT_CAL=...`. The full search artifacts
(`top50_fixed.json`, `wf2_deep_summary.json`) and the search script
(`search_mysx_deep.py`) are in [`calendar/`](calendar/) and
[`cryptanalysis/DMITM/`](cryptanalysis/DMITM/).

### 2. API v2

A new packet format (VERSION=0x02, namespace `v2`) adds:

- **Rotation calendar selected by header byte** (CAL=0 for consecutive,
  CAL=1 for `rand_s9_45430`). No environment variable in production
  code.
- **512-bit secrets** processed through **HKDF-SHA512**, recovering the
  `2^256` Grover bound that v1 lost to HKDF-SHA256 (`2^128`).
- **512-bit MAC keys** and **HMAC-SHA512** with 64-byte tags.
- **One key per message** (32-byte random salt), eliminating nonce
  reuse in the key stream.
- **Authenticated header** (MAC covers version, calendar, KDF,
  KDF params, salt, nonce, AAD length, CT length).
- **Argon2id** for password paths (scrypt and PBKDF2-SHA512 as
  fallbacks, with explicit bounds).

The v1 API (`aeadEncrypt`, `aeadDecrypt`, `deriveAeadKeys`,
`deriveAeadKeysFromPassword`, `NonceGuard`) is kept unchanged for
reading existing packets and is **deprecated for new data**.

## Reading this repository

```
.
├── README.md                       # This file
├── PAPER.md                        # v0.2-draft paper (spec + partial analysis + PENDING list)
├── KAT_v2.json                     # v0.2 API test vectors (block_v02, v2 seal/open, KDF, parse, security)
├── mysx.prod.js                    # Reference implementation (v1 + v2, calendar=rand_s9_45430 injected)
├── generate_kat_v2.py              # v0.2 KAT generator (deterministic salt/nonce)
├── verify_v2_usage.js              # 12-check smoke test for v2 API
├── package.json                    # pinned @noble/hashes (Argon2id adapter)
├── package-lock.json
├── MYSX-paper.pdf                  # Rendered paper
├── calendar/                       # Rotation schedule selection artifacts
│   ├── CALENDAR_v02.txt            #   MYSX_ROT_CAL=22,5,8,... (31 explicit values)
│   ├── set_calendar.js             #   Injects the calendar into mysx.prod.js
│   ├── gen_rand_s9_45430.sh        #   Reproduces the calendar from scratch
│   ├── top50_fixed.json            #   21 finalists with metadata
│   ├── top_all_fixed.json          #   Full 88-candidate list
│   ├── test5_results.json          #   R=5 screening results
│   └── crosstest_results.json      #   Cross-test results
├── cryptanalysis/
│   ├── DMITM/                      # Impossible-differential analyses
│   │   ├── dmitm_verify.py         #   Exact DMITM (forward + backward)
│   │   ├── dmitm_trunc.py          #   Truncated-bit impossible differentials
│   │   ├── dmitm_impossible.py     #   Miss-in-the-middle over weight-0 chains
│   │   ├── search_mysx_cal.py      #   1M random schedule search (older pipeline)
│   │   ├── search_mysx_deep.py     #   1M random schedule search (deep pipeline)
│   │   ├── run_5round_test.py      #   R=5 screening
│   │   ├── run_full_analysis.py    #   Full analysis of a candidate
│   │   └── wf2_deep_summary.json   #   8 candidates × 7 metrics (raw data §4.13)
│   └── models/
│       └── linear/
│           ├── mysx_linear_model.py     # Exact linear model of F + round
│           ├── LINEAR_MODEL.md          #   Model documentation
│           └── linear_model_data.json   #   Data for §4 (except §4.10)
├── LEGACY_V1/                      # v0.1-draft2 (frozen reference)
│   ├── README.md                   #   v0.1 README (see this for full v0.1 analysis)
│   ├── PAPER.md                    #   v0.1 paper
│   ├── SPEC.md                     #   v0.1 specification
│   ├── SECURITY.md                 #   v0.1 security summary
│   ├── TODO.md                     #   v0.1 open items
│   ├── KAT.json                    #   v0.1 test vectors
│   ├── mysx.prod.js                #   v0.1 implementation
│   ├── mysx.test.js                #   v0.1 functional tests (17 tests)
│   ├── generate_kat.py             #   v0.1 KAT generator
│   ├── cryptanalysis/              #   v0.1 cryptanalysis
│   ├── misc/                       #   v0.1 misc scripts (beam search, MILP, etc.)
│   ├── diffResults/                #   v0.1 differential offset sweep logs
│   ├── dpResults/                  #   v0.1 integral offset sweep logs
│   ├── dpResults_v2/               #   v0.1 r0=15 saturation runs
│   ├── beam_results.json           #   v0.1 beam search results
│   └── NIST_SP_800-22_report.txt   #   v0.1 NIST STS report
└── node_modules/                   # @noble/hashes for Argon2id KAT
```

## What is measured for v0.2 (partial analysis)

All numbers below are reproducible with the scripts in
[`cryptanalysis/DMITM/`](cryptanalysis/DMITM/) and the schedule in
[`calendar/CALENDAR_v02.txt`](calendar/CALENDAR_v02.txt). They are in
PAPER.md §2.8, §4.12, §4.13.

- **Exact DMITM**: 9 rounds (v0.1: 17). Structural consequence of the
  weight-0 chain, verified by exhaustive linear algebra over the whole
  left-half difference space, both directions.
- **Weight-0 chain**: 5 rounds (v0.1: 13). Exhaustive linear algebra.
- **Integral at r0=0, word0**: 9 balanced bits at R=5 (v0.1: 21),
  4 at R=6 (v0.1: 4). Division property with `(1,1)`-invalid XOR rule,
  HiGHS solver.
- **Linear single-trail weights**: R=10 forward=1, backward=3
  (v0.1: 1, 1); R=14 forward=8, backward=11 (v0.1: 5, 5). Beam search
  over the exact model, 31 offsets, both directions. Higher weight is
  more secure.
- **MILP differential at R=5**: 4 (v0.1: 0).
- **Cross-language consistency**: Python `mysx_linear_model.py` and
  JavaScript `mysx.prod.js` produce identical block digest for the
  v0.2 calendar. Verified by `KAT_v2.json` (`block_digest_cal1`).

## What is PENDING for v0.2 (not re-measured)

The following sections of the v0.1 paper were analyzed for the
consecutive schedule and are **PENDING** for the v0.2 schedule. They
are marked as such in PAPER.md, with the command needed to re-run them.

- Differential offset sweep and MILP upper bounds at R≥6 (v0.1 §3.2,
  §3.5). Only R=5 measured for v0.2.
- Linear beam beyond R=14 (v0.1 §4.5, §4.10). Only R=10 and R=14
  measured for v0.2.
- Exact linear hulls at r=10,11,12 (v0.1 §4.6). Not re-run for v0.2.
- Full 31-offset integral sweep and r0=15 peak (v0.1 §4.9). Only r0=0
  measured for v0.2.
- NIST SP 800-22 statistical battery (v0.1 §4.11). Not re-run for v0.2.
- Truncated impossible differential (v0.1: 39 rounds). Not measured for
  v0.2.
- Single-bit and multi-bit truncated-propagated impossibles. Not
  measured for v0.2.
- Simon normalized coverage comparison (v0.1 §7). Not re-run for v0.2.

**The v0.2 analysis is incomplete by design.** This repository is a
working document with explicit PENDING marks. Do not infer security
from the absence of v0.2-specific results in those sections.

## Inheritance from v0.1

The following sections are **inherited unchanged** from v0.1 because
they are properties of the round function or of the key schedule, and
do not depend on the rotation schedule:

- Exact LAT of F (PAPER.md §4.2, v0.1 §4.2).
- Mask propagation rules (PAPER.md §4.3, v0.1 §4.3).
- Previous incorrect linear models and why they failed (PAPER.md §4.8,
  v0.1 §4.8).
- Related-key audit (PAPER.md §5, v0.1 §5). Key schedule unchanged.
  The 22 tests should be re-run on the v0.2 branch to confirm
  reproducibility, but the results are expected to be identical.
- Grover bound (PAPER.md §6, v0.1 §6). Updated for v2: 2^256 with a
  64-byte secret through HKDF-SHA512, 2^128 with the v1 API or a 32-byte
  secret.
- Simon comparison (PAPER.md §7, v0.1 §7). The structural differences
  are unchanged; the MYSX-specific comparisons (linear hull, integral,
  impossible) are PENDING for v0.2.

## Usage (research only)

### v2 API (recommended for new data)

```javascript
const mysx = require('./mysx.prod.js');
const { v2 } = mysx;

(async () => {
  // Optional: register Argon2id provider for password paths
  try {
    const { argon2idAsync } = await import('@noble/hashes/argon2.js');
    v2.setArgon2Provider(v2.argon2FromNoble(argon2idAsync));
  } catch (e) {
    // No Argon2: falls back to scrypt (Node) or PBKDF2 (with allowPbkdf2: true)
    console.warn('Argon2id unavailable:', e.message);
  }

  // 1. Generate a 64-byte secret (one per user/context; store it)
  const secret = v2.generateSecret();

  // 2. Encrypt
  const plaintext = new TextEncoder().encode('hola mundo');
  const aad = new TextEncoder().encode('user=alice');
  const packet = await v2.seal(plaintext, { secret }, {
    aad,
    context: 'app:chat:v1',   // separates keys between applications
    // cal: v2.CAL.V02 is the default (rand_s9_45430)
  });

  // 3. Decrypt
  const recovered = await v2.open(packet, { secret }, {
    aad,
    context: 'app:chat:v1',
  });
  console.log(new TextDecoder().decode(recovered));

  // 4. Check declared nominal security
  console.log(v2.securityLevel({ secret }));
  // -> { classicalBits: 512, groverBits: 256, ... }
})();
```

**Password path:**

```javascript
const packet = await v2.seal(plaintext, { password: 'correct horse battery staple' }, {
  context: 'app:notes:v1',
  // default KDF: Argon2id (if provider registered), scrypt (Node), PBKDF2 (with allowPbkdf2: true)
});
```

**v1 API (deprecated for new data, kept for reading existing packets):**

```javascript
const { aeadEncrypt, aeadDecrypt, deriveAeadKeys, NonceGuard } = mysx;
```

Notes on the v2 API:

- `v2.seal` draws a fresh 32-byte salt and 16-byte nonce per message.
  Different salt means different key, so nonce reuse does not leak
  plaintext across messages.
- `_salt` and `_nonce` are internal parameters (for KAT generation
  only). Do **not** pass them in production.
- The 12-check smoke test can be run with
  `MYSX_ENABLE_TEST=1 node verify_v2_usage.js`. It verifies:
  calendar injection, v2 API completeness, Argon2 provider status,
  round-trip with raw secret, packet version/cal/kdf bytes, round-trip
  with password, `securityLevel` values, v1 compatibility.
- The test API (`mysx.TEST`) is disabled by default; only enabled with
  `MYSX_ENABLE_TEST=1`.
- All public inputs are type-checked (`Uint8Array` with exact lengths).

### Calendar injection

If you clone the repository fresh and `mysx.prod.js` does not yet have
the calendar injected (the `V02_CALENDAR` field is `null`), inject it:

```bash
cd calendar
node set_calendar.js CALENDAR_v02.txt
cd ..
node -c mysx.prod.js && echo "syntax OK"
MYSX_ENABLE_TEST=1 node -e "require('./mysx.prod.js').TEST.verifyKAT().then(ok => console.log('KAT v0.1:', ok ? 'OK' : 'FAIL'))"
```

## KAT digests

Three KAT files:

- **`KAT_v2.json`** (current, v0.2 API): `block_v02` (block cipher
  with cal=1), `v2_raw` (v2.seal/open with secret), `v2_password_argon2`,
  `v2_password_scrypt`, `v2_password_pbkdf2`, `v2_kdf` (direct key
  derivation), `v2_parse` (header parsing), `security_level`,
  `block_digest_cal0`, `block_digest_cal1`.
- **`LEGACY_V1/KAT.json`** (v0.1 reference): `block`, `aead`, `kdf`
  vectors for the consecutive schedule, HKDF-SHA256, PBKDF2-SHA256.
  Public digest:
  `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`
  (SHA-256 over the full JSON).
- **`KNOWN_KAT_DIGEST = 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`**
  (v0.1 fast-regression): SHA-256 over 16 blocks with `key[i] = i`.
  The `block_digest_cal0` field of `KAT_v2.json` must equal this value;
  if it does not, the v1 path is broken.

A third-party implementation should target `KAT_v2.json` (block_v02
vectors for the v0.2 block, v2 vectors for the v0.2 API) and
`KNOWN_KAT_DIGEST` (for the consecutive calendar). The v0.1 KAT is
frozen in `LEGACY_V1/` for reference.

## Reproducing the results

### v0.2 (current schedule)

```bash
export MYSX_ROT_CAL=22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31

# Exact DMITM = 9 rounds
python3 cryptanalysis/DMITM/dmitm_verify.py exact

# Weight-0 chain = 5 rounds
python3 misc/diff_free_chain_table.py

# Linear weights R=10 and R=14, both directions
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 10 --beam 2000 --jobs 1 --direction backward
python3 misc/mysx_linear_beam.py run --offsets 0-30 --rounds 14 --beam 2000 --jobs 1 --direction backward

# Integral at r0=0, word0 (needs highs: pip install highspy)
python3 misc/mysx_division_property_v2.py --rounds 5-6 --active word0 --r0 0 --solver highs

# MILP differential R=5
python3 misc/mysx_milp2.py --rounds 5 --input-bit 63 --r0 10 --solver cbc --time-limit 180

# Cross-language consistency
MYSX_ENABLE_TEST=1 node -e "require('./mysx.prod.js').TEST.generateKAT(1).then(console.log)"
python3 -c "import sys;sys.path.insert(0,'cryptanalysis/models/linear');from mysx_linear_model import kat_digest;print(kat_digest())"
# The two lines above must produce identical hashes

unset MYSX_ROT_CAL
```

### v0.1 (inherited from LEGACY_V1)

To reproduce the v0.1 analyses documented in `LEGACY_V1/PAPER.md`:

```bash
cd LEGACY_V1
# The v0.1 implementation is here (without MYSX_ROT_CAL support)
python3 misc/diff_free_chain_table.py
python3 misc/verify_diff_13r.py
python3 cryptanalysis/models/linear/mysx_linear_model.py selftest
MYSX_ENABLE_TEST=1 node mysx.test.js
```

Or use the current repo without `MYSX_ROT_CAL` (the v0.2 code defaults
to the consecutive schedule for backwards compatibility):

```bash
unset MYSX_ROT_CAL
python3 cryptanalysis/DMITM/dmitm_verify.py exact     # -> max 13, total 17
python3 misc/diff_free_chain_table.py                  # -> r0=10 -> 13
```

### Full v0.2 re-analysis (PENDING items)

The PENDING items in PAPER.md §3, §4.4–4.6, §4.9 sweep, §4.10, §4.11,
§4.12 (truncated), and §5 (re-validation) can be run with the
corresponding v0.1 commands from `LEGACY_V1/README.md`, with
`MYSX_ROT_CAL` set and after re-compiling `dmitm_trunc.py --n_bits 256`.
See PAPER.md §8 for the current limitations.

## What this paper establishes (v0.2)

- **A new rotation schedule selected by systematic search**: 1M random
  31-period schedules filtered by weight-0 chain and exact DMITM,
  finalists ranked by a multi-dimensional score. The selected schedule
  improves 6 of 9 measured metrics and ties 3, with no regressions.
  The consecutive schedule of v0.1 was in the worst ~2% of 3000 random
  schedules by exact DMITM.
- **Partial v0.2 analysis** (see PAPER.md §2.8, §4.12, §4.13):
  exact DMITM = 9 rounds, weight-0 chain = 5 rounds, integral dp5 = 9
  and dp6 = 4, linear R=10/14 both directions (1/3/8/11), MILP R=5 = 4.
  Cross-language consistency between Python and JavaScript for the
  v0.2 calendar.
- **A new v2 AEAD/packet format** with rotation calendar selected by
  header byte, HKDF-SHA512 (recovering the 2^256 Grover bound),
  512-bit MAC keys, HMAC-SHA512 tags, one key per message, Argon2id
  for password paths.
- **Inherited from v0.1** (properties of the round function or key
  schedule, not of the rotation schedule): the exact LAT of F, the
  exact mask propagation rules, the 22-test key schedule audit, the
  Grover bound, the Simon structural comparison. See
  [`LEGACY_V1/README.md`](LEGACY_V1/README.md) and `LEGACY_V1/PAPER.md`
  for the full v0.1 analysis.

## What this paper does **not** establish (v0.2)

- **No re-analysis of the v0.1 differential, linear, or integral
  analyses beyond the specific metrics listed above.** The offset
  sweep, beam to 128 rounds, exact hulls, full integral sweep, NIST
  SP 800-22 battery, truncated impossible differential, and single-bit /
  multi-bit truncated-propagated impossibles are **PENDING** for v0.2.
- **No lower bound** on any trail weight for either schedule.
- **No key-recovery attack** attempted.
- **No related-key bound** (heuristic only, key schedule unchanged).
- **No boomerang or algebraic analysis.**
- **No external review.**
- **No post-quantum analysis** beyond the trivial Grover bound.

## Design weaknesses acknowledged

These are from the v0.1 paper (see `LEGACY_V1/README.md` for the full
text) and remain relevant for v0.2 unless explicitly superseded:

- **Slow diffusion**: 15 rounds until the worst input bit reaches all
  output bits (comparable to ChaCha20's ratio to total rounds).
- **Myszkowski permutation is not cryptographically optimized**:
  a structured permutation would strictly improve diffusion per round.
- **Key schedule has structural asymmetries** (bit 160 slowest to
  diffuse in subkeys).
- **Linear structure at short range was exact for v0.1** (9-round
  `|corr| = 1` chains at windows 12 and 27). **Superseded in v0.2**:
  the weight-0 chain max is 5 rounds and the exact DMITM is 9 rounds,
  measured in PAPER.md §4.13. The 16-round verified linear distinguisher
  of v0.1 (offset-20 backward trail, rounds 98–113) is a property of
  the v0.1 schedule; the analogous v0.2 result is PENDING.
- **Position inside the cipher matters**: the cost of a 14-round trail
  depends strongly on where it sits in the period-31 schedule. This is
  a property of the rotation schedule, which is why v0.2 changes it.
- **Integral distinguishers are offset-dependent** (v0.1: 6/5 rounds
  at r0=0, 10 rounds at r0=15). For v0.2, only r0=0 is measured
  (9 balanced at R=5, 4 at R=6); the r0=15 peak is PENDING.

## Citation

```
StringManolo. "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys
(v0.2-draft)". 2026. https://github.com/stringmanolo/MYSX-256
```

The v0.1-draft2 paper (frozen reference) is cited as:

```
StringManolo. "MYSX-256/512: A 256-bit Block Cipher with 512-bit Keys
(v0.1-draft2)". 2026. https://github.com/stringmanolo/MYSX-256/tree/v0.1-draft2
```

## Final warning

**MYSX has not been externally audited.** This paper is the author's
self-analysis, not a certification. No result here replaces an
independent cryptographic review. The v0.2 analysis is **partial by
design**: sections that were measured for v0.1 and have not been
re-executed for v0.2 are marked **PENDING** with the commands needed
to resolve them.

**Do not use MYSX to protect real data.** For production:
**AES-256-GCM** or **XChaCha20-Poly1305**.
