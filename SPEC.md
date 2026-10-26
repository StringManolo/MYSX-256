# MYSX-256/512 — Specification

Version: 0.2-draft (experimental)
Status: draft. The cipher core (round function, key schedule) is frozen
from v0.1. The rotation calendar and the v2 packet format are new in
v0.2. The v1 API is frozen for backwards compatibility.

## 0. Reading guide

This document specifies three things:

1. **The MYSX-256/512 block cipher** (§1–§7). Frozen from v0.1, with one
   change in v0.2: the rotation calendar (§5).
2. **The v1 legacy API** (§8–§10). Frozen for backwards compatibility.
   Deprecated for new data.
3. **The v2 API** (§11–§15). Recommended for new data. New packet
   format, new KDFs, new security levels.

A third-party implementation that only needs to read/write v0.2 packets
can implement §1–§7 and §11–§15. A third-party implementation that needs
to read legacy v0.1 packets must also implement §8–§10.

The security analysis (why the rotation calendar was changed, why HKDF-SHA512
replaced HKDF-SHA256, what is measured and what is PENDING) is in
[`PAPER.md`](PAPER.md). This document specifies behavior only.

## 1. Parameters

| Parameter | Value |
|---|---|
| Block size | 256 bits (8 words of 32 bits) |
| Key size | 512 bits (16 words of 32 bits) for the block cipher |
| Rounds | 128 |
| Structure | SPN-like: 4 parallel Feistel cells + byte transposition |
| Non-linearity | `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` |
| Diffusion | Myszkowski transposition (keyword `MYSZKOWS`) |
| **Rotation** | **`ROT_CAL[r mod 31]`** where `ROT_CAL` is a 31-value permutation of `1..31` (§5) |
| Final whitening | XOR with 8 words from the key schedule |

**Structural note.** MYSX is sometimes described as a "2-branch
Feistel" by analogy with Simon. Strictly, each round applies four
independent Feistel cells over 32-bit word pairs (§7.2), then a byte
transposition over the full 32-byte state (§7.3), then word rotations
(§7.4). It is more accurately classified as an SPN with Feistel cells.
The "Feistel" label is a convenience.

## 2. Notation

- `rotl(x, n)`: circular left rotation of `x` by `n` bits.
- `∧`: bitwise AND.
- `⊕`: bitwise XOR.
- `s[r]`: state at round `r` (`s[0]` = plaintext, `s[128]` = ciphertext).
- `s[r][i]`: word `i` (0..7) of the state at round `r`.
- `rk[r][i]`: subkey `i` (0..7) of round `r`.
- `rkFinal[i]`: word `i` (0..7) of the final whitening.
- `ROT_CAL[]`: a permutation of `1..31` (§5).
- `CAL`: a one-byte rotation-calendar selector used in v2 packets (§11).
- `KDF`: a one-byte key-derivation selector used in v2 packets (§12).
- `LP(x)`: length prefix, `u16_be(len(x)) || x`. Used in HKDF `info` and MAC input.

## 3. Constants

```
CONST[0..7] = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]
```

These constants are the fractional digits of π (same as Blowfish).

### 3.1. Myszkowski permutation

Keyword: `MYSZKOWS` (8 letters, S repeated at positions 3 and 8).

Alphabetical order: K(5), M(1), O(6), S(3,8), W(7), Y(2), Z(4).

The byte permutation `MYZ_PERM[0..31]` is constructed as:

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

The inverse permutation `MYZ_INV` satisfies `MYZ_INV[MYZ_PERM[i]] = i`.

## 4. Key schedule (frozen from v0.1)

### 4.1. Initialization

Input: key `K[0..63]` (64 bytes).

Initial state `s[0..15]` (16 words of 32 bits):

```
s[i] = big_endian_word(K[4i .. 4i+3])
```

### 4.2. Expansion

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

### 4.3. Final whitening

After the 128 rounds:

```
for i in 0..7:
    rkFinal[i] = s[i] ⊕ s[(i+8) mod 16] ⊕ CONST[(128+i) mod 8]
```

## 5. Rotation calendar (new in v0.2)

A rotation calendar is a permutation of `1..31`. The block cipher uses
`shift = ROT_CAL[r mod 31]` at round `r`. The calendar is selected per
packet by the one-byte `CAL` field in v2 packets (§11). Two calendar
identifiers are defined:

| CAL | Name | Status | Value |
|---|---|---|---|
| `0x00` | `CONSECUTIVE_V1` | v0.1, deprecated | `[1,2,3,...,31]` |
| `0x01` | `V02` | v0.2, recommended | `[22,5,8,7,17,10,30,1,11,26,6,3,12,23,25,13,28,20,21,19,24,2,18,9,4,15,29,27,16,14,31]` |

The `V02` calendar is:

```
index:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14
value: 22   5   8   7  17  10  30   1  11  26   6   3  12  23  25

index: 15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30
value: 13  28  20  21  19  24   2  18   9   4  15  29  27  16  14  31
```

An implementation MUST reject any `CAL` value not in this table.
Implementations MAY add new calendar identifiers in the future; the
`CAL` byte is the versioning mechanism.

**Selecting a calendar in the reference implementation.**

- The default for v2 packets is `CAL = 0x01` (`V02`).
- `CAL = 0x00` (`CONSECUTIVE_V1`) is available for cross-testing the
  block cipher against v0.1, but MUST NOT be used for new v2 packets.
- The calendar is a hardcoded table in `mysx.prod.js` (injected via
  `node set_calendar.js CALENDAR_v02.txt`). The library MUST NOT read
  the rotation calendar from an environment variable at runtime.
- Analysis tools (`search_mysx_deep.py`, `dmitm_verify.py`, etc.) use
  `MYSX_ROT_CAL` as a development convenience. That environment
  variable is not part of the public API.

**Selecting a calendar programmatically (block cipher only, no AEAD).**

A third-party block cipher implementation takes `ROT_CAL` as a
parameter of the round function. A third-party AEAD implementation
takes `CAL` from the packet header. These are separate concerns: the
block cipher is calendar-parameterized, the v2 AEAD reads the calendar
from the packet and passes it to the block cipher.

## 6. Block cipher interface

A block cipher implementation exposes:

```
MYSX_encrypt(plaintext: 32 bytes, key: 64 bytes, ROT_CAL: 31-entry table) -> ciphertext: 32 bytes
MYSX_decrypt(ciphertext: 32 bytes, key: 64 bytes, ROT_CAL: 31-entry table) -> plaintext: 32 bytes
```

The 32-byte plaintext and ciphertext are 8 big-endian 32-bit words.
The 64-byte key is 16 big-endian 32-bit words (initial state of the
key schedule). `ROT_CAL` is the permutation of §5.

## 7. Round function

Each round `r` transforms state `s[r]` into `s[r+1]` in four steps.

### 7.1. AddRoundKey

```
for i in 0..7:
    s[r][i] = s[r][i] ⊕ rk[r][i]
```

### 7.2. Feistel per pair

For `p = 0..3`:

```
L = s[r][p]
R = s[r][p + 4]
s_mid[p]     = R
s_mid[p + 4] = L ⊕ F(R)
```

where `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.

### 7.3. Myszkowski transposition

Convert `s_mid[0..7]` to bytes (big-endian per word):

```
bytes[4i .. 4i+3] = big_endian(s_mid[i])
```

Apply the permutation:

```
permuted[j] = bytes[MYZ_PERM[j]]  for j = 0..31
```

Reconstruct words:

```
s_perm[i] = big_endian_word(permuted[4i .. 4i+3])
```

### 7.4. Word rotation

```
shift = ROT_CAL[r mod 31]
for i in 0..7:
    s[r+1][i] = rotl(s_perm[i], shift)
```

## 8. Encryption

```
s[0] = plaintext  (as 8 big-endian words)
for r = 0..127:
    apply round r (section 7) with ROT_CAL = the selected calendar
for i = 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128]  (as 32 big-endian bytes)
```

## 9. Decryption

Inverse of encryption:

```
s[128] = ciphertext
for i = 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
for r = 127..0:
    apply inverse round r (inverse of section 7, in reverse order)
plaintext = s[0]
```

The inverse round consists of:

1. Inverse rotation: `rotl(word, 32 - shift)` where `shift = ROT_CAL[r mod 31]`.
2. Inverse transposition: `bytes[MYZ_PERM[j]] = permuted[j]`.
3. Inverse Feistel: `R = newL`, `L = newR ⊕ F(R)`.
4. XOR with `rk[r][i]`.

## 10. v1 legacy AEAD (deprecated for new data)

The v1 API is frozen. It MUST be implemented for reading existing
packets. It MUST NOT be used for new data.

### 10.1. CTR mode

32-byte counter:

```
counter[0..15]  = nonce (16 bytes)
counter[16..31] = 0  (128 bits, big-endian)
```

For each 32-byte plaintext block:

```
keystream = MYSX_encrypt(counter, key, ROT_CAL=CONSECUTIVE_V1)
ciphertext_block = plaintext_block ⊕ keystream
counter[16..31] += 1  (big-endian)
```

The v1 CTR mode uses `CAL = 0` (consecutive calendar). A v1 packet
cannot carry a v2 calendar.

### 10.2. v1 packet format

```
VERSION(1)=0x01 | NONCE(16) | CT(n) | TAG(32)
```

MAC input:

```
VERSION(1) | NONCE(16) | AAD_LEN(u32_be) | AAD | CT_LEN(u32_be) | CT
```

TAG = HMAC-SHA256(macKey, MAC input), 32 bytes.

Verification: the decryptor MUST verify the TAG before decrypting.

### 10.3. v1 key derivation

From a 64-byte `encKey` and a 32-byte `macKey` passed by the caller:

```
encKey = HKDF-SHA256(secret, salt, info = context || ":enc", L = 64)
macKey = HKDF-SHA256(secret, salt, info = context || ":mac", L = 32)
```

From a password (PBKDF2-SHA256 + HKDF):

```
prk    = PBKDF2-SHA256(password, salt, iterations = 600000, L = 32)
encKey = HKDF-SHA256(prk, salt, info = context || ":enc", L = 64)
macKey = HKDF-SHA256(prk, salt, info = context || ":mac", L = 32)
```

The HKDF-SHA256 bottleneck caps the effective quantum security at
`2^128` (see §13 and PAPER.md §6). Do not use v1 for new data.

### 10.4. v1 test vectors

`LEGACY_V1/KAT.json`. Public digest
`5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`
(SHA-256 over the full JSON). Internal regression digest
`KNOWN_KAT_DIGEST = 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`
(SHA-256 over 16 blocks with `key[i] = i`).

## 11. v2 packet format (recommended for new data)

### 11.1. Packet layout

```
VERSION(1)=0x02 | CAL(1) | KDF(1) | KDF_PARAMS(var) | SALT(32) | NONCE(16) | CT(n) | TAG(64)
```

The fields are concatenated with no length prefixes except where
specified for `KDF_PARAMS` (§11.2).

- `VERSION`: always `0x02` for v2 packets. A v1 packet (`0x01`) MUST
  be rejected by the v2 parser.
- `CAL`: rotation calendar selector. See §5.
- `KDF`: key-derivation selector. See §12.
- `KDF_PARAMS`: KDF-specific parameters. The length depends on `KDF`.
- `SALT`: 32 bytes of fresh randomness. Generated per packet.
- `NONCE`: 16 bytes of fresh randomness. Generated per packet.
- `CT`: ciphertext of the plaintext (may be empty).
- `TAG`: HMAC-SHA512 tag, 64 bytes.

### 11.2. KDF parameters by selector

| KDF | Name | Params | Length | Defaults |
|---|---|---|---|---|
| `0x00` | `RAW` | none | 0 | — |
| `0x01` | `ARGON2ID` | `memKiB(u32_be) \|\| passes(u8) \|\| lanes(u8)` | 6 | `{memKiB: 65536, passes: 3, lanes: 4}` |
| `0x02` | `PBKDF2_SHA512` | `iterations(u32_be)` | 4 | `{iterations: 600000}` |
| `0x03` | `SCRYPT` | `logN(u8) \|\| r(u8) \|\| p(u8)` | 3 | `{logN: 17, r: 8, p: 1}` |

The parser MUST validate each parameter against the bounds in §12.4.
Out-of-bounds packets MUST be rejected with a non-descript
`authentication failed` error (not a specific "parameters out of
bounds" leak).

### 11.3. MAC input

```
MAC_INPUT = HEADER | LP(AAD) | LP(CT)
```

where `LP(x) = u32_be(len(x)) || x` for the MAC (note: `u32`, not the
`u16` used in HKDF `info`; the MAC uses `u32` for AAD and CT to support
large plaintexts), and `HEADER` is the byte sequence
`VERSION | CAL | KDF | KDF_PARAMS | SALT | NONCE` exactly as it appears
in the packet.

TAG = HMAC-SHA512(macKey, MAC_INPUT), 64 bytes.

Verification: the decryptor MUST verify the TAG before decrypting
(encrypt-then-MAC). The verification MUST be constant-time.

**Note on the `u32` vs `u16` length prefix.** The `LP()` used inside
the HKDF `info` field (§12.2) uses a 2-byte length prefix; the
length-prefix used in the MAC input uses a 4-byte length prefix. This
is intentional: HKDF info is short, MAC input may contain up to
`MAX_CT_BYTES` (2^31-1) bytes.

## 12. v2 key derivation

### 12.1. Derivation pipeline

```
ikm     = raw secret (KDF=RAW) | password-derived key (KDF=Argon2id/PBKDF2/scrypt)
PRK     = HKDF-Extract-SHA512(salt = SALT, ikm)
info    = LP("MYSX-256/512 v2") | CAL | KDF | LP(context) | LP(label)
encKey  = HKDF-Expand(PRK, info(label="enc"), 64)
macKey  = HKDF-Expand(PRK, info(label="mac"), 64)
```

where `LP(x) = u16_be(len(x)) || x`.

### 12.2. HKDF `info` construction

```
info = LP(utf8("MYSX-256/512 v2"))
     | CAL (1 byte)
     | KDF (1 byte)
     | LP(utf8(context))
     | LP(utf8(label))
```

`context` is an application-provided string (empty string allowed, but
callers SHOULD use a non-empty, application-specific context).
`label` is `"enc"` or `"mac"`.

### 12.3. `ikm` construction

**KDF=RAW (0x00).** The caller passes `creds.secret`, a 64-byte or
32-byte `Uint8Array`. The `ikm` is `creds.secret` verbatim. A
64-byte secret gives nominal `2^256` Grover security (see §13); a
32-byte secret gives `2^128`.

**KDF=Argon2id (0x01), PBKDF2_SHA512 (0x02), scrypt (0x03).** The
caller passes `creds.password` (string or `Uint8Array`) and optionally
`creds.keyfile` (`Uint8Array`).

- Normalize the password with NFKC (`String.prototype.normalize('NFKC')`
  in JavaScript; `unicodedata.normalize('NFKC', pw)` in Python).
- Derive a 64-byte password key with the selected KDF and the
  `KDF_PARAMS` from the packet (or the defaults from §11.2 for sealing).
- `ikm = LP(password_key) | LP(keyfile)`, where `LP(x) = u16_be(len(x)) || x`
  (the 2-byte length prefix, consistent with the HKDF info).

### 12.4. KDF bounds and defaults

| KDF | Parameter | Bounds | Default |
|---|---|---|---|
| Argon2id | `memKiB` | 19456 – 1048576 (19 MiB – 1 GiB) | 65536 |
| Argon2id | `passes` | 2 – 16 | 3 |
| Argon2id | `lanes` | 1 – 16 | 4 |
| PBKDF2-SHA512 | `iterations` | 210000 – 10000000 | 600000 |
| scrypt | `logN` | 15 – 20 | 17 |
| scrypt | `r` | 8 – 16 | 8 |
| scrypt | `p` | 1 – 16 | 1 |
| scrypt | `128 · 2^logN · r` | ≤ 2^30 bytes (1 GiB) | — |

The parser MUST reject out-of-bounds parameters. The sealer MUST use
parameters within bounds; the defaults are chosen to satisfy RFC 9106
(second recommended Argon2id option: 64 MiB, t=3, p=4).

### 12.5. Argon2id provider (injection API)

JavaScript runtimes do not consistently expose Argon2id natively. The
reference implementation exposes an injection API:

```javascript
v2.setArgon2Provider(fn);
```

where `fn` has signature:

```
fn({ password: Uint8Array, salt: Uint8Array, memKiB: number, passes: number, lanes: number, dkLen: number }) -> Uint8Array | Promise<Uint8Array>
```

Recommended provider: `@noble/hashes`, which is pure JavaScript, has
zero dependencies, and runs in Node and browsers. The adapter is:

```javascript
const { argon2idAsync } = await import('@noble/hashes/argon2.js');
v2.setArgon2Provider(v2.argon2FromNoble(argon2idAsync));
```

If no provider is registered and `opts.allowNativeArgon2` is true,
the Node.js native `crypto.argon2Sync` (Node ≥ 24.7, documented as
experimental) is used. Otherwise the sealer falls back to scrypt
(Node only), then to PBKDF2-SHA512 (only if `opts.allowPbkdf2` is
explicitly true). If no KDF is available, the sealer throws.

**An implementation MUST NOT silently fall back to a weaker KDF.**
The user opts in explicitly by setting `allowPbkdf2` or
`allowNativeArgon2`, or by registering a provider.

## 13. v2 security levels (declared)

`v2.securityLevel(creds)` returns the nominal key-recovery security:

| Creds | `classicalBits` | `groverBits` |
|---|---|---|
| `{secret: Uint8Array(64)}` | 512 | 256 |
| `{secret: Uint8Array(32)}` | 256 | 128 |
| `{password, keyfile: Uint8Array(>=64)}` | 512 | 256 |
| `{password, keyfile: < 64 bytes}` or `{password}` | null | null |

The `null` values are intentional: they signal "security is limited by
password entropy; the nominal key-layer figures do not apply". The
note field explains the exact trade-off. For a 64-byte secret, the
`note` states that `2^256` Grover applies per target, and
`2^256/sqrt(N)` if an attacker needs only one of N messages.

## 14. v2 test vectors

`KAT_v2.json`. Contains:

- `block_v02`: 8 block-cipher vectors with `CAL=0x01`. The key is
  `key[i] = i` for `i = 0..63`, the plaintext is `pt[j] = (t*32 + j) &
  0xff` for `t = 0..7`, and the ciphertext is the output of
  `MYSX_encrypt(pt, key, V02_CALENDAR)`. The digest
  `block_digest_cal1 = SHA-256(all 16 blocks of pt||ct)` is in the
  file.
- `v2_raw`: a v2 packet with `KDF=RAW`, a 64-byte secret
  `0xA5,0xA5,...`, a fixed salt and nonce, an AAD `0xAA,0xBB,0xCC`,
  a context `kat-v2`, and a plaintext `"KAT v2 test message"`. The
  packet bytes are the full 64-byte-tag packet. `roundtrip_ok: true`
  is the expected round-trip result.
- `v2_password_argon2`: a v2 packet with `KDF=ARGON2ID`,
  parameters `{memKiB: 65536, passes: 3, lanes: 4}`, a fixed salt and
  nonce, the same AAD and context, and the same plaintext. The packet
  bytes are the full packet. This vector is only meaningful if the
  Argon2id provider is deterministic given the same inputs; a
  third-party implementation MUST match the packet byte-for-byte.
- `v2_password_scrypt`: a v2 packet with `KDF=SCRYPT`, parameters
  `{logN: 15, r: 8, p: 1}`, same salt/nonce/AAD/context/plaintext.
- `v2_password_pbkdf2`: a v2 packet with `KDF=PBKDF2_SHA512`,
  parameters `{iterations: 210000}`, same salt/nonce/AAD/context/plaintext.
- `v2_kdf`: a direct derivation of `encKey` and `macKey` from a
  64-byte secret, a 32-byte salt, `CAL=0x01`, `KDF=RAW`, and a context
  `kat-kdf-context`. The `encKey` and `macKey` are 64 bytes each.
- `v2_parse`: the parsed header of the `v2_raw` packet, as a JSON object
  (version, cal, kdf, kdf_params, salt, nonce, header_len).
- `security_level`: the `securityLevel` outputs for four credential
  types (64-byte secret, 32-byte secret, password + 16-byte keyfile,
  password + 64-byte keyfile).
- `block_digest_cal0` and `block_digest_cal1`: SHA-256 digests of the
  16 internal blocks (pt||ct) for the two calendars. `block_digest_cal0`
  MUST equal `KNOWN_KAT_DIGEST = 3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`;
  if it does not, the v1 block-cipher path is broken.
- `argon2_provider`: a string identifying the Argon2id provider used to
  generate the vectors (`"noble"`, `"native"`, or `"none"`). A third-
  party implementation should compare its `v2_password_argon2` packet
  with the one in `KAT_v2.json` only if the provider identifiers match;
  otherwise the packet may differ (Argon2id is not required to produce
  identical output across providers that use the same parameters;
  the RFC 9106 test vectors are the normative source for Argon2id
  compatibility).

## 15. Public API surface (reference implementation)

The reference implementation is `mysx.prod.js` (Node.js / browser).

**v2 (recommended):**

- `v2.seal(plaintext, creds, opts)` -> `Uint8Array` (packet).
- `v2.open(packet, creds, opts)` -> `Uint8Array` (plaintext).
- `v2.generateSecret()` -> `Uint8Array(64)`.
- `v2.securityLevel(creds)` -> `{classicalBits, groverBits, note}`.
- `v2.setArgon2Provider(fn)` -> void.
- `v2.argon2FromNoble(argon2idAsync)` -> `fn`.
- `v2.CAL` -> `{CONSECUTIVE_V1: 0, V02: 1}`.
- `v2.KDF` -> `{RAW: 0, ARGON2ID: 1, PBKDF2_SHA512: 2, SCRYPT: 3}`.
- `v2.DEFAULTS` -> KDF parameter defaults.
- `v2.LIMITS` -> KDF parameter bounds.

`creds` is `{secret: Uint8Array(64|32)}` or
`{password: string | Uint8Array, keyfile?: Uint8Array}`.

`opts` for `seal`: `{aad, context, cal, kdf, kdfParams, argon2Provider,
allowNativeArgon2, allowPbkdf2, _salt, _nonce}`. The `_salt` and
`_nonce` options are for KAT generation only and MUST NOT be used in
production.

`opts` for `open`: `{aad, context, expectKdf, argon2Provider,
allowNativeArgon2, allowPbkdf2}`.

**v1 (deprecated):**

- `aeadEncrypt(plaintext, key, macKey, opts)` -> `Uint8Array`.
- `aeadDecrypt(packet, key, macKey, opts)` -> `Uint8Array`.
- `deriveAeadKeys(secret, opts)` -> `{encKey, macKey}`.
- `deriveAeadKeysFromPassword(password, salt, opts)` -> `{encKey, macKey}`.
- `NonceGuard` -> class.
- `CONFIG` -> constants.

**Test API:** disabled by default. Enabled by setting
`MYSX_ENABLE_TEST=1` before requiring the module. Not part of the
public surface.

## 16. References

- Simon (NSA, 2013): function `F`.
- Myszkowski (1902): transposition with repeated-letter keyword.
- Blowfish (Schneier, 1993): π constants.
- HKDF (RFC 5869), HKDF-SHA512 (RFC 5869 §2.3 with SHA-512).
- PBKDF2 (RFC 8018), HMAC (RFC 2104).
- Argon2 (RFC 9106), Argon2id.
- scrypt (RFC 7914).
- NFKC normalization (Unicode Standard Annex #15).

## 17. Warning

MYSX **has not been externally audited**. The security analysis is in
[`PAPER.md`](PAPER.md). It documents the properties that are
established, the properties that are PENDING for v0.2, and the
limitations. No result in this specification is a security claim.

**Do not use MYSX to protect real data.**
