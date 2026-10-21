# MYSX-256/512 — Specification

Version: 0.1 (experimental)
Status: frozen. Any change requires a new version.

## 1. Parameters

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

**Structural note.** MYSX is sometimes described as a "2-branch
Feistel" by analogy with Simon. Strictly, each round applies four
independent Feistel cells over 32-bit word pairs (§5.2), then a byte
transposition over the full 32-byte state (§5.3), then word rotations
(§5.4). It is more accurately classified as an SPN with Feistel cells.
The "Feistel" label is a convenience.

## 2. Notation

- `rotl(x, n)`: circular left rotation of `x` by `n` bits.
- `∧`: bitwise AND.
- `⊕`: bitwise XOR.
- `s[r]`: state at round `r` (`s[0]` = plaintext, `s[128]` = ciphertext).
- `s[r][i]`: word `i` (0..7) of the state at round `r`.
- `rk[r][i]`: subkey `i` (0..7) of round `r`.
- `rkFinal[i]`: word `i` (0..7) of the final whitening.

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
   2, 7,10,15,18,23,26,31,     # S,S (columns 2 and 7, read row-wise)
   6,14,22,30,                 # W (column 6)
   1, 9,17,25,                 # Y (column 1)
   3,11,19,27                  # Z (column 3)
]
```

The inverse permutation `MYZ_INV` satisfies `MYZ_INV[MYZ_PERM[i]] = i`.

## 4. Key schedule

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

## 5. Round function

Each round `r` transforms state `s[r]` into `s[r+1]` in four steps:

### 5.1. AddRoundKey

```
for i in 0..7:
    s[r][i] = s[r][i] ⊕ rk[r][i]
```

### 5.2. Feistel per pair

For `p = 0..3`:

```
L = s[r][p]
R = s[r][p + 4]
s_mid[p]     = R
s_mid[p + 4] = L ⊕ F(R)
```

where `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.

### 5.3. Myszkowski transposition

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

### 5.4. Word rotation

```
shift = (r mod 31) + 1
for i in 0..7:
    s[r+1][i] = rotl(s_perm[i], shift)
```

## 6. Encryption

```
s[0] = plaintext  (as 8 big-endian words)
for r = 0..127:
    apply round r (section 5)
for i in 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128]  (as 32 big-endian bytes)
```

## 7. Decryption

Inverse of encryption:

```
s[128] = ciphertext
for i in 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
for r = 127..0:
    apply inverse round r (inverse of section 5, in reverse order)
plaintext = s[0]
```

The inverse round consists of:

1. Inverse rotation: `rotl(word, 32 - shift)`.
2. Inverse transposition: `bytes[MYZ_PERM[j]] = permuted[j]`.
3. Inverse Feistel: `R = newL`, `L = newR ⊕ F(R)`.
4. XOR with `rk[r][i]`.

## 8. Mode of operation (CTR)

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

## 9. AEAD (encrypt-then-MAC)

Packet: `VERSION(1) ‖ NONCE(16) ‖ CT(n) ‖ TAG(32)`

MAC input: `VERSION ‖ NONCE ‖ AAD_LEN(4 BE) ‖ AAD ‖ CT_LEN(4 BE) ‖ CT`

TAG: `HMAC-SHA256(macKey, MAC input)`

Verification: the decryptor verifies the TAG before decrypting.

## 10. Key derivation

### 10.1. From a random secret (HKDF-SHA256)

```
encKey = HKDF-SHA256(secret, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(secret, salt, info = context ‖ ":mac", L = 32)
```

### 10.2. From a password (PBKDF2-SHA256 + HKDF)

```
prk    = PBKDF2-SHA256(password, salt, iterations = 600000, L = 32)
encKey = HKDF-SHA256(prk, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(prk, salt, info = context ‖ ":mac", L = 32)
```

## 11. Test vectors

See [KAT.json](KAT.json).

The public KAT digest is
`5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`
(SHA-256 over the full `KAT.json`). A third-party implementation should
target this digest. The internal regression digest
`3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`
(SHA-256 over 16 blocks with `key[i] = i`) is a strict subset of the
public KAT.

**The test vectors were not changed in 0.1.1.**

## 12. References

- Simon (NSA, 2013): function `F`.
- Myszkowski (1902): transposition with repeated-letter keyword.
- Blowfish (Schneier, 1993): π constants.
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104).

## 13. Warning

MYSX **has not been externally audited**. The security analysis in
[SECURITY.md](SECURITY.md) documents what has been tested and what has
not. The exact linear analysis of `F` and of the round is documented
in [`cryptanalysis/models/linear/LINEAR_MODEL.md`](cryptanalysis/models/linear/LINEAR_MODEL.md)
and summarized in [SECURITY.md](SECURITY.md) §2. It establishes a
closed-form LAT, exact mask propagation with key-dependent sign, and
verified short-range structure, but **no bound over 128 rounds**. See
[PAPER.md](PAPER.md) §4 for the full discussion.

**Do not use in production.**
