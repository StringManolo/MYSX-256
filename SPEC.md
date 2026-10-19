# MYSX-256/512 — Especificación

Versión: 0.1 (experimental)
Estado: congelada. Cualquier cambio requiere versión nueva.

## 1. Parámetros

| Parámetro | Valor |
|---|---|
| Tamaño de bloque | 256 bits (8 palabras de 32 bits) |
| Tamaño de clave | 512 bits (16 palabras de 32 bits) |
| Rondas | 128 |
| Estructura | Feistel de 2 ramas (128 + 128 bits) |
| No linealidad | `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` |
| Difusión | Transposición de Myszkowski (keyword `MYSZKOWS`) |
| Rotación | `rotl(word, (r mod 31) + 1)` por palabra y ronda |
| Whitening final | XOR con 8 palabras del key schedule |

## 2. Notación

- `rotl(x, n)`: rotación circular a la izquierda de `x` por `n` bits.
- `∧`: AND bit a bit.
- `⊕`: XOR bit a bit.
- `s[r]`: estado en la ronda `r` (`s[0]` = texto plano, `s[128]` = texto cifrado).
- `s[r][i]`: palabra `i` (0..7) del estado en la ronda `r`.
- `rk[r][i]`: subclave `i` (0..7) de la ronda `r`.
- `rkFinal[i]`: palabra `i` (0..7) del whitening final.

## 3. Constantes

```
CONST[0..7] = [
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
]
```

Estas constantes son los dígitos fraccionarios de π (mismos que Blowfish).

### 3.1. Permutación de Myszkowski

Keyword: `MYSZKOWS` (8 letras, S repetida en posiciones 3 y 8).

Orden alfabético: K(5), M(1), O(6), S(3,8), W(7), Y(2), Z(4).

La permutación de bytes `MYZ_PERM[0..31]` se construye como:

```
MYZ_PERM = [
   4,12,20,28,                 # K (columna 4)
   0, 8,16,24,                 # M (columna 0)
   5,13,21,29,                 # O (columna 5)
   2, 7,10,15,18,23,26,31,     # S,S (columnas 2 y 7, leídas por filas)
   6,14,22,30,                 # W (columna 6)
   1, 9,17,25,                 # Y (columna 1)
   3,11,19,27                  # Z (columna 3)
]
```

La permutación inversa `MYZ_INV` satisface `MYZ_INV[MYZ_PERM[i]] = i`.

## 4. Key schedule

### 4.1. Inicialización

Entrada: clave `K[0..63]` (64 bytes).

Estado inicial `s[0..15]` (16 palabras de 32 bits):

```
s[i] = big_endian_word(K[4i .. 4i+3])
```

### 4.2. Expansión

Para `r = 0 .. 127`:

```
spread = (r + 1) * 0x9E3779B9  (mod 2^32)

# Subclaves de ronda
for i in 0..7:
    rk[r][i] = s[i] ⊕ s[(i+5) mod 16] ⊕ s[(i+11) mod 16]
               ⊕ CONST[(r+i) mod 8] ⊕ spread

# Para i = 0..3: plegar fk en rk
for i in 0..3:
    fk = s[(i+8) mod 16] ⊕ CONST[(r+i+3) mod 8]
    rk[r][i] = rk[r][i] ⊕ fk

# Actualización del estado (Feistel 8+8, biyectiva)
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

### 4.3. Whitening final

Después de las 128 rondas:

```
for i in 0..7:
    rkFinal[i] = s[i] ⊕ s[(i+8) mod 16] ⊕ CONST[(128+i) mod 8]
```

## 5. Función de ronda

Cada ronda `r` transforma el estado `s[r]` en `s[r+1]` mediante cuatro pasos:

### 5.1. AddRoundKey

```
for i in 0..7:
    s[r][i] = s[r][i] ⊕ rk[r][i]
```

### 5.2. Feistel por parejas

Para `p = 0..3`:

```
L = s[r][p]
R = s[r][p + 4]
s_mid[p]     = R
s_mid[p + 4] = L ⊕ F(R)
```

donde `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)`.

### 5.3. Transposición de Myszkowski

Convertir `s_mid[0..7]` a bytes (big-endian por palabra):

```
bytes[4i .. 4i+3] = big_endian(s_mid[i])
```

Aplicar la permutación:

```
permuted[j] = bytes[MYZ_PERM[j]]  para j = 0..31
```

Reconstruir palabras:

```
s_perm[i] = big_endian_word(permuted[4i .. 4i+3])
```

### 5.4. Rotación por palabra

```
shift = (r mod 31) + 1
for i in 0..7:
    s[r+1][i] = rotl(s_perm[i], shift)
```

## 6. Cifrado

```
s[0] = plaintext  (como 8 palabras big-endian)
for r = 0..127:
    aplicar ronda r (sección 5)
for i = 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
ciphertext = s[128]  (como 32 bytes big-endian)
```

## 7. Descifrado

Inverso del cifrado:

```
s[128] = ciphertext
for i = 0..7:
    s[128][i] = s[128][i] ⊕ rkFinal[i]
for r = 127..0:
    aplicar ronda inversa r (inverso de sección 5, en orden inverso)
plaintext = s[0]
```

La ronda inversa consiste en:

1. Rotación inversa: `rotl(word, 32 - shift)`.
2. Transposición inversa: `bytes[MYZ_PERM[j]] = permuted[j]`.
3. Feistel inverso: `R = newL`, `L = newR ⊕ F(R)`.
4. XOR con `rk[r][i]`.

## 8. Modo de operación (CTR)

Contador de 32 bytes:

```
counter[0..15]  = nonce (16 bytes)
counter[16..31] = 0  (128 bits, big-endian)
```

Para cada bloque de 32 bytes de plaintext:

```
keystream = MYSX_encrypt(counter)
ciphertext_block = plaintext_block ⊕ keystream
counter[16..31] += 1  (big-endian)
```

## 9. AEAD (encrypt-then-MAC)

Paquete: `VERSION(1) ‖ NONCE(16) ‖ CT(n) ‖ TAG(32)`

MAC input: `VERSION ‖ NONCE ‖ AAD_LEN(4 BE) ‖ AAD ‖ CT_LEN(4 BE) ‖ CT`

TAG: `HMAC-SHA256(macKey, MAC input)`

Verificación: el descifrador verifica el TAG antes de descifrar.

## 10. Derivación de claves

### 10.1. Desde secreto aleatorio (HKDF-SHA256)

```
encKey = HKDF-SHA256(secret, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(secret, salt, info = context ‖ ":mac", L = 32)
```

### 10.2. Desde contraseña (PBKDF2-SHA256 + HKDF)

```
prk    = PBKDF2-SHA256(password, salt, iterations = 600000, L = 32)
encKey = HKDF-SHA256(prk, salt, info = context ‖ ":enc", L = 64)
macKey = HKDF-SHA256(prk, salt, info = context ‖ ":mac", L = 32)
```

## 11. Vectores de prueba

Ver [KAT.json](KAT.json).

## 12. Referencias

- Simon (NSA, 2013): función `F`.
- Myszkowski (1902): transposición con keyword de letras repetidas.
- Blowfish (Schneier, 1993): constantes de π.
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104).

## 13. Advertencia

MYSX **no ha sido auditado externamente**. El análisis de seguridad
en [SECURITY.md](SECURITY.md) documenta lo que se ha probado y lo que
no. **No usar en producción.**

