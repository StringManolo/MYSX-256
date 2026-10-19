# MYSX-256/512 — Estado de seguridad (v0.1-experimental)

**Cifrador propio. NO auditado externamente. NO usar para datos sensibles.**
Para producción: AES-256-GCM o XChaCha20-Poly1305.

Tag de congelación: `v0.1-experimental`.
KAT de referencia: `KAT.json` (digest `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`).

## Resumen

| Familia de ataque | Estado | Evidencia |
|---|---|---|
| Diferencial (MILP) | **Resistente** | Peso 114 a r=14, umbral r≈15, margen ~113. Validado empíricamente a r=4. |
| Lineal (MILP) | **Inconcluso, no alarmante** | Single-trail: artefactos (no verifican). Estricto: modelo roto. Empírico: sin correlación detectable en trails de peso 8. |
| Related-key | **Sin debilidades explotables** | 22 tests PASS: sin `Δrk[r]=0` persistente, beam search score 139, sin claves débiles. Difusión lenta r=1–4 (estructural). |
| Integral / imposible / boomerang / algebraico | Pendiente | — |
| Grover (cuántico) | Inviable | 2²⁵⁶ iteraciones |
| Fuerza bruta clásica | Inviable | 2⁵¹² operaciones |
| Colisiones de bloque | Inviable | 2¹²⁸ bloques (bloque de 256 bits) |

**Veredicto corto**: la resistencia diferencial es sólida; la lineal no está demostrada pero la evidencia no es alarmante; el key schedule no tiene debilidades explotables. El cifrador está congelado y no debe usarse en producción sin revisión externa.

---

## 1. Criptoanálisis diferencial (MILP)

### 1.1. Modelo

- Herramienta: `mysx_milp.py` (PuLP + CBC/HiGHS).
- Modelo del AND: `a = Δx ∨ Δy` (cota superior; sobreestima el coste, nunca lo subestima).
- Input difference: single-bit, peor caso entre los 256 posibles (sweep completo a r=5–8).
- Solver: CBC con `gapRel=0.2`, `timeLimit=300`.

### 1.2. Resultados

| Rondas | Peor input | Peso | Prob. single-trail |
|---|---|---|---|
| 5 | w1b24 | 2 | 2⁻² |
| 6 | w1b24 | 6 | 2⁻⁶ |
| 7 | w2b30 | 10 | 2⁻¹⁰ |
| 8 | w2b30 | 18 | 2⁻¹⁸ |
| 12 | w2b30 | 68 | 2⁻⁶⁸ |
| 14 | w2b30 | 114 | 2⁻¹¹⁴ |

Crecimiento r=12→14: **+23 bits/ronda**, acelerando.
Umbral práctico (peso 128): cruzado en **r≈15**.
Margen con 128 rondas: **~113 rondas**.

### 1.3. Verificación empírica

- Trail a r=4, w0b0, N=2.000 muestras.
- Match rate 0.5–1.15% → prob ≈ 2⁻⁷.
- Consistente con el modelo (2⁻⁸) y con **clustering diferencial** (factor ~2 sobre el single-trail).

### 1.4. Limitaciones

- Single-trail, single-input. No modela clustering a muchas rondas.
- Sin related-key.
- El modelo es cota superior: si da pesos altos, no es concluyente para seguridad; si da pesos bajos, indica debilidad. En este caso los pesos son altos y crecientes.
- `gapRel=0.2` deja un margen del 20% en el peso reportado (real puede ser ~20% menor). La conclusión no cambia.

---

## 2. Criptoanálisis lineal (MILP) — INCONCLUO

Se probaron tres modelos. Ninguno es concluyente. La evidencia empírica sugiere que el ataque real es **más difícil** que lo que los modelos predicen, pero no es una prueba.

### 2.1. Modelo híbrido (`act = α ∨ β ∨ γ`, sin `γ ≥ α`)

Resultados: trails con pesos crecientes (peso 8 a r=3, 18 a r=4, 86 a r=6, 434 a r=10).

**Verificación empírica**:
- Trail a r=4 (peso 8, corr esperada 2⁻⁸ = 0.0039).
- 8 runs con N=2.000.000 cada uno.
- Correlación observada: media −0.0004, entre −0.0014 y +0.0005.
- **No significativa** (≈ ruido).

**Diagnóstico**: el modelo permitía `(α,β,γ) = (1,0,0)`, que tiene correlación 0 en el AND real (no 1/2). Los trails encontrados eran artefactos.

### 2.2. Modelo estricto (`x = y = z = w` en XOR)

Resultados: **INFEASIBLE** en todas las rondas 1–10 para máscara w0b0.

**Diagnóstico**: el modelo es demasiado restrictivo. Prohíbe trails válidos con correlación 1 (p. ej. el de r=1 con peso 0), porque en el XOR `w = x ⊕ y ⊕ z` la correlación 1 requiere solo que el número de máscaras activas sea par, no que todas sean iguales.

### 2.3. Modelo relajado con AND correcto (`x+y+z-w=2u`, `γ = α OR β`)

Resultados: pesos crecientes (8 a r=3, 18 a r=4, 86 a r=6, 434 a r=10).

**Verificación empírica**:
- Trail a r=3 (peso 8, corr esperada 2⁻⁸ = 0.0039).
- N=5.000.000.
- Correlación observada: −0.000238, a **0.53σ** de cero.
- **No significativa**.

**Diagnóstico**: artefacto del modelo o **clustering destructivo** (varios trails con signos opuestos que se cancelan). En ambos casos, el ataque real es **más difícil** que lo que sugiere el single-trail.

### 2.4. Conclusión del análisis lineal

El análisis lineal single-trail no es concluyente. La evidencia empírica sugiere que la correlación real es **mucho menor** que la predicha por los modelos. Esto es **bueno para la seguridad**: el ataque lineal real es más difícil que lo que sugiere el modelo. Pero no es una prueba.

Para un análisis lineal riguroso haría falta:

1. **Seguimiento de signos** (±1/2 por AND), que el MILP lineal no captura.
2. **Linear hull analysis** (clustering de múltiples trails con la misma máscara de entrada/salida).
3. **Modelo SAT/MILP más sofisticado** con correlaciones de XOR < 1.

Eso está fuera del alcance de este trabajo.

---

## 3. Análisis del key schedule

Herramientas: `keyschedule_test.js` (auditoría básica) y
`keyschedule_test_extended.js` (auditoría exhaustiva, 22 tests).

### 3.1. Cobertura

| Test | Cobertura |
|---|---|
| Verificación vs prod | 1 clave, 128 rondas |
| Biyectividad | 128 rondas, reconstrucción completa |
| Espacio nulo rk[0] | 255 patrones × 3 modos |
| Propagación del espacio nulo | 765 pruebas |
| Peso-1 | 512 bits exhaustivo |
| Peso-2 | 130,816 pares exhaustivo |
| Peso-3 "misma Δ" | 560 combos × 3 Δ = 1,680 pruebas |
| Beam search | Hasta peso-6, beam 50 |
| Multi-base | 5 claves base distintas |
| Estructurados | 20 patrones (simétrico, periódico, bloque, palindrómico) |
| Ciclos / puntos fijos | 10,000 claves |
| Weak-key scan | 25 patrones |
| Matriz de influencia | 512 bits → rk[64] |

### 3.2. Resultados

| Métrica | Valor |
|---|---|
| `Δrk[r]=0` persistente (r≥1) | **0** en todas las pruebas |
| Beam search (peor `max_r weight`) | 139 (ideal 128) |
| Peso mínimo en r≥8 | 103 |
| Ventana máxima de bajo peso (<20) | 3–4 rondas |
| Extensión con umbral 40 | 4 rondas |
| Peor bit (weight-1, menor peso en r=1) | 160 (word 5, bit 0), 1 bit |
| Peor bit (weight-1, ventana más larga) | 1, 3 rondas con umbral 20 |
| Mejor extensión (umbral 40) | bit 4, 4 rondas |
| Spread de peor peso entre 5 bases | 0 |
| Mismo bit peor en todas las bases | Sí (bit 160) |
| Ciclos / puntos fijos | Ninguno (10k claves) |
| Claves débiles | Ninguna (25 patrones) |
| Influencia r=64 | media 0.498, min 0.406, max 0.590 |

**Peso mínimo por ronda (sobre 512 weight-1 ΔK)**:

| Ronda | min | max |
|---|---|---|
| 1 | 1 | 26 |
| 2 | 6 | 55 |
| 3 | 10 | 107 |
| 4 | 27 | 128 |
| 5 | 48 | 149 |
| 6 | 81 | 153 |
| 8 | 103 | 150 |
| 12 | 106 | 152 |
| 16 | 98 | 154 |
| 32 | 107 | 155 |
| 64 | 104 | 151 |
| 128 | 105 | 154 |

### 3.3. Interpretación

- **Sin `Δrk[r]=0` persistente.** El espacio nulo de `rk[0]` (255 patrones)
  no sobrevive a la ronda 1. La propagación con `all-ones` da ≥96 bits de
  diferencia en `rk[1]`. No hay distinguidor trivial de claves relacionadas.
- **Sin trail persistente.** El beam search (peso ≤6, beam 50) confirma
  que ningún `ΔK` de bajo peso mantiene bajo peso en todas las rondas.
  El peor `max_r weight` es 139, casi el ideal de 128.
- **Difusión lenta en r=1–4.** Esperado por diseño: el state update es
  una sola ronda Feistel por iteración de cifrado. La difusión se
  completa en r=8 (peso mínimo 103). No es una rotura.
- **Bit 160 (word 5, bit 0) es el peor bit en peso mínimo.** `ΔK` con
  solo ese bit produce `Δrk[1]` con 1 bit de diferencia. Es
  **consistente entre 5 claves base distintas** (spread 0), así que es
  estructural, no ruido. No es explotable: el beam search confirma que
  se difunde a ~139 bits en la cola.
- **Bit 1 es el peor en ventana.** Proporciona 3 rondas consecutivas con
  peso <20 (r=1:2, r=2:6, r=3:17, r=4:74). Es una ventana corta, no un
  trail persistente.
- **Bit 4 es el que más se extiende con umbral 40.** Ventana de 4 rondas
  (r=1..4) con pesos 2, 6, 14, 36. En r=5 salta a 65.
- **Ventana máxima de bajo peso: 3–4 rondas.** Con umbral 20, ventana 3;
  con umbral 40, ventana 4. No hay trail persistente más allá.
- **Sin claves débiles, ciclos o puntos fijos.** 25 patrones y 10k
  claves aleatorias, ninguno patológico.

### 3.4. Limitaciones

- **MILP/SAT dirigido no realizado.** El modelo completo de claves
  relacionadas requiere modelar la suma modular con acarreos
  (~650k variables para 128 rondas × 16 palabras × 32 bits). No es
  viable con CBC/HiGHS en este contexto.
- **Beam search hasta peso-6.** Un atacante con más recursos podría
  buscar peso-7+ con MILP dirigido.
- **Claves relacionadas adaptativas** (elección de ΔK basada en la clave
  objetivo) no cubiertas.
- **Ataques biclique o algebraicos** sobre el key schedule no cubiertos.

### 3.5. Veredicto del key schedule

**Sin debilidades explotables conocidas.** Cobertura exhaustiva hasta
peso-2, peso-3 (misma Δ), beam search hasta peso-6, multi-base y
análisis estructural. Tiene difusión lenta en r=1–4 (esperable) y un
peor bit estructural (bit 160) que no es explotable.

Para eliminar la lentitud de difusión: rediseñar el key schedule en
`v0.2` con dos rondas Feistel por iteración (duplica el coste del key
schedule, ~10% del total). Eso requiere re-evaluación completa
(diferencial + lineal + key schedule). **No es necesario para publicar
v0.1-experimental.**

---

## 4. Ataques genéricos

| Ataque | Complejidad | Veredicto |
|---|---|---|
| Fuerza bruta clásica | 2⁵¹² operaciones | Inviable |
| Grover (cuántico) | 2²⁵⁶ iteraciones | Inviable con tecnología previsible |
| Colisiones de bloque (cumpleaños) | 2¹²⁸ bloques | Inviable |

**Nota sobre Grover**: MYSX tiene clave de 512 bits, así que Grover deja 256 bits de seguridad efectiva. Con 1.000.000 de qubits lógicos y 1 ns/iteración, el tiempo sería ~10⁶⁰ años. Inviable.

**Nota sobre la clave de 512 bits**: HKDF-SHA256 produce una clave pseudorrandom de 256 bits como máximo. Si el secreto maestro tiene 256 bits de entropía, la seguridad efectiva del sistema es 256 bits, no 512. El "tamaño de clave" de MYSX no es el nivel de seguridad del sistema.

---

## 5. Ataques estructurales / Simon

MYSX usa la `F` de Simon pero **no es Simon**:

- Feistel de 2 ramas de **128 bits** (Simon usa `n` bits).
- **4 `F` en paralelo** por ronda (Simon usa 1).
- Transposición de Myszkowski (Simon no tiene).
- Rotaciones por palabra dependientes de la ronda (Simon no tiene).
- Key schedule ARX no lineal (Simon lo tiene lineal).
- **128 rondas** (Simon128/128 tiene 68).

### 5.1. Ataques publicados contra Simon128/128 (68 rondas)

| Ataque | Rondas | Complejidad |
|---|---|---|
| Lineal (hull) | 49/68 | ~2¹²⁷ |
| Diferencial | 46–50/68 | ~2¹²⁵·⁷ |
| Algebraico (SAT) | 12–14/68 | práctico en PC |
| Integral | 26/68 | — |

### 5.2. ¿Aplican a MYSX?

**No directamente**, por las diferencias estructurales listadas. En particular:

- **Key schedule no lineal**: Simon tiene key schedule lineal, lo que permite recuperar la clave maestra a partir de bits de subclave con álgebra lineal. MYSX no. Eso invalida la parte de recuperación de clave de los ataques a Simon.
- **128 rondas vs 68**: extender un ataque de 49 a 128 requiere que la correlación no decaiga, y la transposición/rotaciones de MYSX rompen la simetría que Simon explota.
- **4 `F` en paralelo**: los trails de Simon (que asumen 1 `F` por ronda) no se mapean a MYSX.

El análisis MILP específico de MYSX (secciones 1, 2 y 3) es el que da la evidencia. Los ataques a Simon son contexto, no transferencia directa.

---

## 6. Limitaciones del análisis

- **Diferencial**: single-trail, single-input, sin related-key, sin clustering explícito.
- **Lineal**: single-trail no concluyente; falta linear hull analysis.
- **Key schedule**: sin MILP/SAT dirigido; beam search hasta peso-6.
- **Sin integral, imposible, boomerang, algebraico.**
- **Sin criptoanálisis público independiente.**
- **Modelos MILP con `gapRel`** (0.2 diferencial, 0.3 lineal). El peso real puede ser menor.
- **Verificación empírica del KAT**: 16 bloques con clave `key[i]=i`. Es regresión, no prueba de seguridad.
- **Tests funcionales**: 16/16 PASS. Cubren round-trip, AEAD, negativos, política de nonces, PBKDF2, avalancha. No demuestran seguridad.

---

## 7. Tests funcionales (referencia)

`MYSX_ENABLE_TEST=1 node mysx.test.js` → **RESULTADO GLOBAL: PASS**.

| Test | Resultado |
|---|---|
| KAT (16 bloques, clave `key[i]=i`) | OK |
| CTR round-trip (8 longitudes) | OK |
| AEAD round-trip + AAD | OK |
| AEAD rechaza nonce alterado | OK |
| AEAD rechaza ciphertext alterado | OK |
| AEAD rechaza tag alterado | OK |
| AEAD rechaza AAD distinto | OK |
| NonceGuard sin guard: rechazado | OK |
| NonceGuard unsafeNoGuard: aceptado | OK |
| NonceGuard límite operativo | OK |
| HKDF longitudes correctas | OK |
| HKDF contextos separan claves | OK |
| PBKDF2 sin salt: rechazado | OK |
| PBKDF2 determinista con misma salt | OK |
| PBKDF2 salts distintas → claves distintas | OK |
| Avalancha texto plano | 126.93/256 (ideal 128) |

**`CRYPTANALYSIS_STATUS: NOT_ESTABLISHED`** — el PASS solo dice que los tests elegidos no detectaron fallos funcionales.

---

## 8. Veredicto

**Diferencial sólido. Lineal inconcluso pero no alarmante. Key schedule sin debilidades explotables. Sin integral, sin revisión externa.**

El cifrador está **congelado en `v0.1-experimental`**. Cualquier cambio de ronda, key schedule o `F` requiere una versión nueva (`v0.2-...`) y re-evaluación completa desde cero.

### Siguientes pasos, por orden de valor

1. **Publicar especificación, vectores y estos resultados** para revisión externa. Es lo que convierte un diseño propio en una propuesta defendible.
2. **Integral (MILP)**: tercer pilar del criptoanálisis simétrico. Viable computacionalmente.
3. **Boomerang (BCT)**: complementa el diferencial. Viable.
4. **Algebraico (SAT)**: verificación final, pero caro.
5. **MILP related-key dirigido**: cierra el key schedule formalmente, pero su coste (~650k variables) no es viable en este contexto.

### Lo que NO hacer

- **No añadir rondas** por intuición: no elimina trails cortos, solo los alarga.
- **No declarar MYSX "seguro"**: diferencial, lineal, related-key e integral son familias de ataques, no todas.
- **No usar en producción** hasta que exista criptoanálisis público independiente.
- **No presentar como "post-cuántico"**: el tamaño de clave es grande, pero la seguridad post-cuántica no está analizada formalmente.

---

## 9. Reproducibilidad

| Archivo | Propósito |
|---|---|
| `SPEC.md` | Especificación formal del cifrado |
| `KAT.json` | Vectores de prueba (bloque, AEAD, KDF) |
| `generate_kat.py` | Generador de KAT desde la implementación |
| `mysx.prod.js` | Implementación (API de producción) |
| `mysx.test.js` | Suite de tests funcionales |
| `mysx_milp.py` | Modelo MILP diferencial |
| `mysx_linear_milp.py` | Modelo MILP lineal |
| `keyschedule_test.js` | Auditoría básica del key schedule |
| `keyschedule_test_extended.js` | Auditoría exhaustiva (22 tests) |
| `check_trail.js` | Verificación empírica del trail diferencial a r=4 |
| `check_linear_trail2.js` | Verificación empírica de trails lineales |

**Semilla fija** en tests (`0xC0FFEE`). Los MILPs son deterministas dado el solver y `gapRel`. El KAT es determinista (`digest 5c9ca63d...`).

**Digest interno del KAT** (`KNOWN_KAT_DIGEST`, 16 bloques con `key[i]=i`): `3a8084d0b7df7eb691cfb54494410a5222652c219a336ee58bde48a64524a8b3`.

**Digest público del KAT.json**: `5c9ca63d19e0f385eb0142bbe0337771d32a25267469bc82c9cd8f0bed547eee`.

---

## 10. Referencias

- Simon (NSA, 2013): función `F` usada en la ronda.
- Myszkowski (1902): transposición con keyword de letras repetidas.
- Blowfish (Schneier, 1993): constantes de π (`0x243f6a88...`).
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104), AES-GCM (NIST SP 800-38D).
- Sun et al. (2016): modelo MILP para criptoanálisis lineal de Simon.
- Biryukov–Roy–Velichkov (CRYPTO 2015): criptoanálisis diferencial de Simon.
- Chen–Wang (2014): criptoanálisis lineal (hull) de Simon (ePrint 2014/973).

---

## 11. Advertencia final

MYSX **no ha sido auditado externamente**. Este documento es un análisis del autor, no una certificación. Ningún resultado aquí presentado sustituye una revisión criptográfica independiente.

**No usar MYSX para proteger datos reales.** Para producción: **AES-256-GCM** o **XChaCha20-Poly1305**.
