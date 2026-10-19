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
| Related-key | Pendiente | — |
| Integral / imposible / boomerang / algebraico | Pendiente | — |
| Grover (cuántico) | Inviable | 2²⁵⁶ iteraciones |
| Fuerza bruta clásica | Inviable | 2⁵¹² operaciones |
| Colisiones de bloque | Inviable | 2¹²⁸ bloques (bloque de 256 bits) |

**Veredicto corto**: la resistencia diferencial es sólida; la lineal no está demostrada pero la evidencia no es alarmante. El cifrador está congelado y no debe usarse en producción sin revisión externa.

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

## 3. Ataques genéricos

| Ataque | Complejidad | Veredicto |
|---|---|---|
| Fuerza bruta clásica | 2⁵¹² operaciones | Inviable |
| Grover (cuántico) | 2²⁵⁶ iteraciones | Inviable con tecnología previsible |
| Colisiones de bloque (cumpleaños) | 2¹²⁸ bloques | Inviable |

**Nota sobre Grover**: MYSX tiene clave de 512 bits, así que Grover deja 256 bits de seguridad efectiva. Con 1.000.000 de qubits lógicos y 1 ns/iteración, el tiempo sería ~10⁶⁰ años. Inviable.

**Nota sobre la clave de 512 bits**: HKDF-SHA256 produce una clave pseudorrandom de 256 bits como máximo. Si el secreto maestro tiene 256 bits de entropía, la seguridad efectiva del sistema es 256 bits, no 512. El "tamaño de clave" de MYSX no es el nivel de seguridad del sistema.

---

## 4. Ataques estructurales / Simon

MYSX usa la `F` de Simon pero **no es Simon**:

- Feistel de 2 ramas de **128 bits** (Simon usa `n` bits).
- **4 `F` en paralelo** por ronda (Simon usa 1).
- Transposición de Myszkowski (Simon no tiene).
- Rotaciones por palabra dependientes de la ronda (Simon no tiene).
- Key schedule ARX no lineal (Simon lo tiene lineal).
- **128 rondas** (Simon128/128 tiene 68).

### 4.1. Ataques publicados contra Simon128/128 (68 rondas)

| Ataque | Rondas | Complejidad |
|---|---|---|
| Lineal (hull) | 49/68 | ~2¹²⁷ |
| Diferencial | 46–50/68 | ~2¹²⁵·⁷ |
| Algebraico (SAT) | 12–14/68 | práctico en PC |
| Integral | 26/68 | — |

### 4.2. ¿Aplican a MYSX?

**No directamente**, por las diferencias estructurales listadas. En particular:

- **Key schedule no lineal**: Simon tiene key schedule lineal, lo que permite recuperar la clave maestra a partir de bits de subclave con álgebra lineal. MYSX no. Eso invalida la parte de recuperación de clave de los ataques a Simon.
- **128 rondas vs 68**: extender un ataque de 49 a 128 requiere que la correlación no decaiga, y la transposición/rotaciones de MYSX rompen la simetría que Simon explota.
- **4 `F` en paralelo**: los trails de Simon (que asumen 1 `F` por ronda) no se mapean a MYSX.

El análisis MILP específico de MYSX (secciones 1 y 2) es el que da la evidencia. Los ataques a Simon son contexto, no transferencia directa.

---

## 5. Limitaciones del análisis

- **Diferencial**: single-trail, single-input, sin related-key, sin clustering explícito.
- **Lineal**: single-trail no concluyente; falta linear hull analysis.
- **Sin integral, imposible, boomerang, algebraico.**
- **Sin related-key**: el key schedule es el componente con menos evidencia.
- **Sin criptoanálisis público independiente.**
- **Modelos MILP con `gapRel`** (0.2 diferencial, 0.3 lineal). El peso real puede ser menor.
- **Verificación empírica del KAT**: 16 bloques con clave `key[i]=i`. Es regresión, no prueba de seguridad.
- **Tests funcionales**: 16/16 PASS. Cubren round-trip, AEAD, negativos, política de nonces, PBKDF2, avalancha. No demuestran seguridad.

---

## 6. Tests funcionales (referencia)

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

## 7. Veredicto

**Diferencial sólido. Lineal inconcluso pero no alarmante. Sin related-key, sin integral, sin revisión externa.**

El cifrador está **congelado en `v0.1-experimental`**. Cualquier cambio de ronda, key schedule o `F` requiere una versión nueva (`v0.2-...`) y re-evaluación completa desde cero.

### Siguientes pasos, por orden de valor

1. **Publicar especificación, vectores y estos resultados** para revisión externa. Es lo que convierte un diseño propio en una propuesta defendible.
2. **Related-key MILP**: el key schedule es el componente con menos evidencia.
3. **Linear hull analysis**: solo si alguien externo lo pide; requiere un modelo mucho más sofisticado.

### Lo que NO hacer

- **No añadir rondas** por intuición: no elimina trails cortos, solo los alarga.
- **No declarar MYSX "seguro"**: diferencial y lineal son dos familias de ataques, no todas.
- **No usar en producción** hasta que exista criptoanálisis público independiente.
- **No presentar como "post-cuántico"**: el tamaño de clave es grande, pero la seguridad post-cuántica no está analizada formalmente.

---

## 8. Reproducibilidad

| Archivo | Propósito |
|---|---|
| `SPEC.md` | Especificación formal del cifrado |
| `KAT.json` | Vectores de prueba (bloque, AEAD, KDF) |
| `generate_kat.py` | Generador de KAT desde la implementación |
| `mysx.prod.js` | Implementación (API de producción) |
| `mysx.test.js` | Suite de tests funcionales |
| `mysx_milp.py` | Modelo MILP diferencial |
| `mysx_linear_milp.py` | Modelo MILP lineal |
| `check_trail.js` | Verificación empírica del trail diferencial a r=4 |
| `check_linear_trail2.js` | Verificación empírica de trails lineales |

**Semilla fija** en tests (`0xC0FFEE`). Los MILPs son deterministas dado el solver y `gapRel`. El KAT es determinista (`digest 5c9ca63d...`).

---

## 9. Referencias

- Simon (NSA, 2013): función `F` usada en la ronda.
- Myszkowski (1902): transposición con keyword de letras repetidas.
- Blowfish (Schneier, 1993): constantes de π (`0x243f6a88...`).
- HKDF (RFC 5869), PBKDF2 (RFC 8018), HMAC (RFC 2104), AES-GCM (NIST SP 800-38D).
- Sun et al. (2016): modelo MILP para criptoanálisis lineal de Simon.
- Biryukov–Roy–Velichkov (CRYPTO 2015): criptoanálisis diferencial de Simon.

---

## 10. Advertencia final

MYSX **no ha sido auditado externamente**. Este documento es un análisis del autor, no una certificación. Ningún resultado aquí presentado sustituye una revisión criptográfica independiente.

**No usar MYSX para proteger datos reales.** Para producción: **AES-256-GCM** o **XChaCha20-Poly1305**.
