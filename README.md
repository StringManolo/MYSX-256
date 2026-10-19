# MYSX-256/512

Cifrado por bloques experimental de 256 bits de bloque y 512 bits de clave.
Diseño propio, **no auditado externamente**. **No usar en producción.**

## Estado

| Aspecto | Estado |
|---|---|
| Especificación | [SPEC.md](SPEC.md) |
| Vectores de prueba | [KAT.json](KAT.json) |
| Análisis de seguridad | [SECURITY.md](SECURITY.md) |
| Criptoanálisis diferencial | Validado (margen ~113 rondas) |
| Criptoanálisis lineal | Inconcluso (no alarmante) |
| Related-key | Validado |
| Revisión externa | No realizada |
| Versión | `v0.1-experimental` (congelada) |

## Advertencia

**No uses MYSX para proteger datos reales.** Para producción, usa
AES-256-GCM o XChaCha20-Poly1305. MYSX existe como propuesta de
investigación y como ejercicio didáctico.

## Qué es

MYSX es una red de Feistel de 2 ramas de 128 bits con:

- **Bloque**: 256 bits (8 palabras de 32 bits).
- **Clave**: 512 bits (16 palabras de 32 bits).
- **Rondas**: 128.
- **No linealidad**: `F(x) = (rotl(x,1) ∧ rotl(x,8)) ⊕ rotl(x,2)` (función de Simon).
- **Difusión**: transposición de Myszkowski (keyword `MYSZKOWS`) + rotaciones por palabra.
- **Key schedule**: ARX biyectivo (Feistel 8+8).
- **Whiten final**: XOR con 8 palabras derivadas del key schedule.

El diseño prioriza simplicidad estructural (sin S-boxes, sin tablas)
sobre eficiencia. La seguridad se basa en el número de rondas y en la
difusión de Myszkowski + rotaciones.

## Estructura del repositorio
```
.
├── README.md
├── SPEC.md                    # Especificación formal
├── SECURITY.md                # Análisis de seguridad
├── KAT.json                   # Vectores de prueba
├── generate_kat.py            # Script para regenerar KAT.json
├── mysx.prod.js               # Implementación (API de producción)
├── mysx.test.js               # Suite de tests
├── mysx_milp.py               # Modelo MILP diferencial
├── mysx_linear_milp.py        # Modelo MILP lineal
├── check_trail.js             # Verificación empírica diferencial
└── check_linear_trail2.js     # Verificación empírica lineal
```

## Uso (solo para investigación)

```javascript
const { aeadEncrypt, aeadDecrypt, deriveAeadKeys, NonceGuard } = require('./mysx.prod.js');

const master = crypto.getRandomValues(new Uint8Array(32));
const { encKey, macKey } = await deriveAeadKeys(master, { context: 'demo' });
const guard = new NonceGuard();

const plaintext = new TextEncoder().encode('hola mundo');
const packet = await aeadEncrypt(plaintext, encKey, macKey, { nonceGuard: guard });
const recovered = await aeadDecrypt(packet, encKey, macKey);
```

## Reproducir los resultados

```bash
# Tests funcionales + KAT
MYSX_ENABLE_TEST=1 node mysx.test.js

# Análisis diferencial
python3 mysx_milp.py --rounds 1-14 --input-bit 0

# Análisis lineal
python3 mysx_linear_milp.py --rounds 1-10

# Verificación empírica de trails
node check_trail.js          # trail diferencial a r=4
node check_linear_trail2.js  # trail lineal a r=3
```

