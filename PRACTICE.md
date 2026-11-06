# Guía práctica / Practice guide

Ejercicios **offline y locales** sobre este modelo. No interactúan con
ninguna red, host, laboratorio ni plataforma; no hay nada que "explotar".
El objetivo es entender por qué Terrapin funciona y por qué strict KEX lo
detiene, leyendo y modificando código que corre en tu máquina.

*English summary at the end.*

## Objetivos

1. Explicar con el código por qué inyectar N mensajes antes de NEWKEYS y
   borrar N después deja los contadores alineados (`src/model.rs`,
   `Sender::send`, `Receiver::receive`).
2. Distinguir las dos contramedidas de OpenSSH: (a) rechazo de paquetes
   inesperados en el KEX inicial y (b) reset de la secuencia en cada NEWKEYS.
3. Entender por qué la negociación es bilateral y solo cuenta el KEXINIT
   inicial.
4. Ver por qué un vínculo tipo AES-GCM (contador por clave) no es afectado.
5. Escribir escenarios y tests propios con veredictos calculados, no fijados.

## Prerrequisitos

- Rust estable (probado con rustc 1.99.1) y `cargo`.
- Lectura: RFC 4253 §6.4 y §8; sección "strict key exchange extension" de
  OpenSSH PROTOCOL (tag V_9_6_P1); notas de OpenSSH 9.6. Enlaces en
  [SOURCES.md](SOURCES.md).

## Comandos locales

```sh
cargo test                                   # todos los tests
cargo run --release --bin terrapin-model -- run fixtures/scenarios/04_terrapin_legacy_seqbound.json
cargo run --release --bin terrapin-model -- matrix fixtures/scenarios fixtures/sweep /tmp/out
diff -r results /tmp/out && (cd results && sha256sum -c SHA256SUMS)
```

El campo `trace` de `run` muestra, paso a paso, `recv_seq_before`,
`recv_seq_after`, fase y acción del receptor.

## Ejercicios graduados

**Nivel 1 — leer la traza.**
Ejecuta `run` sobre `01_benign_legacy` y `04_terrapin_legacy_seqbound`.
Compara `recv_seq_before` del primer paquete cifrado en ambos. ¿Por qué en
04 el receptor espera 4 y el paquete que llega (`ServiceAccept`) fue enviado
con 4? Respuesta en `Sender::send` y en la operación `drop`.

**Nivel 2 — contar.**
Copia 04 a un archivo nuevo e inyecta dos mensajes (`Ignore` y `Debug`) con
`inject_before` índice 1, y borra los índices 3 y 4. Predice el veredicto
antes de ejecutar. Luego inyecta dos y borra uno. Verificado en
`tests/practice.rs`: 2/2 → `silent_truncation` (pierde 3 y 4); 2/1 →
`detected`.

**Nivel 3 — dónde se puede cortar.**
Mueve el `drop` al índice 5 (no es el primer paquete cifrado). Mueve la
inyección al índice 2 (justo antes de NEWKEYS). ¿Qué cambia? Compara con la
frase de las notas de 9.6: "deleting an equal number of consecutive messages
immediately after encryption starts". Verificado: drop 5 → `detected`;
inyección en 2 → `silent_truncation`.

**Nivel 4 — contramedidas por separado.**
Con strict en ambos lados, inyecta `Debug` en vez de `Ignore`. Después usa
las configuraciones de `07_terrapin_strict_a_only` y `08_terrapin_strict_b_only`.
Explica qué rama de `Receiver::receive` termina la conexión en cada caso.
Verificado: `Debug` bajo strict → `StrictUnexpectedDuringInitialKex`.

**Nivel 5 — negociación.**
Estudia 09, 10, 11, 12 y 15. Escribe en una frase por qué un solo lado con
soporte no basta, y por qué un marcador en un re-KEXINIT no activa strict.
Encuentra la línea de `Sender`/`Receiver` que lo garantiza.

**Nivel 6 — interoperabilidad.**
Abre `results/sweep.csv` y filtra `base=sweep_base_benign_rekey`. Explica los
8 `false_abort`: ¿qué pares de configuraciones son y por qué la contramedida
(b) tiene que aplicarse en ambos extremos? Recuerda que esos pares son
contrafactuales a propósito (un lado con (b) desactivada): no describen strict
KEX conforme ni un defecto de la especificación.

**Nivel 7 — extender el modelo (código).**
Agrega a `Msg` un mensaje nuevo válido "en cualquier momento" (por ejemplo
`Ping`, código 192 en PROTOCOL). Decide si `is_any_time` debe incluirlo,
agrega un escenario y su entrada en `fixtures/expected.json`, y un test. Los
tests existentes deben seguir pasando.

**Nivel 8 — aplicación defensiva.**
Escribe una función pura que, dadas dos `EndpointCfg`, devuelva si el par es
(i) vulnerable a la edición de 04, (ii) protegido, (iii) incompatible tras un
re-intercambio. Valídala contra `results/sweep.csv` en un test.

## Vínculo entre el modelo y CVE-2023-48795

| CVE / protocolo real | Modelo |
|---|---|
| Número de secuencia implícito `uint32` en el MAC (RFC 4253 §6.4) | `Sender.send_seq`, `Receiver.recv_seq`, `Tag::Seq` |
| ChaCha20-Poly1305 / EtM usan esa secuencia | `CipherBinding::SeqBound` |
| AES-GCM usa contador de invocación (RFC 5647 §7.1) | `CipherBinding::InvocationCounter` |
| MitM inyecta antes de NEWKEYS y borra después | `AttackOp::InjectBefore` + `AttackOp::Drop` |
| EXT_INFO borrado sin detección | fixture 04, `lost_honest_indices = [3]` |
| strict KEX (a) y (b) | `EndpointCfg.reject_unexpected`, `EndpointCfg.reset_seq` |
| KEXINIT en el hash H | flag `tampered` → `ExchangeHashMismatch` |

Lo que el modelo **no** es: no ejecuta SSH, no prueba ninguna
implementación, y no sirve para atacar conexiones reales. Ver
[LIMITATIONS.md](LIMITATIONS.md).

---

## English summary

Offline, local exercises only; nothing here touches a network, host, lab or
platform. Goals: explain counter alignment under inject-N/drop-N, separate
countermeasures (a) and (b), understand bilateral initial-only negotiation,
see why a per-key invocation counter is unaffected, and write your own
scenarios with computed verdicts.

Levels: (1) read the trace of fixtures 01 vs 04; (2) inject 2 / drop 2
(silent) vs inject 2 / drop 1 (detected); (3) drop a non-first encrypted
packet (detected) and move the injection to just before NEWKEYS (silent);
(4) `Debug` under strict, then (a)-only and (b)-only; (5) negotiation
fixtures 09–12 and 15; (6) explain the 8 benign `false_abort` rows in
`results/sweep.csv` (deliberately asymmetric counterfactual pairs, not a
strict-KEX defect); (7) add a new any-time message type with scenario,
expectation and test; (8) write a pure pair classifier and validate it
against the sweep. Claims for levels 2–4 are checked by `tests/practice.rs`.
The mapping table above links each real CVE element to the model code.
