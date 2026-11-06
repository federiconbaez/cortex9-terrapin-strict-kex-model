# cortex9-terrapin-strict-kex-model

[English](README.md)

Modelo de estados abstracto y ejecutable del vínculo entre el número de
secuencia del transporte SSH y las dos contramedidas "strict KEX" de OpenSSH,
para razonar sobre el ataque de truncamiento de prefijo Terrapin
(CVE-2023-48795).

**Es un modelo, no una reproducción de CVE-2023-48795.** No hay sockets, ni
intercambio de claves real, ni cifrados o MAC reales, y no puede apuntarse a
ningún host. Ver [LIMITATIONS.md](LIMITATIONS.md).

## Qué se modela

- Emisor y receptor por dirección, cada uno con un número de secuencia
  `uint32` que empieza en 0, se incrementa tras cada paquete y da la vuelta en
  2^32 (RFC 4253 §6.4).
- Dos vínculos de cifrado:
  - `SeqBound`: tras NEWKEYS, un paquete solo verifica si la secuencia del
    emisor coincide con la del receptor (representa ChaCha20-Poly1305 / MAC
    EtM que usan la secuencia implícita).
  - `InvocationCounter`: contador por clave puesto a 0 en NEWKEYS e
    incrementado por paquete cifrado (representa AES-GCM, RFC 5647 §7.1).
- Negociación strict-KEX: cada lado agrega su marcador solo en el KEXINIT
  **inicial**; un extremo activa strict solo si ve el marcador del **par** en
  el KEXINIT **inicial** del par. Los marcadores en KEXINIT posteriores se
  ignoran.
- Contramedida (a): durante el KEX inicial, terminar ante cualquier paquete
  inesperado o fuera de secuencia, incluidos IGNORE/DEBUG, y si el primer
  paquete no es KEXINIT.
- Contramedida (b): poner la secuencia a 0 tras enviar o recibir NEWKEYS, en
  **cada** NEWKEYS.
- Cada contramedida se puede desactivar por separado; la variante defectuosa
  `reset_seq_first_only` solo reinicia en el primer NEWKEYS.
- Manipular un KEXINIT (p. ej. quitar un marcador) se detecta en la respuesta
  del intercambio, abstrayendo que ambos KEXINIT entran en el hash H
  (RFC 4253 §8).

Los veredictos se **calculan** a partir de las transiciones del receptor y de
los paquetes legítimos de capa superior no entregados: `intact`,
`silent_truncation`, `silent_modification`, `detected` y `false_abort` (sin
atacante, conexión terminada). El modelo nunca lee el resultado esperado
(`fixtures/expected.json` solo lo leen los tests).

## Uso

```sh
cargo test
cargo run --release --bin terrapin-model -- matrix fixtures/scenarios fixtures/sweep results
(cd results && sha256sum -c SHA256SUMS)
```

## Resultados

La tabla completa está en [README.md](README.md#results-generated-resultsscenarioscsv)
y en `results/scenarios.csv`. Resumen del barrido contrafactual
(`results/sweep.csv`, 100 filas):

- Ataque, `SeqBound`: 14 detectados, 11 truncamientos silenciosos (9 con algún
  lado `legacy`; 2 donde el cliente receptor no tiene ninguna contramedida y
  el servidor tampoco reinicia).
- Ataque, `InvocationCounter`: 25/25 detectados.
- Benigno con un re-intercambio, `SeqBound`: 17 intactos, 8 `false_abort`,
  exactamente los pares donde un lado reinicia la secuencia y el otro no.
- Benigno, `InvocationCounter`: 25/25 intactos.

Estas cifras describen solo el modelo; no son mediciones de ninguna
implementación SSH.

## Licencia

Apache-2.0. Ver [LICENSE](LICENSE).
