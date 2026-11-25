# Attack Surface Mapper — especificación viva

> **Borrador sin validar.** Lo generó un agente a partir del código y de la documentación: describe lo que hace el código en la referencia indicada, no reglas confirmadas por el mantenedor, que lo revisará la primera vez que se trabaje en esta área.

Referencia revisada: `origin/main` (`f7773bd`), 29 de agosto de 2026. Área inicial: perfiles de ejecución, clasificación de hallazgos y resultados.

## Perfiles y ejecución

- `passive-stealth` y `passive-recon-safe` solo recorren la superficie observada (GET al mismo host, sin Nuclei, Nmap ni rutas inventadas); `passive-recon-enum` añade enumeración de rutas comunes y Nuclei, y `active-aggressive`, Nmap y navegación dinámica. Siguen aceptándose nombres antiguos y, sin perfil, se aplica `normal`, que lanza Nuclei y enumeración. El target de la CLI se suma a los de `--targets-file` y del YAML, sin sustituirlos, y la lista se deduplica. [Perfiles](PROFILES.md) · [README](../README.md)
- Si Nuclei o Nmap están activos y no están en `PATH`, ese target falla y solo queda en `errors` del manifest; un fallo del descubrimiento no detiene el run. El proceso devuelve `1` si queda algún hallazgo `high` o `critical`, `2` si fallan todos los targets, `4` si falta la configuración indicada o no hay targets, y `0` en el resto, aunque fallen algunos targets. [Etapas](PIPELINE.md) · [CLI](../main.py)

## Hallazgos

- HTTP, navegación, Nuclei y Nmap comparten un modelo de hallazgo con `finding_id` y `correlation_id` deterministas. `finding_role` distingue `discovery` (inventario y contexto), `candidate` y `validated`, que exige `verification_status: confirmed`: un descubrimiento no se presenta como vulnerabilidad confirmada. [Arquitectura](ARCHITECTURE.md) · [Contratos de salida](OUTPUTS.md)
- La etiqueta de prioridad sale de `priority_score` (0–100, con el cálculo en `priority_reason`): `critical` desde 85, `high` desde 60 y `medium` desde 30. El descubrimiento, la documentación de API, las cabeceras y los puertos web estándar de Nmap tienen tope, y sumar fuentes solo sube la prioridad con confirmación o confianza alta. [Cálculo de prioridad](../src/attack_surface_mapper/analysis/enrichment.py)

## Resultados

- Cada run deja en `scans/<nombre o fecha>/` un manifest (perfil, configuración efectiva, etapas, superficie observada y errores), informes agregados y, por target, hallazgos, informes y artefactos crudos, que deben tratarse como datos sensibles. Los informes separan riesgo de aplicación, superficie a revisar, higiene, servicios de red y descubrimiento; el agregado lista como máximo 50 hallazgos y el detalle completo queda en cada target. [Contratos de salida](OUTPUTS.md) · [Estructura](STRUCTURE.md)
- `--compare` contrasta con un `vulnerabilities.json` anterior, el mismo para todos los targets del run, y marca hallazgos nuevos, resueltos, promovidos o regresados, también cuando solo cambia `priority_score`. [CHANGELOG](../CHANGELOG.md)
- Los resultados se quedan en el disco del operador: [export_elasticsearch_bundle.py](../scripts/export_elasticsearch_bundle.py) prepara aparte, desde un run terminado, mappings, NDJSON `_bulk` y ayudas de ingesta, sin enviar nada ni exportar `raw`. Cada hallazgo usa su `finding_id` como `_id`, así que indexar otro run con el mismo prefijo lo sustituye en vez de acumular historial. [Arquitectura](ARCHITECTURE.md) · [Guía rápida](../QUICK_DEMO.md)

## Sustituido

| Antes | Ahora | Cambio y fecha |
| --- | --- | --- |
| `passive-recon` era el reconocimiento con enumeración | Se separa en `passive-recon-safe` y `passive-recon-enum`; `passive-recon` queda como alias del segundo | v10.22.2 ([CHANGELOG](../CHANGELOG.md)) |
| `/graphql`, `/swagger` o `/api-docs` accesibles eran fallos de autorización y `Swagger UI Exposed` podía llegar a `critical` | Son superficie `api`, con tope `medium` salvo evidencia más fuerte | `d1951a5` y `df6e969`, 8 de abril de 2026 |
| La prioridad era una etiqueta sin puntuación, calculada desde la severidad | `priority_score` con `scoring_version`; la etiqueta sale de la puntuación | `c89f5e0`, 10 de abril de 2026 |

## Pendiente

- **En duda:** según el [CHANGELOG](../CHANGELOG.md), con `--use-nmap` y sin Nmap instalado el resultado se mantiene con un aviso; el código hace fallar el target entero.
- **En duda:** `--profile` usa los valores de la [CLI](../main.py) y no lee [config/profiles](../config/profiles), cuyos YAML añaden targets de laboratorio locales y, en los perfiles con Nuclei, plantillas propias; además, la [guía rápida](../QUICK_DEMO.md) presenta `--profile active` como modo agresivo con Nmap, pero solo `active-aggressive` lo activa. Falta decidir qué definición manda.
- **En duda:** [SECURITY.md](../SECURITY.md) exige escanear solo sistemas autorizados, pero la [guía rápida](../QUICK_DEMO.md) lanza el perfil por defecto contra `https://example.com/` y [config.example.yml](../config/examples/config.example.yml), que propone el [README](../README.md), añade Nmap (`-sC`) y Nuclei contra ese dominio.
- **En duda:** [OUTPUTS.md](OUTPUTS.md) cita `stages_executed` y `collectors_used` en el manifest, pero el código escribe `pipeline.stages` y `pipeline.collectors`.
