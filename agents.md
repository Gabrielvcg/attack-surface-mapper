# Attack Surface Mapper - Agent Context

## Proyecto

Este proyecto es una herramienta Python 3.11+ para mapear superficie de ataque web y de servicios expuestos. Combina:

- Nuclei para checks por plantillas.
- Nmap opcional para descubrimiento de puertos/servicios.
- Validadores HTTP propios para headers, TLS, fingerprinting, paneles, autenticacion, API, ficheros sensibles y secretos.
- Crawling y browser discovery con backends `requests`, `scrapling` o `auto`.
- Correlacion, enriquecimiento, deduplicacion y reporting por target y agregado.

El paquete principal vive en `src/attack_surface_mapper`. `main.py` es la CLI y tambien ajusta `sys.path` para usar el paquete local.

## Arquitectura Actual

La ejecucion se organiza como pipeline:

1. `NucleiStage`
2. `NmapStage`
3. `BrowserDiscoveryStage`
4. `PassiveValidationStage`
5. `CorrelationStage`
6. `ReportingStage`

`ScanOrchestrator` en `src/attack_surface_mapper/orchestrator.py` es una fachada de compatibilidad que construye `ScanSettings` y `ScanOutputs`, y delega en `ScanPipeline`.

`ScanContext` es el estado compartido entre etapas. Guarda settings, outputs, artifacts, debug, findings, URLs observadas, acciones observadas y llamadas API observadas.

## Flujo de CLI

`main.py`:

- Define `PROFILE_DEFAULTS`.
- Lee argumentos CLI y YAML (`config/profiles` y `config/examples`).
- Resuelve targets desde argumento posicional, `--targets-file` y YAML.
- Construye directorios bajo `scans/<run_name_or_timestamp>/`.
- Ejecuta targets en paralelo con `ThreadPoolExecutor`.
- Escribe `run_manifest.json`.
- Genera informes agregados con `write_aggregate_reports`.
- Devuelve `1` si hay findings `critical` o `high`, `2` si hay errores sin resultados, `0` si todo queda sin altos/criticos.

Importante: si se pasa target por CLI, convive con targets de YAML en `resolve_targets`; el README dice "override", pero el codigo acumula y deduplica.

## Perfiles Operativos

Perfiles relevantes en `config/profiles`:

- `passive-stealth`: bajo ruido, sin Nuclei/Nmap, `observed_only`, sin baseline probe, crawler corto y sin JS. Aun deja `secrets: true` en YAML, pero `observed_only` evita secrets si no hay crawling extra en la etapa pasiva.
- `passive-recon-safe`: navegacion segura GET-only, JS hints, sin enumeracion hardcoded, `observed_only: true`, sin Nuclei/Nmap.
- `passive-recon-enum`: enumeracion GET-only visible, baseline probe, auth/API/panels/sensitive files/secrets activos, Nuclei passive, sin Nmap.
- `passive-recon`: alias de compatibilidad hacia `passive-recon-enum`.
- `active-aggressive`: maxima cobertura, Nuclei, Nmap, Scrapling dynamic, modo HTTP active.

La idea central del proyecto es controlar el trade-off stealth vs coverage vs signal quality.

## Componentes Clave

- `http_client.py`: sesiones HTTP `RequestsHttpSession` y `ScraplingHttpSession`, trazas debug thread-local, normalizacion de headers, delays ligeros en modo pasivo, fallback a `requests` si `auto` no puede inicializar Scrapling.
- `validators/crawler.py`: crawler simple BFS same-host, prioriza enlaces de alto valor, ignora estaticos salvo JS/include_static, fallback interno de Scrapling a requests ante errores de transporte.
- `collectors/crawling/browser_discovery.py`: convierte documentos crawleados en `observed_urls`, `observed_actions` y `observed_api_calls`; separa API-like URLs de navegacion observada.
- `validators/discovery.py`: analiza documentos HTML/JS, extrae forms, rutas candidatas, panel/api/auth paths, JS hints y findings de discovery.
- `validators/http_fingerprint.py`: baseline random path y comparacion anti-fallback para reducir falsos positivos.
- `validators/auth_validator.py`: cookies, endpoints protegidos `401/403`, superficies sensibles accesibles, y reduccion de falsos positivos de login/register publico.
- `validators/api_validator.py`: CORS wildcard y docs/API GraphQL/Swagger/OpenAPI con scoring contra baseline.
- `validators/panels_validator.py`: paneles/metrics/actuator/swagger/login con scoring y filtro de login surface.
- `validators/sensitive_files_validator.py`: `.env`, `.git/HEAD`, configs, backups, robots/sitemap, etc.; requiere firmas por tipo.
- `validators/secrets_validator.py`: patrones para API keys, JWT, AWS, GitHub, Google, Slack y private keys en documentos crawleados.
- `validators/fingerprint_validator.py`: tecnologias probables por headers/body: Apache, Nginx, IIS, Express, PHP, Django, Spring Boot, WordPress, Next.js, Angular, React, Vue.
- `parsers/nuclei_parser.py`: JSONL a `Vulnerability`, raw compacto con redaccion y categoria inferida.
- `parsers/nmap_parser.py`: XML Nmap a `Vulnerability`, categorias de servicios, priorizacion de web standard vs DB/brokers/admin/remote-access, filtro de falsos positivos en target HTTP con puerto explicito.
- `analysis/enrichment.py`: calcula `priority`, `confidence`, `recommendation`, `evidence_summary`, `kind` y asset normalization.
- `analysis/correlation.py`: agrupa findings por `correlation_key`, mergea fuentes, agrupa API endpoints y referencias API cliente.
- `reporting/generator.py`: markdown/html/csv/summary/comparison por target, separando confirmados, plausibles, red y discovery.
- `batch/aggregate.py`: reporting agregado, agrupa servicios de red compartidos por asset host/port, separa shared assets, target-specific, network y discovery.

## Modelo de Hallazgo

`Vulnerability` es el modelo comun. Campos importantes:

- Identidad: `source`, `title`, `template_id`, `matcher_name`, `matched_at`, `target`.
- Clasificacion: `severity`, `priority`, `category`, `confidence`, `verification_status`, `kind`.
- Evidencia: `evidence`, `evidence_summary`, `raw`.
- Correlacion: `source_count`, `related_sources`, `related_titles`, `related_targets`, `related_evidence`.
- Activo: `host`, `port`, `scheme`, `target_host_original`, `asset_host`, `asset_port`.

`dedup_key()` deduplica dentro del stage de correlacion antes de enriquecer. `correlation_key()` agrupa por categorias semanticas como `/metrics`, Swagger/OpenAPI, GraphQL, admin, login, API surface y discovery.

## Outputs

Cada run crea:

- `scans/<run>/run_manifest.json`
- `scans/<run>/reports/aggregate_summary.json`
- `scans/<run>/reports/aggregate_report.md`
- `scans/<run>/reports/aggregate_findings.csv`
- `scans/<run>/targets/<slug>/findings/vulnerabilities.json`
- `scans/<run>/targets/<slug>/reports/report.md|html|csv|summary.json|comparison.json`
- `scans/<run>/targets/<slug>/artifacts/nuclei_raw.jsonl`
- `scans/<run>/targets/<slug>/artifacts/nmap_raw.xml`
- `scans/<run>/targets/<slug>/debug/debug_*` si `--debug`

`run_manifest.json` captura stages, collectors, observed URLs, actions count, API calls y conteos por target.

## Testing

Tests en `tests/` cubren regresiones desde v7 hasta v10.22.5:

- parsing Nuclei/Nmap
- enrichment/correlation/reporting
- reduccion de falsos positivos en SPAs/fallbacks
- auth/API/panels/sensitive files
- Scrapling mapper y fallback a requests
- discovery pipeline, formularios y JS hints
- perfiles v10.22
- limpieza del manifest y separacion de observed API calls
- refinamiento de login/register surfaces

Comandos utiles:

```bash
python -m pytest
python -m pytest tests/test_v10_22_5_auth_surface_refinement.py
python -m py_compile main.py $(find src -name '*.py')
```

Estado verificado el 2026-04-07:

- `python -m py_compile main.py $(find src -name '*.py')` pasa sin errores.
- `python -m pytest` da `64 passed` tras los ajustes de reduccion de falsos positivos en headers, CORS, paneles, cookies y ficheros sensibles.

El proyecto es un repo Git local con remoto `origin` en `git@github.com:Gabrielvcg/attack-surface-mapper.git`.

## Precauciones Conocidas

- No editar `.venv`, `__pycache__`, `.pytest_cache` ni outputs bajo `scans/` salvo que se pida.
- `Nuclei` y `Nmap` son herramientas externas; tests unitarios suelen mockear o probar parsers.
- `Playwright` solo hace falta para Scrapling dynamic/active.
- Mantener bajo ruido en perfiles passive: evitar probes inventados cuando `observed_only` es true.
- Mantener separadas URLs navegadas (`observed_urls`) y referencias API pasivas (`observed_api_calls`).
- El codigo actual tiene tests que parecen desalineados con cambios de naming: algunos esperan `API Hint Discovered In Client-Side Content`, mientras el changelog v10.22.4 y el codigo usan `Client-Side API Reference Observed`.
- Revisar regresiones antes de tocar discovery/auth/manifest; hay tests especificos para API references, `entry_response` opcional y redirects de `/admin` a login.
- `README` afirma que el target CLI sobrescribe YAML, pero `resolve_targets` actualmente acumula targets y deduplica.
- `config/examples/passive-extended.yml` usa `profile: passive-extended`, pero `PROFILE_DEFAULTS` no lo contiene; si se usa, cae a defaults de `normal` salvo que YAML aporte settings concretos.

## Estilo de Cambios

- Preferir patrones existentes: dataclasses, listas de `Vulnerability`, helpers de baseline/fingerprint y scoring heuristico.
- Para nuevas detecciones, incluir `category`, `confidence`, `verification_status`, `needs_manual_validation` si aplica, `recommendation` si es especifica y tests de falso positivo.
- Para cambios de perfiles, actualizar YAML, docs y tests.
- Para cambios de output/reporting, revisar target report y aggregate report.
- Mantener copy de informes en espanol, como el proyecto existente.
