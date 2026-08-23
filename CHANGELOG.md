# Attack Surface Mapper

## v10.22.9 quality hardening

- Repairs corrupted UTF-8 text in API/auth validation evidence so generated Spanish reports remain readable and professional.
- Adds a minimal GitHub Actions quality gate for source compilation and the full pytest suite.
- Adds a regression test that rejects mojibake markers in Python source files.
- Aligns the package name, version and description with the public project identity.
- Repairs legacy changelog encoding so the project history is readable.

## v10.22.8 polish

- Añade un exportador independiente de Elasticsearch (`scripts/export_elasticsearch_bundle.py`) que empaqueta findings, summaries y run manifest desde un run ya generado sin tocar el pipeline principal.
- Genera mappings estables, NDJSON `_bulk` y helpers de ingesta para las tres vías pedidas por el tutor: manual/Kibana Dev Tools, `curl` y Python.
- Reutiliza el contrato actual del hallazgo (`finding_id`, `correlation_id`, `priority_score`, `finding_role`, `validated`, `validation_basis`, etc.) y evita exportar `raw` completo para mantener los índices más estables.

- Introduce un scoring estructurado (`scoring_version`, `priority_score`) basado en severidad, confianza, rol del hallazgo y base de validación, manteniendo la salida `low/medium/high/critical` pero haciéndola más estable y auditable.
- Expone el score numérico y su razón en reportes, CSV, agregados y matriz de revisión para facilitar comparativas futuras e ingest estructurado.
- Ajusta `comparison.json` para detectar cambios en `priority_score` aunque la etiqueta de prioridad no cambie, mejorando el seguimiento fino entre runs.

- Introduce una capa de validación explícita en el modelo de hallazgo con `finding_role`, `validated` y `validation_basis`, separando mejor descubrimiento, candidatos y evidencia validada.
- Propaga esa semántica a `report.summary.json`, `aggregate_summary.json`, `comparison.json` y la matriz de revisión para dejar el output estructurado más estable y más honesto.
- Mantiene compatibilidad con hallazgos previos o JSON legacy: reporting, agregado y comparación infieren el rol de validación cuando el campo nuevo todavía no existe.
- Amplía el golden set y la exportación de revisión con `finding_role`, `validated` y `validation_basis` para afinar falsos positivos con una semántica más clara.

- Conserva el `debug_http_trace` de browser discovery y validación pasiva en una misma ejecución para facilitar análisis de ruido y troubleshooting.
- Ajusta el resumen ejecutivo para que la nota sobre hallazgos altos/críticos confirmados dependa de los datos reales del run.
- Amplía el `summary-json` con campos ya existentes del modelo (`kind`, `confidence`, `asset_host`, `asset_port`, `source_count`, `evidence_summary`) para mantener el output más preparado para consumo estructurado futuro.
- Alinea la documentación con el comportamiento real de targets CLI + YAML: se combinan y deduplican, no se sobrescriben.
- Separa `asset_host` estable de `asset_host_resolved` para que los outputs humanos y estructurados no cambien de hostname a IP según el punto del pipeline.
- Añade identificadores deterministas por hallazgo y correlación para facilitar ingest futura en sistemas de indexación.
- Reutiliza una única baseline probe compartida entre validadores HTTP durante la validación pasiva, reduciendo requests redundantes.
- Documenta una validación repetible con Juice Shop para contrastar perfiles pasivos.
- Añade `scripts/validate_labs.ps1` para repetir validaciones de laboratorio con Juice Shop y DVWA desde Windows/PowerShell.
- Estabiliza `report.summary.json`, `aggregate_summary.json` y `run_manifest.json` con secciones y claves más predecibles para futuro consumo estructurado.
- Endurece `scripts/validate_labs.ps1` para validar artefactos generados, IDs estables y un mínimo configurable de hallazgos.
- Reduce falsos positivos de `APIValidator` descartando pantallas de login servidas desde rutas como `/swagger` o `/graphql`.
- Enriquece `comparison.json` y la sección de comparativa en reportes con promociones, regresiones y cambios de confianza/verificación.
- Alinea mejor `verification_status`, `needs_manual_validation` y prioridad para que un hallazgo `confirmed` no siga marcado como revisión manual por inercia de categoría.
- Añade una matriz de revisión exportable (`reviews/lab_findings_review.csv`) para etiquetar hallazgos de labs como `verdadero`, `falso` o `dudoso` durante el afinado de falsos positivos.
- Ajusta la priorización de correlación para dar más peso a evidencia `confirmed` y evita que la mera multiplicidad de fuentes infle hallazgos todavía `likely`.

- Permite validar `passive-recon-enum` dentro del flujo repetible de labs con un override local (`config/examples/lab-passive-recon-enum.yml`) que desactiva Nuclei y mantiene el perfil comparable en Docker.
- Evita que headers confirmados de severidad media, como CSP ausente, escalen a prioridad `high` solo por estar confirmados; la prioridad se reserva mejor para evidencia aplicativa o impacto más claro.
- Endurece `APIValidator`, `PanelsValidator` y `SensitiveFilesValidator` contra superficies de login servidas desde rutas de docs, respuestas HTML que simulan ficheros y respuestas GraphQL demasiado débiles o indistinguibles del fallback.
- Reordena `top_findings` y el agregado para que hallazgos confirmados de aplicación queden por delante de inventario, fingerprints y headers higiénicos cuando comparten prioridad similar.

- Acota mejor la prioridad de documentación y superficies API: `Swagger UI Exposed` deja de escalar a `critical`, `GraphQL Endpoint Accessible Without Authentication` se mantiene en `medium` cuando sigue en `likely`, y el inventario `Multiple API Endpoints Exposed` no compite como si fuese una confirmación de impacto.
- Ajusta la matriz de revisión para que headers de higiene y superficies de inventario API queden en `revisar` o `descubrimiento`, evitando priorizar por defecto hallazgos que todavía son de contexto o endurecimiento.
- Separa mejor el reporting entre riesgo de aplicación, higiene/endurecimiento y descubrimiento: `report.summary.json` expone listas dedicadas (`top_risk_findings`, `top_hygiene_findings`, `top_discovery_findings`) y el markdown mueve headers/TLS a una sección propia para que no compitan visualmente con acceso indebido real.
- Ajusta `AuthValidator` para que rutas de superficie API como `/graphql`, `/swagger` o `/api-docs` no se expresen por defecto como fallo de autorización: ahora se reportan como `api` (`GraphQL Surface Exposed`, `Swagger UI Exposed`, etc.) y se acotan a `likely/medium` salvo evidencia más fuerte.
- Filtra `top_risk_findings` para dejar fuera señales de baja prioridad como CORS amplio `likely` cuando ya existen hallazgos medios/altos más accionables, manteniendo el summary centrado en lo que primero merece revisión.

## v10.22.6 false-positive tuning

- Alinea `--profile passive-stealth`, `--profile passive-recon-safe` y `--profile active-aggressive` con la semántica de los YAML para evitar que la CLI ejecute Nuclei, Nmap o probes hardcoded cuando no toca.
- El manifest de ejecución ya registra el perfil usado por CLI, no solo el definido en YAML.
- Evita correlacionar hallazgos heterogéneos solo porque comparten rutas como `/login`: headers, fingerprints y formularios ya no se fusionan en un falso hallazgo de mayor prioridad.
- Reduce ruido en headers: checks de CSP/X-Frame/Referrer se aplican solo a documentos de navegador, y cabeceras de bajo impacto quedan con prioridad baja.
- Ajusta CORS: `Access-Control-Allow-Origin: *` sin credenciales se clasifica como señal low/likely, no como hallazgo confirmado de mayor impacto.
- Trata `/login` como superficie de descubrimiento, no como panel expuesto.
- Endurece detección de ficheros sensibles: `.zip` y `.DS_Store` requieren firma real, no solo `Content-Type`.
- Reduce ruido de cookies: se ignoran cookies no relacionadas con sesión/auth y no se exige `HttpOnly` en cookies CSRF/XSRF.
- Validado contra Docker local con OWASP Juice Shop y DVWA en perfiles `passive-stealth` y `passive-recon-safe`.

Versión 10.10 del proyecto: mantiene el pipeline de **Nuclei + validaciones propias + correlación + reporting**, conserva **descubrimiento opcional con Nmap** y mejora el crawling con **Scrapling + fallback a requests**, además de promover formularios y pistas de endpoints descubiertos a nuevas validaciones.

## Qué aporta la v10

- Integración opcional de **Nmap** (`-Pn -sV`) para descubrimiento de servicios.
- Backend HTTP unificado para validadores y crawling: `auto`, `requests` o `scrapling`.
- Dos perfiles nuevos orientados a operación: `passive` y `active`.
- Integración de Scrapling en todo el acceso HTTP de la herramienta:
  - crawler
  - validadores HTTP
  - fingerprinting de respuestas
  - debug probe
- Corrección del mapper de respuestas de Scrapling: ahora prioriza `status`, `headers`, `body` y `encoding`, normaliza cabeceras case-insensitive y evita perder HTML/content-type en el crawler.
- Modo `active` para render dinámico con Scrapling (`DynamicSession`) y descubrimiento mejorado en superficies modernas.
- Hallazgos de red convertidos al mismo modelo común `Vulnerability`.
- Enriquecimiento de puertos/servicios con categorías como:
  - `network-service`
  - `database`
  - `remote-access`
  - `message-broker`
  - `admin-surface`
  - `web-service`
- Reporting agregado con hallazgos HTTP y de red en la misma ejecución.
- Soporte por CLI y por YAML para activar/desactivar Nmap.
- Persistencia del XML bruto de Nmap por target (`nmap_raw.xml`) cuando Nmap está activado.

## Capacidades principales

### Detección HTTP / AppSec

- Nuclei para checks rápidos y extensibles.
- Validaciones propias de:
  - headers de seguridad
  - TLS
  - paneles expuestos
  - autenticación / endpoints protegidos
  - API / Swagger / GraphQL / OpenAPI
  - ficheros sensibles
  - crawling básico y detección de secretos

### Detección de red (opcional)

- Descubrimiento de puertos/servicios con Nmap.
- Clasificación de servicios abiertos como superficie de red.
- Correlación con hallazgos ya encontrados por Nuclei.
- Casos típicos útiles:
  - `epmd` / RabbitMQ
  - SSH / FTP
  - Redis / MongoDB / MySQL / PostgreSQL
  - HTTP / HTTPS auxiliares

### Calidad del análisis

- modelo de hallazgo unificado
- deduplicación
- correlación
- prioridad final separada de la severidad
- `confidence`
- `verification_status`
- separación entre:
  - vulnerabilidades y misconfiguraciones
  - superficie descubierta o protegida

### Operatividad

- target único o múltiples targets
- configuración por CLI y YAML
- ejecución por lotes
- workers en paralelo
- informes por target y agregados

## Requisitos

- Python 3.11+
- **Nuclei** instalado en `PATH`
- plantillas de Nuclei actualizadas
- **Nmap** instalado en `PATH` si quieres usar descubrimiento de red

Instalación:

```bash
pip install -r requirements.txt
# si usas Scrapling, instala también navegadores/dependencias
python -m playwright install
# opcional para modo dynamic; fetcher no necesita navegador
```

## Uso rápido

### 1) Escaneo básico

```bash
python main.py https://example.com
```

### 2) Escaneo profundo con Nmap

```bash
python main.py https://example.com --profile deep --use-nmap --nmap-top-ports 200 --debug
```

### 3) Batch scan desde fichero

```bash
python main.py --targets-file targets.txt --workers 3 --profile deep --use-nmap
```

### 4) Configuración desde YAML

```bash
python main.py --config config/examples/config.example.yml
```

## Opciones de línea de comandos

### Entrada

- `target`
- `--targets-file targets.txt`
- `--config config.yml`

### Generales

- `--profile {quick,normal,deep,passive,active,active-aggressive,passive-stealth,passive-recon-safe,passive-recon-enum}`
- `--workers 4`
- `--output-root scans`
- `--run-name nombre_scan`

### Nuclei

- `--severity low,medium,high,critical`
- `--tags exposure,misconfig,cve`
- `--templates /ruta/templates`
- `--rate-limit 100`
- `--timeout 15`
- `--retries 2`
- `--include-raw`
- `--show-stderr`
- `--no-follow-redirects`
- `--compare ruta/vulnerabilities.json`

### Nmap

- `--use-nmap`
- `--nmap-top-ports 100`
- `--nmap-args -sC,-T4`
- `--nmap-timing -T4`

Notas:
- La herramienta ejecuta Nmap como `nmap -Pn -sV --top-ports <N> -oX -` y añade los argumentos extra indicados.
- Si Nmap no está instalado y `--use-nmap` está activo, el resultado se mantiene pero se registrará el aviso correspondiente.

### Módulos HTTP

- `--skip-headers`
- `--skip-panels`
- `--skip-tls`
- `--skip-crawl`
- `--skip-secrets`
- `--skip-auth`
- `--skip-api`
- `--skip-sensitive-files`
- `--validator-timeout 8`
- `--crawl-max-pages 40`
- `--crawl-max-depth 2`
- `--crawl-include-js`
- `--http-backend {auto,requests,scrapling}`
- `--http-mode {passive,active}`
- `--panel-paths /admin,/swagger,/metrics,/actuator,/management`

### Reporting

- `--report-title "Informe corporativo"`
- `--report-formats md,html,csv,summary-json,comparison-json`
- `--skip-reports`
- `--debug`

## Estructura de salida

Cada ejecución crea una carpeta tipo:

```text
scans/
  2026-03-21_180316/
    run_manifest.json
    reports/
      aggregate_report.md
      aggregate_findings.csv
      aggregate_summary.json
    targets/
      http_example.com/
        nuclei_raw.jsonl
        nmap_raw.xml
        vulnerabilities.json
        debug_counts.json
        debug_probe.json
        reports/
          report.md
          report.html
          report.csv
          report.summary.json
```

## Interpretación de resultados

La herramienta separa los hallazgos en tres grupos conceptuales:

1. **Vulnerabilidades / misconfiguraciones**
   - exposición real
   - configuraciones inseguras
   - servicios abiertos que conviene revisar

2. **Superficie descubierta o protegida**
   - endpoints sensibles que existen pero devuelven `401/403`
   - documentación/API protegida
   - superficie útil para enumeración

3. **Pendientes de validación manual**
   - hallazgos con señales suficientes pero sin confirmación fuerte

## Ejemplos

### Escaneo web sin TLS ni crawling

```bash
python main.py https://example.com --skip-tls --skip-crawl
```

### Escaneo de varios targets con Nmap y reportes

```bash
python main.py --targets-file targets.txt --workers 4 --profile deep --use-nmap --nmap-top-ports 200 --report-formats md,html,csv
```

### Baseline comparando una ejecución anterior

```bash
python main.py https://example.com --compare scans/old_run/targets/https_example.com/vulnerabilities.json
```

## Limitaciones conocidas

- La validación HTTP intenta reducir falsos positivos en SPAs/fallbacks, pero sigue siendo heurística.
- Nmap es opcional y puede aumentar el tiempo total del escaneo.
- La herramienta no explota vulnerabilidades: detecta, correlaciona y reporta.

## Recomendación de uso

- Usa `normal` para auditorías rápidas.
- Usa `deep` para pruebas más completas.
- Activa `--use-nmap` cuando quieras complementar AppSec con superficie de red.
- Revisa especialmente los hallazgos con `needs_manual_validation` y las secciones de `discovery`.


## Novedades v9.2

- Se separan los **servicios y puertos descubiertos** de las vulnerabilidades web y de la superficie protegida.
- La priorización de Nmap es más útil: 80/443 quedan como descubrimiento estándar de bajo impacto, mientras que bases de datos, brokers, acceso remoto y superficies administrativas ganan más peso.
- Los informes Markdown agregados y por target muestran ahora una sección específica para descubrimiento de red.


## Novedades v9.3

- Títulos de Nmap más profesionales (por ejemplo, `Exposed MariaDB Service`).
- Ajuste semántico del informe para separar mejor hallazgos confirmados web de servicios de red descubiertos.
- Priorización algo más alta para middleware Erlang/RabbitMQ cuando aparece EPMD expuesto.


## Novedades v9.4

- Re-categorización de EPMD/RabbitMQ como `message-broker`.
- Prioridad reducida para servicios web estándar en `80/443`.
- Mayor confianza para endpoints protegidos descubiertos mediante `401/403`.
- Mejora semántica en el informe detallado para separar mejor hallazgos web/app de descubrimiento de red.


## Novedades v9.5.3

- Reducción de falsos positivos en paneles administrativos que redirigen a login.
- `/admin` o `/dashboard` que terminan en una pantalla de autenticación ya no se reportan como acceso sin autenticación.
- Esas superficies se degradan a hallazgos de descubrimiento de bajo impacto cuando aplica.


## Perfiles Scrapling en v10.4

- `passive-stealth.yml`: usa `requests` para todo el discovery.
- `passive-extended.yml`: usa `requests` en validadores y `scrapling` con `scrapling_mode: fetcher` en el crawler. No necesita navegador.
- `active-aggressive.yml`: usa `requests` en validadores y `scrapling` con `scrapling_mode: dynamic` en el crawler. Requiere instalar navegadores de Playwright con `python -m playwright install`.

## Instalación recomendada

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Para el perfil activo dinámico:

```bash
python -m playwright install
```


## Cambios relevantes en la v10.11

- Se corrige el adapter de Scrapling para leer primero los atributos documentados por Scrapling (`status`, `headers`, `body`, `encoding`) en vez de asumir una interfaz estilo `requests`.
- Las cabeceras HTTP se normalizan de forma case-insensitive y se expone siempre `Content-Type` cuando está presente aunque Scrapling lo entregue en minúsculas.
- El debug HTTP del backend Scrapling ahora registra `body_length` a partir de `content`, evitando falsos `0` cuando el texto no se había reconstruido aún.
- Se añaden tests de regresión para el caso observado en `http://localhost:8080/login.php`, donde antes el crawler hacía `skip_non_document` con `content_type: ""`.
- Limitación conocida: el error `curl: (52) Empty reply from server` en algunos targets locales del fetcher sigue siendo un problema de transporte del backend HTTP; la v10.9 corrige el mapper y la pérdida de contenido, no ese fallo de red concreto.


### Novedades de la 10.10

- fallback automático del crawler de `scrapling` a `requests` cuando falla el transporte del fetcher (`curl: (52)` y similares).
- análisis de documentos descubiertos para extraer formularios, acciones, rutas candidatas y pistas API en HTML/JS.
- promoción de candidatos descubiertos a validaciones de paneles, autenticación y superficies API.
- nuevos hallazgos de discovery para formularios de login, formularios de subida y pistas de endpoints API embebidas.
- métricas extra en `debug_counts`: `crawl_candidate_paths`, `crawl_forms` y `crawl_js_hints`.

### Novedades de la 10.11

- mejora del parser de atributos HTML para soportar formularios con atributos sin comillas, frecuente en aplicaciones PHP clásicas como DVWA.
- la detección de formularios de autenticación ahora también usa heurísticas por nombres de campos y ruta, no sólo `type=password`.
- el crawler prioriza enlaces de valor alto (`login`, `admin`, `api`, `graphql`, `swagger`, `*.js`) y evita seguir imágenes y otros estáticos de poco valor salvo que se pida expresamente.
- el parser de Nmap descarta fingerprints genéricos de `network-service` que contradicen un target HTTP explícito en el mismo puerto, reduciendo falsos positivos como `Exposed PPP Service` en `http://localhost:3000`.
- nuevos tests de regresión para DVWA y para la limpieza del falso positivo de Nmap.


## Perfiles operativos v10.12

### 1. `passive-stealth`
Pensado para observación de muy bajo ruido.

- No ejecuta Nuclei ni Nmap.
- No lanza probes de baseline `__attack_surface_mapper_not_found__`.
- No prueba rutas inventadas como `.env`, `.git/HEAD`, `swagger`, `metrics` o `graphql`.
- Solo navega el target inicial, redirects naturales y recursos observados en la respuesta.
- Usa `User-Agent` de navegador.

Ejemplo:

```bash
python main.py --config config/profiles/passive-stealth.yml --debug
```

### 2. `passive-recon`
Reconocimiento GET-only, con enumeración visible pero sin payloads ni explotación.

- Puede probar rutas comunes.
- Puede descubrir superficies API, Swagger, GraphQL, metrics y ficheros sensibles.
- Mantiene modo HTTP `passive`.

Ejemplo:

```bash
python main.py --config passive-recon.yml --debug
```

### 3. `active`
Perfil agresivo para máxima cobertura.

- Habilita crawling dinámico.
- Ejecuta Nuclei completo.
- Ejecuta Nmap.
- Acepta mayor huella en logs.

Ejemplo:

```bash
python main.py --config active-aggressive.yml --debug
```


## 10.12.1

- Corrige el cableado de perfiles para claves nuevas de configuración (`user_agent`, `run_nuclei`, `baseline_probe`, `observed_only`) evitando fallos de `argparse.Namespace` cuando solo se definen en YAML.
- `passive-stealth.yml` vuelve a ejecutar el flujo observado-only sin lanzar probes inventados ni Nuclei/Nmap.


## Novedades v10.13

- Fingerprinting HTTP ligero para detectar tecnologías probables a partir de headers y contenido (por ejemplo Apache, PHP, Express, Spring Boot, Angular o WordPress).
- Correlación más útil para superficie API: los hallazgos repetitivos de endpoints se agrupan en resúmenes como `Multiple API Endpoints Exposed (N)` o `Multiple API Hints Discovered In Client-Side Content (N)`.
- Priorización algo mejor cuando se detecta exposición de múltiples endpoints de API en el mismo target.
- Menos ruido en el reporting agregado y por target, manteniendo el detalle en la evidencia resumida.


## Novedades v10.13.1

- Reduce las peticiones duplicadas del perfil `passive-stealth` reutilizando la misma respuesta base para validaciones de cabeceras y fingerprinting.
- En `observed_only`, desactiva crawling y extracción de secretos para que el perfil stealth se limite a una navegación base por target.

## Novedades v10.20

- Refactorización orientada a pipeline con etapas explícitas (`NucleiStage`, `NmapStage`, `PassiveValidationStage`, `CorrelationStage`, `ReportingStage`).
- Introducción de `ScanContext` como modelo compartido entre etapas.
- Nueva familia de módulos `collectors/` para separar Nuclei, Nmap, backends HTTP y crawling de la lógica de validación y reporting.
- `orchestrator.py` pasa a actuar como fachada de compatibilidad sobre el nuevo pipeline.
- Documentación adicional en `docs/PIPELINE.md`.


## v10.21

- Pipeline manifest por ejecución.
- Normalización consistente de `asset_host`.
- Clasificación adicional de findings con `kind`.
- Evidencia resumida más limpia.


## v10.22.1 hotfix

- Corrige el error `name 'urlparse' is not defined` en la fase de validación pasiva.
- Sustituye User-Agents internos del proyecto por valores genéricos para reducir exposición del nombre de la herramienta en logs de aplicación.
- Endurece `browser_discovery` para no abortar toda la fase cuando el colector falla; el fallo queda reflejado en debug y el run puede continuar.
- Mantiene el flujo de recon/active sin dejar el manifiesto vacío por un error puntual del stage.



## v10.22.2

Cambios principales:
- separación explícita de perfiles `passive-recon-safe` y `passive-recon-enum`
- `passive-recon.yml` queda como alias de compatibilidad para `passive-recon-enum`
- los perfiles de recon pasan a usar `requests` por defecto para evitar el ruido y la inestabilidad de Scrapling fetcher contra Juice Shop
- fallback automático del crawler a `requests` tras errores repetidos de transporte en Scrapling
- `Scrapling` fetcher deja de inyectar cabeceras stealth automáticas como `Referer` artificial
- throttling ligero en modo pasivo para evitar ráfagas demasiado obvias en logs
- el pipeline reduce el probing hardcoded cuando el perfil funciona en `observed_only`

### Perfiles recomendados
- `config/profiles/passive-stealth.yml`: navegación mínima y muy discreta
- `config/profiles/passive-recon-safe.yml`: crawling seguro con hints de JS, sin enumeración de rutas sensibles
- `config/profiles/passive-recon-enum.yml`: enumeración GET-only visible pero todavía no agresiva
- `config/profiles/active-aggressive.yml`: máxima cobertura


## v10.22.4 polish

- `passive-recon-safe` mantiene la navegación realista y evita inflar `observed_urls` con referencias API extraídas de JS.
- Las pistas descubiertas en cliente pasan a llamarse `Client-Side API Reference Observed` para reflejar que son observación pasiva, no probing activo.
- Se limpia el inventario observado separando mejor URLs navegadas de referencias API vistas en código cliente.


## v10.22.5
- reutiliza la primera respuesta HTML del browser discovery como base para validaciones pasivas en `passive-recon-safe`.
- reduce la doble petición visible al root/login en perfiles `observed_only`.
