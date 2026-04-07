# Organización de carpetas v10.14

## Objetivo

Reducir ruido en la raíz del proyecto y separar claramente:
- código fuente
- configuración
- ejemplos
- artefactos de ejecución
- depuración

## Configuración

- `config/profiles/`: perfiles listos para usar (`passive-stealth`, `passive-recon`, `active-aggressive`).
- `config/examples/`: ejemplos y configuraciones históricas de laboratorio.

## Salidas por target

- `findings/`: resultados estructurados finales.
- `reports/`: informes consumibles por humano.
- `artifacts/`: crudos de herramientas y soporte.
- `debug/`: trazas y ficheros auxiliares de depuración.
