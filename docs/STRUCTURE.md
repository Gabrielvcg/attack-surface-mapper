# Organizacion de carpetas v10.14

## Objetivo

Reducir ruido en la raiz del proyecto y separar claramente:
- codigo fuente
- configuracion
- ejemplos
- artefactos de ejecucion
- depuracion

## Configuracion

- `config/profiles/`: perfiles listos para usar (`passive-stealth`, `passive-recon`, `active-aggressive`).
- `config/examples/`: ejemplos y configuraciones historicas de laboratorio.

## CMS

- `src/attack_surface_mapper/cms/`: deteccion y enrutado modular de CMS.
  El pipeline principal solo conoce el stage generico; los checks especificos
  viven en modulos como WordPress para evitar acoplamiento innecesario.

## Salidas por target

- `findings/`: resultados estructurados finales.
- `reports/`: informes consumibles por humano.
- `artifacts/`: crudos de herramientas y soporte.
- `debug/`: trazas y ficheros auxiliares de depuracion.
