# Profiles

## passive-stealth
- Navegación mínima.
- Sin probes de superficie inventados.
- Pensado para bajo ruido y validaciones derivadas de la respuesta base.

## passive-recon-safe
- Discovery pasivo seguro.
- GET-only.
- Navegación, recursos enlazados e hints de JavaScript.
- Sin enumeración hardcoded de `/admin`, `/.env`, `/swagger`, `/graphql` y similares.

## passive-recon-enum
- Enumeración GET-only visible pero controlada.
- Parte de la navegación observada y añade probing de endpoints y ficheros comunes.
- Útil para ampliar superficie sin pasar todavía a activa agresiva.

## passive-recon
- Alias de compatibilidad para `passive-recon-enum`.

## active-aggressive
- Añade Nuclei, Nmap y validación más profunda.
- Usa Scrapling dinámico cuando está disponible.
- Mayor cobertura y más ruido esperado.
