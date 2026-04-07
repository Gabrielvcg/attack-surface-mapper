# Security Policy

Attack Surface Mapper is intended for authorised security testing, internal audits and controlled lab environments.

Do not run active modules, Nuclei templates, Nmap discovery or endpoint enumeration against third-party systems without explicit permission. For broad external reconnaissance, use only the passive profiles agreed with the target owner and keep logs, scope and configuration available for review.

Recommended defaults:

- Use `passive-stealth` or `passive-recon-safe` for low-noise discovery.
- Use `passive-recon-enum`, Nuclei and Nmap only when enumeration is authorised.
- Use `active-aggressive` only for approved audits or lab targets.

If you find a security issue in this project, document:

- affected version or commit,
- reproduction steps,
- impact,
- suggested fix or mitigation.
