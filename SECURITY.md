# Security Policy

## Scope and supported versions

Attack Surface Mapper is a security testing tool, not a hosted service. The latest commit on the default branch is the supported development line. Older commits may contain known limitations and should not be used as a security baseline without review.

Attack Surface Mapper is intended for authorised security testing, internal audits and controlled lab environments.

Do not run active modules, Nuclei templates, Nmap discovery or endpoint enumeration against third-party systems without explicit permission. For broad external reconnaissance, use only the passive profiles agreed with the target owner and keep logs, scope and configuration available for review.

Recommended defaults:

- Use `passive-stealth` or `passive-recon-safe` for low-noise discovery.
- Use `passive-recon-enum`, Nuclei and Nmap only when enumeration is authorised.
- Use `active-aggressive` only for approved audits or lab targets.

If you find a security issue in this project, do not include credentials, live target details or private scan output in a public issue. Use GitHub's private vulnerability reporting when it is available, or contact the maintainer through the GitHub profile.

Document:

- affected version or commit,
- reproduction steps,
- impact,
- suggested fix or mitigation.

Reports that affect the scanner's own code, report redaction, dependency safety or accidental credential exposure are especially valuable. Please allow time for triage before public disclosure.
