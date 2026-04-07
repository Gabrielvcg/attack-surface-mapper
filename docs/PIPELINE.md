# Pipeline

Orden actual de stages:

1. NucleiStage
2. NmapStage
3. BrowserDiscoveryStage
4. PassiveValidationStage
5. CorrelationStage
6. ReportingStage

`BrowserDiscoveryStage` rellena:
- `observed_urls`
- `observed_actions`
- `observed_api_calls`

La validación posterior reutiliza esta superficie observada para ampliar cobertura y reducir probes ciegos.
