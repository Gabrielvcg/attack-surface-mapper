# Pipeline

Orden actual de stages:

1. NucleiStage
2. NmapStage
3. BrowserDiscoveryStage
4. PassiveValidationStage
5. CMSRoutingStage
6. CorrelationStage
7. ReportingStage

`BrowserDiscoveryStage` rellena:
- `observed_urls`
- `observed_actions`
- `observed_api_calls`

La validacion posterior reutiliza esta superficie observada para ampliar cobertura y reducir probes ciegos.

`CMSRoutingStage` mantiene el pipeline global desacoplado de tecnologias
concretas. Detecta CMS a partir de contenido y URLs ya observadas, y solo
activa modulos especializados cuando aplica. La primera implementacion incluye
WordPress y deja el patron preparado para Drupal, Joomla u otros CMS.
