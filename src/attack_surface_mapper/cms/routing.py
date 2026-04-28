from __future__ import annotations

from attack_surface_mapper.cms.detector import CMSDetector, DetectedCMS
from attack_surface_mapper.cms.wordpress import WordPressModule
from attack_surface_mapper.core import ScanContext
from attack_surface_mapper.models.vulnerability import Vulnerability


class CMSModule:
    name = 'cms'

    def supports(self, detection: DetectedCMS) -> bool:  # pragma: no cover - interface only
        return False

    def run(self, context: ScanContext, detection: DetectedCMS) -> list[Vulnerability]:  # pragma: no cover - interface only
        return []


class CMSRoutingStage:
    name = 'cms_routing'

    def __init__(self, detector: CMSDetector | None = None, modules: list[CMSModule] | None = None) -> None:
        self.detector = detector or CMSDetector()
        self.modules = modules or [WordPressModule()]

    def run(self, context: ScanContext) -> ScanContext:
        if not context.settings.run_cms_detection:
            context.debug.counts[self.name] = 0
            return context

        context.mark_stage(self.name)
        context.mark_collector('cms-detector')
        entry_body = getattr(context.artifacts.entry_response, 'text', '') if context.artifacts.entry_response else ''
        detections = self.detector.detect(
            target=context.target,
            documents=context.artifacts.crawled_documents or {},
            observed_urls=sorted(context.observed_urls),
            entry_body=entry_body,
        )
        context.artifacts.cms_detections = detections

        findings: list[Vulnerability] = []
        for detection in detections:
            for module in self.modules:
                if module.supports(detection):
                    context.mark_collector(f'cms:{module.name}')
                    findings.extend(module.run(context, detection))

        context.debug.counts['cms_detections'] = len(detections)
        context.debug.counts[self.name] = len(findings)
        context.add_findings(findings)
        return context
