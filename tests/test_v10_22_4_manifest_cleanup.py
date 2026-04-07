from attack_surface_mapper.pipeline.stages import BrowserDiscoveryStage, NucleiStage, NmapStage
from attack_surface_mapper.core.scan_context import ScanContext
from attack_surface_mapper.core.scan_context import ScanSettings, ScanOutputs


def test_browser_discovery_stage_does_not_promote_api_calls_to_observed_urls(monkeypatch):
    class DummyResult:
        documents = {}
        observed_urls = ["http://localhost:3000/"]
        observed_actions = []
        observed_api_calls = ["http://localhost:3000/api/Users", "http://localhost:3000/rest/user/login"]
        analysis = None

    class DummyCollector:
        def __init__(self, *args, **kwargs):
            pass
        def collect(self, target):
            return DummyResult()

    monkeypatch.setattr('attack_surface_mapper.pipeline.stages.BrowserDiscoveryCollector', DummyCollector)
    ctx = ScanContext(target='http://localhost:3000', settings=ScanSettings(run_crawl=True, browser_discovery_enabled=True), outputs=ScanOutputs())
    BrowserDiscoveryStage().run(ctx)

    assert 'http://localhost:3000/' in ctx.observed_urls
    assert 'http://localhost:3000/api/Users' not in ctx.observed_urls
    assert 'http://localhost:3000/rest/user/login' not in ctx.observed_urls
    assert 'http://localhost:3000/api/Users' in ctx.observed_api_calls


def test_disabled_stages_are_not_marked_executed():
    ctx = ScanContext(target='http://localhost:3000', settings=ScanSettings(run_nuclei=False, run_nmap=False, run_crawl=False, browser_discovery_enabled=False), outputs=ScanOutputs())
    NucleiStage().run(ctx)
    NmapStage().run(ctx)
    BrowserDiscoveryStage().run(ctx)
    assert ctx.debug.stages_executed == []
