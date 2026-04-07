from attack_surface_mapper.pipeline.stages import PassiveValidationStage
from attack_surface_mapper.core.scan_context import ScanContext, ScanOutputs, ScanSettings


def test_passive_validation_stage_imports_urlparse_and_runs_with_observed_urls():
    settings = ScanSettings(observed_only=False, run_headers=False, run_tls=False, run_sensitive_files=False, run_panels=False, run_auth=False, run_api=False, run_secrets=False, run_crawl=False, debug=False)
    ctx = ScanContext(target="http://localhost:3000", outputs=ScanOutputs(), settings=settings)
    ctx.observed_urls.update({"http://localhost:3000/login", "http://localhost:3000/graphql"})
    stage = PassiveValidationStage()
    result = stage.run(ctx)
    assert result is ctx
