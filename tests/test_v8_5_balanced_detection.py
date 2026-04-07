
from attack_surface_mapper.validators.api_validator import APIValidator
from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.panels_validator import PanelsValidator


class DummyResponse:
    def __init__(self, url, text='', status_code=200, headers=None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {'Content-Type': 'text/html'}


def test_api_validator_keeps_plausible_swagger_when_successful_and_sparse():
    validator = APIValidator()
    resp = DummyResponse('http://x/swagger', text='<html>ok</html>', headers={'Content-Type': 'text/html'})
    include, _, _, verification, *_ = validator._classify_path('/swagger', resp, 'ok', 'text/html', baseline=None)
    assert include is True
    assert verification in {'likely', 'needs_manual_validation', 'confirmed'}


def test_auth_validator_keeps_plausible_metrics_even_without_strong_signature():
    validator = AuthValidator()
    resp = DummyResponse('http://x/metrics', text='ok', headers={'Content-Type': 'text/plain'})
    include, _, _, verification = validator._classify_open_access('/metrics', resp, 'ok', baseline=None)
    assert include is True
    assert verification in {'likely', 'needs_manual_validation', 'confirmed'}


def test_panels_validator_keeps_plausible_actuator():
    validator = PanelsValidator()
    resp = DummyResponse('http://x/actuator', text='{}', headers={'Content-Type': 'application/json'})
    include, _, _, verification = validator._classify('/actuator', resp, '{}', baseline=None)
    assert include is True
    assert verification in {'likely', 'needs_manual_validation', 'confirmed'}
