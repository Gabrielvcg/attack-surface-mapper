from types import SimpleNamespace

from attack_surface_mapper.validators.auth_validator import AuthValidator
from attack_surface_mapper.validators.discovery import DiscoveredForm, DiscoveryAnalysis, findings_from_analysis
from main import build_arg_parser


class FakeResponse:
    def __init__(self, url: str, text: str, status_code: int = 200, headers: dict | None = None, content: bytes | None = None):
        self.url = url
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.content = content if content is not None else text.encode()
        self.raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: []))


def test_auth_validator_skips_public_register_and_login_surfaces(monkeypatch):
    login_html = "<html><form><input name='username'><input type='password'><input name='csrfmiddlewaretoken'></form></html>"
    register_html = "<html><form><input name='email'><input type='password'><input name='csrfmiddlewaretoken'></form><a>create account</a></html>"

    def fake_get(self, url, timeout=0, allow_redirects=True, headers=None):
        if url == 'https://target.example':
            return FakeResponse(url, '<html>home</html>')
        if '__attack_surface_mapper_not_found__' in url:
            return FakeResponse(url, '<html>not found</html>', status_code=404)
        if url.endswith('/accounts/login') or url.endswith('/accounts/login/'):
            return FakeResponse('https://target.example/accounts/login/', login_html)
        if url.endswith('/accounts/register') or url.endswith('/accounts/register/'):
            return FakeResponse('https://target.example/accounts/register/', register_html)
        return FakeResponse(url, '<html>not found</html>', status_code=404)

    monkeypatch.setattr('requests.sessions.Session.get', fake_get)
    findings = AuthValidator(timeout=1, paths=('/accounts/login', '/accounts/register')).run('https://target.example')
    assert findings == []


def test_discovery_titles_registration_forms_separately():
    form = DiscoveredForm(
        page_url='https://target.example/accounts/register/',
        action_url='https://target.example/accounts/register/',
        action_path='/accounts/register/',
        method='post',
        input_names=['email', 'password1', 'password2'],
        input_types=['email', 'password', 'password'],
        has_password=True,
        has_csrf_token=True,
        has_file_input=False,
    )
    analysis = DiscoveryAnalysis(
        discovered_urls=['https://target.example/accounts/register/'],
        candidate_paths=[],
        panel_paths=[],
        api_paths=[],
        auth_paths=['/accounts/register/'],
        forms=[form],
        js_hints=[],
    )
    findings = findings_from_analysis('https://target.example', analysis)
    assert findings[0].title == 'Registration Form Discovered Via Crawl'


def test_cli_accepts_active_aggressive_profile():
    parser = build_arg_parser()
    args = parser.parse_args(['--profile', 'active-aggressive', 'https://target.example'])
    assert args.profile == 'active-aggressive'
