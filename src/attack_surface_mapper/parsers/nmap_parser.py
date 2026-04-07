from __future__ import annotations

from xml.etree import ElementTree as ET
from urllib.parse import urlparse

from attack_surface_mapper.models.vulnerability import Vulnerability


def _target_scheme_and_port(target: str) -> tuple[str, str | None]:
    parsed = urlparse(target)
    return parsed.scheme.lower(), str(parsed.port) if parsed.port else None


def _should_skip_probable_false_positive(target: str, service: str, port: str | None, category: str, product: str | None = None) -> bool:
    scheme, target_port = _target_scheme_and_port(target)
    if scheme not in {'http', 'https'}:
        return False
    if not port or target_port != port:
        return False
    if category != 'network-service':
        return False
    if (service or '').lower() in {'http', 'https', 'ssl/http', 'tcpwrapped', 'unknown'}:
        return False
    if product:
        return False
    return True


SERVICE_TO_CATEGORY = {
    'epmd': 'message-broker',
    'rabbitmq': 'message-broker',
    'http': 'web-service',
    'https': 'web-service',
    'ssh': 'remote-access',
    'ftp': 'file-transfer',
    'mysql': 'database',
    'mariadb': 'database',
    'ms-sql-s': 'database',
    'postgresql': 'database',
    'mongodb': 'database',
    'redis': 'database',
    'tomcat': 'admin-surface',
    'kibana': 'admin-surface',
    'grafana': 'admin-surface',
    'elasticsearch': 'search-service',
}

STANDARD_WEB_PORTS = {'80', '443'}
SENSITIVE_PORTS = {'21', '22', '1433', '3306', '4369', '5672', '8000', '8080', '8443', '9000', '9001', '15672', '27017', '6379'}


SERVICE_TITLE_OVERRIDES = {
    "mysql": "Exposed MariaDB Database Service",
    "mariadb": "Exposed MariaDB Database Service",
    "ms-sql-s": "Exposed Microsoft SQL Server Service",
    "ftp": "Exposed FTP Service",
    "http": "Exposed HTTP Service",
    "https": "Exposed HTTPS Service",
    "epmd": "Exposed Erlang Port Mapper Service",
}


def _guess_category(service_name: str, tunnel: str | None = None, product: str | None = None, port: str | None = None) -> str:
    name = (service_name or '').lower()
    product_name = (product or '').lower()
    if tunnel == 'ssl' and name == 'http':
        name = 'https'
    for key, category in SERVICE_TO_CATEGORY.items():
        if key in name or key in product_name:
            return category
    if port in {'1433', '3306', '5432', '27017', '6379'}:
        return 'database'
    if port in {'9000', '8080', '8443', '15672'} and name in {'http', 'https'}:
        return 'admin-surface'
    return 'network-service'


def _service_profile(service: str, port: str | None, category: str, product: str | None = None) -> tuple[str, str, str]:
    name = (service or '').lower()
    product_name = (product or '').lower()
    if category == 'database':
        return 'medium', 'high', 'base de datos expuesta detectada por Nmap; revisar segmentación y autenticación'
    if category in {'message-broker', 'admin-surface'}:
        return 'medium', 'medium', 'servicio de infraestructura o administración expuesto; revisar necesidad operativa'
    if category == 'remote-access':
        return 'medium', 'medium', 'superficie de acceso remoto expuesta; revisar segmentación y credenciales'
    if category == 'file-transfer':
        return 'low', 'medium', 'servicio de transferencia expuesto; revisar si debe estar publicado'
    if category == 'web-service':
        if port in STANDARD_WEB_PORTS:
            return 'low', 'low', 'servicio web estándar descubierto; visibilidad esperable pero conviene validar hardening'
        if 'tomcat' in product_name or port in {'8080', '8443', '9000', '9001'}:
            return 'medium', 'medium', 'servicio web secundario o administrativo descubierto; revisar exposición'
        return 'low', 'medium', 'servicio web no estándar descubierto; revisar si su exposición es necesaria'
    if port in SENSITIVE_PORTS:
        return 'medium', 'medium', 'puerto sensible descubierto por Nmap; revisar exposición y controles'
    return 'low', 'low', 'servicio de red descubierto por Nmap; revisar exposición y necesidad operativa'


class NmapParser:
    def parse_xml(self, xml_text: str) -> list[dict]:
        if not xml_text.strip():
            return []
        root = ET.fromstring(xml_text)
        results: list[dict] = []
        for host in root.findall('host'):
            address = host.find('address')
            host_ip = address.get('addr') if address is not None else None
            for port in host.findall('./ports/port'):
                state = port.find('state')
                if state is None or state.get('state') != 'open':
                    continue
                service = port.find('service')
                script_elems = port.findall('script')
                scripts = []
                for s in script_elems:
                    scripts.append({'id': s.get('id') or '', 'output': s.get('output') or ''})
                service_name = service.get('name') if service is not None else ''
                product = service.get('product') if service is not None else None
                version = service.get('version') if service is not None else None
                extrainfo = service.get('extrainfo') if service is not None else None
                tunnel = service.get('tunnel') if service is not None else None
                results.append({
                    'host': host_ip,
                    'protocol': port.get('protocol'),
                    'port': port.get('portid'),
                    'service': service_name,
                    'product': product,
                    'version': version,
                    'extrainfo': extrainfo,
                    'tunnel': tunnel,
                    'scripts': scripts,
                })
        return results

    def to_vulnerabilities(self, target: str, xml_text: str, include_raw: bool = False) -> list[Vulnerability]:
        parsed = self.parse_xml(xml_text)
        vulns: list[Vulnerability] = []
        for item in parsed:
            host = item.get('host') or target
            port = item.get('port')
            service = item.get('service') or 'unknown'
            tunnel = item.get('tunnel')
            location = f"{host}:{port}" if port else host
            category = _guess_category(service, tunnel, item.get('product'), str(port) if port is not None else None)
            if _should_skip_probable_false_positive(target, service, str(port) if port is not None else None, category, item.get('product')):
                continue
            product_bits = [bit for bit in (item.get('product'), item.get('version'), item.get('extrainfo')) if bit]
            service_label = service.upper() if service.isalpha() and len(service) <= 5 else service.title()
            title = SERVICE_TITLE_OVERRIDES.get(service.lower(), f'Exposed {service_label} Service')
            description = (
                f'El servicio {service_label} está expuesto públicamente y accesible desde red externa en {location}. '
                'Esto amplía la superficie de ataque si no está correctamente restringido o endurecido.'
            )
            evidence = f"open/{item.get('protocol')} {service} {' '.join(product_bits).strip()}".strip()
            recommendation = 'Revisar si el servicio abierto es necesario, restringir exposición por red y verificar autenticación y endurecimiento del servicio.'
            references = []
            if category == 'database':
                db_name = 'MariaDB' if service.lower() in {'mysql', 'mariadb'} else ('Microsoft SQL Server' if service.lower() == 'ms-sql-s' else service_label)
                title = f'Exposed {db_name} Service'
                description = (
                    f'El servicio de base de datos {db_name} está expuesto públicamente en {location}. '
                    'La exposición directa de bases de datos puede facilitar enumeración o intentos de acceso no autorizado.'
                )
            elif category == 'file-transfer':
                title = 'Exposed FTP Service' if service.lower() == 'ftp' else title
                description = (
                    f'El servicio de transferencia de ficheros {service_label} está expuesto públicamente en {location}. '
                    'Conviene revisar si realmente debe estar accesible desde Internet y validar autenticación y cifrado.'
                )
            elif category == 'web-service' and item.get('product'):
                title = f'Exposed HTTP Service ({item.get("product")}{(" " + item.get("version")) if item.get("version") else ""})' if service.lower() in {'http','https'} else title
            if service == 'epmd':
                title = 'Exposed Erlang Port Mapper Service'
                description = 'Se ha detectado EPMD expuesto, asociado habitualmente a Erlang/RabbitMQ. Esta exposición puede facilitar enumeración de nodos y reconocimiento de middleware.'
                recommendation = 'Revisar si EPMD debe estar expuesto, limitar acceso por red y validar la configuración de RabbitMQ/Erlang.'
                references = [
                    'https://nmap.org/nsedoc/scripts/epmd-info.html',
                    'https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd',
                ]
            severity, priority, priority_reason = _service_profile(service, str(port) if port is not None else None, category, item.get('product'))
            verification = 'confirmed'
            confidence = 'high'
            cwe = []
            if category in {'database', 'message-broker', 'admin-surface', 'remote-access'}:
                cwe = ['CWE-200']
            extra_scripts = item.get('scripts') or []
            related = [s.get('id') for s in extra_scripts if s.get('id')]
            related_evidence = [s.get('output') for s in extra_scripts if s.get('output')]
            evidence_summary = evidence if not related_evidence else '; '.join([evidence, *related_evidence[:2]])
            vulns.append(Vulnerability(
                source='nmap',
                title=title,
                description=description,
                severity=severity,
                target=location,
                evidence=evidence,
                cwe=cwe,
                references=references,
                tags=['nmap', 'service-discovery', service, item.get('protocol') or 'tcp'],
                template_id=f'nmap-{service}-{port}',
                matched_at=location,
                host=host,
                port=str(port) if port is not None else None,
                scheme='https' if tunnel == 'ssl' else ('http' if service in {'http', 'https'} else None),
                type=item.get('protocol'),
                category=category,
                confidence=confidence,
                priority=priority,
                priority_reason=priority_reason,
                recommendation=recommendation,
                needs_manual_validation=False,
                verification_status=verification,
                evidence_summary=evidence_summary,
                source_count=1,
                related_sources=related,
                related_evidence=related_evidence,
                raw=item if include_raw else {},
            ))
        return vulns
