from __future__ import annotations

from attack_surface_mapper.cms import CMSDetector, CMSRoutingStage
from attack_surface_mapper.core import ScanContext, ScanSettings


def test_cms_detector_detects_wordpress_from_observed_content() -> None:
    detector = CMSDetector()

    detections = detector.detect(
        target='https://example.test',
        documents={
            'https://example.test/': '''
                <html>
                  <head><meta name="generator" content="WordPress 6.5"></head>
                  <body>
                    <script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>
                    <link href="/wp-content/themes/twentytwentyfour/style.css" rel="stylesheet">
                  </body>
                </html>
            ''',
        },
        observed_urls=['https://example.test/wp-json/'],
    )

    assert len(detections) == 1
    detection = detections[0]
    assert detection.name == 'wordpress'
    assert detection.confidence == 'high'
    assert detection.signals['plugins'] == ['contact-form-7']
    assert detection.signals['themes'] == ['twentytwentyfour']
    assert detection.signals['paths'] == ['https://example.test/wp-json/']


def test_cms_routing_stage_runs_wordpress_module_without_global_wordpress_stage() -> None:
    context = ScanContext(target='https://example.test', settings=ScanSettings(run_cms_detection=True))
    context.artifacts.crawled_documents = {
        'https://example.test/': '''
            <html>
              <head><meta name="generator" content="WordPress 6.5"></head>
              <body>
                <script src="/wp-content/plugins/woocommerce/assets/app.js"></script>
                <a href="/wp-login.php">Login</a>
              </body>
            </html>
        '''
    }
    context.add_observed('https://example.test/wp-login.php')
    context.add_observed('https://example.test/wp-json/')

    result = CMSRoutingStage().run(context)

    titles = {finding.title for finding in result.findings}
    assert 'CMS Detected (WordPress)' in titles
    assert 'WordPress Login Surface Observed' in titles
    assert 'WordPress REST API Surface Observed' in titles
    assert 'WordPress Plugins Observed (1)' in titles
    assert result.debug.counts['cms_detections'] == 1
    assert result.debug.counts['cms_routing'] == 4
    assert 'cms-detector' in result.debug.collectors_used
    assert 'cms:wordpress' in result.debug.collectors_used


def test_cms_routing_reports_wordpress_installer_with_specific_title() -> None:
    context = ScanContext(target='https://example.test', settings=ScanSettings(run_cms_detection=True))
    context.artifacts.crawled_documents = {
        'https://example.test/wp-admin/install.php': '''
            <html>
              <body>
                <h1>WordPress</h1>
                <p>Este es el famoso proceso de instalacion de WordPress en cinco minutos.</p>
                <script src="/wp-includes/js/wp-emoji-release.min.js"></script>
              </body>
            </html>
        '''
    }
    context.add_observed('https://example.test/wp-admin/install.php')

    result = CMSRoutingStage().run(context)

    installer = next(finding for finding in result.findings if finding.title == 'WordPress Installer Exposed')
    assert installer.category == 'configuration'
    assert installer.needs_manual_validation is True
    assert installer.verification_status == 'likely'
    assert 'installer' in installer.tags


def test_cms_routing_dedupes_wordpress_installer_steps() -> None:
    context = ScanContext(target='https://example.test', settings=ScanSettings(run_cms_detection=True))
    context.artifacts.crawled_documents = {
        'https://example.test/wp-admin/install.php': '<script src="/wp-includes/js/wp.js"></script> WordPress',
        'https://example.test/wp-admin/install.php?step=1': '<script src="/wp-includes/js/wp.js"></script> WordPress',
    }
    context.add_observed('https://example.test/wp-admin/install.php')
    context.add_observed('https://example.test/wp-admin/install.php?step=1')

    result = CMSRoutingStage().run(context)

    installers = [finding for finding in result.findings if finding.title == 'WordPress Installer Exposed']
    assert len(installers) == 1


def test_cms_routing_stage_can_be_disabled() -> None:
    context = ScanContext(target='https://example.test', settings=ScanSettings(run_cms_detection=False))
    context.artifacts.crawled_documents = {
        'https://example.test/': '<meta name="generator" content="WordPress 6.5"><script src="/wp-content/themes/foo/style.css"></script>'
    }

    result = CMSRoutingStage().run(context)

    assert result.findings == []
    assert result.debug.counts['cms_routing'] == 0
