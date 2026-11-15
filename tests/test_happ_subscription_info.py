"""Public synthetic metadata and strict header/link boundaries."""
import base64
from urllib.parse import urlsplit

import pytest

from wg_panel.happ_subscription_info import (
    build_headers,
    profile_caption,
    profile_label,
    subscription_title,
)


def headers(**overrides):
    return build_headers(**{
        'upload_bytes': 12, 'download_bytes': 34,
        'panel_base_url': 'https://panel.example.test',
        'device_path': '/device/synthetic-phone/happ',
        'usage_month': '2026-11', 'usage_scope': 'device', **overrides,
    })


def announcement(result):
    prefix, encoded = result['announce'].split(':', 1)
    assert prefix == 'base64'
    return base64.b64decode(encoded, validate=True).decode('utf-8')


@pytest.mark.parametrize('mode,label,caption', [
    ('all', '🌐 Всё через VPN', 'Весь интернет через VPN'),
    ('custom', '🧠 Умный VPN', 'Сайты из списка через VPN'),
    ('by-ru-direct', '🏡 РБ/РФ напрямую', 'РБ/РФ мимо · остальное VPN'),
    ('by-direct', '🇧🇾 Беларусь напрямую', 'Беларусь мимо · остальное VPN'),
    ('ru-direct', '🇷🇺 Россия напрямую', 'Россия мимо · остальное VPN'),
])
def test_profile_labels_and_short_captions_are_logical_unicode(mode, label, caption):
    assert profile_label(mode) == label
    assert profile_caption(mode) == caption
    assert len(caption) <= 30


@pytest.mark.parametrize('mode,suffix', [
    ('all', '🌐 Всё'), ('custom', '🧠 Умный'), ('by-ru-direct', '🏡 РБ/РФ'),
    ('by-direct', '🇧🇾 РБ'), ('ru-direct', '🇷🇺 РФ'),
])
@pytest.mark.parametrize('comparison', [False, True])
def test_single_profile_titles_fit_happ_limit(mode, suffix, comparison):
    title = subscription_title(mode, comparison=comparison)
    assert title == 'Kabagun VPN · ' + suffix
    assert len(title) <= 25


def test_bundle_titles_distinguish_dns_comparison():
    assert subscription_title('bundle') == '🛡️ Kabagun VPN'
    assert subscription_title('bundle', comparison=True) == 'Kabagun VPN · 🧪 DNS'
    assert len(subscription_title('bundle')) <= 25
    assert len(subscription_title('bundle', comparison=True)) <= 25


@pytest.mark.parametrize('value', [None, True, False, 1, [], {}, '', 'unknown',
                                 'all\nInjected: yes', 'private-synthetic-text'])
@pytest.mark.parametrize('present', [profile_label, profile_caption, subscription_title])
def test_presentation_rejects_invalid_modes_without_echoing_input(present, value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        present(value)


@pytest.mark.parametrize('present', [profile_label, profile_caption])
def test_bundle_is_not_a_routing_profile(present):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        present('bundle')


@pytest.mark.parametrize('mode', ['bundle', 'all'])
@pytest.mark.parametrize('value', [None, 0, 1, '', 'true', [], {}])
def test_title_comparison_flag_requires_a_boolean(mode, value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        subscription_title(mode, comparison=value)


@pytest.mark.parametrize('upload,download', [(0, 0), (12, 34), ((1 << 63) - 1, (1 << 63) - 1)])
def test_explicit_counts_have_no_invented_quota_or_expiry(upload, download):
    result = headers(upload_bytes=upload, download_bytes=download)
    assert result['subscription-userinfo'] == f'upload={upload}; download={download}; total=0'
    assert set(result) == {'subscription-userinfo', 'profile-web-page-url', 'support-url', 'announce'}
    assert 'expire' not in str(result)
    assert all(value.isascii() and '\r' not in value and '\n' not in value
               for value in result.values())


def test_unknown_directions_do_not_become_invented_zero_usage():
    result = headers(upload_bytes=None, download_bytes=None)
    assert 'subscription-userinfo' not in result


@pytest.mark.parametrize('field', ['upload_bytes', 'download_bytes'])
@pytest.mark.parametrize('value', [-1, True, False, 1.5, '12', '0\r\nInjected: yes', None, 1 << 63])
def test_invalid_counts_are_rejected_without_echoing_input(field, value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(**{field: value})


@pytest.mark.parametrize('base,expected', [
    ('https://panel.example.test', 'https://panel.example.test'),
    ('https://panel.example.test/', 'https://panel.example.test'),
    ('https://panel.example.test/panel', 'https://panel.example.test/panel'),
    ('https://panel.example.test/panel/', 'https://panel.example.test/panel'),
    ('https://panel.example.test:8443/base/v2/', 'https://panel.example.test:8443/base/v2'),
])
def test_links_preserve_origin_and_base_path(base, expected):
    result = headers(panel_base_url=base)
    assert result['profile-web-page-url'] == expected + '/device/synthetic-phone/happ'
    assert result['support-url'] == expected + '/'
    assert urlsplit(result['profile-web-page-url']).netloc == urlsplit(base).netloc
    assert urlsplit(result['support-url']).netloc == urlsplit(base).netloc


@pytest.mark.parametrize('base', [
    'http://panel.example.test', '//panel.example.test',
    'https://user:secret@panel.example.test', 'https://panel.example.test?token=synthetic',
    'https://panel.example.test?', 'https://panel.example.test/#synthetic',
    'https://panel.example.test/\r\nInjected: yes', ' https://panel.example.test',
    'https://panel.example.test/%0a', 'https://panel.example.test/../other',
    'https://panel.example.test/base//other', 'https://panel.example.test/base\\other',
    'https://panel.example.test/happ/sub/synthetic-token/bundle',
    'https://localhost', 'https://127.0.0.1', 'https://10.0.0.1',
    'https://panel.internal', 'https://[::1]', 'https://127.1', 'https://0x7f.1',
    'https://panel.example.test:99999',
    'https://panel.example.test:0', 'https://panel.example.test./',
    'https://panel.example.test/' + 'x' * 2048, None,
])
def test_unsafe_or_nonpublic_panel_base_is_rejected(base):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(panel_base_url=base)


@pytest.mark.parametrize('path', [
    '/happ/sub/synthetic-phone/synthetic-token/bundle',
    '/device/synthetic-phone/happ?token=synthetic-token',
    '/device/synthetic-phone/happ#synthetic-token',
    'https://other.example.test/device/synthetic-phone', '//other.example.test',
    '/device/../secret', '/device/synthetic-phone%2fhapp',
    '/device/synthetic-phone/happ\r\nInjected: yes', '/device/synthetic-phone/download',
    '/device/' + 'x' * 129, None,
])
def test_device_page_only_never_accepts_subscription_links_or_tokens(path):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(device_path=path)


@pytest.mark.parametrize('comparison', [False, True])
@pytest.mark.parametrize('scope', ['device', 'account'])
def test_utf8_announcement_describes_exact_profile_and_usage_scope(comparison, scope):
    text = announcement(headers(comparison=comparison, usage_scope=scope))
    assert len(text) <= 200
    assert len(text.splitlines()) == 3
    assert text.splitlines()[1] == '🌐 Всё через VPN · 🧠 Умный VPN · 🏡 РБ/РФ напрямую'
    assert ('6 профилей' in text) is comparison
    assert '2026-11' in text
    assert ('все устройства аккаунта' if scope == 'account' else 'это устройство') in text
    assert 'Безлимит' in text
    assert 'семейный/обычный DNS' in text if comparison else 'Умный VPN' in text


@pytest.mark.parametrize('safe,status', [
    (None, '♾️ Безлимит'),
    (True, '♾️ Безлимит · 🛡️ Семейная защита'),
    (False, '♾️ Безлимит · 🌐 Обычный DNS'),
])
def test_explicit_dns_status_is_encoded_in_standard_ascii_headers(safe, status):
    result = headers(safe_internet=safe)
    text = announcement(result)
    assert text.splitlines()[0] == status
    assert base64.b64encode(text.encode('utf-8')).decode('ascii') == result['announce'][7:]
    assert all(value.isascii() and '\r' not in value and '\n' not in value
               for value in result.values())


@pytest.mark.parametrize('value', [0, 1, '', 'false', 'true', [], {}, 'private\nInjected: yes'])
def test_dns_status_requires_a_boolean_or_none(value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(safe_internet=value)


@pytest.mark.parametrize('safe', [None, False, True])
@pytest.mark.parametrize('comparison,control', [(False, False), (True, False), (True, True)])
@pytest.mark.parametrize('scope', ['device', 'account', 'sources'])
@pytest.mark.parametrize('started', [None, '9999-12-31'])
def test_banner_is_three_bounded_lines_for_every_status_scope_and_period(
        safe, comparison, control, scope, started):
    text = announcement(headers(safe_internet=safe, comparison=comparison,
                                comparison_control=control, usage_scope=scope,
                                usage_started_at=started))
    lines = text.splitlines()
    assert len(lines) == 3 and len(text) <= 200
    assert lines[0].startswith('♾️ Безлимит')
    assert lines[2] == (
        ('Учёт с 31.12.9999' if started else 'Трафик за 2026-11') + ': '
        + {'device': 'это устройство', 'account': 'все устройства аккаунта',
           'sources': 'устройства подписки'}[scope] + '.')
    if comparison:
        assert f'{7 if control else 6} профилей' in lines[0]
        assert 'семейный/обычный DNS' in lines[0]
        assert 'Семейная защита' not in lines[0]
    assert ('контроль UDP без QUIC' in text) is control


@pytest.mark.parametrize('field,value', [
    ('usage_month', '2026-00'), ('usage_month', '2026-13'), ('usage_month', '0000-01'),
    ('usage_month', '2026-11\r\nInjected: yes'), ('usage_month', None),
    ('usage_scope', 'unknown'), ('usage_scope', 'account\nprivate'),
    ('usage_scope', []), ('comparison', 1), ('comparison', 'false'),
    ('comparison_control', 1), ('comparison_control', 'true'), ('comparison_control', True),
])
def test_announcement_inputs_are_bounded_and_have_no_arbitrary_private_text(field, value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(**{field: value})


@pytest.mark.parametrize('comparison', [False, True])
def test_explicit_started_date_and_sources_scope_replace_month_text(comparison):
    text = announcement(headers(usage_started_at='2026-11-14', usage_scope='sources',
                                comparison=comparison))
    assert 'Учёт с 14.11.2026' in text
    assert 'устройства подписки' in text
    assert 'Трафик за' not in text
    assert len(text) <= 200


def test_started_date_does_not_require_legacy_month_argument():
    result = build_headers(upload_bytes=0, download_bytes=0,
                           panel_base_url='https://panel.example.test',
                           device_path='/device/synthetic-phone', usage_scope='device',
                           usage_started_at='2026-11-14')
    assert 'Учёт с 14.11.2026' in announcement(result)


@pytest.mark.parametrize('value', ['2026-02-30', '2026-11-14\nsecret', '14.11.2026',
                                 '2026-11-14T12:00:00Z', '', 123])
def test_invalid_explicit_start_date_is_rejected(value):
    with pytest.raises(ValueError, match='^Invalid subscription presentation data$'):
        headers(usage_started_at=value)
