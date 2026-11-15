"""Smart routing requests use independent approvals and never unblock family DNS."""
# Shared runtime fixture intentionally shadows test arguments.
# ruff: noqa: F811
import copy

import pytest
from test_happ_rules_routes import CSRF, browser, runtime  # noqa: F401

from wg_panel import app, core, family_dns, family_dns_requests, security
from wg_panel import family_dns_notifications as notices
from wg_panel.routes import happ_rules as pages
from wg_panel.routes import telegram as callbacks


@pytest.fixture
def proposals(runtime, monkeypatch):
    queued = []
    monkeypatch.setattr(notices, 'submit_background', lambda *args: queued.append(args) or True)
    monkeypatch.setattr(pages, 'public_rate_limiter', security.WindowRateLimiter())
    monkeypatch.setattr(family_dns, 'status', lambda: pytest.fail('Smart approval touched DNS'))
    monkeypatch.setattr(family_dns, 'change', lambda *args: pytest.fail('Smart approval changed DNS'))
    return queued


def form(**extra):
    return {'csrf_token': CSRF, 'domain': 'new.example.org', 'reason': 'Route this service', **extra}


def submit():
    assert browser('member').post('/happ/requests', data=form()).status_code == 303
    return family_dns_requests.list_requests(kind='smart')[0]


def test_ordinary_nonfamily_user_can_submit_without_mutating_lists(proposals, runtime):
    client = browser('member')
    client.post('/happ/requests', data=form())
    client.post('/happ/requests', data=form(domain='NEW.EXAMPLE.ORG.'))
    assert runtime.calls == [] and runtime.queued == []
    assert len(family_dns_requests.list_requests(kind='smart')) == 1
    assert family_dns_requests.list_requests() == []
    assert len(proposals) == 1
    _, text, silent, parse_mode, buttons = proposals[0]
    assert 'Умный VPN' in text and 'Семейный DNS не изменится' in text
    assert silent and parse_mode is None
    assert all(button['callback_data'].startswith('smart:') for button in buttons[0])
    body = client.get('/happ/requests', headers={'Accept-Language': 'ru'}).get_data(as_text=True)
    assert 'Заявки в Умный VPN' in body and 'Ожидает одобрения' in body
    assert 'smart_request_' not in body


def test_smart_web_approval_uses_managed_revision_and_publication_once(proposals, runtime):
    record = submit()
    url = f"/admin/happ-rules/requests/{record['id']}/approve"
    assert browser('member').post(url, data=form()).status_code == 302
    assert runtime.calls == []
    admin = browser()
    assert admin.post(url, data=form()).status_code == 303
    assert admin.post(url, data=form()).status_code == 303
    assert family_dns_requests.list_requests(kind='smart')[0]['status'] == 'approved'
    assert 'domain:new.example.org' in runtime.snapshot['rules']
    assert len([row for row in runtime.calls if row[0] == 'change']) == 1
    assert len(runtime.queued) == 1


def test_pending_rejection_never_applies_or_publishes(proposals, runtime):
    record = submit()
    response = browser().post(f"/admin/happ-rules/requests/{record['id']}/reject", data=form())
    assert response.status_code == 303
    assert runtime.calls == [] and runtime.queued == []
    assert family_dns_requests.list_requests(kind='smart')[0]['status'] == 'rejected'


def test_csrf_authentication_and_account_lifecycle_protect_submit_and_review(proposals):
    assert browser(None).post('/happ/requests', data=form()).status_code == 302
    assert browser('member').post('/happ/requests', data=form(csrf_token='wrong')).status_code == 400
    record = submit()
    url = f"/admin/happ-rules/requests/{record['id']}/approve"
    assert browser().get(url).status_code == 405
    assert browser().post(url, data=form(csrf_token='wrong')).status_code == 400
    core.mutate_users(lambda users: users['member'].update(account_id='f' * 64))
    body = browser('member').get('/happ/requests').get_data(as_text=True)
    assert 'new.example.org' not in body
    browser().post(url, data=form())
    assert family_dns_requests.list_requests(kind='smart')[0]['status'] == 'pending'


def test_publication_backpressure_does_not_revert_active_routing(proposals, runtime, monkeypatch):
    record = submit()
    from wg_panel import happ_shared_rules
    monkeypatch.setattr(happ_shared_rules, 'enqueue_publication', lambda: False)
    browser().post(f"/admin/happ-rules/requests/{record['id']}/approve", data=form())
    assert 'domain:new.example.org' in runtime.snapshot['rules']
    assert family_dns_requests.list_requests(kind='smart')[0]['status'] == 'approved'


def test_telegram_smart_callback_cannot_act_on_dns_request_and_needs_admin(proposals, monkeypatch):
    record = submit()
    jobs, replies, edits = [], [], []
    monkeypatch.setattr(callbacks, 'TG_CHAT_ID', '42')
    monkeypatch.setattr(callbacks, 'TG_WEBHOOK_SECRET', 'synthetic-secret')
    monkeypatch.setattr(callbacks, 'answer_callback', lambda *args: replies.append(args))
    monkeypatch.setattr(callbacks, 'edit_tg_message', lambda *args, **kw: edits.append((args, kw)))
    monkeypatch.setattr(callbacks, 'submit_background', lambda *args: jobs.append(args) or True)
    payload = {'callback_query': {'id': 'cb', 'from': {'id': 42},
               'message': {'chat': {'id': 42}, 'message_id': 10},
               'data': f"smart:approve:{record['id']}"}}
    headers = {'X-Telegram-Bot-Api-Secret-Token': 'synthetic-secret'}
    client = app.test_client()
    assert client.post('/tg_webhook', json=payload).status_code == 403
    bad = copy.deepcopy(payload)
    bad['callback_query']['from']['id'] = 41
    assert client.post('/tg_webhook', json=bad, headers=headers).status_code == 403
    assert jobs == []
    assert client.post('/tg_webhook', json=payload, headers=headers).status_code == 200
    jobs[0][0](*jobs[0][1:])
    assert family_dns_requests.list_requests(kind='smart')[0]['status'] == 'approved'
    assert 'Умного VPN' in edits[-1][0][2]
    assert edits[-1][1] == {'remove_buttons': True}
    assert family_dns_requests.list_requests() == []
