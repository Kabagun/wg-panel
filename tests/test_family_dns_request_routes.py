"""End-to-end proposal permissions, private history and authenticated admin actions."""
# Shared imported pytest fixtures intentionally shadow test arguments.
# ruff: noqa: F811
import copy
from dataclasses import replace

import pytest
from test_family_dns_routes import (  # noqa: F401
    authenticated_client,
    runtime,
    state,
)
from werkzeug.datastructures import MultiDict

from wg_panel import account_policy, app, core, family_dns, family_dns_requests, security, wireguard
from wg_panel import family_dns_notifications as notices
from wg_panel.routes import family_dns as pages
from wg_panel.routes import telegram as callbacks


@pytest.fixture
def proposals(runtime, monkeypatch):
    account_policy.save_account_policies({'member': {'safe_internet_locked': True}})
    monkeypatch.setattr(wireguard, 'get_user_devices', lambda _username: [])
    queued = []
    monkeypatch.setattr(notices, 'submit_background', lambda *args: queued.append(args) or True)
    monkeypatch.setattr(pages, 'public_rate_limiter', security.WindowRateLimiter())
    return queued


def data(**extra):
    return {'csrf_token': 'synthetic-csrf', 'domain': 'docs.example.org',
            'reason': 'Needed for school', **extra}


def submit():
    response = authenticated_client('member').post('/family-dns/requests', data=data())
    assert response.status_code == 303
    return family_dns_requests.list_requests()[0]


def test_request_creation_is_not_dns_mutation_and_duplicate_notifies_once(proposals, runtime):
    client = authenticated_client('member')
    client.post('/family-dns/requests', data=data())
    client.post('/family-dns/requests', data=data(domain='DOCS.EXAMPLE.ORG.'))
    assert runtime == []
    stored = family_dns_requests.list_requests()
    assert len(stored) == 1 and stored[0]['status'] == 'pending'
    assert len(proposals) == 1
    _function, text, silent, parse_mode, buttons = proposals[0]
    assert silent and parse_mode is None
    assert 'member' in text and 'docs.example.org' in text
    assert 'для всех' in text
    assert all(len(button['callback_data'].encode()) <= 64 for button in buttons[0])
    body = client.get('/family-dns/requests', headers={'Accept-Language': 'ru'}).get_data(as_text=True)
    assert 'Ожидает одобрения' in body and 'docs.example.org' in body
    assert 'family_request_' not in body


def test_user_history_is_account_scoped_even_after_recreation(proposals):
    record = submit()
    old_id = record['account_id']
    core.mutate_users(lambda users: users['member'].update(account_id='a' * 64))
    response = authenticated_client('member').get('/family-dns/requests')
    assert 'docs.example.org' not in response.get_data(as_text=True)
    assert family_dns_requests.list_requests(old_id)[0]['id'] == record['id']
    admin = authenticated_client().get('/admin/family-dns').get_data(as_text=True)
    assert 'docs.example.org' not in admin


def test_normal_account_cannot_submit_until_family_protection_is_enabled(proposals):
    account_policy.save_account_policies({})
    response = authenticated_client('member').post('/family-dns/requests', data=data())
    assert response.status_code == 403 and family_dns_requests.list_requests() == []


def test_submit_requires_login_csrf_and_unpaused_account(proposals):
    assert authenticated_client(None).post('/family-dns/requests', data=data()).status_code == 302
    client = authenticated_client('member')
    assert client.post('/family-dns/requests', data=data(csrf_token='wrong')).status_code == 400
    core.mutate_users(lambda users: users['member'].update(paused=True))
    assert client.post('/family-dns/requests', data=data()).status_code == 302
    assert family_dns_requests.list_requests() == []


def test_ambiguous_and_invalid_domain_cannot_queue_requests(proposals):
    form = MultiDict(data())
    form.add('domain', 'other.example.org')
    client = authenticated_client('member')
    client.post('/family-dns/requests', data=form)
    client.post('/family-dns/requests', data=data(domain='https://example.org/private?key=secret'))
    assert family_dns_requests.list_requests() == [] and proposals == []


def test_notification_backpressure_preserves_admin_queue(proposals, monkeypatch):
    monkeypatch.setattr(notices, 'submit_background', lambda *args: False)
    record = submit()
    assert record['status'] == 'pending'
    body = authenticated_client().get('/admin/family-dns').get_data(as_text=True)
    assert 'docs.example.org' in body


def test_web_admin_review_is_versioned_and_does_not_reapply(proposals, runtime, monkeypatch, state):
    record = submit()
    def apply(operation, domain, generation):
        runtime.append((operation, domain, generation))
        return replace(state, domains=(*state.domains, domain), generation=generation + 1)
    monkeypatch.setattr(family_dns, 'change', apply)
    url = f"/admin/family-dns/requests/{record['id']}/approve"
    member = authenticated_client('member')
    assert member.post(url, data=data()).status_code == 302
    assert runtime == []
    admin = authenticated_client()
    assert admin.get(url).status_code == 405
    assert admin.post(url, data=data(csrf_token='wrong')).status_code == 400
    assert admin.post(url, data=data()).status_code == 303
    assert admin.post(url, data=data()).status_code == 303
    assert runtime == [('status',), ('add', 'docs.example.org', state.generation)]
    assert family_dns_requests.list_requests()[0]['status'] == 'approved'
    body = member.get('/family-dns/requests', headers={'Accept-Language': 'ru'}).get_data(as_text=True)
    assert 'Одобрено' in body


def test_web_rejection_does_not_call_dns_and_failed_apply_stays_pending(proposals, runtime, monkeypatch):
    record = submit()
    admin = authenticated_client()
    admin.post(f"/admin/family-dns/requests/{record['id']}/reject", data=data())
    assert runtime == [] and family_dns_requests.list_requests()[0]['status'] == 'rejected'
    second, _ = family_dns_requests.submit('member', record['account_id'], 'second.example.org')
    def fail(*args):
        raise family_dns.FamilyDnsError('apply_failed')
    monkeypatch.setattr(family_dns, 'change', fail)
    admin.post(f"/admin/family-dns/requests/{second['id']}/approve", data=data())
    assert next(r for r in family_dns_requests.list_requests() if r['id'] == second['id'])['status'] == 'pending'


def test_user_comments_are_autoescaped(proposals):
    authenticated_client('member').post('/family-dns/requests', data=data(reason='<script>bad()</script>'))
    for client, path in ((authenticated_client('member'), '/family-dns/requests'),
                         (authenticated_client(), '/admin/family-dns')):
        body = client.get(path).get_data(as_text=True)
        assert '<script>bad()</script>' not in body and '&lt;script&gt;' in body


def test_authenticated_telegram_admin_uses_same_review_service(proposals, runtime, monkeypatch, state):
    record = submit()
    replies, edits, jobs = [], [], []
    monkeypatch.setattr(callbacks, 'TG_CHAT_ID', '42')
    monkeypatch.setattr(callbacks, 'TG_WEBHOOK_SECRET', 'synthetic-secret')
    monkeypatch.setattr(callbacks, 'answer_callback', lambda *args: replies.append(args))
    monkeypatch.setattr(callbacks, 'edit_tg_message', lambda *args, **kw: edits.append((args, kw)))
    monkeypatch.setattr(callbacks, 'submit_background', lambda *args: jobs.append(args) or True)
    monkeypatch.setattr(family_dns, 'change', lambda operation, domain, generation:
                        replace(state, domains=(*state.domains, domain), generation=generation + 1))
    payload = {'callback_query': {'id': 'cb', 'from': {'id': 42},
               'message': {'chat': {'id': 42}, 'message_id': 10},
               'data': f"dns:approve:{record['id']}"}}
    client = app.test_client()
    assert client.post('/tg_webhook', json=payload).status_code == 403
    bad_actor = copy.deepcopy(payload)
    bad_actor['callback_query']['from']['id'] = 41
    headers = {'X-Telegram-Bot-Api-Secret-Token': 'synthetic-secret'}
    assert client.post('/tg_webhook', json=bad_actor, headers=headers).status_code == 403
    assert jobs == [] and runtime == []
    assert client.post('/tg_webhook', json=payload, headers=headers).status_code == 200
    assert len(jobs) == 1 and replies[-1][1] == 'Проверяю заявку…'
    jobs[0][0](*jobs[0][1:])
    assert family_dns_requests.list_requests()[0]['status'] == 'approved'
    assert edits[-1][1] == {'remove_buttons': True}
    assert runtime == [('status',)]
