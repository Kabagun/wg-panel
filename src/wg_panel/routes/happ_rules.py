"""Site-managed Happ routing domains with independent asynchronous publication."""

import re
from datetime import UTC, datetime

from flask import abort, flash, redirect, request, session, url_for

from .. import core, family_dns_requests, happ_pilot, happ_shared_rules
from ..auth import admin_required, approved_required
from ..i18n import t
from ..security import client_ip, public_rate_limiter, rate_limited_response
from ..ui import render_page
from .family_dns import _proposal_error


def _require_managed():
    if not happ_pilot.pilot_enabled() or not happ_shared_rules.managed_mode():
        abort(404)


def _time_label(value):
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")
    except (AttributeError, TypeError, ValueError, OverflowError):
        return "—"


def _publication(revision):
    try:
        state = happ_shared_rules.publication_status(core.DATA_DIR, revision)
        if state.get("status") in {"never", "pending", "updated", "unchanged", "error"}:
            return state
    except (OSError, ValueError):
        pass
    return {"status": "error", "last_attempt_at": None, "last_success_at": None,
            "commit": None, "published_revision": None}


@core.app.route("/admin/happ-rules")
@approved_required
@admin_required
def admin_happ_rules():
    _require_managed()
    state = None
    publication = None
    try:
        state = happ_shared_rules.load_snapshot(core.DATA_DIR, happ_pilot.shared_rules_url())
        publication = _publication(state["revision"])
    except (OSError, ValueError):
        pass
    proposals, requests_error = [], False
    try:
        users = core.load_users()
        proposals = [item for item in family_dns_requests.list_requests(kind='smart')
                     if users.get(item['username'], {}).get('account_id') == item['account_id']]
    except family_dns_requests.RequestError:
        requests_error = True
    return render_page(
        "happ_rules.html", "happ_admin_title", state=state, publication=publication,
        domains=[rule.removeprefix("domain:") for rule in state["rules"]] if state else [],
        time_label=_time_label, proposals=proposals, requests_error=requests_error,
    ), 200 if state else 503


def _enqueue_publication():
    return happ_shared_rules.enqueue_publication()


def _change(operation):
    try:
        if (set(request.form) - {"csrf_token", "domain", "revision"}
                or any(len(request.form.getlist(field)) != 1
                       for field in ("csrf_token", "domain", "revision"))):
            raise ValueError("invalid_domain")
        domain = request.form["domain"]
        if not domain or len(domain) > 253:
            raise ValueError("invalid_domain")
        revision = request.form["revision"]
        if not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("stale_revision")
        source = happ_pilot.shared_rules_url()
        previous = happ_shared_rules.load_snapshot(core.DATA_DIR, source)["revision"]
        changed = happ_shared_rules.change(core.DATA_DIR, source, operation, domain, revision)
    except (OSError, ValueError) as failure:
        code = str(failure)
        if code not in {"invalid_domain", "stale_revision", "unavailable"}:
            code = "unavailable"
        flash(t("happ_admin_error_" + code, core._lang()), "error")
        return redirect(url_for("admin_happ_rules"), code=303)
    if changed["revision"] == previous:
        flash(t("happ_admin_unchanged", core._lang()), "ok")
    else:
        flash(t("happ_admin_added" if operation == "add" else "happ_admin_removed",
                core._lang()), "ok")
        if not _enqueue_publication():
            flash(t("happ_admin_queue_delayed", core._lang()), "error")
    return redirect(url_for("admin_happ_rules"), code=303)


@core.app.route("/admin/happ-rules/add", methods=["POST"])
@approved_required
@admin_required
def admin_happ_rules_add():
    _require_managed()
    return _change("add")


@core.app.route("/admin/happ-rules/remove", methods=["POST"])
@approved_required
@admin_required
def admin_happ_rules_remove():
    _require_managed()
    return _change("remove")


@core.app.route('/happ/requests', methods=['GET', 'POST'])
@approved_required
def smart_vpn_requests_page():
    _require_managed()
    username = session['user']
    user = core.load_users()[username]
    if request.method == 'POST':
        allowed, retry = public_rate_limiter.consume(
            'smart_vpn_proposal', user['account_id'] + ':' + client_ip(), 5, 3600)
        if not allowed:
            return rate_limited_response(retry)
        try:
            domains, reasons = request.form.getlist('domain'), request.form.getlist('reason')
            if len(domains) != 1 or len(reasons) > 1:
                raise family_dns_requests.RequestError('invalid_domain')
            record, created = family_dns_requests.submit(
                username, user['account_id'], domains[0], reasons[0] if reasons else '', kind='smart')
            if created:
                from ..family_dns_notifications import notify_request
                notify_request(record, kind='smart')
            flash(t('family_request_submitted' if created else 'family_request_duplicate', core._lang()), 'ok')
        except family_dns_requests.RequestError as failure:
            flash(_proposal_error(failure), 'error')
        return redirect(url_for('smart_vpn_requests_page'), code=303)
    proposals, unavailable = [], False
    try:
        proposals = family_dns_requests.list_requests(user['account_id'], kind='smart')
    except family_dns_requests.RequestError:
        unavailable = True
    return render_page('family_dns_requests.html', 'smart_request_title',
                       proposals=proposals, protected=True, unavailable=unavailable, request_kind='smart')


@core.app.route('/admin/happ-rules/requests/<request_id>/<decision>', methods=['POST'])
@approved_required
@admin_required
def admin_smart_vpn_review(request_id, decision):
    _require_managed()
    if decision not in {'approve', 'reject'}:
        abort(404)
    try:
        family_dns_requests.review(request_id, decision, session['user'], kind='smart')
        flash(t('smart_request_approved' if decision == 'approve'
                else 'family_request_reviewed_reject', core._lang()), 'ok')
    except family_dns_requests.RequestError as failure:
        flash(_proposal_error(failure), 'error')
    return redirect(url_for('admin_happ_rules'), code=303)
