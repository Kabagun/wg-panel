"""Administrator controls for shared family DNS exceptions."""

import re
from datetime import UTC, datetime

from flask import abort, flash, redirect, request, session, url_for

from .. import family_dns, family_dns_requests
from ..auth import admin_required, approved_required
from ..core import _lang, app, load_users
from ..i18n import t
from ..security import client_ip, public_rate_limiter, rate_limited_response
from ..ui import render_page


def _time_label(value):
    if value is None:
        return "—"
    try:
        return datetime.fromtimestamp(value, UTC).strftime("%d.%m.%Y %H:%M UTC")
    except (ValueError, OverflowError, OSError):
        return "—"


@app.route("/admin/family-dns")
@admin_required
def admin_family_dns():
    state = None
    error = None
    try:
        state = family_dns.status()
    except family_dns.FamilyDnsError as failure:
        error = failure.code
    proposals, requests_error = [], False
    try:
        users = load_users()
        proposals = [item for item in family_dns_requests.list_requests()
                     if users.get(item['username'], {}).get('account_id') == item['account_id']]
    except family_dns_requests.RequestError:
        requests_error = True
    return render_page(
        "family_dns.html", "family_dns_title", state=state, error=error,
        time_label=_time_label, proposals=proposals, requests_error=requests_error,
    )


def _change(operation):
    try:
        domains = request.form.getlist("domain")
        generations = request.form.getlist("expected_generation")
        if len(domains) != 1:
            raise family_dns.FamilyDnsError("invalid_domain")
        if len(generations) != 1 or not re.fullmatch(r"0|[1-9][0-9]{0,19}", generations[0]):
            raise family_dns.FamilyDnsError("stale_generation")
        family_dns.change(operation, domains[0], int(generations[0]))
        flash(t("family_dns_added" if operation == "add" else "family_dns_removed", _lang()), "ok")
    except family_dns.FamilyDnsError as failure:
        flash(t("family_dns_error_" + failure.code, _lang()), "error")
    return redirect(url_for("admin_family_dns"), code=303)


@app.route("/admin/family-dns/allow", methods=["POST"])
@admin_required
def admin_family_dns_allow():
    return _change("add")


@app.route("/admin/family-dns/allow/remove", methods=["POST"])
@admin_required
def admin_family_dns_remove():
    return _change("remove")


def _family_protection(username):
    from .. import wireguard
    from ..account_policy import account_safe_internet_locked
    if account_safe_internet_locked(username):
        return True
    for name in wireguard.get_user_devices(username):
        device = wireguard.get_device(wireguard.client_name(username, name))
        if device and not device.get('happ_transport_internal') and device.get('safe_internet'):
            return True
    return False


def _proposal_error(error):
    prefix = 'family_dns_error_' if isinstance(error, family_dns.FamilyDnsError) else 'family_request_error_'
    key = prefix + error.code
    text = t(key, _lang())
    return t('family_request_error_unavailable', _lang()) if text == key else text


@app.route('/family-dns/requests', methods=['GET', 'POST'])
@approved_required
def family_dns_requests_page():
    username = session['user']
    user = load_users()[username]
    protected = _family_protection(username)
    if request.method == 'POST':
        if not protected:
            abort(403)
        allowed, retry = public_rate_limiter.consume(
            'family_dns_proposal', user['account_id'] + ':' + client_ip(), 5, 3600)
        if not allowed:
            return rate_limited_response(retry)
        try:
            domains, reasons = request.form.getlist('domain'), request.form.getlist('reason')
            if len(domains) != 1 or len(reasons) > 1:
                raise family_dns_requests.RequestError('invalid_domain')
            record, created = family_dns_requests.submit(
                username, user['account_id'], domains[0], reasons[0] if reasons else '')
            if created:
                from ..family_dns_notifications import notify_request
                notify_request(record)
            flash(t('family_request_submitted' if created else 'family_request_duplicate', _lang()), 'ok')
        except (family_dns_requests.RequestError, family_dns.FamilyDnsError) as failure:
            flash(_proposal_error(failure), 'error')
        return redirect(url_for('family_dns_requests_page'), code=303)
    proposals, unavailable = [], False
    try:
        proposals = family_dns_requests.list_requests(user['account_id'])
    except family_dns_requests.RequestError:
        unavailable = True
    return render_page('family_dns_requests.html', 'family_request_title',
                       proposals=proposals, protected=protected, unavailable=unavailable)


@app.route('/admin/family-dns/requests/<request_id>/<decision>', methods=['POST'])
@admin_required
def admin_family_dns_review(request_id, decision):
    if decision not in {'approve', 'reject'}:
        abort(404)
    try:
        family_dns_requests.review(request_id, decision, session['user'])
        flash(t('family_request_reviewed_' + decision, _lang()), 'ok')
    except (family_dns_requests.RequestError, family_dns.FamilyDnsError) as failure:
        flash(_proposal_error(failure), 'error')
    return redirect(url_for('admin_family_dns'), code=303)
