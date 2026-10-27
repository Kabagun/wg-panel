"""Administrator controls for shared family DNS exceptions."""

import re
from datetime import UTC, datetime

from flask import flash, redirect, request, url_for

from .. import family_dns
from ..auth import admin_required
from ..core import _lang, app
from ..i18n import t
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
    return render_page(
        "family_dns.html", "family_dns_title", state=state, error=error,
        time_label=_time_label,
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
