"""Site-managed Happ routing domains with independent asynchronous publication."""

import re
import subprocess
from datetime import UTC, datetime

from flask import abort, flash, redirect, request, url_for

from .. import core, happ_pilot, happ_shared_rules
from ..auth import admin_required, approved_required
from ..i18n import t
from ..ui import render_page


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
    return render_page(
        "happ_rules.html", "happ_admin_title", state=state, publication=publication,
        domains=[rule.removeprefix("domain:") for rule in state["rules"]] if state else [],
        time_label=_time_label,
    ), 200 if state else 503


def _enqueue_publication():
    try:
        result = subprocess.run(
            ["systemctl", "--no-block", "start", "wg-panel-happ-publish.service"],
            capture_output=True, timeout=5, check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


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
