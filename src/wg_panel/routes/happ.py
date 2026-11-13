"""Owner-scoped Happ configuration and revocable read-only subscriptions."""
import hmac
import json
import re

from flask import Response, abort, flash, redirect, request, session, url_for

from .. import core, happ_pilot, wireguard
from ..auth import admin_required, approved_required
from ..happ_config import MODES
from ..i18n import t
from ..security import client_ip, public_rate_limiter, rate_limited_response
from ..ui import render_page


def _require_pilot():
    if not happ_pilot.pilot_enabled():
        abort(404)


def _pilot_device(wg_name, *, public=False):
    _require_pilot()
    device = wireguard.get_device(wg_name)
    if (not happ_pilot.is_pilot_device(device) or device.get('deletion_protected')
            or device.get('vpn_type', 'wireguard') != 'wireguard'):
        abort(404)
    user = core.load_users().get(device['owner'], {})
    if not happ_pilot.available_for_user(user):
        abort(404)
    if not public and device['owner'] != session.get('user'):
        abort(404)
    return device, user


def _mode(device):
    mode = request.values.get('mode', 'all' if device['safe_internet'] else 'custom')
    if mode not in MODES or (device['safe_internet'] and mode != 'all'):
        abort(404)
    return mode


def _subscription_url(device, user, mode):
    base = core.app.config.get('HAPP_PUBLIC_BASE_URL', f'https://{core.DOMAIN}')
    return base.rstrip('/') + url_for('happ_subscription', wg_name=device['wg_name'],
                                      token=happ_pilot.subscription_token(device, user), mode=mode)


def _valid_export_mode(device, mode):
    return mode == 'bundle' or (mode in MODES and (not device['safe_internet'] or mode == 'all'))


@core.app.route('/admin/happ-pilot', methods=['GET', 'POST'], endpoint='happ_pilot')
@approved_required
@admin_required
def happ_pilot_page():
    _require_pilot()
    if request.method == 'POST':
        name = request.form.get('device', '').strip().lower()
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?', name):
            flash(t('ui_name_hint', core._lang()), 'error')
        else:
            ok, wg_name, _error = happ_pilot.create_pilot_device(session['user'], name)
            if ok:
                return redirect(url_for('view_happ_device', wg_name=wg_name), code=303)
            flash(t('happ_create_failed', core._lang()), 'error')
        return redirect(url_for('happ_pilot'), code=303)
    user = core.load_users()[session['user']]
    own = wireguard.get_user_devices(session['user'])
    devices = []
    for name in own:
        device = wireguard.get_device(wireguard.client_name(session['user'], name))
        if happ_pilot.is_pilot_device(device):
            devices.append(device)
    limit = user.get('max_devices', 3)
    return render_page('happ_pilot.html', 'happ_title', devices=devices, max_devices=limit,
                       can_add=not user.get('paused') and (limit == -1 or len(own) < limit))


@core.app.route('/device/<wg_name>/happ')
@approved_required
def view_happ_device(wg_name):
    device, user = _pilot_device(wg_name)
    mode = _mode(device)
    try:
        revision, rules = happ_pilot.get_rules(user['account_id'])
        config = happ_pilot.exported_config(device, mode, rules)
        subscription_url = _subscription_url(device, user, 'bundle')
        shared_context = happ_pilot.shared_rules_context()
    except ValueError:
        return 'Happ configuration is unavailable.', 503
    import_url = 'happ://add/' + subscription_url
    return render_page('happ_device.html', 'happ_title', device=device, wg_name=wg_name,
                       mode=mode, modes=[{'id': key, 'title_key': 'happ_mode_' + key.replace('-', '_'),
                                         'enabled': not device['safe_internet'] or key == 'all'}
                                        for key in happ_pilot.BUNDLE_MODES], proxy_rules=rules,
                       rules_text='\n'.join(rule.removeprefix('domain:') for rule in rules)
                       if shared_context['shared_rules'] else '\n'.join(rules), rules_revision=revision,
                       config_json=json.dumps(config, ensure_ascii=False, indent=2),
                       subscription_url=subscription_url, import_url=import_url,
                       qr=happ_pilot.qr_for_link(import_url), owner_paused=False,
                       owner_pause_pending=False, **shared_context)


def _response(device, mode, rules):
    config = (happ_pilot.exported_bundle(device, rules) if mode == 'bundle'
              else happ_pilot.exported_config(device, mode, rules))
    response = Response(json.dumps(config, ensure_ascii=False, indent=2),
                        content_type='application/json; charset=utf-8')
    response.headers.set('Content-Disposition', 'attachment',
                         filename=f"{device['device']}-{mode}.json")
    response.headers['routing'] = happ_pilot.routing_header(device, mode, config)
    response.headers['profile-title'] = 'VPN modes' if mode == 'bundle' else f'Happ pilot - {mode}'
    response.headers['profile-update-interval'] = '1'
    response.headers['tun-enable'] = '1'
    return response


@core.app.route('/device/<wg_name>/happ/<mode>/download')
@approved_required
def download_happ_device(wg_name, mode):
    device, user = _pilot_device(wg_name)
    if not _valid_export_mode(device, mode):
        abort(404)
    try:
        _revision, rules = happ_pilot.get_rules(user['account_id'])
        return _response(device, mode, rules)
    except ValueError:
        return 'Happ configuration is unavailable.', 503


@core.app.route('/account/happ-rules', methods=['POST'])
@approved_required
def update_happ_rules():
    wg_name = request.form.get('wg_name', '')
    device, user = _pilot_device(wg_name)
    if happ_pilot.shared_rules_url():
        abort(403)
    mode = _mode(device)
    try:
        revisions = request.form.getlist('revision')
        values = request.form.getlist('rules')
        if len(revisions) != 1 or len(values) != 1 or not re.fullmatch(r'0|[1-9][0-9]{0,12}', revisions[0]):
            raise ValueError
        happ_pilot.save_rules(user['account_id'], values[0], int(revisions[0]))
        flash(t('happ_rules_saved', core._lang()), 'ok')
    except ValueError:
        flash(t('happ_rules_failed', core._lang()), 'error')
    return redirect(url_for('view_happ_device', wg_name=wg_name, mode=mode), code=303)


@core.app.route('/device/<wg_name>/happ/rotate', methods=['POST'])
@approved_required
def rotate_happ_subscription(wg_name):
    device, _user = _pilot_device(wg_name)
    mode = _mode(device)
    happ_pilot.rotate_subscription(wg_name)
    flash(t('happ_rotated', core._lang()), 'ok')
    return redirect(url_for('view_happ_device', wg_name=wg_name, mode=mode), code=303)


@core.app.route('/happ/sub/<wg_name>/<token>/<mode>')
def happ_subscription(wg_name, token, mode):
    _require_pilot()
    allowed, retry = public_rate_limiter.consume('happ_subscription', client_ip(), 60, 60)
    if not allowed:
        return rate_limited_response(retry)
    with core._wireguard_lock:
        device, user = _pilot_device(wg_name, public=True)
        if (not _valid_export_mode(device, mode)
                or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token)):
            abort(404)
        try:
            if not hmac.compare_digest(token, happ_pilot.subscription_token(device, user)):
                abort(404)
            _revision, rules = happ_pilot.get_rules(user['account_id'])
            return _response(device, mode, rules)
        except ValueError:
            return 'Happ configuration is unavailable.', 503
