"""Closed pilot acceptance with synthetic identities, keys and resolver state."""

import base64
import hashlib
import json
import logging
import re
from types import SimpleNamespace

import pytest
from flask import url_for
from werkzeug.datastructures import MultiDict

from wg_panel import (
    account_policy,
    app,
    core,
    happ_pilot,
    infrastructure,
    security,
    traffic,
    wireguard,
)
from wg_panel.dns_enforcement import SafeDnsEnforcementError
from wg_panel.happ_config import MODES
from wg_panel.routes import devices as device_routes
from wg_panel.routes import happ as happ_routes

ADMIN = "pilotadmin"
OTHER = "otheradmin"
PILOT = "u10-pilotadmin-pilot"
SECOND = "u10-pilotadmin-second"
FOREIGN = "u10-otheradmin-pilot"
CLASSIC = "u5-alice-phone"
ROUTER = "u10-pilotadmin-router"
PRIVATE = base64.b64encode(bytes(32)).decode()
PUBLIC = base64.b64encode(bytes([1]) * 32).decode()
PSK = base64.b64encode(bytes([2]) * 32).decode()
CSRF = "synthetic-csrf"


def config(address="10.0.0.2"):
    return (
        f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = {address}/32\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\n"
        f"PublicKey = {PUBLIC}\nPresharedKey = {PSK}\n"
        "Endpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


def browser(username=ADMIN):
    client = app.test_client()
    if username:
        user = core.load_users()[username]
        with client.session_transaction() as session:
            session.update(user=username, account_id=user["account_id"], session_version=1,
                           _csrf_token=CSRF)
    return client


def subscription(name=PILOT, mode="custom", token=None):
    device = wireguard.get_device(name)
    if token is None:
        token = happ_pilot.subscription_token(device, core.load_users()[device["owner"]])
    with app.test_request_context():
        return url_for("happ_subscription", wg_name=name, token=token, mode=mode)


def rules_form(**changes):
    return {"csrf_token": CSRF, "wg_name": PILOT, "mode": "custom", "revision": "0",
            "rules": "Example.ORG\n192.0.2.12/24", **changes}


@pytest.fixture
def runtime(monkeypatch, tmp_path):
    data = tmp_path / "data"
    wg = tmp_path / "wireguard"
    clients = wg / "clients"
    clients.mkdir(parents=True)
    for module, attribute, value in (
        (core, "DATA_DIR", data), (core, "WG_DIR", wg), (core, "CLIENTS_DIR", clients),
        (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "device_meta.json"),
        (core, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "DEVICE_META_FILE", data / "device_meta.json"),
        (traffic, "TRAFFIC_FILE", data / "traffic.json"), (traffic, "CLIENTS_DIR", clients),
        (wireguard, "CLIENTS_DIR", clients), (wireguard, "WG_DIR", wg),
    ):
        monkeypatch.setattr(module, attribute, str(value))
    monkeypatch.setitem(app.config, "TESTING", True)
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", True)
    monkeypatch.setitem(app.config, "HAPP_PUBLIC_BASE_URL", "https://vpn.example.test")
    monkeypatch.setattr(app, "secret_key", b"synthetic-happ-test-signing-key-32-bytes")
    monkeypatch.setattr(happ_pilot, "qr_for_link", lambda _link: None)
    monkeypatch.setattr(device_routes, "qr_svg_b64", lambda _name: None)
    monkeypatch.setattr(device_routes, "send_telegram", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(wireguard, "_run_script",
                        lambda *_args, **_kwargs: pytest.fail("unexpected peer mutation"))
    clock = [1000.0]
    monkeypatch.setattr(happ_routes, "public_rate_limiter",
                        security.WindowRateLimiter(clock=lambda: clock[0]))
    core.save_users({
        ADMIN: {"role": "admin", "approved": True, "max_devices": -1,
                "session_version": 1, "account_id": "a" * 64},
        OTHER: {"role": "admin", "approved": True, "max_devices": -1,
                "session_version": 1, "account_id": "b" * 64},
        "alice": {"role": "user", "approved": True, "max_devices": 3,
                  "session_version": 1, "account_id": "c" * 64},
    })
    metadata = {}
    for index, (name, owner, label, pilot) in enumerate((
        (PILOT, ADMIN, "pilot", True), (SECOND, ADMIN, "second", True),
        (FOREIGN, OTHER, "pilot", True), (CLASSIC, "alice", "phone", False),
        (ROUTER, ADMIN, "router", False),
    ), 2):
        (clients / f"{name}.conf").write_text(config(f"10.0.0.{index}"), encoding="utf-8", newline="\n")
        metadata[name] = {"owner": owner, "device": label, "vpn_type": "wireguard",
                          "safe_internet": False, "happ_pilot": pilot}
        if pilot:
            metadata[name]["happ_subscription_nonce"] = str(index) * 64
    metadata[ROUTER]["deletion_protected"] = True
    traffic.save_device_meta(metadata)
    account_policy.save_account_policies({})
    target = wg / "safe-dns-target"
    target.write_text("10.8.0.1:18004\n", encoding="ascii")
    return SimpleNamespace(data=data, wg=wg, clients=clients, target=target, clock=clock)


def test_disabled_pilot_hides_entry_choice_and_all_exports(runtime, monkeypatch):
    (runtime.data / "happ_pilot.json").write_text('{"version":1,"enabled":true}')
    path = subscription()
    monkeypatch.setitem(app.config, "HAPP_PILOT_ENABLED", False)
    admin = browser()
    for url in ("/admin/happ-pilot", f"/device/{PILOT}/happ",
                f"/device/{PILOT}/happ/custom/download", path):
        assert admin.get(url).status_code == 404
    for url in ("/dashboard", "/add"):
        page = admin.get(url).get_data(as_text=True)
        assert 'href="/admin/happ-pilot"' not in page
        assert 'name="client_app"' not in page
    assert admin.post("/add", data={"csrf_token": CSRF, "device": "new",
                                          "client_app": "happ"}).status_code == 403
    assert admin.get(f"/device/{PILOT}/download").status_code == 200


@pytest.mark.parametrize("username", [None, "alice", OTHER])
def test_private_pilot_device_requires_approved_owning_admin(runtime, username):
    client = browser(username)
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/custom/download"):
        response = client.get(url)
        assert response.status_code in {302, 404}
        assert response.mimetype != "application/json"
    if username != OTHER:
        assert client.get("/admin/happ-pilot").status_code == 302
    else:
        page = client.get("/admin/happ-pilot").get_data(as_text=True)
        assert f'href="/device/{FOREIGN}/happ"' in page
        assert f'href="/device/{PILOT}/happ"' not in page


@pytest.mark.parametrize("mode", MODES)
def test_public_subscription_without_session_exports_central_dns_and_import_headers(runtime, mode):
    response = browser(None).get(subscription(mode=mode))
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    assert "attachment;" in response.headers["Content-Disposition"]
    assert response.headers["tun-enable"] == "1"
    assert response.headers["profile-update-interval"] == "1"
    assert response.headers["Cache-Control"].startswith("no-store")
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "Set-Cookie" not in response.headers
    exported = response.get_json()
    assert exported["dns"]["servers"] == ["10.8.0.1"]
    vpn, = [item for item in exported["outbounds"] if item["tag"] == "vpn"]
    assert vpn["protocol"] == "wireguard"
    assert vpn["settings"]["secretKey"] == PRIVATE
    assert vpn["settings"]["remoteDNS"] == ["10.8.0.1"]
    peer, = vpn["settings"]["peers"]
    assert peer["endpoint"] == "vpn.example.test:51820"
    assert peer["publicKey"] == PUBLIC and peer["preSharedKey"] == PSK
    prefix = "happ://routing/onadd/"
    assert response.headers["routing"].startswith(prefix)
    routing = json.loads(base64.b64decode(response.headers["routing"].removeprefix(prefix)))
    assert routing["RemoteDNSIP"] == routing["DomesticDNSIP"] == "10.8.0.1"
    assert routing["RemoteDNSType"] == routing["DomesticDNSType"] == "DoU"


def test_bundle_contains_three_independent_presets_with_one_identity_and_dns(runtime):
    identity = core.load_users()[ADMIN]['account_id']
    happ_pilot.save_rules(identity, 'ai.example.org\n192.0.2.0/24', 0)
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    assert response.headers['Cache-Control'].startswith('no-store')
    assert response.headers['profile-title'] == 'VPN modes'
    assert response.headers['tun-enable'] == '1'
    assert 'Set-Cookie' not in response.headers
    bundle = response.get_json()
    assert isinstance(bundle, list) and len(bundle) == 3
    assert len({item['remarks'] for item in bundle}) == 3
    assert happ_pilot.BUNDLE_MODES == ('all', 'custom', 'by-ru-direct')
    for mode, item in zip(happ_pilot.BUNDLE_MODES, bundle, strict=True):
        assert item == browser(None).get(subscription(mode=mode)).get_json()
        assert item['dns']['servers'] == ['10.8.0.1']
        assert item['meta']['serverDescription']
    settings = [next(o for o in item['outbounds'] if o['tag'] == 'vpn')['settings']
                for item in bundle]
    assert settings[0] == settings[1] == settings[2]
    assert bundle[0]['routing']['rules'][-1]['outboundTag'] == 'vpn'
    assert bundle[1]['routing']['rules'][-1]['outboundTag'] == 'direct'
    assert bundle[2]['routing']['rules'][-1]['outboundTag'] == 'vpn'
    assert any(rule.get('domain') == ['domain:ai.example.org']
               and rule['outboundTag'] == 'vpn' for rule in bundle[1]['routing']['rules'])
    assert any(rule.get('ip') == ['geoip:by', 'geoip:ru']
               and rule['outboundTag'] == 'direct' for rule in bundle[2]['routing']['rules'])
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert {'geoip:by', 'geoip:ru'} <= set(routing['DirectIp'])
    assert len(routing['DirectIp']) == len(set(routing['DirectIp']))
    assert routing['RemoteDNSIP'] == routing['DomesticDNSIP'] == '10.8.0.1'
    assert routing['ProxyIp'] == ['10.8.0.1']
    assert routing['Geoipurl'].endswith('/geoip.dat')
    assert browser().get(f'/device/{PILOT}/happ/bundle/download').get_json() == bundle


def test_protected_bundle_exports_only_full_tunnel_without_geo_bypass(runtime):
    account_policy.save_account_policies({ADMIN: {'safe_internet_locked': True}})
    response = browser(None).get(subscription(mode='bundle'))
    assert response.status_code == 200
    assert response.get_json() == [browser(None).get(subscription(mode='all')).get_json()]
    routing = json.loads(base64.b64decode(
        response.headers['routing'].removeprefix('happ://routing/onadd/')))
    assert not any(ip.startswith('geoip:') for ip in routing['DirectIp'])
    assert routing['GlobalProxy'] == 'true'


def test_preview_mode_does_not_change_bundle_import_or_advertise_retired_modes(runtime):
    admin = browser()
    url = 'https://vpn.example.test' + subscription(mode='bundle')
    for mode in happ_pilot.BUNDLE_MODES:
        page = admin.get(f'/device/{PILOT}/happ?mode={mode}').get_data(as_text=True)
        assert url in page and f'happ://add/{url}' in page
        assert f'/device/{PILOT}/happ/bundle/download' in page
        assert 'value="by-direct"' not in page and 'value="ru-direct"' not in page


def test_bundle_token_rotation_revokes_all_presets_without_replacing_peer(runtime):
    old = subscription(mode='bundle')
    before = (runtime.clients / f'{PILOT}.conf').read_bytes()
    assert browser(None).get(old).status_code == 200
    assert browser().post(f'/device/{PILOT}/happ/rotate',
                          data={'csrf_token': CSRF, 'mode': 'custom'}).status_code == 303
    assert browser(None).get(old).status_code == 404
    assert browser(None).get(subscription(mode='bundle')).status_code == 200
    assert (runtime.clients / f'{PILOT}.conf').read_bytes() == before


@pytest.mark.parametrize("token", ["x" * 43, "short", "z" * 100, "é" * 43])
def test_wrong_or_malformed_subscription_credentials_fail_closed(runtime, token):
    assert browser(None).get(subscription(token=token)).status_code == 404


@pytest.mark.parametrize("mode", MODES[1:])
def test_protected_device_rejects_split_modes_without_downgrading_protection(runtime, mode):
    account_policy.save_account_policies({ADMIN: {"safe_internet_locked": True}})
    before = account_policy.load_account_policies()
    assert browser().get(f"/device/{PILOT}/happ/{mode}/download").status_code == 404
    assert browser(None).get(subscription(mode=mode)).status_code == 404
    assert browser(None).get(subscription(mode="all")).status_code == 200
    assert account_policy.load_account_policies() == before


def test_subscription_rotation_requires_csrf_and_revokes_old_link_only(runtime):
    admin = browser()
    old = subscription()
    original_config = (runtime.clients / f"{PILOT}.conf").read_bytes()
    nonce = traffic.load_device_meta()[PILOT]["happ_subscription_nonce"]
    url = f"/device/{PILOT}/happ/rotate"
    assert admin.get(url).status_code == 405
    assert admin.post(url, data={"mode": "custom"}).status_code == 400
    assert traffic.load_device_meta()[PILOT]["happ_subscription_nonce"] == nonce
    assert browser(None).get(old).status_code == 200
    assert admin.post(url, data={"csrf_token": CSRF, "mode": "custom"}).status_code == 303
    assert browser(None).get(old).status_code == 404
    assert browser(None).get(subscription()).status_code == 200
    assert (runtime.clients / f"{PILOT}.conf").read_bytes() == original_config


@pytest.mark.parametrize("mode", ["custom", "bundle"])
@pytest.mark.parametrize("change", ["paused", "pause_pending", "unapproved", "revoking",
                                   "demoted", "account_deleted", "account_recreated",
                                   "device_revoked", "device_deleted", "config_deleted"])
def test_public_subscription_obeys_live_account_and_device_lifecycle(runtime, change, mode):
    path = subscription(mode=mode)
    assert browser(None).get(path).status_code == 200
    if change in {"paused", "pause_pending", "revoking"}:
        core.mutate_users(lambda users: users[ADMIN].update({change: True}))
    elif change == "unapproved":
        core.mutate_users(lambda users: users[ADMIN].update(approved=False))
    elif change == "demoted":
        core.mutate_users(lambda users: users[ADMIN].update(role="user"))
    elif change == "account_deleted":
        core.mutate_users(lambda users: users.pop(ADMIN))
    elif change == "account_recreated":
        core.mutate_users(lambda users: users[ADMIN].update(account_id="d" * 64))
    elif change == "device_revoked":
        traffic.mutate_device_meta(lambda meta: meta[PILOT].update(revoked=True))
    elif change == "device_deleted":
        traffic.mutate_device_meta(lambda meta: meta.pop(PILOT))
    else:
        (runtime.clients / f"{PILOT}.conf").unlink()
    assert browser(None).get(path).status_code == 404


def test_gets_preserve_raw_wireguard_files_metadata_users_and_permanent_policy(runtime):
    admin = browser()
    paths = [*runtime.clients.glob("*.conf"), runtime.data / "device_meta.json",
             runtime.data / "users.json", runtime.data / "account_policy.json", runtime.target]
    before = {path: path.read_bytes() for path in paths}
    for path in ("/admin/happ-pilot", f"/device/{PILOT}/happ", "/dashboard", "/add",
                 f"/device/{PILOT}/happ/custom/download", subscription(),
                 f"/device/{PILOT}/happ/bundle/download", subscription(mode="bundle")):
        assert admin.get(path).status_code == 200
    classic = browser("alice").get(f"/device/{CLASSIC}/download")
    assert classic.status_code == 200
    assert classic.get_data() == before[runtime.clients / f"{CLASSIC}.conf"]
    assert b"DNS = 1.1.1.1, 8.8.8.8" in classic.get_data()
    assert admin.get(f"/device/{PILOT}/download").get_data() == before[
        runtime.clients / f"{PILOT}.conf"
    ]
    assert {path: path.read_bytes() for path in paths} == before
    assert admin.get(f"/device/{PILOT}").location.endswith(f"/device/{PILOT}/happ")


def test_rules_save_is_csrf_checked_canonical_and_shared_by_account_identity(runtime):
    admin = browser()
    identity = core.load_users()[ADMIN]["account_id"]
    assert admin.post("/account/happ-rules", data=rules_form(csrf_token="bad")).status_code == 400
    assert happ_pilot.get_rules(identity) == (0, [])
    assert admin.post("/account/happ-rules", data=rules_form()).status_code == 303
    assert happ_pilot.get_rules(identity) == (1, ["domain:example.org", "192.0.2.0/24"])
    page = admin.get(f"/device/{SECOND}/happ").get_data(as_text=True)
    assert "domain:example.org" in page and 'name="revision" value="1"' in page
    other_identity = core.load_users()[OTHER]["account_id"]
    assert happ_pilot.get_rules(other_identity) == (0, [])
    core.mutate_users(lambda users: users[ADMIN].update(account_id="d" * 64))
    assert happ_pilot.get_rules("d" * 64) == (0, [])
    assert browser().post("/account/happ-rules", data=rules_form(rules="new.example")).status_code == 303
    assert happ_pilot.get_rules("d" * 64) == (1, ["domain:new.example"])
    assert happ_pilot.get_rules(identity) == (1, ["domain:example.org", "192.0.2.0/24"])


@pytest.mark.parametrize("change", ["stale", "invalid_rule", "script", "bad_revision",
                                   "duplicate_revision", "duplicate_rules", "foreign_target"])
def test_failed_rules_updates_never_overwrite_current_owner_list(runtime, change):
    admin = browser()
    identity = core.load_users()[ADMIN]["account_id"]
    assert admin.post("/account/happ-rules", data=rules_form()).status_code == 303
    before = (runtime.data / "happ_rules.json").read_bytes()
    form = MultiDict(rules_form(revision="1", rules="replacement.example"))
    if change == "stale":
        form["revision"] = "0"
    elif change == "invalid_rule":
        form["rules"] = "regexp:.*"
    elif change == "script":
        form["rules"] = "<script>synthetic()</script>"
    elif change == "bad_revision":
        form["revision"] = "-1"
    elif change == "duplicate_revision":
        form.add("revision", "1")
    elif change == "duplicate_rules":
        form.add("rules", "second.example")
    else:
        form["wg_name"] = FOREIGN
    response = admin.post("/account/happ-rules", data=form)
    assert response.status_code == (404 if change == "foreign_target" else 303)
    assert (runtime.data / "happ_rules.json").read_bytes() == before
    assert happ_pilot.get_rules(identity)[0] == 1
    if change == "script":
        page = admin.get(response.location).get_data(as_text=True)
        assert "<script>synthetic()</script>" not in page


def test_device_label_is_escaped_in_happ_page_and_json_stays_collapsed(runtime):
    label = "test <script>synthetic()</script>"
    traffic.mutate_device_meta(lambda meta: meta[PILOT].update(device=label))
    page = browser().get(f"/device/{PILOT}/happ").get_data(as_text=True)
    assert "test &lt;script&gt;synthetic()&lt;/script&gt;" in page
    assert "<script>synthetic()</script>" not in page
    details = re.findall(r'<details class="happ-private-details"([^>]*)>(.*?)</details>',
                         page, re.DOTALL)
    assert len(details) == 2 and all("open" not in attrs for attrs, _body in details)
    assert any('id="happ-config-block"' in body for _attrs, body in details)
    assert page.count("data-copy-status") == 2


@pytest.mark.parametrize("target_state", ["missing", "invalid"])
def test_missing_or_invalid_central_dns_fails_closed_without_affecting_classic_download(
    runtime, target_state,
):
    path = subscription()
    before = {file.name: file.read_bytes() for file in runtime.clients.glob("*.conf")}
    if target_state == "missing":
        runtime.target.unlink()
    else:
        runtime.target.write_text("invalid-target\n", encoding="ascii")
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/custom/download", path):
        response = browser().get(url)
        assert response.status_code == 503
        assert response.mimetype != "application/json"
        assert "routing" not in response.headers
        assert PRIVATE not in response.get_data(as_text=True)
    assert browser("alice").get(f"/device/{CLASSIC}/download").status_code == 200
    assert {name: (runtime.clients / name).read_bytes() for name in before} == before


def test_corrupted_rule_storage_fails_closed_on_private_and_public_exports(runtime):
    path = subscription()
    (runtime.data / "happ_rules.json").write_text('{"version":1,"accounts":"invalid"}')
    for url in (f"/device/{PILOT}/happ", f"/device/{PILOT}/happ/custom/download", path):
        response = browser().get(url)
        assert response.status_code == 503
        assert response.mimetype != "application/json"
        assert PRIVATE not in response.get_data(as_text=True)


def test_classic_or_ordinary_owner_device_is_not_a_pilot_export(runtime):
    assert browser().get(f"/device/{CLASSIC}/happ").status_code == 404
    traffic.mutate_device_meta(lambda meta: meta[CLASSIC].update(
        happ_pilot=True, happ_subscription_nonce="f" * 64,
    ))
    assert browser().get(f"/device/{CLASSIC}/happ/all/download").status_code == 404
    assert browser(None).get(subscription(CLASSIC)).status_code == 404


def test_forged_happ_choice_is_denied_but_classic_creation_remains_available(runtime, monkeypatch):
    calls = []
    monkeypatch.setattr(wireguard, "create_device", lambda *_args: pytest.fail("forged pilot"))
    monkeypatch.setattr(device_routes, "create_device",
                        lambda owner, name: calls.append((owner, name)) or (True, "classic-new", ""))
    alice = browser("alice")
    response = alice.post("/add", data={"csrf_token": CSRF, "device": "new", "client_app": "happ"})
    assert response.status_code == 403 and not calls
    response = alice.post("/add", data={"csrf_token": CSRF, "device": "new"})
    assert response.status_code == 302 and response.location.endswith("/device/classic-new")
    assert calls == [("alice", "new")]


@pytest.mark.parametrize("path", ["/admin/happ-pilot", "/add"])
def test_creating_fresh_pilot_marks_only_new_device_and_preserves_existing_profiles(
    runtime, monkeypatch, path,
):
    before = {file.name: file.read_bytes() for file in runtime.clients.glob("*.conf")}
    calls = []
    reconciled = []

    def create(owner, name):
        calls.append((owner, name))
        wg_name = f"u{len(owner)}-{owner}-{name}"
        (runtime.clients / f"{wg_name}.conf").write_text(config("10.0.0.20"), encoding="utf-8")
        traffic.set_device_meta(wg_name, owner, name)
        return True, wg_name, ""

    monkeypatch.setattr(wireguard, "create_device", create)
    monkeypatch.setattr(wireguard, "_sync_safe_dns",
                        lambda ips, **_kwargs: reconciled.append(tuple(ips)) or tuple(ips))
    monkeypatch.setattr(device_routes, "create_device",
                        lambda *_args: pytest.fail("pilot must not call classic route creator"))
    admin = browser()
    form = {"csrf_token": CSRF, "device": "fresh", "client_app": "happ"}
    assert admin.post(path, data={**form, "csrf_token": "bad"}).status_code == 400
    assert not calls
    response = admin.post(path, data=form)
    assert response.status_code in {302, 303}
    name = "u10-pilotadmin-fresh"
    assert response.location.endswith(f"/device/{name}/happ")
    assert calls == [(ADMIN, "fresh")]
    item = traffic.load_device_meta()[name]
    assert item["happ_pilot"] is True
    assert re.fullmatch(r"[0-9a-f]{64}", item["happ_subscription_nonce"])
    assert len(reconciled) == 1 and "10.0.0.20" in reconciled[0]
    assert {name: (runtime.clients / name).read_bytes() for name in before} == before


@pytest.mark.parametrize("device_name", ["pilot", "router"])
def test_existing_or_router_profile_cannot_be_adopted_as_pilot(runtime, monkeypatch, device_name):
    paths = [*runtime.clients.glob("*.conf"), runtime.data / "device_meta.json"]
    before = {path: path.read_bytes() for path in paths}
    monkeypatch.setattr(wireguard, "create_device",
                        lambda *_args: pytest.fail("existing identity must not be reprovisioned"))
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": device_name})
    assert response.status_code == 303
    assert {path: path.read_bytes() for path in paths} == before


@pytest.mark.parametrize("name", ["../router", "bad name", "x" * 65, "__"])
def test_invalid_pilot_names_cannot_reach_provisioning(runtime, monkeypatch, name):
    before = traffic.load_device_meta()
    monkeypatch.setattr(wireguard, "create_device",
                        lambda *_args: pytest.fail("invalid name reached provisioning"))
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": name})
    assert response.status_code == 303
    assert traffic.load_device_meta() == before


def test_protected_router_and_registered_infrastructure_are_never_exported(runtime, monkeypatch):
    traffic.mutate_device_meta(lambda meta: meta[ROUTER].update(
        happ_pilot=True, happ_subscription_nonce="f" * 64,
    ))
    assert browser().get(f"/device/{ROUTER}/happ").status_code == 404
    assert browser(None).get(subscription(ROUTER)).status_code == 404
    directory = runtime.wg / "infrastructure"
    directory.mkdir(mode=0o700)
    source = config("10.0.0.50").encode()
    profile = directory / "opaque-router.conf"
    profile.write_bytes(source)
    profile.chmod(0o600)
    monkeypatch.setattr(infrastructure, "_public_key", lambda _key: PUBLIC)
    core.write_json_private(str(runtime.data / "infrastructure_peers.json"), {
        "version": 1, "peers": {"opaque-router": {
            "kind": "router", "label": "synthetic-router", "public_key": PUBLIC,
            "ipv4": "10.0.0.50", "config_sha256": hashlib.sha256(source).hexdigest(),
        }},
    })
    before = profile.read_bytes()
    assert browser().get("/device/opaque-router/happ").status_code == 404
    assert browser().get("/device/opaque-router/happ/all/download").status_code == 404
    assert browser(None).get("/happ/sub/opaque-router/" + "x" * 43 + "/all").status_code == 404
    assert profile.read_bytes() == before


def test_public_subscription_is_rate_limited_and_recovers_after_window(runtime):
    client = browser(None)
    invalid = subscription(token="x" * 43)
    for _ in range(60):
        assert client.get(invalid).status_code == 404
    response = client.get(subscription())
    assert response.status_code == 429 and int(response.headers["Retry-After"]) > 0
    assert client.get(subscription(), environ_base={"REMOTE_ADDR": "198.51.100.20"}).status_code == 200
    runtime.clock[0] += 61
    assert client.get(subscription()).status_code == 200


def test_pilot_source_dns_redirect_does_not_lock_account_or_select_classic_devices(runtime):
    selected = set(wireguard._safe_dns_ips(traffic.load_device_meta()))
    assert selected == {"10.0.0.2", "10.0.0.3", "10.0.0.4"}
    assert "10.0.0.5" not in selected
    assert account_policy.load_account_policies() == {}
    assert wireguard.get_device(PILOT)["safe_internet"] is False
    assert wireguard.get_device(CLASSIC)["safe_internet"] is False


def test_failed_pilot_dns_reconciliation_cannot_leave_exportable_new_peer(runtime, monkeypatch):
    name = "u10-pilotadmin-fresh"

    def create(owner, label):
        (runtime.clients / f"{name}.conf").write_text(config("10.0.0.20"), encoding="utf-8")
        traffic.set_device_meta(name, owner, label)
        return True, name, ""

    def unavailable(**_kwargs):
        raise SafeDnsEnforcementError("synthetic DNS helper failure")

    def remove(wg_name):
        assert wg_name == name
        (runtime.clients / f"{name}.conf").unlink()
        traffic.mutate_device_meta(lambda meta: meta.pop(name))
        return True

    monkeypatch.setattr(wireguard, "create_device", create)
    monkeypatch.setattr(wireguard, "reconcile_safe_dns", unavailable)
    monkeypatch.setattr(wireguard, "delete_device", remove)
    response = browser().post("/admin/happ-pilot", data={"csrf_token": CSRF, "device": "fresh"})
    assert response.status_code in {303, 503}
    assert name not in traffic.load_device_meta()
    assert not (runtime.clients / f"{name}.conf").exists()


def test_access_log_redacts_subscription_device_and_credential(runtime, caplog):
    path = subscription()
    token = path.split("/")[-2]
    with caplog.at_level(logging.INFO, logger="werkzeug"):
        logging.getLogger("werkzeug").info('"GET %s HTTP/1.1" 200', path)
    assert "/happ/sub/[redacted]" in caplog.text
    assert token not in caplog.text and PILOT not in caplog.text
