"""Cross-module Safe internet behavior with synthetic personal/router state."""

import base64
import hashlib
from types import SimpleNamespace

import pytest

from wg_panel import account_policy, app, core, infrastructure, runner, traffic, wireguard
from wg_panel.dns_enforcement import SafeDnsEnforcementError

REAL_SYNC_SAFE_DNS = wireguard._sync_safe_dns

PRIVATE = base64.b64encode(bytes([11]) * 32).decode()
PUBLIC = base64.b64encode(bytes([12]) * 32).decode()
SERVER = base64.b64encode(bytes([13]) * 32).decode()
PSK = base64.b64encode(bytes([14]) * 32).decode()
ROUTER = "u5-alice-router"
PHONE = "u5-alice-phone"
ROUTER_IP = "10.0.0.2"
PHONE_IP = "10.0.0.3"


def config(address):
    return (
        f"[Interface]\nPrivateKey = {PRIVATE}\nAddress = {address}/32\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n[Peer]\n"
        f"PublicKey = {SERVER}\nPresharedKey = {PSK}\n"
        "Endpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )


@pytest.fixture
def unified_runtime(tmp_path, monkeypatch):
    data = tmp_path / "data"
    wg = tmp_path / "wireguard"
    clients = wg / "clients"
    configs = wg / "infrastructure"
    for directory in (data, wg, clients, configs):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
    for name, value in {
        "DATA_DIR": data, "WG_DIR": wg, "CLIENTS_DIR": clients,
        "USERS_FILE": data / "users.json", "DEVICE_META_FILE": data / "device_meta.json",
        "TRAFFIC_FILE": data / "traffic.json",
    }.items():
        monkeypatch.setattr(core, name, str(value))
    for module in (traffic, wireguard):
        monkeypatch.setattr(module, "CLIENTS_DIR", str(clients))
    monkeypatch.setattr(wireguard, "WG_DIR", str(wg))
    monkeypatch.setattr(traffic, "DEVICE_META_FILE", str(data / "device_meta.json"))
    monkeypatch.setattr(traffic, "TRAFFIC_FILE", str(data / "traffic.json"))
    monkeypatch.setitem(app.config, "TESTING", True)
    core.save_users({
        "alice": {"role": "user", "approved": True, "max_devices": 5},
        "admin": {"role": "admin", "approved": True, "max_devices": -1},
    })
    traffic.save_device_meta({
        PHONE: {"owner": "alice", "device": "phone", "vpn_type": "wireguard",
                "safe_internet": True},
    })
    account_policy.save_account_policies({})
    phone = clients / f"{PHONE}.conf"
    phone.write_text(config(PHONE_IP), encoding="utf-8")
    phone.chmod(0o600)
    router = configs / f"{ROUTER}.conf"
    router_content = config(ROUTER_IP).encode()
    router.write_bytes(router_content)
    router.chmod(0o600)
    core.write_json_private(str(data / "infrastructure_peers.json"), {
        "version": 1, "peers": {
            ROUTER: {"kind": "router", "label": "home-router", "public_key": PUBLIC,
                     "ipv4": ROUTER_IP,
                     "config_sha256": hashlib.sha256(router_content).hexdigest()},
        },
    })
    commands = []
    qr_inputs = []
    updates = []

    def run(command, **kwargs):
        commands.append(tuple(command))
        if command == ["wg", "pubkey"]:
            assert kwargs["input"] == PRIVATE + "\n"
            return SimpleNamespace(returncode=0, stdout=PUBLIC + "\n", stderr="")
        if command[:1] == ["qrencode"]:
            qr_inputs.append(kwargs["input"])
            return SimpleNamespace(returncode=0, stdout=b"<svg></svg>", stderr=b"")
        pytest.fail("unexpected runtime command during isolated integration test")

    def unexpected_helper(*_args, **_kwargs):
        pytest.fail("unexpected peer helper mutation")

    monkeypatch.setattr(infrastructure.subprocess, "run", run)
    monkeypatch.setattr(wireguard, "_run_script", unexpected_helper)
    monkeypatch.setattr(wireguard, "_sync_safe_dns",
                        lambda ips, **_kwargs: updates.append(tuple(ips)))
    return SimpleNamespace(
        root=tmp_path, data=data, wg=wg, clients=clients, phone=phone, router=router,
        target=wg / "safe-dns-target", commands=commands, qr_inputs=qr_inputs, updates=updates,
    )


def browser(username="alice"):
    client = app.test_client()
    user = core.load_users()[username]
    with client.session_transaction() as session:
        session["user"] = username
        session["account_id"] = user["account_id"]
        session["session_version"] = user["session_version"]
        session["_csrf_token"] = "synthetic-csrf-token"
    return client


def duplicate_personal_router(runtime, *, revoked=False):
    duplicate = runtime.clients / f"{ROUTER}.conf"
    duplicate.write_text(config("10.0.0.99"), encoding="utf-8")
    duplicate.chmod(0o600)
    metadata = traffic.load_device_meta()
    metadata[ROUTER] = {
        "owner": "alice", "device": "router", "vpn_type": "legacy",
        "safe_internet": False, "revoked": revoked,
    }
    traffic.save_device_meta(metadata)


def contents(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob("*") if path.is_file()}


def test_custom_dns_is_identical_in_rendered_config_qr_and_download(unified_runtime):
    runtime = unified_runtime
    runtime.target.write_text("10.0.0.1:18004\n", encoding="ascii")
    original = runtime.phone.read_bytes()
    expected = config(PHONE_IP).replace("DNS = 1.1.1.1, 8.8.8.8", "DNS = 10.0.0.1").replace(
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1",
    )
    assert wireguard.get_config(PHONE) == expected
    assert wireguard.qr_svg_b64(PHONE).startswith("data:image/svg+xml;base64,")
    assert runtime.qr_inputs == [expected.encode()]
    response = browser().get(f"/device/{PHONE}/download")
    assert response.status_code == 200
    assert response.get_data(as_text=True) == expected
    assert "no-store" in response.headers["Cache-Control"]
    assert runtime.phone.read_bytes() == original


def test_missing_custom_target_preserves_legacy_protected_dns(unified_runtime):
    assert "DNS = 1.1.1.3, 1.0.0.3\n" in wireguard.get_config(PHONE)
    assert wireguard.qr_svg_b64(PHONE)
    assert b"DNS = 1.1.1.3, 1.0.0.3\n" in unified_runtime.qr_inputs[0]


def test_ordinary_profile_retains_standard_dns_with_a_custom_target(unified_runtime):
    unified_runtime.target.write_text("10.0.0.1:18004", encoding="ascii")
    metadata = traffic.load_device_meta()
    metadata[PHONE]["safe_internet"] = False
    traffic.save_device_meta(metadata)
    assert "DNS = 1.1.1.1, 8.8.8.8\n" in wireguard.get_config(PHONE)


@pytest.mark.parametrize("content", ["10.0.0.1:0", "resolver.example.test:53\nextra"])
def test_invalid_custom_target_blocks_protected_config_and_qr(unified_runtime, content):
    unified_runtime.target.write_text(content, encoding="ascii")
    with pytest.raises(SafeDnsEnforcementError):
        wireguard.get_config(PHONE)
    with pytest.raises(SafeDnsEnforcementError):
        wireguard.qr_svg_b64(PHONE)
    assert unified_runtime.qr_inputs == []


@pytest.mark.parametrize("suffix", ["", "/download"])
def test_invalid_custom_target_routes_return_generic_503(unified_runtime, suffix):
    marker = "resolver.example.test:private-marker"
    unified_runtime.target.write_text(marker, encoding="ascii")
    response = browser().get(f"/device/{PHONE}{suffix}")
    body = response.get_data(as_text=True)
    assert response.status_code == 503
    assert "configuration is unavailable" in body
    assert marker not in body
    assert str(unified_runtime.wg) not in body
    assert PRIVATE not in body
    assert "no-store" in response.headers["Cache-Control"]


@pytest.mark.parametrize(
    "changes,expected",
    [({}, {ROUTER_IP, PHONE_IP}),
     ({"excluded": PHONE}, {ROUTER_IP}),
     ({"excluded": ROUTER}, {ROUTER_IP, PHONE_IP}),
     ({"override": {PHONE: False, ROUTER: False}}, {ROUTER_IP})],
)
def test_router_protection_survives_personal_exclusions_and_overrides(
    unified_runtime, changes, expected
):
    duplicate_personal_router(unified_runtime)
    assert set(wireguard._safe_dns_ips(traffic.load_device_meta(), **changes)) == expected


def test_account_policy_and_infrastructure_protection_are_independent(unified_runtime):
    metadata = traffic.load_device_meta()
    metadata[PHONE]["safe_internet"] = False
    traffic.save_device_meta(metadata)
    account_policy.save_account_policies({"alice": {"safe_internet_locked": True}})
    assert set(wireguard._safe_dns_ips(metadata, override={PHONE: False, ROUTER: False})) == {
        ROUTER_IP, PHONE_IP
    }
    assert wireguard.get_device(PHONE)["safe_internet"]


def test_account_activation_validates_target_before_firewall_or_policy_changes(
    unified_runtime, monkeypatch
):
    unified_runtime.target.write_text("127.0.0.1:18004\n", encoding="ascii")
    monkeypatch.setattr(wireguard, "_sync_safe_dns", REAL_SYNC_SAFE_DNS)

    def unexpected_firewall(*_args, **_kwargs):
        pytest.fail("invalid target reached firewall execution")

    monkeypatch.setattr(wireguard, "sync_safe_dns", unexpected_firewall)
    assert not wireguard.set_account_safe_internet("alice", confirmed=True)
    assert account_policy.load_account_policies() == {}


def test_router_remains_enforced_without_personal_users_profiles_or_policies(unified_runtime):
    core.save_users({})
    traffic.save_device_meta({})
    account_policy.save_account_policies({})
    result = wireguard.reconcile_safe_dns(require_helper=True, allow_unavailable=False)
    assert set(result["ips"]) == {ROUTER_IP}
    assert unified_runtime.updates == [(ROUTER_IP,)]


@pytest.mark.parametrize("revoked", [False, True])
def test_duplicate_personal_router_cannot_be_listed_read_or_revoked(unified_runtime, revoked):
    runtime = unified_runtime
    duplicate_personal_router(runtime, revoked=revoked)
    before = contents(runtime.root)
    assert wireguard.get_all_devices() == [("alice", "phone", PHONE)]
    assert wireguard.get_user_devices("alice") == ["phone"]
    assert wireguard.get_device(ROUTER) is None
    assert wireguard.get_config(ROUTER) is None
    assert wireguard.qr_svg_b64(ROUTER) is None
    assert not wireguard.delete_device(ROUTER)[0]
    assert runtime.qr_inputs == []
    assert runtime.updates == []
    assert contents(runtime.root) == before


def test_reserved_router_name_blocks_allocation_before_any_helper_mutation(unified_runtime):
    before = contents(unified_runtime.root)
    success, name, _error = wireguard.create_device("alice", "router")
    assert not success
    assert name == ""
    assert unified_runtime.updates == []
    assert contents(unified_runtime.root) == before


def test_admin_routes_cannot_download_or_delete_duplicate_personal_router(unified_runtime):
    duplicate_personal_router(unified_runtime)
    before = contents(unified_runtime.root)
    client = browser("admin")
    assert client.get(f"/device/{ROUTER}/download").status_code == 403
    response = client.post(f"/device/{ROUTER}/delete", data={"csrf_token": "synthetic-csrf-token"})
    assert response.status_code == 302
    assert unified_runtime.updates == []
    assert contents(unified_runtime.root) == before


def test_helper_environment_carries_isolated_infrastructure_paths(unified_runtime, monkeypatch):
    monkeypatch.setenv("INFRASTRUCTURE_CLIENTS_DIR", "untrusted-inherited-directory")
    monkeypatch.setenv("INFRASTRUCTURE_REGISTRY", "untrusted-inherited-registry")
    environment = wireguard._script_environment()
    assert environment["WG_DIR"] == str(unified_runtime.wg)
    assert environment["CLIENTS_DIR"] == str(unified_runtime.clients)
    assert environment["INFRASTRUCTURE_CLIENTS_DIR"] == str(unified_runtime.router.parent)
    assert environment["INFRASTRUCTURE_REGISTRY"] == str(
        unified_runtime.data / "infrastructure_peers.json"
    )


def test_runner_blocks_unready_infrastructure_before_background_or_server_actions(monkeypatch):
    def unready():
        raise infrastructure.InfrastructureStateError("synthetic private deployment detail")

    def unexpected_action(*_args, **_kwargs):
        pytest.fail("unready infrastructure must block background/server/state mutations")

    monkeypatch.setattr(runner, "assert_infrastructure_ready", unready)
    monkeypatch.setattr(runner, "ensure_private_dir", lambda _path: None)
    monkeypatch.setattr(runner, "ensure_admin", unexpected_action)
    monkeypatch.setattr(runner, "migrate_device_metadata", unexpected_action)
    monkeypatch.setattr(runner, "set_tg_webhook", unexpected_action)
    monkeypatch.setattr(runner.threading, "Thread", unexpected_action)
    monkeypatch.setattr(runner.app, "run", unexpected_action)
    monkeypatch.setattr(runner, "ENABLE_HTTP_REDIRECT", True)
    with pytest.raises(infrastructure.InfrastructureStateError):
        runner.main()
