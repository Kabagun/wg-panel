from html.parser import HTMLParser

import pytest

from wg_panel import app, core, traffic, wireguard


class DashboardHTML(HTMLParser):
    """Keep ancestry and text so assertions exercise rendered link semantics."""

    def __init__(self, html):
        super().__init__()
        self.nodes = []
        self.stack = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": dict(attrs), "ancestors": tuple(self.stack), "text": ""}
        self.nodes.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                       "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        for node in self.stack:
            node["text"] += data

    def with_class(self, name):
        return [node for node in self.nodes if name in node["attrs"].get("class", "").split()]

    def within(self, ancestor):
        return [node for node in self.nodes
                if any(parent is ancestor for parent in node["ancestors"])]


@pytest.fixture
def dashboard_account(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    for module, attribute, value in (
        (core, "DATA_DIR", data),
        (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "devices.json"),
        (traffic, "DEVICE_META_FILE", data / "devices.json"),
        (traffic, "CLIENTS_DIR", clients),
        (wireguard, "CLIENTS_DIR", clients),
    ):
        monkeypatch.setattr(module, attribute, str(value))
    app.config.update(TESTING=True)

    def create(username="alice", role="user", paused=False):
        core.save_users({username: {
            "role": role, "approved": True, "max_devices": 3,
            "session_version": 1, "paused": paused,
        }})
        name = wireguard.client_name(username, "phone")
        config = "[Interface]\nPrivateKey = synthetic-key\nAddress = 10.0.0.2/32\n"
        (clients / f"{name}.conf").write_text(config, encoding="utf-8")
        traffic.set_device_meta(name, username, "phone")
        browser = app.test_client()
        with browser.session_transaction() as session:
            session.update(
                user=username, account_id=core.load_users()[username]["account_id"],
                session_version=1, _csrf_token="test-csrf",
            )
        response = browser.get("/dashboard", headers={"Accept-Language": "ru"})
        assert response.status_code == 200
        return browser, DashboardHTML(response.get_data(as_text=True)), name, config

    return create


@pytest.mark.parametrize("paused", [False, True])
def test_device_card_is_one_main_link_with_independent_download(dashboard_account, paused):
    browser, document, name, config = dashboard_account(paused=paused)
    card, = document.with_class("device-card")
    main, = document.with_class("device-card-main")
    action, = document.with_class("device-action")
    card_nodes = document.within(card)
    links = [node for node in card_nodes if node["tag"] == "a"]
    assert len(links) == 2
    assert main["tag"] == "a"
    assert main["attrs"]["href"] == f"/device/{name}"
    assert main["attrs"].get("role") is None
    assert main["attrs"].get("tabindex") is None
    assert main["attrs"].get("onclick") is None
    main_nodes = document.within(main)
    assert not [node for node in main_nodes if node["tag"] in {"a", "button", "input"}]
    assert any(node["tag"] == "h3" and node["text"] == "phone" for node in main_nodes)
    assert any(node["tag"] == "dl" for node in main_nodes)
    assert any(node is action for node in main_nodes)
    assert action["text"] == ("Открыть конфиг" if paused else "Настроить")
    assert len([node for node in document.within(action) if node["tag"] == "svg"]) == 2
    labelled_by = main["attrs"]["aria-labelledby"].split()
    labels = [node for node in main_nodes if node["attrs"].get("id") in labelled_by]
    assert len(labels) == 2
    assert {node["text"] for node in labels} == {"phone", action["text"]}

    download, = [node for node in links if node is not main]
    assert not any(node is download for node in main_nodes)
    assert download["attrs"]["href"] == f"/device/{name}/download"
    assert download["attrs"]["aria-label"] == "Скачать конфигурацию: phone"
    attachment = browser.get(download["attrs"]["href"])
    assert attachment.status_code == 200
    assert attachment.mimetype == "application/octet-stream"
    assert attachment.headers["Content-Disposition"] == "attachment; filename=phone.conf"
    # Existing config rendering can append DNS; the saved config remains the payload.
    assert attachment.get_data(as_text=True).startswith(config)


@pytest.mark.parametrize("username,role", [("maintainer", "admin"), ("alice", "user")])
def test_dashboard_account_protection_visibility_follows_role(dashboard_account, username, role):
    _browser, document, _name, _config = dashboard_account(username=username, role=role)
    assert bool(document.with_class("protection-settings")) == (role == "user")
    protection_forms = [node for node in document.nodes
                        if node["attrs"].get("action") == "/account/safe-internet"]
    assert bool(protection_forms) == (role == "user")
    dns_links = [node for node in document.with_class("nav-link")
                 if node["attrs"].get("href") == "/admin/family-dns"]
    assert bool(dns_links) == (role == "admin")


@pytest.mark.parametrize("paused", [False, True])
def test_dashboard_guide_follows_heading_once_and_stays_hidden_when_paused(
    dashboard_account, paused,
):
    _browser, document, _name, _config = dashboard_account(paused=paused)
    guides = document.with_class("setup-guide")
    assert len(guides) == (0 if paused else 1)
    if not paused:
        main, = [node for node in document.nodes if node["attrs"].get("id") == "main"]
        direct_children = [node for node in document.nodes
                           if node["ancestors"] and node["ancestors"][-1] is main]
        assert "page-heading" in direct_children[0]["attrs"]["class"].split()
        assert direct_children[1] is guides[0]
        metrics, = document.with_class("metrics-grid")
        assert document.nodes.index(guides[0]) < document.nodes.index(metrics)
