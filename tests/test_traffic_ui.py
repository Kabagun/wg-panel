from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from wg_panel import app, core, traffic, wireguard
from wg_panel.i18n import t
from wg_panel.routes import admin as admin_routes

MONTH = "2027-01"
OLD_MONTH = "2026-12"
NAMES = ("u5-alice-phone", "u5-alice-laptop", "u3-bob-tablet")


@dataclass(eq=False)
class Element:
    tag: str
    attrs: dict
    ancestors: tuple
    text: str = ""


class TrafficHTML(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.nodes = []
        self.stack = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = Element(tag, dict(attrs), tuple(self.stack))
        self.nodes.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                       "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        for node in self.stack:
            node.text += data

    def within(self, ancestor):
        return [node for node in self.nodes if ancestor in node.ancestors]

    def device_rows(self):
        table, = [node for node in self.nodes if "data-traffic-table" in node.attrs]
        assert table.tag == "table"
        rows = {}
        for row in self.within(table):
            if row.tag != "tr" or "data-traffic-download" not in row.attrs:
                continue
            link, = [node for node in self.within(row)
                     if node.tag == "a" and node.attrs.get("href", "").startswith("/device/")]
            rows[link.attrs["href"].removeprefix("/device/")] = row
        return rows


@pytest.fixture
def traffic_page(monkeypatch, tmp_path):
    data = tmp_path / "data"
    clients = tmp_path / "wireguard" / "clients"
    clients.mkdir(parents=True)
    for module, attribute, value in (
        (core, "DATA_DIR", data),
        (core, "USERS_FILE", data / "users.json"),
        (core, "DEVICE_META_FILE", data / "devices.json"),
        (core, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "DEVICE_META_FILE", data / "devices.json"),
        (traffic, "TRAFFIC_FILE", data / "traffic.json"),
        (traffic, "CLIENTS_DIR", clients),
        (wireguard, "CLIENTS_DIR", clients),
        (wireguard, "WG_DIR", clients.parent),
    ):
        monkeypatch.setattr(module, attribute, str(value))
    app.config.update(TESTING=True)
    core.save_users({
        "operator": {"role": "admin", "approved": True, "session_version": 1},
        "alice": {"role": "user", "approved": True},
        "bob": {"role": "user", "approved": True},
    })
    metadata = {}
    for index, name in enumerate(NAMES, 2):
        _prefix, owner, device = name.split("-", 2)
        metadata[name] = {"owner": owner, "device": device, "vpn_type": "wireguard"}
        (clients / f"{name}.conf").write_text(
            f"[Interface]\nAddress = 10.8.0.{index}/32\n", encoding="utf-8",
        )
    metadata["u5-alice-deleted"] = {
        "owner": "alice", "device": "deleted", "vpn_type": "wireguard",
    }
    traffic.save_device_meta(metadata)

    class UTCMonthBoundary(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is UTC
            return datetime(2027, 1, 1, 0, 15, tzinfo=UTC)

    monkeypatch.setattr(admin_routes, "datetime", UTCMonthBoundary)
    monkeypatch.setattr(admin_routes, "collect_traffic", lambda: None)
    browser = app.test_client()
    with browser.session_transaction() as session:
        session.update(
            user="operator", account_id=core.load_users()["operator"]["account_id"],
            session_version=1, _csrf_token="synthetic-csrf",
        )

    def render(values, *, query="", lang="en"):
        records = {
            name: {"monthly": {
                MONTH: {"tx": download, "rx": upload},
                OLD_MONTH: {"tx": 100_000, "rx": 200_000},
            }}
            for name, (download, upload) in zip(NAMES, values, strict=True)
        }
        records["u5-alice-deleted"] = {"monthly": {MONTH: {"tx": 500_000, "rx": 500_000}}}
        traffic.save_traffic(records)
        response = browser.get("/traffic" + query, headers={"Accept-Language": lang})
        assert response.status_code == 200
        assert traffic.load_traffic() == records
        return TrafficHTML(response.get_data(as_text=True))

    return render


def test_share_uses_current_utc_month_and_existing_devices_without_query_recalculation(traffic_page):
    values = [(10, 5), (30, 15), (0, 0)]
    shares = []
    for query in ("", "?sort=upload&direction=ascending&q=tablet"):
        document = traffic_page(values, query=query)
        rows = document.device_rows()
        assert set(rows) == set(NAMES)
        metrics = [node.text for node in document.nodes
                   if "metric-value" in node.attrs.get("class", "").split()]
        assert metrics == ["40 B", "20 B", "60 B"]
        rendered_shares = {}
        for name, row in rows.items():
            meter, = [node for node in document.within(row) if node.tag == "meter"]
            rendered_shares[name] = float(meter.attrs["value"])
        assert rendered_shares == dict(zip(NAMES, (25, 75, 0), strict=True))
        month_pill, = [node for node in document.nodes
                       if "month-pill" in node.attrs.get("class", "").split()]
        assert MONTH in month_pill.text
        shares.append(rendered_shares)
    assert shares[0] == shares[1]


def test_zero_current_total_produces_zero_shares_despite_old_or_deleted_usage(traffic_page):
    document = traffic_page([(0, 0), (0, 0), (0, 0)])
    metrics = [node.text for node in document.nodes
               if "metric-value" in node.attrs.get("class", "").split()]
    assert metrics == ["0 B", "0 B", "0 B"]
    for row in document.device_rows().values():
        assert row.attrs["data-traffic-download"] == "0"
        assert row.attrs["data-traffic-upload"] == "0"
        meter, = [node for node in document.within(row) if node.tag == "meter"]
        assert float(meter.attrs["value"]) == 0


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_numeric_sort_data_controls_and_history_preserve_the_rendered_device_records(
    traffic_page, lang,
):
    sizes = (900 * 1024**2, 2 * 1024**3, 10 * 1024**3)
    values = list(zip(sizes, (sizes[2], sizes[0], sizes[1]), strict=True))
    document = traffic_page(values, lang=lang)
    rows = document.device_rows()
    assert set(rows) == set(NAMES)
    history_ids = []
    for name, (download, upload) in zip(NAMES, values, strict=True):
        row = rows[name]
        assert row.attrs["data-traffic-download"] == str(download)
        assert row.attrs["data-traffic-upload"] == str(upload)
        assert traffic.fmt_bytes(download) in row.text
        assert traffic.fmt_bytes(upload) in row.text
        trigger, = [node for node in document.within(row)
                    if "data-history-trigger" in node.attrs]
        history_id = trigger.attrs["popovertarget"]
        history_ids.append(history_id)
        history, = [node for node in document.within(row) if node.attrs.get("id") == history_id]
        assert history.attrs["popover"] == "auto"
        assert MONTH in history.text and OLD_MONTH in history.text
        label, = [node for node in document.within(history)
                  if node.attrs.get("id") == history.attrs["aria-labelledby"]]
        assert label.text == name.rsplit("-", 1)[1]
    assert len(set(history_ids)) == len(NAMES)
    all_ids = [node.attrs["id"] for node in document.nodes if "id" in node.attrs]
    assert len(all_ids) == len(set(all_ids))

    for direction in ("download", "upload"):
        controls = [node for node in document.nodes
                    if node.attrs.get("data-traffic-sort") == direction]
        assert controls
        assert any(any(parent.tag == "th" for parent in node.ancestors) for node in controls)
        assert all(node.tag == "button" and node.attrs.get("type") == "button"
                   and (node.text.strip() or node.attrs.get("aria-label")) for node in controls)
    help_popover, = [node for node in document.nodes
                     if node.attrs.get("id") == "traffic-share-help"]
    assert help_popover.attrs["popover"] == "auto"
    assert t("ui_usage_share_help", lang) in help_popover.text
    help_title, = [node for node in document.within(help_popover)
                   if node.attrs.get("id") == help_popover.attrs["aria-labelledby"]]
    assert help_title.text == t("ui_usage_share_help_title", lang)
    help_controls = [node for node in document.nodes
                     if node.attrs.get("popovertarget") == "traffic-share-help"
                     and node.attrs.get("popovertargetaction") != "hide"]
    assert help_controls
    assert any(any(parent.tag == "th" for parent in node.ancestors) for node in help_controls)
    assert all(node.tag == "button" and node.attrs.get("type") == "button"
               and node.attrs.get("aria-label") == help_title.text for node in help_controls)
