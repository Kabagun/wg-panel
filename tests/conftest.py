import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_ROOT = REPO_ROOT / "temp" / "pytest-bootstrap"
os.environ.setdefault("WG_PANEL_DATA_DIR", str(BOOTSTRAP_ROOT / "data"))
os.environ.setdefault("WG_PANEL_WG_DIR", str(BOOTSTRAP_ROOT / "wireguard"))
os.environ.setdefault("WG_PANEL_CLIENTS_DIR", str(BOOTSTRAP_ROOT / "wireguard" / "clients"))
os.environ.setdefault("WG_PANEL_ADMIN_USER", "admin")
os.environ.setdefault("WG_PANEL_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("WG_PANEL_ENABLE_INTERNAL_TLS", "0")
os.environ.setdefault("WG_PANEL_ENABLE_HTTP_REDIRECT", "0")
os.environ.setdefault("WG_PANEL_PAYMENT_ACCOUNT", "test-account")
os.environ.setdefault("WG_PANEL_TELEGRAM_WEBHOOK_SECRET", "test-webhook-secret")


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "family_archive: explicitly restore retired family protection for legacy coverage",
    )


@pytest.fixture(autouse=True)
def family_archive_opt_in(request, monkeypatch):
    """Ordinary tests retain production defaults; archive coverage opts in by marker."""
    if request.node.get_closest_marker("family_archive") is not None:
        from wg_panel import app
        monkeypatch.setitem(app.config, "FAMILY_PROTECTION_ENABLED", True)
        monkeypatch.setenv("WG_PANEL_FAMILY_PROTECTION_ENABLED", "1")
