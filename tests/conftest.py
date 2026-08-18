import os
from pathlib import Path

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
