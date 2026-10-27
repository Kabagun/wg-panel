import math
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

from .access import reconcile_paused_users
from .core import (
    BIND_HOST,
    CLIENTS_DIR,
    DATA_DIR,
    DOMAIN,
    ENABLE_HTTP_REDIRECT,
    ENABLE_INTERNAL_TLS,
    HTTP_REDIRECT_PORT,
    MAX_REDIRECT_CONNECTIONS,
    PORT,
    REDIRECT_SOCKET_TIMEOUT_SECS,
    SSL_CERT,
    SSL_KEY,
    app,
    ensure_admin,
    ensure_private_dir,
)
from .infrastructure import assert_infrastructure_ready
from .payments import process_payment_reminders
from .telegram import set_tg_webhook
from .traffic import collect_traffic
from .wireguard import migrate_device_metadata, reconcile_safe_dns


class HTTPSRedirect(BaseHTTPRequestHandler):
    """Redirect one GET/POST request to the configured HTTPS endpoint."""

    def do_GET(self):
        """Return the existing permanent redirect and close the connection."""
        self.send_response(301)
        self.send_header("Location", f"https://{DOMAIN}{self.path}")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_POST(self):
        """Apply the same redirect to POST requests."""
        self.do_GET()

    def log_message(self, *args):
        """Suppress routine redirect request logs."""


class BoundedRedirectServer(ThreadingMixIn, HTTPServer):
    """Bound handler admission and total connection lifetime, including headers."""

    daemon_threads = True

    def __init__(self, address, handler=HTTPSRedirect, *, max_connections=32, deadline=5.0):
        if max_connections < 1 or not math.isfinite(deadline) or deadline <= 0:
            raise ValueError("Redirect capacity and deadline must be positive and finite")
        self._slots = threading.BoundedSemaphore(max_connections)
        self._deadline = deadline
        self._accepted = {}
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        """Reject excess connections before allocating their handler threads."""
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self._accepted[request] = time.monotonic()
        try:
            request.settimeout(self._deadline)
            super().process_request(request, client_address)
        except Exception:
            self._accepted.pop(request, None)
            self.shutdown_request(request)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        """Close even trickling sockets at an absolute deadline and release capacity."""
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        remaining = max(0, self._accepted.pop(request) + self._deadline - time.monotonic())
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        try:
            timer.start()
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self.shutdown_request(request)
            self._slots.release()

    def handle_error(self, request, client_address):
        """Treat closed/expired client connections as ordinary disconnects."""
        if not isinstance(sys.exception(), (ConnectionError, TimeoutError)):
            super().handle_error(request, client_address)


def main():
    """Reconcile persisted state and start the single-process panel service."""
    assert_infrastructure_ready()

    def run_redirect():
        try:
            with BoundedRedirectServer(
                (BIND_HOST, HTTP_REDIRECT_PORT),
                max_connections=MAX_REDIRECT_CONNECTIONS,
                deadline=REDIRECT_SOCKET_TIMEOUT_SECS,
            ) as server:
                server.serve_forever()
        except (OSError, ValueError) as e:
            import sys
            print(f"[HTTP REDIRECT] Failed to bind on :{HTTP_REDIRECT_PORT}: {e}", file=sys.stderr, flush=True)

    if ENABLE_HTTP_REDIRECT:
        threading.Thread(target=run_redirect, daemon=True).start()

    def traffic_loop():
        import time
        time.sleep(10)  # wait for app to fully start
        while True:
            try:
                collect_traffic()
            except (OSError, ValueError) as exc:
                import sys
                print(f"[TRAFFIC] {exc}", file=sys.stderr, flush=True)
            time.sleep(60)

    def payment_loop():
        import time
        while True:
            try:
                process_payment_reminders()
            except (OSError, ValueError) as exc:
                import sys
                print(f"[PAYMENTS] {exc}", file=sys.stderr, flush=True)
            time.sleep(300)

    ensure_private_dir(CLIENTS_DIR)
    ensure_private_dir(DATA_DIR)
    ensure_admin()
    migration = migrate_device_metadata(dry_run=False)
    print(
        f"[DEVICE META] total={migration['total']} migrated={migration['migrated']}",
        flush=True,
    )
    paused_users = reconcile_paused_users()
    print(f"[VPN PAUSE] users={paused_users}", flush=True)
    safe_dns = reconcile_safe_dns()
    print(
        f"[SAFE DNS] devices={safe_dns['safe_devices']} ips={len(safe_dns['ips'])}",
        flush=True,
    )
    set_tg_webhook()
    threading.Thread(target=traffic_loop, daemon=True).start()
    threading.Thread(target=payment_loop, daemon=True).start()
    cert_ready = os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)
    ssl_ctx = (SSL_CERT, SSL_KEY) if ENABLE_INTERNAL_TLS and cert_ready else None
    if ENABLE_INTERNAL_TLS and not cert_ready:
        import sys
        print("[TLS] Cert files missing, starting without internal TLS", file=sys.stderr, flush=True)
    app.run(host=BIND_HOST, port=PORT, debug=False, ssl_context=ssl_ctx, threaded=True)
