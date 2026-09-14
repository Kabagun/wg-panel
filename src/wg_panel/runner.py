import os
import threading

from .core import (
    BIND_HOST,
    CLIENTS_DIR,
    DATA_DIR,
    DOMAIN,
    ENABLE_HTTP_REDIRECT,
    ENABLE_INTERNAL_TLS,
    HTTP_REDIRECT_PORT,
    PORT,
    REDIRECT_SOCKET_TIMEOUT_SECS,
    SSL_CERT,
    SSL_KEY,
    app,
    ensure_admin,
    ensure_private_dir,
)
from .payments import process_payment_reminders
from .telegram import set_tg_webhook
from .traffic import collect_traffic
from .wireguard import migrate_device_metadata, reconcile_safe_dns


def main():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class HTTPSRedirect(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(301)
            self.send_header("Location", f"https://{DOMAIN}{self.path}")
            self.end_headers()
        def do_POST(self):
            self.do_GET()
        def log_message(self, *a):
            pass

    def run_redirect():
        from socketserver import ThreadingMixIn

        class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
            daemon_threads = True
            def get_request(self):
                sock, addr = super().get_request()
                try:
                    sock.settimeout(REDIRECT_SOCKET_TIMEOUT_SECS)
                except (OSError, ValueError) as exc:
                    import sys

                    print(f"[HTTP REDIRECT] Failed to set socket timeout: {exc}", file=sys.stderr)
                return sock, addr

        try:
            ThreadingHTTPServer(("0.0.0.0", HTTP_REDIRECT_PORT), HTTPSRedirect).serve_forever()
        except OSError as e:
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
