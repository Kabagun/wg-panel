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
)
from .telegram import set_tg_webhook
from .traffic import collect_traffic


def main():
    from http.server import HTTPServer, BaseHTTPRequestHandler

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
                except Exception:
                    pass
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
            except Exception:
                pass
            time.sleep(60)

    threading.Thread(target=traffic_loop, daemon=True).start()
    set_tg_webhook()

    os.makedirs(CLIENTS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    ensure_admin()
    cert_ready = os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY)
    ssl_ctx = (SSL_CERT, SSL_KEY) if ENABLE_INTERNAL_TLS and cert_ready else None
    if ENABLE_INTERNAL_TLS and not cert_ready:
        import sys
        print("[TLS] Cert files missing, starting without internal TLS", file=sys.stderr, flush=True)
    app.run(host=BIND_HOST, port=PORT, debug=False, ssl_context=ssl_ctx, threaded=True)
