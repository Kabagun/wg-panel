import socket
import threading
import time
from http.client import HTTPConnection

import pytest

from wg_panel import runner


def test_redirect_bounds_slow_connections_expires_drips_and_recovers(monkeypatch):
    monkeypatch.setattr(runner, "DOMAIN", "vpn.example.com")
    count_lock = threading.Lock()
    full = threading.Event()
    drained = threading.Event()
    released = threading.Event()
    counts = {"active": 0, "peak": 0}

    class Server(runner.BoundedRedirectServer):
        completed = 0

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                with count_lock:
                    self.completed += 1
                    if self.completed == 2:
                        released.set()

    class Handler(runner.HTTPSRedirect):
        def setup(self):
            super().setup()
            with count_lock:
                counts["active"] += 1
                counts["peak"] = max(counts["peak"], counts["active"])
                if counts["active"] == 2:
                    full.set()

        def finish(self):
            try:
                super().finish()
            finally:
                with count_lock:
                    counts["active"] -= 1
                    if not counts["active"]:
                        drained.set()

    server = None
    for port in range(18000, 18100):
        try:
            server = Server(
                ("127.0.0.1", port), Handler, max_connections=2, deadline=0.8,
            )
            break
        except OSError:
            continue
    assert server is not None, "No free local test port in 18000-18099"
    serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    serving.start()
    sockets = []
    try:
        for _ in range(2):
            sock = socket.create_connection(server.server_address, timeout=2)
            sock.sendall(b"GET / HTTP/1.1\r\nX-Slow: ")
            sockets.append(sock)
        assert full.wait(2)
        extra = socket.create_connection(server.server_address, timeout=2)
        sockets.append(extra)
        try:
            assert extra.recv(1) == b""
        except ConnectionResetError:
            pass
        start = time.monotonic()
        # Bytes arrive more frequently than the idle timeout; the absolute
        # connection deadline must still terminate both handlers.
        while not drained.wait(0.1) and time.monotonic() - start < 2:
            for sock in sockets[:2]:
                try:
                    sock.sendall(b"x")
                except OSError:
                    pass
        assert drained.is_set()
        assert released.wait(2)
        assert counts["peak"] == 2
        for method in ("GET", "POST"):
            client = HTTPConnection(*server.server_address, timeout=2)
            try:
                client.request(method, "/login?next=devices")
                response = client.getresponse()
                assert response.status == 301
                assert response.getheader("Location") == "https://vpn.example.com/login?next=devices"
                assert response.getheader("Connection") == "close"
                response.read()
            finally:
                client.close()
    finally:
        for sock in sockets:
            sock.close()
        server.shutdown()
        server.server_close()
        serving.join(2)


@pytest.mark.parametrize("deadline", [0, -1, float("nan"), float("inf")])
def test_redirect_rejects_unbounded_deadline(deadline):
    with pytest.raises(ValueError):
        runner.BoundedRedirectServer(("127.0.0.1", 18000), deadline=deadline)
