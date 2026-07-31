"""Secure, dependency-free HTTP and SSE transport for BitClone."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
import json
from pathlib import Path
import socket
import ssl
import threading
from typing import Any, Iterable
from urllib.parse import parse_qs, urlsplit

from src.api.contracts import API_VERSION, JSON_MEDIA_TYPE, ROUTES
from src.api.events import EventHub, NodeEventMonitor
from src.api.security import (
    APICredential,
    AuditRecorder,
    BearerAuthenticator,
    OriginPolicy,
    SlidingWindowRateLimiter,
    redact_secrets,
)
from src.api.service import APIError, NodeApplicationService, RPCError
from src.core import get_logger


logger = get_logger(__name__)
CSRF_HEADER = "X-BitClone-CSRF"
RPC_PATHS = {"/", "/rpc", f"/api/{API_VERSION}/rpc"}
MAX_RPC_BODY_BYTES = 1_000_000
STATIC_ROOT = Path(__file__).with_name("static")
STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/console": ("index.html", "text/html; charset=utf-8"),
    "/assets/console.css": ("console.css", "text/css; charset=utf-8"),
    "/assets/console.js": ("console.js", "text/javascript; charset=utf-8"),
    "/assets/bitcoin-math-lab-mark.svg": ("bitcoin-math-lab-mark.svg", "image/svg+xml"),
}


def _match_route(path: str):
    for route in ROUTES:
        match = route.pattern.fullmatch(path)
        if match is not None:
            return route, match.groupdict()
    return None, {}


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


class _BitCloneRequestHandler(BaseHTTPRequestHandler):
    server: "BitCloneHTTPServer"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        target = urlsplit(self.path)
        static_asset = STATIC_ROUTES.get(target.path)
        if static_asset is not None:
            self._write_static(*static_asset)
            return
        route, path_parameters = _match_route(target.path)
        if route is None:
            self._write_error(
                APIError(404, "route_not_found", "The requested API route does not exist")
            )
            return

        try:
            allowed_origin = self.server.origin_policy.validate(self.headers.get("Origin"))
            try:
                principal = self.server.authenticator.authenticate(
                    self.headers.get("Authorization"),
                    route.required_scope,
                )
            except APIError:
                self.server.auth_rate_limiter.check(self.client_address[0])
                raise
            rate_key = (
                f"{self.client_address[0]}:"
                f"{principal.credential_id if principal is not None else 'anonymous'}"
            )
            remaining = self.server.rate_limiter.check(rate_key)
        except APIError as error:
            self.server.audit.record(
                "request_denied",
                client=self.client_address[0],
                path=target.path,
                code=error.code,
            )
            self._write_error(error)
            return

        self._allowed_origin = allowed_origin
        self._rate_limit_remaining = remaining
        if route.operation_id == "events":
            self._stream_events()
            return

        try:
            result = self.server.application.dispatch(
                route.operation_id,
                path_parameters,
                parse_qs(target.query, keep_blank_values=True),
            )
        except APIError as error:
            self._write_error(error)
            return
        except Exception as error:
            logger.exception("Unhandled BitClone API request failure")
            self.server.events.publish(
                "warning",
                {
                    "code": "api_request_failure",
                    "path": target.path,
                    "message": "An internal API request failed.",
                    "error_type": type(error).__name__,
                },
            )
            self._write_error(
                APIError(500, "internal_error", "The request could not be completed")
            )
            return
        self._write_json(HTTPStatus.OK, result)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path in RPC_PATHS:
            self._handle_rpc()
            return
        self._reject_mutating_method()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutating_method()

    def do_PATCH(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutating_method()

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._reject_mutating_method()

    def _reject_mutating_method(self) -> None:
        try:
            self._allowed_origin = self.server.origin_policy.validate(
                self.headers.get("Origin")
            )
            if self._allowed_origin is not None and self.headers.get(CSRF_HEADER) != "1":
                raise APIError(
                    403,
                    "csrf_validation_failed",
                    f"Browser mutations require the {CSRF_HEADER} header",
                )
        except APIError as error:
            self.server.audit.record(
                "request_denied",
                client=self.client_address[0],
                path=urlsplit(self.path).path,
                code=error.code,
            )
            self._write_error(error)
            return
        self._write_error(
            APIError(405, "method_not_allowed", "This route does not accept this method"),
            allow="GET",
        )

    def _handle_rpc(self) -> None:
        try:
            self._allowed_origin = self.server.origin_policy.validate(
                self.headers.get("Origin")
            )
            principal = self.server.authenticator.authenticate_rpc(
                self.headers.get("Authorization"),
                "read",
            )
            self._rate_limit_remaining = self.server.rate_limiter.check(
                f"{self.client_address[0]}:{principal.credential_id}"
            )
        except APIError as error:
            self.server.audit.record(
                "request_denied",
                client=self.client_address[0],
                path=urlsplit(self.path).path,
                code=error.code,
            )
            self._write_error(error)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._write_rpc_payload(
                {"result": None, "error": {"code": -32700, "message": "Parse error"}, "id": None}
            )
            return
        if not 0 < content_length <= MAX_RPC_BODY_BYTES:
            self._write_rpc_payload(
                {
                    "result": None,
                    "error": {"code": -32600, "message": "Invalid Request"},
                    "id": None,
                }
            )
            return
        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write_rpc_payload(
                {"result": None, "error": {"code": -32700, "message": "Parse error"}, "id": None}
            )
            return

        requests = payload if isinstance(payload, list) else [payload]
        if not requests:
            requests = [None]
        methods = [
            request.get("method")
            for request in requests
            if isinstance(request, dict)
        ]
        required_scope = (
            "admin"
            if any(
                isinstance(method, str)
                and self.server.application.rpc_required_scope(method) == "admin"
                for method in methods
            )
            else "read"
        )
        if required_scope == "admin":
            try:
                principal = self.server.authenticator.authenticate_rpc(
                    self.headers.get("Authorization"),
                    required_scope,
                )
                if (
                        self._allowed_origin is not None
                        and self.headers.get(CSRF_HEADER) != "1"
                ):
                    raise APIError(
                        403,
                        "csrf_validation_failed",
                        f"Browser RPC mutations require the {CSRF_HEADER} header",
                    )
            except APIError as error:
                self.server.audit.record(
                    "request_denied",
                    client=self.client_address[0],
                    path=urlsplit(self.path).path,
                    code=error.code,
                )
                self._write_error(error)
                return

        if required_scope == "admin":
            self.server.audit.record(
                "rpc_mutation",
                client=self.client_address[0],
                credential_id=principal.credential_id,
                methods=methods,
            )

        responses = [
            response
            for request in requests
            if (response := self._rpc_response(request)) is not None
        ]
        if not responses:
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("API-Version", API_VERSION)
            self.send_header("Cache-Control", "no-store")
            self._write_security_headers()
            self.end_headers()
            return
        self._write_rpc_payload(
            responses if isinstance(payload, list) else responses[0]
        )

    def _rpc_response(self, request: Any) -> dict[str, Any] | None:
        request_id = request.get("id") if isinstance(request, dict) else None
        is_notification = isinstance(request, dict) and "id" not in request
        if (
                not isinstance(request, dict)
                or request.get("jsonrpc", "1.0") not in ("1.0", "2.0")
                or not isinstance(request.get("method"), str)
        ):
            return {
                "result": None,
                "error": {"code": -32600, "message": "Invalid Request"},
                "id": request_id,
            }
        try:
            result = self.server.application.dispatch_rpc(
                request["method"],
                request.get("params", []),
            )
            response = {"result": result, "error": None, "id": request_id}
        except RPCError as error:
            response = {"result": None, "error": error.to_data(), "id": request_id}
        except Exception:
            logger.exception("Unhandled BitClone RPC request failure")
            response = {
                "result": None,
                "error": {"code": -32603, "message": "Internal error"},
                "id": request_id,
            }
        return None if is_notification else response

    def _write_rpc_payload(self, payload: Any) -> None:
        self._write_json(HTTPStatus.OK, payload)

    def _stream_events(self) -> None:
        last_event_header = self.headers.get("Last-Event-ID", "0")
        try:
            last_event_id = int(last_event_header)
            if last_event_id < 0:
                raise ValueError
        except ValueError:
            self._write_error(
                APIError(
                    400,
                    "invalid_last_event_id",
                    "Last-Event-ID must be a non-negative integer",
                )
            )
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("API-Version", API_VERSION)
        self._write_security_headers()
        self.end_headers()
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            for event in self.server.events.subscribe(last_event_id):
                if event is None:
                    self.wfile.write(b": heartbeat\n\n")
                else:
                    self.wfile.write(event.to_sse())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            logger.debug("SSE client disconnected: %s", self.client_address[0])
        finally:
            self.close_connection = True

    def _write_error(self, error: APIError, allow: str | None = None) -> None:
        headers: dict[str, str] = {}
        if error.status == HTTPStatus.UNAUTHORIZED:
            headers["WWW-Authenticate"] = 'Bearer realm="BitClone API"'
        if error.status == HTTPStatus.TOO_MANY_REQUESTS and error.details:
            headers["Retry-After"] = str(error.details["retry_after_seconds"])
        self._write_json(error.status, error.to_data(), allow=allow, extra_headers=headers)

    def _write_json(
            self,
            status: int,
            payload: Any,
            allow: str | None = None,
            extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(
            redact_secrets(payload),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", f"{JSON_MEDIA_TYPE}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("API-Version", API_VERSION)
            self.send_header("Cache-Control", "no-store")
            self._write_security_headers()
            if allow is not None:
                self.send_header("Allow", allow)
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("HTTP client disconnected before response completed")

    def _write_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        remaining = getattr(self, "_rate_limit_remaining", None)
        if remaining is not None:
            self.send_header("X-RateLimit-Remaining", str(remaining))
        allowed_origin = getattr(self, "_allowed_origin", None)
        if allowed_origin is not None:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
            self.send_header("Vary", "Origin")

    def _write_static(self, filename: str, content_type: str) -> None:
        try:
            body = (STATIC_ROOT / filename).read_bytes()
        except OSError:
            self._write_error(
                APIError(500, "console_unavailable", "The browser console asset is unavailable")
            )
            return
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("HTTP client disconnected before console asset completed")

    def log_message(self, message: str, *args) -> None:
        logger.info("%s - %s", self.address_string(), message % args)


class BitCloneHTTPServer(HTTPServer):
    """
    Local-first HTTP server with isolated SSE streaming workers.

    Ordinary application requests stay on the owning thread to preserve the
    current SQLite connection's thread affinity. Only `/events`, which reads
    from a thread-safe event hub, is moved to a daemon worker.
    """

    allow_reuse_address = True

    def __init__(
            self,
            application: NodeApplicationService,
            api_token: str,
            host: str = "127.0.0.1",
            port: int = 8334,
            allowed_origins: Iterable[str] | None = None,
            tls_cert: str | Path | None = None,
            tls_key: str | Path | None = None,
            audit_path: Path | None = None,
            rate_limit: int = 120,
            auth_rate_limit: int = 20,
            event_interval: float = 1.0,
    ):
        if (tls_cert is None) != (tls_key is None):
            raise ValueError("Both TLS certificate and key must be provided together")
        if not _is_loopback_host(host) and tls_cert is None:
            raise ValueError("Non-loopback API binding requires TLS")

        self.application = application
        self.authenticator = BearerAuthenticator(
            [APICredential.from_token("local-operator", api_token)]
        )
        self.rate_limiter = SlidingWindowRateLimiter(limit=rate_limit)
        self.auth_rate_limiter = SlidingWindowRateLimiter(limit=auth_rate_limit)
        self.events = EventHub()
        self.event_monitor = NodeEventMonitor(
            application.event_snapshot,
            self.events,
            interval=event_interval,
        )
        self.audit = AuditRecorder(audit_path)
        self._event_threads: set[threading.Thread] = set()
        self._event_threads_lock = threading.Lock()
        super().__init__((host, port), _BitCloneRequestHandler)

        scheme = "https" if tls_cert is not None else "http"
        bound_host, bound_port = self.server_address[:2]
        if allowed_origins is None:
            origins = {
                f"{scheme}://{bound_host}:{bound_port}",
                f"{scheme}://localhost:{bound_port}",
            }
        else:
            origins = set(allowed_origins)
        if not _is_loopback_host(host) and not origins:
            self.server_close()
            raise ValueError("Non-loopback API binding requires at least one allowed origin")
        self.origin_policy = OriginPolicy(origins)
        self._scheme = scheme

        if tls_cert is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(tls_cert), str(tls_key))
            self.socket = context.wrap_socket(self.socket, server_side=True)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"{self._scheme}://{host}:{port}/api/{API_VERSION}"

    def process_request(self, request: socket.socket, client_address) -> None:
        """Move only SSE requests off the SQLite-owning server thread."""
        try:
            first_bytes = request.recv(2048, socket.MSG_PEEK)
        except OSError:
            first_bytes = b""
        event_prefix = f"GET /api/{API_VERSION}/events".encode("ascii")
        if first_bytes.startswith(event_prefix):
            thread = threading.Thread(
                target=self._process_event_request,
                args=(request, client_address),
                name="bitclone-sse-client",
                daemon=True,
            )
            with self._event_threads_lock:
                self._event_threads.add(thread)
            thread.start()
            return
        super().process_request(request, client_address)

    def _process_event_request(self, request: socket.socket, client_address) -> None:
        try:
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except (BrokenPipeError, ConnectionResetError):
            self.shutdown_request(request)
        except Exception:
            self.handle_error(request, client_address)
            self.shutdown_request(request)
        finally:
            thread = threading.current_thread()
            with self._event_threads_lock:
                self._event_threads.discard(thread)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self.events.publish("lifecycle", {"state": "api_started"})
        self.audit.record("api_started", address=self.url)
        self.event_monitor.start()
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            self.event_monitor.stop()
            self.events.publish("lifecycle", {"state": "api_stopping"})
            self.events.close()
            self.audit.record("api_stopped")

    def run(self) -> None:
        try:
            self.serve_forever()
        finally:
            self.server_close()
