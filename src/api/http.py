"""Dependency-free HTTP transport for the BitClone application service."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

from src.api.contracts import API_VERSION, JSON_MEDIA_TYPE, ROUTES
from src.api.service import APIError, NodeApplicationService
from src.core import get_logger


logger = get_logger(__name__)


def _match_route(path: str):
    for route in ROUTES:
        match = route.pattern.fullmatch(path)
        if match is not None:
            return route, match.groupdict()
    return None, {}


class _BitCloneRequestHandler(BaseHTTPRequestHandler):
    server: "BitCloneHTTPServer"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        target = urlsplit(self.path)
        route, path_parameters = _match_route(target.path)
        if route is None:
            self._write_error(
                APIError(404, "route_not_found", "The requested API route does not exist")
            )
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
        except Exception:
            logger.exception("Unhandled BitClone API request failure")
            self._write_error(
                APIError(500, "internal_error", "The request could not be completed")
            )
            return
        self._write_json(HTTPStatus.OK, result)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._write_error(
            APIError(405, "method_not_allowed", "This route does not accept POST requests"),
            allow="GET",
        )

    def _write_error(self, error: APIError, allow: str | None = None) -> None:
        self._write_json(error.status, error.to_data(), allow=allow)

    def _write_json(self, status: int, payload: dict[str, Any], allow: str | None = None) -> None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{JSON_MEDIA_TYPE}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("API-Version", API_VERSION)
        self.send_header("Cache-Control", "no-store")
        if allow is not None:
            self.send_header("Allow", allow)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args) -> None:
        logger.info("%s - %s", self.address_string(), message % args)


class BitCloneHTTPServer(HTTPServer):
    """
    Synchronous local HTTP server for one node application service.

    The server intentionally handles requests on its owning thread. BitClone's
    current SQLite connection is thread-affine; background node work remains in
    its own managed workers.
    """

    allow_reuse_address = True

    def __init__(
            self,
            application: NodeApplicationService,
            host: str = "127.0.0.1",
            port: int = 8334,
    ):
        self.application = application
        super().__init__((host, port), _BitCloneRequestHandler)

    @property
    def url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}/api/{API_VERSION}"

    def run(self) -> None:
        try:
            self.serve_forever()
        finally:
            self.server_close()
