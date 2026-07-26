"""REST route definitions and OpenAPI generation for the BitClone v1 API."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


API_VERSION = "v1"
OPENAPI_VERSION = "3.1.0"
API_PREFIX = f"/api/{API_VERSION}"
JSON_MEDIA_TYPE = "application/json"


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    name: str
    location: str
    schema: dict[str, Any]
    description: str
    required: bool = False

    def to_openapi(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "in": self.location,
            "required": self.required,
            "description": self.description,
            "schema": self.schema,
        }


@dataclass(frozen=True, slots=True)
class RouteSpec:
    path: str
    operation_id: str
    summary: str
    tag: str
    parameters: tuple[ParameterSpec, ...] = ()
    required_scope: str | None = "read"

    @property
    def full_path(self) -> str:
        return f"{API_PREFIX}{self.path}"

    @property
    def pattern(self) -> re.Pattern[str]:
        expression = re.sub(
            r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}",
            r"(?P<\1>[^/]+)",
            self.full_path,
        )
        return re.compile(f"^{expression}/?$")


PAGINATION_PARAMETERS = (
    ParameterSpec(
        "limit",
        "query",
        {"type": "integer", "minimum": 1, "maximum": 200, "default": 50},
        "Maximum number of resources to return.",
    ),
    ParameterSpec(
        "offset",
        "query",
        {"type": "integer", "minimum": 0, "default": 0},
        "Zero-based number of resources to skip.",
    ),
)

DISPLAY_HASH_PARAMETER = ParameterSpec(
    "block_hash",
    "path",
    {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
    "Block hash in conventional display byte order.",
    required=True,
)

TXID_PARAMETER = ParameterSpec(
    "txid",
    "path",
    {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
    "Transaction ID in conventional display byte order.",
    required=True,
)


ROUTES = (
    RouteSpec("", "api_index", "Describe the v1 API", "service", required_scope=None),
    RouteSpec(
        "/openapi.json",
        "openapi",
        "Return the OpenAPI document",
        "service",
        required_scope=None,
    ),
    RouteSpec(
        "/health",
        "health",
        "Check API and node process health",
        "service",
        required_scope=None,
    ),
    RouteSpec(
        "/version",
        "version",
        "Return BitClone and API versions",
        "service",
        required_scope=None,
    ),
    RouteSpec("/capabilities", "capabilities", "Report available product capabilities", "service"),
    RouteSpec(
        "/events",
        "events",
        "Stream node events using Server-Sent Events",
        "events",
        required_scope="events",
    ),
    RouteSpec("/node/status", "node_status", "Return operational node status", "node"),
    RouteSpec("/node/sync", "sync_status", "Return synchronization progress", "node"),
    RouteSpec("/node/trust", "trust_status", "Describe block-data source and trust", "node"),
    RouteSpec("/chain", "chain_summary", "Return active-chain summary", "chain"),
    RouteSpec(
        "/chain/blocks/{block_hash}",
        "get_block",
        "Return a block by hash",
        "chain",
        (DISPLAY_HASH_PARAMETER,),
    ),
    RouteSpec(
        "/peers",
        "list_peers",
        "List ready peers",
        "peers",
        PAGINATION_PARAMETERS,
    ),
    RouteSpec(
        "/peers/address-book",
        "peer_address_book",
        "Return known peer addresses and connection diagnostics",
        "peers",
    ),
    RouteSpec(
        "/mempool",
        "list_mempool",
        "List mempool transactions",
        "mempool",
        PAGINATION_PARAMETERS,
    ),
    RouteSpec(
        "/mempool/{txid}",
        "get_mempool_transaction",
        "Return one mempool transaction",
        "mempool",
        (TXID_PARAMETER,),
    ),
)


def build_openapi_document() -> dict[str, Any]:
    """Generate the API contract from the same registry used for dispatch."""
    paths: dict[str, Any] = {}
    for route in ROUTES:
        success_content = (
            {
                "text/event-stream": {
                    "schema": {"type": "string"},
                }
            }
            if route.operation_id == "events"
            else {
                JSON_MEDIA_TYPE: {
                    "schema": {"type": "object"},
                }
            }
        )
        responses: dict[str, Any] = {
            "200": {
                "description": "Successful response",
                "content": success_content,
            },
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "404": {"$ref": "#/components/responses/NotFound"},
            "429": {"$ref": "#/components/responses/RateLimited"},
        }
        paths[route.full_path or API_PREFIX] = {
            "get": {
                "operationId": route.operation_id,
                "summary": route.summary,
                "tags": [route.tag],
                "parameters": [parameter.to_openapi() for parameter in route.parameters],
                "responses": responses,
                **(
                    {
                        "security": [{"bearerAuth": []}],
                        "x-required-scope": route.required_scope,
                    }
                    if route.required_scope is not None
                    else {"security": []}
                ),
            }
        }

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": "BitClone Local Service API",
            "version": API_VERSION,
            "description": (
                "Local-first API for operating BitClone. Bitcoin monetary values use "
                "integer satoshis and `_sats` field names. Wall-clock timestamps are "
                "RFC 3339 UTC strings; consensus block times use `_unix` field names. "
                "Collection endpoints return `items` and `page` metadata."
            ),
        },
        "servers": [{"url": "/"}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "opaque",
                    "description": (
                        "Pass a BitClone API token. Tokens are supplied through "
                        "BITCLONE_API_TOKEN or generated for one server run."
                    ),
                }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": {"type": "string"},
                                "message": {"type": "string"},
                                "details": {"type": "object"},
                            },
                        }
                    },
                },
                "Page": {
                    "type": "object",
                    "required": ["limit", "offset", "count", "total"],
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1},
                        "offset": {"type": "integer", "minimum": 0},
                        "count": {"type": "integer", "minimum": 0},
                        "total": {"type": "integer", "minimum": 0},
                    },
                },
            },
            "responses": {
                "BadRequest": {
                    "description": "The request parameters are invalid.",
                    "content": {
                        JSON_MEDIA_TYPE: {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                },
                "NotFound": {
                    "description": "The requested resource does not exist.",
                    "content": {
                        JSON_MEDIA_TYPE: {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                },
                "Unauthorized": {
                    "description": "A valid bearer token is required.",
                    "content": {
                        JSON_MEDIA_TYPE: {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                },
                "Forbidden": {
                    "description": "The credential or browser origin is not allowed.",
                    "content": {
                        JSON_MEDIA_TYPE: {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                },
                "RateLimited": {
                    "description": "The request rate limit was exceeded.",
                    "content": {
                        JSON_MEDIA_TYPE: {
                            "schema": {"$ref": "#/components/schemas/Error"}
                        }
                    },
                },
            },
        },
    }
