# SPDX-License-Identifier: MIT
"""P3-1 — Internal contract IR. Decouples extraction from emission."""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Framework(str, Enum):
    NATIVE = "native"
    FLUTTER = "flutter"
    REACT_NATIVE = "react_native"


class TransportType(str, Enum):
    WEBSOCKET = "websocket"
    HTTP_REST = "http_rest"
    TCP_SOCKET = "tcp_socket"
    UDP = "udp"
    BLE = "ble"


class DiscoveryType(str, Enum):
    UDP_BROADCAST = "udp_broadcast"
    ZEROCONF = "zeroconf"
    STATIC_IP = "static_ip"
    NONE = "none"


class AuthType(str, Enum):
    HANDSHAKE = "handshake"     # custom JSON handshake (e.g. grantAccess)
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    NONE = "none"


class Direction(str, Enum):
    TO_DEVICE = "to_device"
    FROM_DEVICE = "from_device"


class FieldKind(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ENUM = "enum"
    OBJECT = "object"
    ARRAY = "array"


class FieldDef(BaseModel):
    name: str
    serialized_name: str | None = None     # @SerializedName / @Json(name=...)
    kind: FieldKind
    required: bool = True
    nullable: bool = False
    enum_values: list[str | int] | None = None
    description: str | None = None


class Endpoint(BaseModel):
    """One logical command or event in the device protocol."""
    model_config = ConfigDict(populate_by_name=True)

    cmd: str                               # protocol command name / path
    transport: TransportType
    direction: Direction
    awaits_response: bool = False          # does caller block waiting for ack?
    request_fields: list[FieldDef] = Field(default_factory=list)
    response_fields: list[FieldDef] = Field(default_factory=list)
    description: str | None = None
    source_class: str | None = None        # Java class where this was found
    confidence: float = 1.0               # 0.0–1.0; <0.7 flagged for review


class TransportContract(BaseModel):
    type: TransportType
    port: int | None = None
    host_source: Literal["static", "discovered", "manual"] = "manual"
    url_template: str | None = None        # e.g. "ws://{host}:{port}"
    tls: bool = False


class DiscoveryMechanism(BaseModel):
    type: DiscoveryType
    port: int | None = None
    broadcast_cmd: str | None = None       # JSON cmd value in broadcast packet
    response_fields: list[FieldDef] = Field(default_factory=list)


class AuthScheme(BaseModel):
    type: AuthType
    handshake_cmd: str | None = None       # e.g. "grantAccess"
    fields: list[FieldDef] = Field(default_factory=list)
    description: str | None = None


class StateSchema(BaseModel):
    """Schema of the device's reported state (from gin / polling response)."""
    push_cmd: str | None = None            # e.g. "gin" for push-based
    fields: list[FieldDef] = Field(default_factory=list)


class DuplicateCheckResult(BaseModel):
    found: bool
    location: Literal["core", "hacs"] | None = None
    name: str | None = None
    repo_url: str | None = None
    coverage_estimate: Literal["full", "partial", "none"] = "none"


class ProtocolIR(BaseModel):
    """Complete extracted protocol contract for one APK. P3-1 IR root object."""
    model_config = ConfigDict(populate_by_name=True)

    # source metadata
    apk_path: str
    package_name: str
    app_name: str
    version_name: str | None = None
    framework: Framework

    # protocol contract
    transport: TransportContract
    discovery: DiscoveryMechanism
    auth: AuthScheme
    state: StateSchema
    commands: list[Endpoint] = Field(default_factory=list)    # app → device
    events: list[Endpoint] = Field(default_factory=list)      # device → app

    # meta
    duplicate_check: DuplicateCheckResult | None = None
    extraction_confidence: float = 1.0
    extractor_notes: list[str] = Field(default_factory=list)
    raw_permissions: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
