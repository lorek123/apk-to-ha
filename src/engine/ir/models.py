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
    HANDSHAKE = "handshake"  # custom JSON handshake (e.g. grantAccess)
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


class EntityHint(str, Enum):
    """Suggested Home Assistant entity platform for a command, event, or state field."""

    SENSOR = "sensor"
    BINARY_SENSOR = "binary_sensor"
    SWITCH = "switch"
    BUTTON = "button"
    SELECT = "select"
    NUMBER = "number"
    TEXT = "text"
    LIGHT = "light"
    MEDIA_PLAYER = "media_player"


class FieldDef(BaseModel):
    name: str
    serialized_name: str | None = None  # @SerializedName / @Json(name=...)
    kind: FieldKind
    required: bool = True
    nullable: bool = False
    enum_values: list[str | int] | None = None
    description: str | None = None
    entity_hint: EntityHint | None = None  # for StateSchema fields → which HA entity type


class Endpoint(BaseModel):
    """One logical command or event in the device protocol."""

    model_config = ConfigDict(populate_by_name=True)

    cmd: str  # protocol command name / path
    transport: TransportType
    direction: Direction
    awaits_response: bool = False  # does caller block waiting for ack?
    request_fields: list[FieldDef] = Field(default_factory=list)
    response_fields: list[FieldDef] = Field(default_factory=list)
    description: str | None = None
    source_class: str | None = None  # Java class where this was found
    confidence: float = 1.0  # 0.0-1.0; <0.7 flagged for review
    entity_hint: EntityHint | None = None  # suggested HA platform for this endpoint


class TransportContract(BaseModel):
    type: TransportType
    port: int | None = None
    host_source: Literal["static", "discovered", "manual"] = "manual"
    url_template: str | None = None  # e.g. "ws://{host}:{port}"
    tls: bool = False


class DiscoveryMechanism(BaseModel):
    type: DiscoveryType
    port: int | None = None
    broadcast_cmd: str | None = None  # JSON cmd value in broadcast packet
    service_type: str | None = None  # mDNS/zeroconf service type e.g. "_device._tcp.local."
    hostname_pattern: str | None = None  # DHCP hostname glob e.g. "mydevice*"
    response_fields: list[FieldDef] = Field(default_factory=list)


class AuthScheme(BaseModel):
    type: AuthType
    handshake_cmd: str | None = None  # e.g. "grantAccess"
    fields: list[FieldDef] = Field(default_factory=list)
    description: str | None = None


class StateSchema(BaseModel):
    """Schema of the device's reported state (from gin / polling response)."""

    push_cmd: str | None = None  # e.g. "gin" for push-based
    fields: list[FieldDef] = Field(default_factory=list)


class DuplicateCheckResult(BaseModel):
    found: bool
    location: Literal["core", "hacs"] | None = None
    name: str | None = None
    repo_url: str | None = None
    coverage_estimate: Literal["full", "partial", "none"] = "none"


class SigningComponent(BaseModel):
    """One logical piece of a signing-input concatenation, in order."""

    kind: str  # "timestamp" | "path" | "body" | "http_method" | "host"
    # | "secret_key" | "nonce" | "literal" | "unknown"
    variable_name: str  # name as it appears in the decompiled source
    value: str | None = None  # populated for kind=="literal" only
    confidence: float = 1.0


class SigningTrace(BaseModel):
    """P2-5 output: reconstructed signing-input layout for one crypto call site."""

    algorithm: str  # e.g. "HMAC-SHA256"
    components: list[SigningComponent]  # signing input parts, in order
    key_source: str | None = None  # variable holding the HMAC key
    source_method: str  # fully-qualified method name
    confidence: float  # min(component confidences) * coverage factor
    unresolved: list[str] = Field(default_factory=list)  # vars the tracer couldn't classify


class CryptoUsage(BaseModel):
    """One detected cryptographic primitive usage found by P2-4."""

    algorithm: str  # normalised, e.g. "HMAC-SHA256", "AES/CBC/PKCS5Padding"
    call_site: str  # Java class name
    context_snippet: str  # up to 3 source lines around the call
    confidence: float = 1.0  # 0..1; <0.5 means inferred from import only


class PayloadSchema(BaseModel):
    """P2-2 — Resolved fields for one @Body parameter or response type."""

    class_name: str  # Java class name (e.g. "PowerRequest")
    fields: list[FieldDef]
    is_collection: bool = False  # True when the wire type is List<class_name>


class StreamingContract(BaseModel):
    """Binary frame-over-WebSocket stream from the device (e.g. camera video)."""

    port: int
    frame_format: str = "jpeg"
    rotate_degrees: int = 0


class PlayStoreInfo(BaseModel):
    """Metadata fetched from Google Play Store during P1."""

    title: str
    description: str  # full description text
    summary: str | None = None  # short 1-2 sentence summary
    category: str | None = None  # e.g. "House & Home", "Tools"
    developer: str | None = None
    developer_id: str | None = None
    rating: float | None = None
    installs: str | None = None  # e.g. "1,000,000+"
    play_store_url: str | None = None


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
    commands: list[Endpoint] = Field(default_factory=list)  # app → device
    events: list[Endpoint] = Field(default_factory=list)  # device → app

    # secondary streaming channel (e.g. camera video WebSocket)
    streaming: StreamingContract | None = None

    # crypto findings (P2-4) and signing traces (P2-5)
    crypto: list[CryptoUsage] = Field(default_factory=list)
    signing_traces: list[SigningTrace] = Field(default_factory=list)

    # meta
    play_store: PlayStoreInfo | None = None
    duplicate_check: DuplicateCheckResult | None = None
    extraction_confidence: float = 1.0
    extractor_notes: list[str] = Field(default_factory=list)
    raw_permissions: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
