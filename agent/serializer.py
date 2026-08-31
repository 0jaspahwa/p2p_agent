# agent/serializer.py
from __future__ import annotations

import json
from typing import Type

from pydantic import BaseModel, ValidationError

from agent.messages import (
    MessageType,
    WireMessage,
    Vouch,
    Revoke,
    HandshakeRequest,
    HandshakeResponse,
    FileRequest,
    FileRequestAck,
    FileRequestReject,
    ChunkHeader,
    TransferComplete,
    ErrorMessage,
    FileInfoRequest,
    FileInfoResponse
)

_TYPE_TO_MODEL: dict[MessageType, Type[BaseModel]] = {
    MessageType.VOUCH: Vouch,
    MessageType.REVOKE: Revoke,
    MessageType.HANDSHAKE_REQUEST: HandshakeRequest,
    MessageType.HANDSHAKE_RESPONSE: HandshakeResponse,
    MessageType.FILE_REQUEST: FileRequest,
    MessageType.FILE_REQUEST_ACK: FileRequestAck,
    MessageType.FILE_REQUEST_REJECT: FileRequestReject,
    MessageType.CHUNK_HEADER: ChunkHeader,
    MessageType.TRANSFER_COMPLETE: TransferComplete,
    MessageType.ERROR: ErrorMessage,
    MessageType.FILE_INFO_REQUEST: FileInfoRequest,
    MessageType.FILE_INFO_RESPONSE: FileInfoResponse,
}


class SerializationError(Exception):
    """Raised when a message can't be encoded to wire format."""


class DeserializationError(Exception):
    """Raised when incoming bytes aren't a valid/known wire message.
    Deliberately a distinct exception from pydantic's ValidationError so
    callers (p2p_server.py, downloader.py) can catch one thing regardless
    of whether the failure was bad JSON, an unknown type, or a schema
    mismatch — they shouldn't need to know pydantic is involved at all."""


def encode(message: WireMessage) -> bytes:
    """Model instance -> UTF-8 JSON bytes ready to write to a socket/stream."""
    try:
        return message.model_dump_json().encode("utf-8")
    except Exception as e:
        raise SerializationError(f"failed to encode {type(message).__name__}: {e}") from e


def decode(raw: bytes) -> WireMessage:
    """Raw bytes off the wire -> the correctly typed pydantic model.
    Reads the `type` field first to know which model to validate against —
    this is manual dispatch rather than a pydantic discriminated Union,
    since these models aren't nested under one parent envelope."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise DeserializationError(f"not valid JSON: {e}") from e

    if not isinstance(payload, dict) or "type" not in payload:
        raise DeserializationError("message missing required 'type' field")

    raw_type = payload["type"]
    try:
        msg_type = MessageType(raw_type)
    except ValueError as e:
        raise DeserializationError(f"unknown message type: {raw_type!r}") from e

    model_cls = _TYPE_TO_MODEL[msg_type]
    try:
        return model_cls.model_validate(payload)
    except ValidationError as e:
        raise DeserializationError(
            f"payload failed schema validation for {msg_type.value}: {e}"
        ) from e


def decode_as(raw: bytes, expected_type: Type[BaseModel]) -> BaseModel:
    """Like decode(), but also enforces the caller got the message type they
    expected. Useful where protocol state makes the next message predictable
    — e.g. p2p_server.py expects FileRequest right after a handshake, and a
    HandshakeRequest arriving there instead is a protocol violation, not
    just 'some other valid message'."""
    msg = decode(raw)
    if not isinstance(msg, expected_type):
        raise DeserializationError(
            f"expected {expected_type.__name__}, got {type(msg).__name__}"
        )
    return msg