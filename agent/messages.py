# agent/messages.py
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    HANDSHAKE_REQUEST = "handshake_request"
    HANDSHAKE_RESPONSE = "handshake_response"
    VOUCH = "vouch"
    REVOKE = "revoke"
    FILE_REQUEST = "file_request"
    FILE_REQUEST_ACK = "file_request_ack"
    FILE_REQUEST_REJECT = "file_request_reject"
    CHUNK_HEADER = "chunk_header"
    TRANSFER_COMPLETE = "transfer_complete"
    ERROR = "error"
    FILE_INFO_REQUEST = "file_info_request"
    FILE_INFO_RESPONSE = "file_info_response"


class Vouch(BaseModel):
    """
    One signed edge in the trust graph: issuer vouches for subject.
    This is the atomic unit trust.py walks to build a path back to a known
    root. messages.py defines the shape only — verification lives in trust.py.
    """
    type: Literal[MessageType.VOUCH] = MessageType.VOUCH
    issuer_id: str            # base64 Ed25519 pubkey of the vouching agent
    subject_id: str           # base64 Ed25519 pubkey of the agent being vouched for
    issued_at: float = Field(default_factory=time.time)
    expires_at: float         # required, not optional — trust lapses on its own,
                               # revocation isn't the only mechanism
    signature: str            # base64 sig over (issuer_id|subject_id|issued_at|expires_at)


class Revoke(BaseModel):
    """Issued by the original voucher to invalidate a Vouch before expiry."""
    type: Literal[MessageType.REVOKE] = MessageType.REVOKE
    issuer_id: str
    subject_id: str
    revoked_at: float = Field(default_factory=time.time)
    reason: str = ""
    signature: str            # base64 sig over (issuer_id|subject_id|revoked_at)


class HandshakeRequest(BaseModel):
    type: Literal[MessageType.HANDSHAKE_REQUEST] = MessageType.HANDSHAKE_REQUEST
    sender_id: str
    trust_chain: list[Vouch] = Field(default_factory=list)
    nonce: str                 # base64 random bytes, fresh per handshake
    timestamp: float = Field(default_factory=time.time)


class HandshakeResponse(BaseModel):
    type: Literal[MessageType.HANDSHAKE_RESPONSE] = MessageType.HANDSHAKE_RESPONSE
    sender_id: str
    trust_chain: list[Vouch] = Field(default_factory=list)
    nonce_signature: str       # base64 sig over the request's nonce — proves key possession
    timestamp: float = Field(default_factory=time.time)


class FileRequest(BaseModel):
    """A byte-range request — not whole-file. Swarm-splitting depends on this
    granularity: downloader.py fires many of these concurrently at different
    peers for disjoint ranges of the same file."""
    type: Literal[MessageType.FILE_REQUEST] = MessageType.FILE_REQUEST
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_hash: str
    range_start: int
    range_end: int              # inclusive
    sender_id: str


class FileRequestAck(BaseModel):
    type: Literal[MessageType.FILE_REQUEST_ACK] = MessageType.FILE_REQUEST_ACK
    request_id: str
    chunk_size: int             # may be < requested range if responder throttles
                                  # for cloud API quota reasons


class FileRequestReject(BaseModel):
    type: Literal[MessageType.FILE_REQUEST_REJECT] = MessageType.FILE_REQUEST_REJECT
    request_id: str
    reason: Literal["no_trust_path", "rate_limited", "file_not_found", "internal_error"]
    detail: str = ""


class ChunkHeader(BaseModel):
    """Precedes a raw byte stream on the same connection — NOT a JSON-wrapped
    chunk. The header is parsed as JSON; chunk_size bytes immediately following
    it on the socket are read raw into the async generator pipe."""
    type: Literal[MessageType.CHUNK_HEADER] = MessageType.CHUNK_HEADER
    request_id: str
    range_start: int
    range_end: int
    chunk_size: int
    checksum: str                # sha256 hex of this byte range


class TransferComplete(BaseModel):
    type: Literal[MessageType.TRANSFER_COMPLETE] = MessageType.TRANSFER_COMPLETE
    request_id: str
    total_bytes: int


class ErrorMessage(BaseModel):
    type: Literal[MessageType.ERROR] = MessageType.ERROR
    request_id: str | None = None
    code: str
    detail: str = ""

class FileInfoRequest(BaseModel):
    """A lightweight query to get the file size before downloading chunks."""
    type: Literal[MessageType.FILE_INFO_REQUEST] = MessageType.FILE_INFO_REQUEST
    file_hash: str
    sender_id: str

class FileInfoResponse(BaseModel):
    type: Literal[MessageType.FILE_INFO_RESPONSE] = MessageType.FILE_INFO_RESPONSE
    file_hash: str
    file_size: int
    file_name: str | None = None

# serializer.py will dispatch incoming JSON to one of these via a
# MessageType -> class lookup table, not a pydantic discriminated Union —
# manual dispatch is simpler here since these aren't nested in a parent model.
WireMessage = (
    HandshakeRequest | HandshakeResponse | Vouch | Revoke
    | FileRequest | FileRequestAck | FileRequestReject
    | ChunkHeader | TransferComplete | ErrorMessage
    | FileInfoRequest | FileInfoResponse 
)