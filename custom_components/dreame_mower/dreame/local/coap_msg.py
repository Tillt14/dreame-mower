"""Minimal CoAP (RFC 7252) message codec — enough for Aliyun ALCS over UDP."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# CoAP message types
CON, NON, ACK, RST = 0, 1, 2, 3
# method codes
GET, POST, PUT, DELETE = 1, 2, 3, 4


def _code(c: int, dd: int) -> int:
    return (c << 5) | dd


METHOD_GET = _code(0, GET)
METHOD_POST = _code(0, POST)

OPT_URI_PATH = 11
OPT_CONTENT_FORMAT = 12
OPT_URI_QUERY = 15
# Aliyun ALCS vendor options
OPT_ALCS_ACCESS_KEY = 2088
OPT_ALCS_AUTH_TOKEN = 2089


@dataclass
class CoapMessage:
    type: int = NON
    code: int = METHOD_POST
    message_id: int = 0
    token: bytes = b""
    options: list[tuple[int, bytes]] = field(default_factory=list)
    payload: bytes = b""

    def add_uri_path(self, path: str) -> None:
        for seg in path.strip("/").split("/"):
            if seg:
                self.options.append((OPT_URI_PATH, seg.encode()))

    def uri_path(self) -> str:
        segs = [v.decode(errors="replace") for n, v in self.options if n == OPT_URI_PATH]
        return "/" + "/".join(segs)

    def encode(self) -> bytes:
        tkl = len(self.token)
        out = bytearray()
        out += struct.pack("!B", (1 << 6) | (self.type << 4) | (tkl & 0x0F))
        out += struct.pack("!B", self.code)
        out += struct.pack("!H", self.message_id)
        out += self.token
        last = 0
        for num, val in sorted(self.options, key=lambda o: o[0]):
            delta = num - last
            last = num
            length = len(val)

            def nibble(x: int) -> tuple[int, bytes]:
                if x < 13:
                    return x, b""
                if x < 269:
                    return 13, struct.pack("!B", x - 13)
                return 14, struct.pack("!H", x - 269)

            dn, dext = nibble(delta)
            lnn, lext = nibble(length)
            out += struct.pack("!B", (dn << 4) | lnn)
            out += dext + lext + val
        if self.payload:
            out += b"\xff" + self.payload
        return bytes(out)

    @classmethod
    def decode(cls, data: bytes) -> "CoapMessage":
        if len(data) < 4:
            raise ValueError("short CoAP packet")
        b0 = data[0]
        tkl = b0 & 0x0F
        msg = cls(
            type=(b0 >> 4) & 0x03,
            code=data[1],
            message_id=struct.unpack("!H", data[2:4])[0],
        )
        i = 4
        msg.token = data[i:i + tkl]
        i += tkl
        last = 0
        while i < len(data):
            if data[i] == 0xFF:
                msg.payload = data[i + 1:]
                break
            dn = data[i] >> 4
            lnn = data[i] & 0x0F
            i += 1

            def ext(kind: int) -> int:
                nonlocal i
                if kind == 13:
                    v = data[i]
                    i += 1
                    return v + 13
                if kind == 14:
                    v = struct.unpack("!H", data[i:i + 2])[0]
                    i += 2
                    return v + 269
                return kind

            delta = ext(dn)
            length = ext(lnn)
            num = last + delta
            last = num
            msg.options.append((num, data[i:i + length]))
            i += length
        return msg
