"""Aliyun ALCS (Alink CoAP Secure) client for LAN local control.

CONFIRMED (standard, testable on any LAN): CoAP codec + multicast discovery +
AES-128-CBC crypto. NEEDS A MOWER TO VERIFY (TODO(device)): exact auth sign
content, which secret, session-key derivation, IV/token transport. The standard
ALCS convention is implemented with verbose logging so one run on a mower's LAN
reveals the real handshake.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import socket
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .coap_msg import METHOD_GET, METHOD_POST, NON, OPT_CONTENT_FORMAT, CoapMessage

_LOG = logging.getLogger(__name__)

MCAST_ADDR = "224.0.1.187"
COAP_PORT = 5683
DISCOVER_PATH = "/dev/core/service/dev"
AUTH_PATH = "/dev/core/service/auth"


def _rand_str(n: int = 15) -> str:
    return os.urandom(n).hex()[:n]


def _pkcs7_pad(b: bytes) -> bytes:
    p = 16 - (len(b) % 16)
    return b + bytes([p]) * p


def _pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    p = b[-1]
    return b[:-p] if 0 < p <= 16 else b


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(_pkcs7_pad(data)) + enc.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _pkcs7_unpad(dec.update(data) + dec.finalize())


class AlcsDevice:
    def __init__(self, ip: str, port: int, product_key: str, device_name: str,
                 info: dict[str, Any] | None = None) -> None:
        self.ip = ip
        self.port = port
        self.product_key = product_key
        self.device_name = device_name
        self.info: dict[str, Any] = info or {}

    def __repr__(self) -> str:
        return f"<AlcsDevice {self.product_key}/{self.device_name} @ {self.ip}:{self.port}>"


def discover(timeout: float = 5.0, iface_ip: str = "0.0.0.0") -> list[AlcsDevice]:
    """CoAP multicast discovery of ALCS devices on the LAN.

    iface_ip: local IP of the LAN adapter to send from, for multi-homed hosts.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if iface_ip and iface_ip != "0.0.0.0":
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
    sock.bind((iface_ip, 0))
    sock.settimeout(0.5)

    req = CoapMessage(type=NON, code=METHOD_GET, message_id=int(time.time()) & 0xFFFF,
                      token=os.urandom(4))
    req.add_uri_path(DISCOVER_PATH)
    _LOG.info("ALCS discovery -> %s:%d %s", MCAST_ADDR, COAP_PORT, DISCOVER_PATH)
    sock.sendto(req.encode(), (MCAST_ADDR, COAP_PORT))

    found: dict[tuple[str, int], AlcsDevice] = {}
    end = time.time() + timeout
    while time.time() < end:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        try:
            msg = CoapMessage.decode(data)
            body: dict[str, Any] = (
                json.loads(msg.payload.decode("utf-8", "replace")) if msg.payload else {}
            )
        except Exception as ex:  # noqa: BLE001
            _LOG.debug("non-JSON reply from %s: %r (%s)", addr, data[:40], ex)
            continue
        _LOG.info("ALCS reply from %s: %s", addr, body)
        d: dict[str, Any] = body.get("data", body)
        pk = str(d.get("productKey") or d.get("pk") or "")
        dn = str(d.get("deviceName") or d.get("dn") or "")
        ip = str(d.get("ipAddress") or d.get("ip") or addr[0])
        port = int(d.get("port") or COAP_PORT)
        found[(ip, port)] = AlcsDevice(ip, port, pk, dn, d)
    sock.close()
    return list(found.values())


def discover_mdns(timeout: float = 5.0) -> list[AlcsDevice]:
    """Find ALCS devices via mDNS/zeroconf as a second discovery path.

    Enumerates every advertised service type and keeps the ones whose TXT records
    or names look like Aliyun / ALCS / Dreame-Mova devices (carry productKey /
    deviceName, or a telling service name). Standard mDNS — works device-free.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceInfo, ServiceListener, Zeroconf
    except Exception as ex:  # noqa: BLE001
        _LOG.info("zeroconf unavailable, skipping mDNS discovery: %s", ex)
        return []

    found: dict[tuple[str, int], AlcsDevice] = {}
    hints = ("alink", "aliyun", "ica", "cosa", "dreame", "mova")

    def _txt(info: "ServiceInfo") -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in (info.properties or {}).items():
            try:
                key = k.decode("utf-8", "replace")
                out[key] = v.decode("utf-8", "replace") if isinstance(v, bytes) else ""
            except Exception:  # noqa: BLE001
                continue
        return out

    class _Listener(ServiceListener):
        def _handle(self, zc: "Zeroconf", type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:  # noqa: BLE001
                return
            if info is None:
                return
            txt = _txt(info)
            name_l = name.lower()
            looks = any(h in name_l for h in hints) or "productKey" in txt or "deviceName" in txt
            if not looks:
                return
            addrs = info.parsed_addresses()
            ip = addrs[0] if addrs else ""
            port = info.port or COAP_PORT
            pk = txt.get("productKey") or txt.get("pk") or ""
            dn = txt.get("deviceName") or txt.get("dn") or ""
            if ip:
                _LOG.info("mDNS candidate %s type=%s ip=%s txt=%s", name, type_, ip, txt)
                found[(ip, port)] = AlcsDevice(ip, port, pk, dn, dict(txt))

        def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            self._handle(zc, type_, name)

        def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            self._handle(zc, type_, name)

        def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

    zc = Zeroconf()
    listener = _Listener()
    try:
        # enumerate all advertised service types, then browse each
        types: list[str] = []

        class _TypeListener(ServiceListener):
            def add_service(self, z: "Zeroconf", type_: str, name: str) -> None:
                types.append(name)

            def update_service(self, z: "Zeroconf", type_: str, name: str) -> None:
                pass

            def remove_service(self, z: "Zeroconf", type_: str, name: str) -> None:
                pass

        ServiceBrowser(zc, "_services._dns-sd._udp.local.", _TypeListener())
        time.sleep(min(timeout, 3.0))
        browsers = [ServiceBrowser(zc, t, listener) for t in list(dict.fromkeys(types))] or [
            ServiceBrowser(zc, "_alink._tcp.local.", listener)
        ]
        time.sleep(timeout)
        del browsers
    finally:
        zc.close()
    return list(found.values())


def discover_all(timeout: float = 6.0, iface_ip: str = "0.0.0.0") -> list[AlcsDevice]:
    """CoAP multicast + mDNS discovery, de-duplicated by (ip, port)."""
    merged: dict[tuple[str, int], AlcsDevice] = {}
    for d in discover(timeout=timeout, iface_ip=iface_ip):
        merged[(d.ip, d.port)] = d
    for d in discover_mdns(timeout=timeout):
        merged.setdefault((d.ip, d.port), d)
    return list(merged.values())


class AlcsSession:
    """Secure session with one ALCS device (experimental — see TODO(device))."""

    def __init__(self, device: AlcsDevice, secret: str, access_key: str = "",
                 access_token: str = "") -> None:
        self.dev = device
        self.secret = secret
        self.access_key = access_key
        self.access_token = access_token
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(5.0)
        self._mid = int(time.time()) & 0xFFFF
        self._auth_token: str = ""
        self._key: bytes = b""

    def _next_mid(self) -> int:
        self._mid = (self._mid + 1) & 0xFFFF
        return self._mid

    def _request(self, path: str, payload: bytes,
                 options: list[tuple[int, bytes]] | None = None) -> CoapMessage:
        msg = CoapMessage(type=0, code=METHOD_POST, message_id=self._next_mid(),
                          token=os.urandom(4), payload=payload)
        msg.add_uri_path(path)
        msg.options.append((OPT_CONTENT_FORMAT, b"\x32"))  # 50 application/json
        if options:
            msg.options.extend(options)
        self._sock.sendto(msg.encode(), (self.dev.ip, self.dev.port))
        data, _ = self._sock.recvfrom(4096)
        return CoapMessage.decode(data)

    def connect(self) -> bool:
        pk, dn = self.dev.product_key, self.dev.device_name
        random_key = _rand_str(15)
        client_id = f"{pk}.{dn}"
        # TODO(device): confirm sign content + signMethod + which secret/key.
        sign_content = f"clientId{client_id}deviceName{dn}productKey{pk}random{random_key}"
        sign_key = (self.access_token or self.secret).encode()
        sign = hmac.new(sign_key, sign_content.encode(), hashlib.sha1).hexdigest()
        params: dict[str, Any] = {
            "prodKey": pk, "deviceName": dn, "clientId": client_id,
            "random": random_key, "sign": sign, "signMethod": "hmacsha1",
            "accessKey": self.access_key,
        }
        body = {"id": self._next_mid(), "version": "1.0",
                "method": "core/service/auth", "params": params}
        _LOG.info("ALCS auth -> %s %s", AUTH_PATH, body)
        resp = self._request(AUTH_PATH, json.dumps(body).encode())
        try:
            rj: dict[str, Any] = json.loads(resp.payload.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            _LOG.error("ALCS auth reply not JSON: %r", resp.payload[:80])
            return False
        _LOG.info("ALCS auth reply: %s", rj)
        data: dict[str, Any] = rj.get("data", {})
        self._auth_token = str(data.get("token", ""))
        device_random = str(data.get("random", ""))
        if not self._auth_token:
            _LOG.error("no token in ALCS auth reply — handshake spec needs the mower to confirm")
            return False
        # TODO(device): confirm session-key derivation.
        material = f"{random_key},{device_random},{self.secret}".encode()
        self._key = hashlib.md5(material).digest()
        _LOG.info("ALCS session up token=%s keylen=%d", self._auth_token, len(self._key))
        return True

    def set_property(self, siid: int, piid: int, value: Any) -> dict[str, Any]:
        return self._thing("set", {f"{siid}.{piid}": value})

    def get_property(self, siid: int, piid: int) -> dict[str, Any]:
        return self._thing("get", [f"{siid}.{piid}"])

    def _thing(self, kind: str, params: Any) -> dict[str, Any]:
        pk, dn = self.dev.product_key, self.dev.device_name
        path = f"/sys/{pk}/{dn}/thing/service/property/{kind}"
        inner = {"id": str(self._next_mid()), "version": "1.0",
                 "method": f"thing.service.property.{kind}", "params": params}
        raw = json.dumps(inner).encode()
        opts: list[tuple[int, bytes]] | None = None
        if self._key:
            iv = os.urandom(16)
            payload = iv + aes_cbc_encrypt(self._key, iv, raw)
            if self._auth_token:
                opts = [(2089, self._auth_token.encode())]
        else:
            payload = raw
        _LOG.info("ALCS %s %s params=%s encrypted=%s", kind, path, params, bool(self._key))
        resp = self._request(path, payload, opts)
        out = resp.payload
        if self._key and out:
            try:
                out = aes_cbc_decrypt(self._key, out[:16], out[16:])
            except Exception as ex:  # noqa: BLE001
                _LOG.warning("ALCS decrypt failed (%s); raw=%r", ex, resp.payload[:60])
        try:
            parsed: dict[str, Any] = json.loads(out.decode("utf-8", "replace"))
            return parsed
        except Exception:  # noqa: BLE001
            return {"raw": out.hex()}

    def close(self) -> None:
        self._sock.close()
