"""Experimental LAN local-control for Dreame mowers over Aliyun ALCS (CoAP).

Direct phone/HA -> mower control on the LAN, no cloud redirect and no emulator.
Mechanism reverse-engineered from the Dreamehome app's Aliyun linksdk
(`com.aliyun.alink.linksdk.alcs.coap.AlcsCoAP`, AES-CBC-128).

STATUS: discovery + CoAP codec are standard and work; the secure-session auth
and key derivation follow the standard ALCS convention but are NOT yet verified
against a real mower (see TODO(device) in alcs.py). Not wired into the
coordinator yet — this package ships the client + probe so the handshake can be
confirmed on a mower's LAN, after which a full `lan` connection mode is wired in.
"""

from .alcs import AlcsDevice, AlcsSession, discover

__all__ = ["AlcsDevice", "AlcsSession", "discover"]
