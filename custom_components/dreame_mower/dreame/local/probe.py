"""Standalone probe for the ALCS LAN path — run on the mower's LAN.

    python -m custom_components.dreame_mower.dreame.local.probe
    python -m ...probe --connect PRODUCTKEY DEVICENAME SECRET [--access-token AT]

Discovery is standard and should list any Aliyun ALCS device. --connect then
tries the (experimental) secure auth and reads battery 3:1; the DEBUG logs
capture the real handshake so the TODO(device) spots in alcs.py can be fixed.
"""
from __future__ import annotations

import argparse
import logging

from .alcs import AlcsDevice, AlcsSession, discover


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--iface", default="0.0.0.0",
                    help="local LAN adapter IP to send multicast from (multi-NIC hosts)")
    ap.add_argument("--connect", nargs=3, metavar=("PRODUCTKEY", "DEVICENAME", "SECRET"))
    ap.add_argument("--access-key", default="")
    ap.add_argument("--access-token", default="")
    ap.add_argument("--ip", help="skip discovery; target this device IP directly")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(name)s %(message)s")

    print(f"discovering ALCS devices for {args.timeout}s ...")
    devices = discover(timeout=args.timeout, iface_ip=args.iface)
    if not devices:
        print("no ALCS devices found (mower on this LAN / powered / awake?)")
    for d in devices:
        print("  found:", d)

    if not args.connect:
        return

    pk, dn, secret = args.connect
    target = next((d for d in devices if d.product_key == pk and d.device_name == dn), None)
    if target is None:
        if not args.ip:
            print("target not discovered; pass --ip to target it directly")
            return
        target = AlcsDevice(args.ip, 5683, pk, dn)

    sess = AlcsSession(target, secret, args.access_key, args.access_token)
    print("connecting (auth) ...")
    if sess.connect():
        print("AUTH OK — battery 3:1 ->", sess.get_property(3, 1))
        print("status 2:1 ->", sess.get_property(2, 1))
    else:
        print("AUTH FAILED — see DEBUG logs; adjust TODO(device) in alcs.py")
    sess.close()


if __name__ == "__main__":
    main()
