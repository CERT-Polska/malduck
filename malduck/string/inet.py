# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.
from __future__ import annotations

import re
import socket

from ..string.bin import p32

__all__ = ["ipv4"]

ipv4_regex = re.compile(
    b"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
    b"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
)


def ipv4(s: bytes | int) -> str | None:
    """
    Decodes IPv4 address and returns dot-decimal notation

    :param s: Buffer or integer value to be decoded as IPv4
    :type s: int or bytes
    :rtype: str
    """
    if isinstance(s, int):
        return socket.inet_ntoa(p32(s)[::-1])
    elif isinstance(s, bytes):
        if len(s) == 4:
            return socket.inet_ntoa(s)
        if re.match(ipv4_regex, s):
            return s.decode()
        return None
    else:
        raise TypeError("Wrong argument type, only bytes and int are allowed.")
