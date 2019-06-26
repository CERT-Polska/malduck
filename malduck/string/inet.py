# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import re
import socket

from ..py2compat import is_integer, is_binary, ensure_string
from ..string.bin import p32

ipv4_regex = re.compile(
    b"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}"
    b"([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
)


def ipv4(s):
    if is_integer(s):
        return socket.inet_ntoa(p32(s)[::-1])
    if is_binary(s):
        if len(s) == 4:
            return socket.inet_ntoa(s)
        if re.match(ipv4_regex, s):
            return ensure_string(s)
