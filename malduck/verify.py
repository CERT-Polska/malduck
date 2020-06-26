# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import re

__all__ = ["Verify", "verify"]

# https://stackoverflow.com/a/52082649
DOMAIN_REGEX = (
    b"^(?=.{1,255}$)(?!-)[A-Za-z0-9\\-]{1,63}(\\.[A-Za-z0-9\\-]{1,63})*\\.?(?<!-)$"
)

# The regex as we use it in Cuckoo.
URL_REGEX = (
    # HTTP/HTTPS.
    b"(https?:\\/\\/)"
    b"((["
    # IP address.
    b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\."
    b"(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])]|"
    # Or domain name.
    b"[a-zA-Z0-9\\.-]+)"
    # Optional port.
    b"(\\:\\d+)?"
    # URI.
    b"(/[\\(\\)a-zA-Z0-9_:%?=/\\.-]*)?"
)


class Verify(object):
    @staticmethod
    def ascii(s: bytes) -> bool:
        return bool(re.match(b"^[\\x20-\\x7f]*$", s, re.DOTALL))

    @staticmethod
    def domain(s: bytes) -> bool:
        return bool(re.match(DOMAIN_REGEX, s, re.DOTALL))

    @staticmethod
    def url(s: bytes) -> bool:
        return bool(re.match(URL_REGEX, s, re.DOTALL))


verify = Verify
