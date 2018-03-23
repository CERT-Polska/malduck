# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import socket

class IPv4(object):
    def __init__(self, addr):
        self.addr = self.parse(addr)

    def parse(self, addr):
        if len(addr) == 4:
            return socket.inet_ntoa(addr)

    def __str__(self):
        return self.addr
