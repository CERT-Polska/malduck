#!/usr/bin/env python3
"""A pure Python module for decompressing aPLib compressed data

Adapted from the original C source code from http://ibsensoftware.com/files/aPLib-1.1.1.zip
Approximately 20 times faster than other Python implementations.
Compatible with both Python 2 and 3.
"""
from io import BytesIO

__all__ = ["APLib"]
__version__ = "0.6"
__author__ = "Sandor Nemes"


class APLib(object):

    __slots__ = "source", "destination", "tag", "bitcount", "strict"

    def __init__(self, source: bytes, strict: bool = True) -> None:
        self.source = BytesIO(source)
        self.destination = bytearray()
        self.tag = 0
        self.bitcount = 0
        self.strict = bool(strict)

    def getbit(self) -> int:
        # check if tag is empty
        self.bitcount -= 1
        if self.bitcount < 0:
            # load next tag
            self.tag = ord(self.source.read(1))
            self.bitcount = 7

        # shift bit out of tag
        bit = self.tag >> 7 & 1
        self.tag <<= 1

        return bit

    def getgamma(self) -> int:
        result = 1

        # input gamma2-encoded bits
        while True:
            result = (result << 1) + self.getbit()
            if not self.getbit():
                break

        return result

    def depack(self) -> bytes:
        r0 = -1
        lwm = 0
        done = False

        try:

            # first byte verbatim
            self.destination += self.source.read(1)

            # main decompression loop
            while not done:
                if self.getbit():
                    if self.getbit():
                        if self.getbit():
                            offs = 0
                            for _ in range(4):
                                offs = (offs << 1) + self.getbit()

                            if offs:
                                self.destination.append(self.destination[-offs])
                            else:
                                self.destination.append(0)

                            lwm = 0
                        else:
                            offs = ord(self.source.read(1))
                            length = 2 + (offs & 1)
                            offs >>= 1

                            if offs:
                                for _ in range(length):
                                    self.destination.append(self.destination[-offs])
                            else:
                                done = True

                            r0 = offs
                            lwm = 1
                    else:
                        offs = self.getgamma()

                        if lwm == 0 and offs == 2:
                            offs = r0
                            length = self.getgamma()

                            for _ in range(length):
                                self.destination.append(self.destination[-offs])
                        else:
                            if lwm == 0:
                                offs -= 3
                            else:
                                offs -= 2

                            offs <<= 8
                            offs += ord(self.source.read(1))
                            length = self.getgamma()

                            if offs >= 32000:
                                length += 1
                            if offs >= 1280:
                                length += 1
                            if offs < 128:
                                length += 2

                            for _ in range(length):
                                self.destination.append(self.destination[-offs])

                            r0 = offs

                        lwm = 1
                else:
                    self.destination += self.source.read(1)
                    lwm = 0

        except (TypeError, IndexError):
            if self.strict:
                raise RuntimeError("aPLib decompression error")

        return bytes(self.destination)

    def pack(self):
        raise NotImplementedError


def main():
    # self-test
    data = b"T\x00he quick\xecb\x0erown\xcef\xaex\x80jumps\xed\xe4veur`t?lazy\xead\xfeg\xc0\x00"
    assert APLib(data).depack() == b"The quick brown fox jumps over the lazy dog"


if __name__ == "__main__":
    main()
