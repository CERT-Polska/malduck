# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import struct

from typing import Optional

from ..bits import rol
from .xor import xor

__all__ = ["rabbit"]


class State:
    def __init__(self) -> None:
        self.x = [0] * 8
        self.c = [0] * 8
        self.carry = 0


class Context:
    def __init__(self) -> None:
        self.m = State()
        self.w = State()


class Rabbit:
    def __init__(self, key: bytes, iv: Optional[bytes]) -> None:
        self.ctx = Context()
        self.set_key(key)
        if iv:
            self.set_iv(iv)

    def g_func(self, x: int) -> int:
        x = x & 0xFFFFFFFF
        x = (x * x) & 0xFFFFFFFFFFFFFFFF
        result = (x >> 32) ^ (x & 0xFFFFFFFF)
        return result

    def set_key(self, key: bytes) -> None:
        # Four subkeys.
        key0, key1, key2, key3 = struct.unpack("IIII", key[:16])

        # Generate initial state variables.
        s = self.ctx.m
        s.x[0] = key0
        s.x[2] = key1
        s.x[4] = key2
        s.x[6] = key3
        s.x[1] = ((key3 << 16) & 0xFFFFFFFF) | ((key2 >> 16) & 0xFFFF)
        s.x[3] = ((key0 << 16) & 0xFFFFFFFF) | ((key3 >> 16) & 0xFFFF)
        s.x[5] = ((key1 << 16) & 0xFFFFFFFF) | ((key0 >> 16) & 0xFFFF)
        s.x[7] = ((key2 << 16) & 0xFFFFFFFF) | ((key1 >> 16) & 0xFFFF)

        # Generate initial counter values.
        s.c[0] = rol(key2, 16)
        s.c[2] = rol(key3, 16)
        s.c[4] = rol(key0, 16)
        s.c[6] = rol(key1, 16)
        s.c[1] = (key0 & 0xFFFF0000) | (key1 & 0xFFFF)
        s.c[3] = (key1 & 0xFFFF0000) | (key2 & 0xFFFF)
        s.c[5] = (key2 & 0xFFFF0000) | (key3 & 0xFFFF)
        s.c[7] = (key3 & 0xFFFF0000) | (key0 & 0xFFFF)
        s.carry = 0

        # Iterate system four times.
        for i in range(4):
            self.next_state(self.ctx.m)

        # Modify the counters.
        for i in range(8):
            self.ctx.m.c[i] ^= self.ctx.m.x[(i + 4) & 7]

        # Copy master instance to work instance.
        self.ctx.w = self.copy_state(self.ctx.m)

    def copy_state(self, state: State) -> State:
        s = State()
        s.carry = state.carry
        s.x = state.x[:]
        s.c = state.c[:]
        return s

    def set_iv(self, iv: bytes) -> None:
        # Generate four subvectors.
        v = [0] * 4
        v[0], v[2] = struct.unpack("II", iv[:8])
        v[1] = (v[0] >> 16) | (v[2] & 0xFFFF0000)
        v[3] = ((v[2] << 16) | (v[0] & 0x0000FFFF)) & 0xFFFFFFFF

        # Modify work's counter values.
        for i in range(8):
            self.ctx.w.c[i] = self.ctx.m.c[i] ^ v[i & 3]

        # Copy state variables but not carry flag.
        self.ctx.w.x = self.ctx.m.x[:]

        # Iterate system four times.
        for i in range(4):
            self.next_state(self.ctx.w)

    def next_state(self, state: State) -> None:
        g = [0] * 8
        x = [0x4D34D34D, 0xD34D34D3, 0x34D34D34]

        # Calculate new counter values.
        for i in range(8):
            tmp = state.c[i]
            state.c[i] = (state.c[i] + x[i % 3] + state.carry) & 0xFFFFFFFF
            state.carry = state.c[i] < tmp

        # Calculate the g-values.
        for i in range(8):
            g[i] = self.g_func(state.x[i] + state.c[i])

        # Calculate new state values.
        j = 7
        for i in range(0, 8, 2):
            state.x[i + 0] = (g[i + 0] + rol(g[j], 16) + rol(g[j - 1], 16)) & 0xFFFFFFFF
            j = (j + 1) & 7
            state.x[i + 1] = (g[i + 1] + rol(g[j], 8) + g[j - 1]) & 0xFFFFFFFF
            j = (j + 1) & 7

    def encrypt(self, msg: bytes) -> bytes:
        x, ret = [0] * 4, []
        for off in range(0, len(msg) + 15, 16):
            self.next_state(self.ctx.w)
            x[0], x[1] = self.ctx.w.x[0], self.ctx.w.x[2]
            x[2], x[3] = self.ctx.w.x[4], self.ctx.w.x[6]
            x[0] ^= (self.ctx.w.x[5] >> 16) ^ (self.ctx.w.x[3] << 16) % 2 ** 32
            x[1] ^= (self.ctx.w.x[7] >> 16) ^ (self.ctx.w.x[5] << 16) % 2 ** 32
            x[2] ^= (self.ctx.w.x[1] >> 16) ^ (self.ctx.w.x[7] << 16) % 2 ** 32
            x[3] ^= (self.ctx.w.x[3] >> 16) ^ (self.ctx.w.x[1] << 16) % 2 ** 32
            ret.append(xor(struct.pack("IIII", *x), msg[off : off + 16]))
        return b"".join(ret)

    decrypt = encrypt


def rabbit(key: bytes, iv: bytes, data: bytes) -> bytes:
    """
    Encrypts/decrypts buffer using Rabbit algorithm

    :param key: Cryptographic key (16 bytes)
    :type key: bytes
    :param iv: Initialization vector (8 bytes)
    :type iv: bytes
    :param data: Buffer to be encrypted/decrypted
    :type data: bytes
    :return: Encrypted/decrypted data
    :rtype: bytes
    """
    return Rabbit(key, iv).decrypt(data)
