# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from roach import disasm

class TestDisasm(object):
    streams = "".join((
        # mov esi, [edi+4]
        "\x8b\x77\x04",
    ))

    def setup(self):
        self.insns = list(disasm(self.streams, 0x1000))

    def test_insns(self):
        insn = self.insns[0]
        assert insn.mnem == "mov"
        assert insn.op1 == "esi"
        assert insn.op1 != "ebp"
        # One of the listed registers.
        assert insn.op1 == ("ebp", "esi")

    def test_equal(self):
        assert disasm("hAAAA", 0)[0].mnem == "push"
        assert disasm("hAAAA", 0)[0].op1.value == 0x41414141
        assert disasm("hAAAA", 0) == disasm("hAAAA", 0)
