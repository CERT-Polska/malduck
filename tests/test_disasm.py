# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

from malduck import disasm


class TestDisasm(object):
    streams = b"".join((
        # mov esi, [edi+4]
        b"\x8b\x77\x04",
        # mov eax, [ebx+4*ecx+4242]
        b"\x8b\x84\x8b\x92\x10\x00\x00",
        # mov al, byte [1333337]
        b"\xa0\x59\x58\x14\x00",
        # mov eax, byte [1333337]
        b"\xa1\x59\x58\x14\x00",
        # push 0x41414141
        b"\x68\x41\x41\x41\x41",
        # call $+5
        b"\xe8\x00\x00\x00\x00",
        # movxz eax, byte [0x400000]
        b"\x0f\xb6\x05\x00\x00\x04\x00",
    ))

    def setup(self):
        self.insns = list(disasm(self.streams, 0x1000))

    def test_insns(self):
        insn1 = self.insns[0]
        assert insn1.mnem == "mov"
        assert insn1.op1 == "esi"
        assert insn1.op1 != "ebp"
        # One of the listed registers.
        assert insn1.op1 == ("ebp", "esi")
        assert insn1.op2 == ("dword", "edi", None, None, 4)
        assert str(insn1) == "mov esi, dword [edi+0x00000004]"

        insn2 = self.insns[1]
        assert insn2.op2.mem == ("dword", "ebx", 4, "ecx", 4242)
        assert str(insn2) == "mov eax, dword [ebx+4*ecx+0x00001092]"

        insn3 = self.insns[2]
        assert insn3.op1 == "al"
        assert insn3.op2.mem == ("byte", None, None, None, 1333337)

        insn4 = self.insns[3]
        assert insn4.op1 == "eax"
        assert insn4.op2.mem == ("dword", None, None, None, 1333337)
        assert str(insn4) == "mov eax, dword [0x00145859]"

        insn5 = self.insns[4]
        assert insn5.op1 == 0x41414141
        assert str(insn5) == "push 0x41414141"

        insn6 = self.insns[5]
        assert insn6.op1.value == insn6.addr + 5

        insn7 = self.insns[6]
        assert insn7.op2.reg is None
        assert insn7.op2 == (None, None, None, 0x400000)

    def test_equal(self):
        assert next(disasm(b"hAAAA", 0)).mnem == "push"
        assert next(disasm(b"hAAAA", 0)).op1.value == 0x41414141
        assert list(disasm(b"hAAAA", 0)) == list(disasm(b"hAAAA", 0))


class TestDisasm64bit(object):
    streams = b"".join((
        # inc rax
        b"\x48\xff\xc0",
        # mov eax, [rip+0x12345678]
        b"\x8b\x05\x78\x56\x34\x12"
        # mov rsi, [edi+4]
        b"\x67\x48\x8b\x77\x04",
        # mov rax, [rbx+4*rcx+4242]
        b"\x48\x8b\x84\x8b\x92\x10\x00\x00",
        # mov al, byte [1333337]
        b"\x8a\x04\x25\x59\x58\x14\x00",
        # mov eax, dword [1333337]
        b"\x8b\x04\x25\x59\x58\x14\x00",
        # push 0x41414141
        b"\x68\x41\x41\x41\x41",
        # call $+5
        b"\xe8\x00\x00\x00\x00",
        # movzx eax, byte [rip]
        b"\x48\x0f\xb6\x05\x00\x00\x00\x00",
        # lea rax, [rax*4 + 0x333333]
        b"\x48\x8d\x04\x85\x33\x33\x33\x00",
    ))

    def setup(self):
        self.insns = list(disasm(self.streams, 0x1000, x64=True))

    def test_insns(self):
        # inc rax
        insn1 = self.insns[0]
        assert insn1.mnem == "inc"
        assert insn1.op1 == "rax"
        assert insn1.op1 != "ebp"

        # mov eax, [rip+0x12345678]
        insn2 = self.insns[1]
        assert insn2.op2.mem == ("dword", "rip", None, None, 0x12345678)
        assert str(insn2) == "mov eax, dword [rip+0x12345678]"

        # mov rsi, [edi+4]
        insn3 = self.insns[2]
        assert insn3.op1 == "rsi"
        assert insn3.op2.mem == ("qword", "edi", None, None, 4)
        assert str(insn3) == "mov rsi, qword [edi+0x00000004]"

        # mov rax, [rbx+4*rcx+4242]
        insn4 = self.insns[3]
        assert insn4.op1 == "rax"
        assert insn4.op2.mem == ("qword", "rbx", 4, "rcx", 4242)
        assert str(insn4) == "mov rax, qword [rbx+4*rcx+0x00001092]"

        # mov al, byte [1333337]
        insn5 = self.insns[4]
        assert insn5.op1 == "al"
        assert insn5.op2.mem == ("byte", None, None, None, 1333337)

        # mov eax, dword [1333337]
        insn6 = self.insns[5]
        assert insn6.op1 == "eax"
        assert insn6.op2.mem == ("dword", None, None, None, 1333337)
        assert str(insn6) == "mov eax, dword [0x00145859]"

        # push 0x41414141
        insn7 = self.insns[6]
        assert insn7.op1 == 0x41414141
        assert str(insn7) == "push 0x0000000041414141"

        # call $+5
        insn8 = self.insns[7]
        assert insn8.mnem == "call"
        assert insn8.op1.value == insn8.addr + 5

        # movzx eax, byte [rip]
        insn9 = self.insns[8]
        assert insn9.op2.reg == "rip"
        assert insn9.op2.mem == ("byte", "rip", None, None, 0)

        # lea rax, [rax*4 + 0x333333]
        insn10 = self.insns[9]
        assert insn10.op1.reg == "rax"
        assert insn10.op2.reg == "rax"

    def test_equal(self):
        assert next(disasm(b"hAAAA", 0)).mnem == "push"
        assert next(disasm(b"hAAAA", 0)).op1.value == 0x41414141
        assert list(disasm(b"hAAAA", 0)) == list(disasm(b"hAAAA", 0))
        assert list(disasm(b"hAAAA", 0)) != list(disasm(b"hAAAB", 0))
