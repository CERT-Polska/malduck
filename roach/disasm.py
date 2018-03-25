# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import capstone.x86
import collections

Memory = collections.namedtuple(
    "Memory", ("size", "base", "scale", "index", "disp")
)

class Operand(object):
    regs = {}
    sizes = {
        1: "byte", 2: "word", 4: "dword", 8: "qword",
    }

    # Index the available x86 registers.
    for _ in dir(capstone.x86):
        if _.startswith("X86_REG_"):
            regs[getattr(capstone.x86, _)] = _.split("_")[2].lower()

    def __init__(self, op):
        self.op = op

    @property
    def is_imm(self):
        return self.op.type == capstone.x86.X86_OP_IMM

    @property
    def is_reg(self):
        return self.op.type == capstone.x86.X86_OP_REG

    @property
    def is_mem(self):
        return self.op.type == capstone.x86.X86_OP_MEM

    @property
    def value(self):
        if self.is_imm:
            return self.op.value.imm
        # TODO Improved memory operand support.
        if self.is_mem:
            return self.op.value.mem.disp
        if self.is_reg:
            return self.regs[self.op.reg]

    @property
    def reg(self):
        if self.is_mem and self.op.value.mem.base:
            return self.regs[self.op.value.mem.base]
        if self.is_reg:
            return self.regs[self.op.reg]
        # TODO Improved memory operand support.

    @property
    def mem(self):
        mem = self.op.value.mem
        if mem.base:
            base = self.regs[mem.base]
        else:
            base = None
        if mem.index:
            index, scale = self.regs[mem.index], mem.scale
        else:
            index, scale = None, None
        return Memory(self.sizes[self.op.size], base, scale, index, mem.disp)

    def __cmp__(self, other):
        if isinstance(other, Operand):
            # We must return 0 on success. TODO Memory operand support.
            return self.op.type != other.op.type or self.value != other.value

        if self.is_imm:
            return self.value != other

        if isinstance(other, basestring):
            other = other,
        if self.is_reg and self.reg in other:
            return 0
        if self.is_mem and self.reg in other:
            return 0
        return -1

    def __str__(self):
        if self.is_imm:
            # TODO x86_64 support.
            return "0x%08x" % (self.value % 2**32)
        if self.is_reg:
            return self.reg
        if self.is_mem:
            s, m = [], self.mem
            if m.base:
                s.append(m.base)
            if m.index:
                s.append("%d*%s" % (m.scale, m.index))
            if m.disp:
                # TODO x86_64 support.
                s.append("0x%08x" % (m.disp % 2**32))
            return "%s [%s]" % (m.size, "+".join(s))

class Instruction(object):
    def __init__(self, mnem=None, op1=None, op2=None, op3=None, addr=None):
        self.insn = None
        self.mnem = mnem
        self.operands = op1, op2, op3
        self._addr = addr

    def parse(self, insn):
        self.insn = insn
        self.mnem = insn.mnemonic

        operands = []
        for op in insn.operands + [None, None, None]:
            operands.append(Operand(op) if op else None)
        self.operands = operands[0], operands[1], operands[2]

    @staticmethod
    def from_capstone(insn):
        ret = Instruction()
        ret.parse(insn)
        return ret

    @property
    def op1(self):
        return self.operands[0]

    @property
    def op2(self):
        return self.operands[1]

    @property
    def op3(self):
        return self.operands[2]

    @property
    def addr(self):
        return self._addr or self.insn.address

    def __cmp__(self, other):
        if not isinstance(other, Instruction):
            return -1
        if self.mnem != other.mnem or self.addr != other.addr:
            return -1
        if self.operands == other.operands:
            return 0
        return -1

    def __str__(self):
        operands = []
        if self.op1 is not None:
            operands.append(str(self.op1))
        if self.op2 is not None:
            operands.append(str(self.op2))
        if self.op3 is not None:
            operands.append(str(self.op3))
        if operands:
            return "%s %s" % (self.mnem, ", ".join(operands))
        return self.mnem

def disasm(data, addr):
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    ret = []
    for insn in cs.disasm(data, addr):
        ret.append(Instruction.from_capstone(insn))
    return ret
