# Copyright (C) 2018 Jurriaan Bremer.
# This file is part of Roach - https://github.com/jbremer/roach.
# See the file 'docs/LICENSE.txt' for copying permission.

import collections
from capstone import CsInsn
from capstone.x86 import X86Op
from typing import Any, List, Optional, Dict, Union, Iterator

__all__ = ["disasm", "insn", "Disassemble", "Instruction", "Operand", "Memory"]

Memory = collections.namedtuple("Memory", ("size", "base", "scale", "index", "disp"))


class Operand:
    """
    Operand object for single :class:`Instruction`
    """

    # These are initialized the first time disasm() is called, see also below.
    _x86_op_imm = None
    _x86_op_reg = None
    _x86_op_mem = None
    regs: Dict[str, Union[str, int]] = {}

    sizes = {
        1: "byte",
        2: "word",
        4: "dword",
        8: "qword",
    }

    def __init__(self, op: X86Op, x64: bool) -> None:
        self.op = op
        self.x64 = x64

    @property
    def is_imm(self) -> bool:
        """Is it immediate operand?"""
        return self.op.type == Operand._x86_op_imm

    @property
    def is_reg(self) -> bool:
        """Is it register operand?"""
        return self.op.type == Operand._x86_op_reg

    @property
    def is_mem(self) -> bool:
        """Is it memory operand?"""
        return self.op.type == Operand._x86_op_mem

    @property
    def value(self) -> Union[str, int]:
        """
        Returns operand value or displacement value for memory operands

        :rtype: str or int or None
        """
        if self.is_imm:
            return self.op.value.imm
        elif self.is_mem:
            return self.op.value.mem.disp
        elif self.is_reg:
            return self.regs[self.op.reg]
        else:
            raise Exception("Invalid Operand type")

    @property
    def reg(self) -> Optional[Union[str, int]]:
        """
        Returns register used by operand.

        For memory operands, returns base register or index register if base is not used.
        For immediate operands or displacement-only memory operands returns None.

        :rtype: str
        """
        if self.is_mem:
            reg = self.op.value.mem.base or self.op.value.mem.index
            if reg:
                return self.regs[reg]
        if self.is_reg:
            return self.regs[self.op.reg]
        return None

    @property
    def mem(self) -> Optional[Memory]:
        """
        Returns :class:`Memory` object for memory operands
        """
        if not self.is_mem:
            return None

        mem = self.op.value.mem
        base: Optional[Union[str, int]] = None
        index: Optional[Union[str, int]] = None
        scale: Optional[int] = None

        if mem.base:
            base = self.regs[mem.base]

        if mem.index:
            index, scale = self.regs[mem.index], mem.scale

        return Memory(self.sizes[self.op.size], base, scale, index, mem.disp)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Operand):
            return self.op.type == other.op.type and self.value == other.value
        if self.is_imm:
            return self.value == other
        if isinstance(other, str):
            other = (other,)
        if self.is_reg and self.reg in other:
            return True
        if self.is_mem and self.reg in other:
            return True
        return False

    def __str__(self) -> str:
        if self.is_imm:
            if self.x64:
                return "0x%016x" % (int(self.value) % 2 ** 64)
            else:
                return "0x%08x" % (int(self.value) % 2 ** 32)
        elif self.is_reg:
            return str(self.reg)
        elif self.is_mem:
            s, m = [], self.mem
            if m is None:
                raise Exception("Invalid mem object")
            if m.base:
                s.append(m.base)
            if m.index:
                s.append("%d*%s" % (m.scale, m.index))
            if m.disp:
                s.append("0x%08x" % (m.disp % 2 ** 32))
            return "%s [%s]" % (m.size, "+".join(s))
        else:
            raise Exception("Invalid Operand type")


class Instruction(object):
    """
    Represents single instruction in :class:`Disassemble`

    short: insn

    Properties correspond to the following elements of instruction:

    .. code-block:: python

        00400000  imul    ecx,   edx,   0
        [addr]    [mnem]  [op1], [op2], [op3]

    Usage example:

    .. code-block:: python

        def get_move_value(self, p, hit, *args):
            # find move value of `mov eax, x`
            for ins in p.disasmv(hit, 0x100):
                if ins.mnem == 'mov' and ins.op1.value == 'eax':
                    return ins.op2.value

    .. seealso::

       :py:meth:`malduck.procmem.ProcessMemory.disasmv`
    """

    def __init__(
        self,
        mnem: Optional[str] = None,
        op1: Optional[Operand] = None,
        op2: Optional[Operand] = None,
        op3: Optional[Operand] = None,
        addr: Optional[int] = None,
        x64: bool = False,
    ) -> None:
        self.insn = None
        self.mnem = mnem
        self.operands = op1, op2, op3
        self._addr = addr
        self.x64 = x64

    def parse(self, insn: CsInsn) -> None:
        self.insn = insn
        self.mnem = insn.mnemonic

        operands: List[Optional[Operand]] = []
        for op in insn.operands + [None, None, None]:
            operands.append(Operand(op, self.x64) if op else None)
        self.operands = operands[0], operands[1], operands[2]

    @staticmethod
    def from_capstone(insn: CsInsn, x64: bool = False) -> "Instruction":
        ret = Instruction()
        ret.x64 = x64
        ret.parse(insn)
        return ret

    @property
    def op1(self) -> Optional[Operand]:
        """First operand"""
        return self.operands[0]

    @property
    def op2(self) -> Optional[Operand]:
        """Second operand"""
        return self.operands[1]

    @property
    def op3(self) -> Optional[Operand]:
        """Third operand"""
        return self.operands[2]

    @property
    def addr(self) -> Optional[int]:
        """Instruction address"""
        if self._addr:
            return self._addr
        if self.insn is not None:
            return self.insn.address
        return None

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Instruction):
            return False
        if self.mnem != other.mnem or self.addr != other.addr:
            return False
        if self.operands == other.operands:
            return True
        return False

    def __str__(self) -> str:
        operands = []
        if self.op1 is not None:
            operands.append(str(self.op1))
        if self.op2 is not None:
            operands.append(str(self.op2))
        if self.op3 is not None:
            operands.append(str(self.op3))
        if operands:
            return "%s %s" % (self.mnem, ", ".join(operands))
        return self.mnem or "<invalid mnem>"


class Disassemble:
    def __init__(self) -> None:
        import capstone.x86

        Operand._x86_op_imm = capstone.x86.X86_OP_IMM
        Operand._x86_op_reg = capstone.x86.X86_OP_REG
        Operand._x86_op_mem = capstone.x86.X86_OP_MEM

        # Index the available x86 registers.
        for reg in dir(capstone.x86):
            if not reg.startswith("X86_REG_"):
                continue
            Operand.regs[getattr(capstone.x86, reg)] = reg.split("_")[2].lower()

    def disassemble(
        self, data: bytes, addr: int, x64: bool = False, count: int = 0
    ) -> Iterator[Instruction]:
        """
        Disassembles data from specific address

        .. versionchanged :: 4.0.0

            Returns iterator instead of list of instructions, accepts maximum
            number of instructions to disassemble

        short: disasm

        :param data: Block of data to disasseble
        :type data: bytes
        :param addr: Virtual address of data
        :type addr: int
        :param x64: Disassemble in x86-64 mode?
        :type x64: bool (default=False)
        :param count: Number of instructions to disassemble
        :type count: int (default=0)
        :return: Returns iterator of instructions
        :rtype: Iterator[:class:`Instruction`]
        """
        import capstone

        cs = capstone.Cs(
            capstone.CS_ARCH_X86, capstone.CS_MODE_64 if x64 else capstone.CS_MODE_32
        )
        cs.detail = True
        for insn in cs.disasm(data, addr, count):
            yield Instruction.from_capstone(insn, x64=x64)

    __call__ = disassemble


disasm = Disassemble()
insn = Instruction
