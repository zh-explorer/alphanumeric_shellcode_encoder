from encoder import util
from functools import cached_property


class Shellcode(object):
    @cached_property
    def asm(self):
        return util.asm(str(self))

    def __len__(self):
        return len(self.asm)

    def code(self):
        raise Exception("do not call virtual class")

    def __str__(self):
        return self.code

    def __add__(self, other):
        return str(self) + str(other)

    def __radd__(self, other):
        return str(other) + str(self)


class Mov(Shellcode):
    stack_mov = """
push {src}
pop {dst}
"""

    stack_mov2 = """
push {src}
push rsp
pop rcx
xor [rcx], {dst}
xor {dst}, [rcx] 
"""
    stack_mov3 = """ 
push {src}
push rsp
pop {tmp}
xor {src}, [{tmp}+0x30]
xor [{tmp}+0x30], {src}
xor [{tmp}+0x30], {dst}
xor {dst}, [{tmp}+0x30]
"""

    def __init__(self, src, dst):
        self.src = src
        self.dst = dst

    @cached_property
    def code(self):
        if self.dst in ("rax", "rcx", "rdx", "r8", "r9", "r10"):
            return self.stack_mov.format(src=self.src, dst=self.dst)
        elif self.dst in ("rdi", "rsi"):
            return self.stack_mov2.format(src=self.src, dst=self.dst)
        elif self.dst in ("rbx", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"):
            if self.src == "rcx":
                tmp = "rdx"
            else:
                tmp = "rcx"
            return self.stack_mov2.format(src=self.src, dst=self.dst, tmp=tmp)
        else:
            raise Exception(f"can't mov to reg {self.dst}")


class Zero(Shellcode):
    clean_rax = """
push 0x30
pop rax
xor al, 0x30
"""
    clean2 = """
push {reg}
push rsp
pop rcx
xor {reg}, [rcx]
"""

    def __init__(self, reg):
        self.clean_reg = reg

    @cached_property
    def code(self):
        if self.clean_reg == "rax":
            return self.clean_rax
        elif self.clean_reg in (
                "rcx", "rdx", "r8", "r9", "r10", "rbx", "r11", "r12", "r13", "r14", "r15", "rsp", "rbp"):
            return self.clean_rax + Mov(src="rax", dst=self.clean_reg)
        elif self.clean_reg in ("rdi", "rsi"):
            return self.clean2.format(reg=self.clean_reg)
        else:
            raise Exception(f"can't clean reg {self.clean_reg}")


class MulReg(Shellcode):
    mul_reg = '''
push {mul1:#x}
push rsp
pop {tmp}
imul {dst}, WORD PTR [{tmp}], {mul2:#x}
'''

    # imul will modify rdi/rsi, this not easy to set
    # so ask to select one
    def __init__(self, mul1: int, mul2: int, dst: str = "di", modify_reg: str = "rax"):
        # keep mul1 the small one
        assert dst in ("di", "si")
        if modify_reg not in ("rcx", "rax", "r8", "r9"):
            raise Exception("the src reg must in rcx, rax, r8, r9")
        self.dst = dst
        self.modify_reg = modify_reg
        self.mul1, self.mul2 = mul1, mul2 if mul1 < mul2 else (mul2, mul1)

        mul2_size = util.num_size(self.mul2)
        mul1_size = util.num_size(self.mul1)
        assert mul1_size <= 2
        assert mul2_size <= 2
        assert util.is_alphanumeric(self.mul1, mul1_size)
        assert util.is_alphanumeric(self.mul2, mul2_size)

        self.mul1 = self.mul1 if mul1_size == 1 else self.mul1 | 0x30300000

    @cached_property
    def code(self):
        return self.mul_reg.format(mul1=self.mul1, mul2=self.mul2, dst=self.dst, tmp=self.modify_reg)

    @staticmethod
    def find_mul(data: int):
        assert util.num_size(data) <= 2
        for i in util.mul_iter():
            if i[0] * i[1] & 0xffff == data:
                return i
        return None


class XorReg(Shellcode):
    xor_reg = '''
push {xor1:#x}
pop rax
xor {reg}, {xor2:#x}
'''
    reg_map = {1: "al", 2: "ax", 4: "eax"}

    def __init__(self, xor1: int, xor2: int):
        xor1_size = util.num_size(xor1)
        xor2_size = util.num_size(xor2)
        assert xor1_size <= 4
        assert xor2_size <= 4
        assert util.is_alphanumeric(xor1, xor1_size)
        assert util.is_alphanumeric(xor2, xor2_size)
        if xor1_size == xor2_size == 2:
            xor1 = xor1 | 0x30300000
            xor2 = xor2 | 0x30300000
        elif xor1_size == 2:
            xor1, xor2 = xor2, xor1

        self.xor1 = xor1
        self.xor2 = xor2

    @cached_property
    def code(self):
        return self.xor_reg.format(xor1=self.xor1, xor2=self.xor2, reg=self.reg_map[util.num_size(self.xor2)])

    @staticmethod
    def find_xor(data: int):
        data_size = util.num_size(data)
        assert data_size <= 4

        if data_size == 1:
            return util.xor_table[data]

        if data_size == 2:
            data_array = util.p16(data)
            if data_array[1] in util.alphanum_pool:
                _, n = util.xor_table[data_array[0]]
                return data ^ n, n
            else:
                n = util.u16(bytes([util.xor_table[i][0] for i in data_array]))
                return n, n ^ data

        if data_size == 4:
            data_array = util.p32(data)
            if data_array[2] in util.alphanum_pool and data_array[3] in util.alphanum_pool:
                if data_array[1] in util.alphanum_pool:
                    _, n = util.xor_table[data_array[0]]
                    return data ^ n, n
                else:
                    n = util.u16(bytes([util.xor_table[i][0] for i in data_array[:2]]))
                    return data ^ n, n
            else:
                n = util.u32(bytes([util.xor_table[i][0] for i in data_array]))
                return n, n ^ data


class MulXorReg(Shellcode):
    mul_xor_reg = '''
xor {reg}, {xor:#x}
'''
    reg_map = {1: "al", 2: "ax"}

    def __init__(self, mul1: int, mul2: int, xor: int, modify_reg="di"):
        assert modify_reg in ("di", "si")
        self.mul1 = mul1
        self.mul2 = mul2

        xor_size = util.num_size(xor)
        assert xor_size <= 2
        assert util.is_alphanumeric(xor_size)

        self.xor = xor
        self.modify_reg = modify_reg

    @cached_property
    def code(self):
        code = ''
        code += MulReg(self.mul1, self.mul2, dst=self.modify_reg)
        code += Mov("r" + self.modify_reg, "rax")
        code += self.mul_xor_reg.format(reg=self.reg_map[util.num_size(self.xor)], xor=self.xor)
        return code

    @staticmethod
    def find_mul_xor(data: int):
        assert util.num_size(data) <= 2
        for i in util.mul_iter():
            if util.is_alphanumeric((i[0] * i[1] & 0xffff) ^ data, 2):
                return i[0], i[1], (i[0] * i[1] & 0xffff) ^ data
        return None
