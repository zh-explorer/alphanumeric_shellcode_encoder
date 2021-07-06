from encoder import util
import typing

import pwn


class Encoder(object):
    def __init__(self, shellcode, base_reg: str, offset: int = 0):
        self.base_reg = base_reg
        self.offset = offset
        self.shellcode = shellcode

    def data_scan(self):
        need_enc = []
        shellcode = bytearray(self.shellcode)
        i = 0
        shellcode_length = len(shellcode)
        while i < shellcode_length:
            if shellcode[i] not in util.alphanum_pool:
                need_enc.append(i)
            i += 1
        return need_enc

    def split_enc_idx(self):
        need_enc = self.data_scan()
        enc_blocks = []

        while len(need_enc) != 0:
            max_size = 0
            max_offset = 0
            first_idx = need_enc[0]
            base_offset = first_idx - 0x7a
            while base_offset <= first_idx - 0x30:
                point = 0
                for idx in need_enc:
                    off = idx - base_offset
                    if 0x30 <= off <= 0x39 or 0x41 <= off <= 0x5a or 0x61 <= off <= 0x7a:
                        point += 1

                if point > max_size:
                    max_size = point
                    max_offset = base_offset
                base_offset += 1

            i = 0
            enc_block = []
            while i < len(need_enc):
                off = need_enc[i] - max_offset
                if 0x30 <= off <= 0x39 or 0x41 <= off <= 0x5a or 0x61 <= off <= 0xff:
                    enc_block.append(off)
                    need_enc.pop(i)
                else:
                    i += 1

            enc_blocks.append((max_offset, enc_block))
        return enc_blocks

    @staticmethod
    def find_max_match(data: typing.List[int]) -> dict:
        xor_data_map = {}

        while len(data) != 0:
            max_point = 0
            max_data = 0

            for i in range(0x100):
                point = 0
                for d in data:
                    if d ^ i in util.alphanum_pool:
                        point += 1

                if point > max_point:
                    max_point = point
                    max_data = i

            i = 0
            while i < len(data):
                if data[i] ^ max_data in util.alphanum_pool:
                    xor_data_map[data[i]] = max_data
                    data.pop(i)
                else:
                    i += 1
        return xor_data_map
