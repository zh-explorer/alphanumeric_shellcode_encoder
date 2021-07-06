from encoder import util
from .shellcode_template import Shellcode, FastNumGen
import typing

import pwn

IdxList = typing.List[int]
EncBlock = typing.Tuple[int, IdxList]


class Encoder(object):
    def __init__(self, shellcode, base_reg: str, offset: int = 0):
        self.base_reg = base_reg
        self.offset = offset
        self.shellcode = shellcode
        self.origin_shellcode = shellcode

    def one_byte_xor_strategy1(self, enc_block: EncBlock) -> typing.Tuple[bytearray, EncBlock, Shellcode, int]:
        enc_shellcode = bytearray(self.shellcode)
        off = enc_block[0]
        idx_list = enc_block[1]
        enc_bytes = [self.shellcode[off + i] for i in idx_list]
        xor_map = self.find_max_match(enc_bytes)

        idx_map: typing.Dict[int, typing.List[int]] = {}

        for i in idx_list:
            xor_data = xor_map[self.shellcode[off + i]]
            if xor_data in idx_map:
                idx_map[xor_data].append(i)
            else:
                idx_map[xor_data] = [i]

        xor_list = [(key, value) for key, value in idx_map.items()]
        xor_list.sort(key=lambda x: len(x[1]))

        # select the max two
        low_data = xor_list[0][0]
        low_enc_idx = xor_list[0][1]
        if len(xor_list) > 1:
            high_data = xor_list[1][0]
            high_enc_idx = xor_list[1][1]
        else:
            high_data = 0
            high_enc_idx = []

        enc_bytes_count = len(low_enc_idx) + len(high_enc_idx)

        # first gen data
        data = low_data + (high_data << 16)
        shellcode = ''
        shellcode += FastNumGen(data=data)
        for idx in low_enc_idx:
            shellcode += "xor [rdx+rsi+{idx:#x}], al".format(idx=idx)
            idx_list.remove(idx)
            enc_shellcode ^= low_data
        for idx in high_enc_idx:
            shellcode += "xor [rdx+rsi+{idx:#x}], ah".format(idx=idx)
            idx_list.remove(idx)
            enc_shellcode ^= high_data

        shellcode_len = util.asm(shellcode)
        score = shellcode_len / enc_bytes_count
        return enc_shellcode, (off, idx_list), shellcode_len, score

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

    def split_enc_idx(self) -> typing.List[typing.Tuple[int, IdxList]]:
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
