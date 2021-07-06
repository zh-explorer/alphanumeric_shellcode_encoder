import pwn
from encoder import Encoder

if __name__ == "__main__":
    sh = pwn.asm(pwn.shellcraft.amd64.linux.sh())
    e = Encoder(shellcode=sh, base_reg="rax", offset=0)
    d = e.split_enc_idx()
    base, offs = d[0]
    data = [sh[base + off] for off in offs]
    print(offs)
    d2 = e.find_max_match(data)
    print(d2)
