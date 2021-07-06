import pwn
from encoder import Encoder, MulReg

alphanum_pool = b"UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789"

if __name__ == "__main__":
    sh = pwn.asm(pwn.shellcraft.amd64.linux.sh())
    e = Encoder(shellcode=sh, base_reg="rax", offset=0)

    print(MulReg.find_mul(0x0080))