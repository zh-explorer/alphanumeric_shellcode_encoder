encode a amd64 shellcode to alphanumeric shellcode

# usage
```python
if __name__ == '__main__':
    sh = pwn.asm(pwn.shellcraft.amd64.linux.sh())
    print(encode(sh, base_reg = "rax", offset = 0))
```

1. the base_reg is the register point to shellcode.

2. the offset if the offset between baes_reg and the start of shellcode
 
3. offset can be negative or any other number's, but a too large number will increase the length of shellcode

4. to use this encoder, the rsp must point to stack or other r/w memory that not overlap shellcode itself 
