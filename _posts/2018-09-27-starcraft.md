---
title: C++ Reversing Basic for Pwnable
date: 2018-09-27 01:19:53
categories:
- C++ Exploit
tags:
- C++ Reversing
---





pwnable.kr starcraft 문제 풀다가 정리

https://alschwalm.com/blog/static/

자세한 사항은 위 링크에 엄청 자세히 설명되어 있다. 역시 영어문서들이 많다.

C랑 가장 다른 점은 vptr이라는 vtable 포인터를 가진다는 점. 컴파일러가 추가해준다.



## Inheritance

```c
Unit -> Terran -> Marine (0x128)
Unit -> Terran -> Firebat (0x128)
Unit -> Terran -> Ghost (0x130)
Unit -> Protoss -> Zealot (0x138)
Unit -> Protoss -> Dragon (0x130)
Unit -> Protoss -> Templar (0x140)
Unit -> Protoss -> Arcon (0x138)
Unit -> Zerg -> Zergling (0x130)
Unit -> Zerg -> Hydralisk (0x130)
Unit -> Zerg -> Ultralisk (0x130)
```

대강 상속 관계가 이렇게 되는데 하나만 예로 들면



```c
struct Unit{
  unit_vtable unit_v;
  unit_mem;
};

struct unit_mem{
    __int32 flag;
    __int32 hp;
    __int32 weapon;
    __int32 armor;
    char unit_name[264];
}

struct unit_vtable{
  char (__fastcall *input_unit)(__int64);
  __int64 (__fastcall *show_unit)(_DWORD *);
  __int64 (__fastcall *attack_unit)(__int64, __int64);
  signed __int64 (__fastcall *select_cheat)(__int64, __int64);
};
```

일단 Unit 구조체를 이렇게 설정해 주었다. 

IDA에서 오버라이딩 함수 설정하는 법은 (물어보기론) 없다고 하니 나의 한계...ㅎ 비슷하면 됐지뭐



```c
struct protoss_vtable{
  unit_vtable unit_v;
};

struct Templar{
  templar_vtable *vtable;
  unit_mem;
  __int64 nop;
  __int64 exit;
  __int64 shield;
  Arcon *arcon;
};

struct templar_vtable{
  protoss_vtable protoss_v;
  void (__fastcall *nop0)();
  void (__fastcall *nop1)();
  void (__fastcall *nop2)();
  void (__fastcall *nop3)();
  __int64 (__fastcall *make_arcon)(__int64);
  __int64 (__fastcall *no_energy)();
  __int64 (__fastcall *no_energy2)();
};

struct Arcon{
  templar_vtable *vtable;
  unit_mem;
  __int64 nop;
  __int64 exit;
  __int64 shield;
};

struct arcon_vtable{
  protoss_vtable protoss_v;
};

```

~~int32인데 귀찮아서 int64로 설정한 변수가 좀 된다...ㅎ protoss 구조체도 다시 설정해줘야 하는데 안함..~~

상속하면 상속한 vtable과 변수가 메모리의 더 윗부분에 있어서 저런식으로 설정해주었다. 

arcon은 templar를 상속하진 않는데 templar 에 의해 생긴다.



취약점 찾았으니 익스하러 가야지
