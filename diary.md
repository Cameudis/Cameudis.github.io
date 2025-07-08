---
layout: page
title: Y²のDiary
permalink: /diary/
---

碎碎念、摸鱼与拾贝日志。

### 2025-7-3
1. CVE-2025-32462: sudo --host 提权。[博客原文](https://www.stratascale.com/vulnerability-alert-CVE-2025-32462-sudo-host)
- `sudo` 的 man 里有介绍 `--host` 参数的用途，基本上就是在使用 `-l` 查询当前用户的权限时，可以加一个 `--host xxx.com` 来查询在另一个 host 上的权限。没错，`sudo` 是支持一个配置文件给多个主机的用户配置权限的。（我终于理解了为什么我机器上的 `sudo` 配置里，第二个字段都是神秘的ALL，原来是“在所有主机上”的意思）
- 然而，`sudo` 的 `--help` 中却说 `--host` 可以和执行命令一起用，然后大家神奇地发现，这个居然能允许用户以“指定host”上自己的权限，在“当前host”上执行命令。这个漏洞完全让 `sudo` 的这套跨host功能变得完全没用了，因为用户现在可以以他拥有的最高权限在任意服务器上执行指令。
2. CVE-2025-32463：sudo 在不加检查地 chroot 后，触发了 Name Service Switch（NSS）操作，导致攻击者可以构造恶意的 NSS 配置文件（/etc/nsswitch.conf）达成提权。[博客原文](https://www.stratascale.com/vulnerability-alert-CVE-2025-32463-sudo-chroot)
-  `chroot` 实在是太危险了，尤其不能允许用户随意chroot到他具有任意写权限的目录下！利用时和配置文件劫持打组合拳有奇效。
- 怀疑这些人每天就关注 `sudo` 这种有 SUID 的 Binary 更新了什么新功能参数，然后研究它们有什么问题。
3. 学习了 [OpenC910](https://github.com/XUANTIE-RV/openc910/) 中的 AXI 总线接口，[ARM IHI0022 手册](https://developer.arm.com/documentation/ihi0022/latest/)写得非常通俗易懂。
4. 大致了解了下 Android 上的 BootLoader 锁和 ARMv8 安全启动的关系：
- BootLoader 锁（OEM锁）是厂商为了防止用户刷入非自家的镜像，在 recovery 模式程序中实现的一个“功能”。
- ARMv8 安全启动（Secure Boot）是一套标准，力求实现标准化的、基于密码学的信任链。ARM 官方提供了 [Trusted Firmware-A (TF-A)](https://www.trustedfirmware.org/projects/tf-a/) 作为 ARMv8-A Secure Boot 的参考实现。（在 ARMv7 中不存在标准化的 Secure Boot，通常由厂商自行实现启动信任链，但也可以使用 TF-A 作为启动软件。）（在 ARMv8-M 中使用的是 Trusted Firmware-M）
1. 搬到了张江，开启暑假打工生涯。住宿是老师在贝壳上租的，叫了保洁来帮忙清理，把屋子里的各种发霉的地方都清掉了。不得不说，虽然在房东和租客之间加上中介服务这一层抽象层会带来额外开销（服务费），但确实能给租客省下不少事。

### 2025-7-4   
1. 大致了解了下 Android 如何在 Linux Kernel 的基础上限制越狱：
- Android 4.3 版本开始，限制了 `setgid` / `setuid` 系统调用，并启用了 SELinux。SELinux 是内核中的Linux Security Module (LSM) 框架的组成部分。LSM 在各种系统调用的函数入口处添加了安全钩子（security hooks），检查 SELinux 的策略（安全规则）来判断当前用户态程序是否具有合法权限。
- SELinux 的粒度比 Linux 原有的权限系统（用户、用户组）细很多，可以对同一个用户的不同进程做不同的权限设置，甚至可以对 root 用户（uid=0，gid=0）的进程做限制。这是通过在策略中将进程划分为不同的 type 完成的，比如在安卓上定义了以下这些 Type：[app.te - platform/external/sepolicy - Git at Google](https://android.googlesource.com/platform/external/sepolicy/+/jb-mr1-dev/app.te)。
- 在 Android 中，即使已经拿到了 root 用户权限，由于安卓自带 SELinux 策略的设置，也是残血的 root 用户。安卓源码中自带的 SELinux 策略会在编译成内核可加载的二进制格式后，集成到内核的 boot image 中或嵌入到 ramdisk 中，受到安全启动链的保护。Android 启动时，init 进程将查找并加载策略文件。
- 因此，Magisk 这种 ROOT 工具会在启动时对 SELinux 的策略进行 patch，见 [awsome-magisk/重读Magisk内部实现细节.md at main · tcc0lin/awsome-magisk · GitHub](https://github.com/tcc0lin/awsome-magisk/blob/main/%E9%87%8D%E8%AF%BBMagisk%E5%86%85%E9%83%A8%E5%AE%9E%E7%8E%B0%E7%BB%86%E8%8A%82.md)。
1. 调整了博客的字体、字体大小和行距。字体设置参考了[博客字体设置方案 \| Daniel’s Blog](https://moecm.com/the-blog-font-setting-scheme/)；字体大小设置为 15 px，行距设置为 2，更适合中文排版了（方块字比较密，行距应该设置得比英文大一些）。
2. 看了[发现外星生命痕迹，确定度99.7%！——等等，这是怎么算出来的？](https://mp.weixin.qq.com/s/Ku9v3mf76TpxQW2Y1rj2LQ)，一篇关于统计学和概率的科普文。即使一项研究的确定度非常高，达到了5σ的黄金标准（置信度约为99.99994%），也有可能是受到干扰因素影响导致的结果，可能会被推翻。
3. 把 OpenC910 的仿真跑通了，并且安装了 vcs、verdi、scl 工具，学会了用 verdi 看 vcs 仿真的波形。
- Vcs、Verdi 安装和使用参考 [ubuntu 18.04 安装 vcs、verdi 2018](https://blog.csdn.net/qq_24287711/article/details/130017583)、[记一次VCS报错：/usr/bin/ld: undefined reference to `pthread_yield`](https://blog.csdn.net/m0_50662459/article/details/130565406)。但不得不说前面那个教程写得特么有点太烂了。验证服务器会跑在 27000 端口，需要确保这个端口可以访问。这篇教程写了如何配置防火墙规则开放 27000 端口，然后说“firewall 没有安装的需要用 apt 进行安装”——我都没有安装防火墙当然不用开放 27000 端口啊！

### 2025-7-5
1. 在外面演出，上午随便找了家店洗吹，下午彩排和演出，晚上聚餐。

### 2025-7-6
1. CVE-2025-33053：一个恶意的 `.url` 文件（Windows 上的 InternetShortcut）可以通过指定 `WorkingDirectory` 字段为一个远程的文件服务器路径，使应用加载恶意的 dll 甚至 exe。
   - 这个漏洞和 CVE-2025-32463 非常相似，我觉得都可以称为“路径劫持”类漏洞，不过它们的根因不太一样。
   - 在 Linux 上许多系统框架都会根据绝对路径找配置文件，把这些路径直接硬编码到代码中，并且在 `man` 手册中进行说明；攻击者可以 `chroot` 就意味着他可以控制根目录位置，进而控制这些配置文件。
   - 而在 Windows 上，这里利用的是系统查找可执行文件/动态链接库的顺序；攻击者可以控制工作目录就意味着他可以劫持 DLL、甚至劫持可执行文件（也就是这个 CVE 的利用手法，攻击者的 `.url` 文件中直接指向的 `iediagcmd.exe` 会使用系统 API 调用 `route.exe print`，触发远程服务器上的恶意 `route.exe` 调用）。
   - 关于 DLL 劫持网上已经有很多写得非常好的资料了，像 CVE-2025-33053 这样的漏洞感觉已经研究地非常充分了：[DLL劫持漏洞 \| Yang Hao's blog](https://yanghaoi.github.io/2021/11/18/dll-jie-chi-lou-dong/)、[Automating DLL Hijack Discovery. A dive into Windows DLLs, DLL… \| by Justin Bui \| Posts By SpecterOps Team Members](https://posts.specterops.io/automating-dll-hijack-discovery-81c4295904b0)。
1. 看[有知有行投资第一课](https://youzhiyouxing.cn/curriculum/lessons)。
- 钱本身不是财富，货币本质上是用来交换的中间物，由于其通用性也常被大家伙当作衡量财富的标准。如果以货币量衡量，现代人类社会的财富一直在不断地增长，然而不能仅仅凭借货币量来衡量人类社会的财富——货币背后的资源、产品、服务才是最重要的。
- 如果我们以资源、产品、服务这些实际价值来衡量的话，大多数人也会认同现代（包括近现代）是一个所谓财富大跃迁的时代，科学的进步、工业化、信息化大大增长了财富增加的速度。在这种背景下，我等一般人能够通过投资来赚钱才成为一种可能的事。否则就是经济学家的那个笑话了：看到地上有十块钱不捡，因为如果有赚钱的机会话，前人一定已经赚过了。在总量不变的情况下有赚必有亏，而亏的大概率是我等没什么知识的普通人。当然，也有人认为现代财富增长的速度并没有那么快——许多我们以为的价值可能只不过是吹出来的泡沫。
- 不管怎么说，在创造财富的过程中，很大一部分的财富是以公司（具体来说，现代股份制公司）的形式生产和创造出来的。从荷兰的东印度公司（1602 年）开始，公司就开始通过售卖自己的股权来筹集资金，而股东则可以享受公司的分红。一个公司的股价是随着市场波动变化的——投资者既按照自己对公司价值的预期（即公司给他回报的分红多少）而购入他的股票，也可以根据市场对公司价值的预期而选择购入或抛出股票（即赚其他投资人的钱）。
1. 下午去了前滩太古里的茑屋书店。太古里的装修和建筑真是太漂亮了，感觉像来到了东京。茑屋书店人很多，很大一片地方，书的质量属于还不错，买了本特德姜的小说集。
2. 晚上六星小聚，四个 pwn 猫齐聚一堂（还有一个外包手），讨论二进制的灰暗未来。绕着徐家汇散步散了挺久的，算是一起锻炼身体了。

### 2025-7-7
1. 看完了《摇滚乃是淑女的爱好》，看到最后主角乐队薄纱了现充乐队，用执着的东西打败了浅薄的东西，还是挺感动的。
2. 学习了 Linux 的 Buddy 内存管理机制，现在终于看得懂了。
- 最好的资料是官方文档：[Memory Management — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/mm/index.html)，我也对照着 [Rubicon: Precise Microarchitectural Attacks with Page-Granular Massaging 这篇论文](https://comsec-files.ethz.ch/papers/rubicon_eurosp25.pdf) 以及 [CVE-2022-27666: Exploit esp6 modules in Linux kernel 这篇博客](https://etenal.me/archives/1825)学习。
3. 继续学习 OpenC910 中的 smart_run SoC，基本搞懂了总线互联的拓扑，原来 SRAM 才是主角。
4. 更新了博客的[友链界面](/links/)，现在可以自动parse YAML格式的数据变成友链卡片了。

### 2025-7-8
1. 学习了 Single Error Correcting 和 Double Error Detecting Code 的原理，当年的图灵奖，太天才了。
2. 继续看论文《Rubicon: Precise Microarchitectural Attacks with Page-Granular Massaging》。
3. 参考 [Linux Kernel Exploitation - Setup | r1ru](https://r1ru.github.io/posts/0/) 配好了简单的 Linux 内核调试环境。下一步准备把 Buddy System 里的一些关键的结构体和函数搞清楚，然后来自己复现下 Rubicon。
- 我在 busybox 的编译选项里打开了 telnetd、tar 支持 gz。我用 musl-gcc 编译好静态的程序之后，用 [PWN Cheatsheet - HackMD](https://hackmd.io/@cameudis/rJuGtPyh6#Qemu) 这里的脚本把它压缩成 `.tar.gz` 后用 `base64` 慢慢发上去，然后解码再解压成原来的程序。搞这么复杂都是因为 busybox 不带 sshd（不能 scp 了），且我的 `qemu-system-x86_64` 是系统包管理器安装的，不支持虚拟文件系统（不能直接共享目录了），有点蠢。
- 内核启动选项中（`qemu -append` 后面跟着的就是内核启动选项）记得要加一个 `nokaslr`，不然 `gdb` 加载了符号文件之后也还是会一脸懵逼的。
- 在 qemu 里可以用户态和内核态使用同一个 gdb 实例来调试，只需要把编译好的用户态文件的符号告诉 gdb 就可以下断点调试用户程序了。具体步骤是首先需要提前在用户态文件的编译选项中加上 `-fno-pie` 以禁用 ASLR，然后 `objdump -S` 看看代码段（`.text`）的加载位置（比如 `0x401020`），最后在 gdb 当中使用 `add-symbole-file <elf> -s .text <addr>` 加载符号信息。不知道为什么 gdb 好像并不能直接正确识别 ELF 文件的地址，所以才需要按照这样手动加载一个段进去。如果需要加载其他段的话直接在后面 append 就可以，比如 `-s .text 0x401020 -s .init 0x401000`。