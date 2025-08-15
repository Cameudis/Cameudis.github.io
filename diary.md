---
layout: post
title: Y²のDiary
permalink: /diary/
toc_max_level: 2
---

碎碎念、摸鱼与拾贝日志。

## 2025-7

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

### 2025-7-9
1. 给博客加了简单的搜索功能，不过现在还没有支持搜索日记内容。
- 用的是 [Algolia](https://www.algolia.com/) 的服务，需要先注册账号，然后把博客内容上传到自己的数据库中，最后在博客的前端中实现一个搜索框，向 Algolia 后端发送请求。
- 将博客内容上传到服务器可以使用 [GitHub - algolia/jekyll-algolia: Add fast and relevant search to your Jekyll site](https://github.com/algolia/jekyll-algolia) 这个插件（别的静态网页生成框架应该也有类似的插件可以用），虽然已经停止维护了，但 jekyll 本身并不经常大更新所以这个插件现在和未来一段时间应该还是可用的。插件的官方文档和教程已经挂了，可以访问 [Algolia for Jekyll \| Add fast and relevant search to your Jekyll site](https://deepakmahakale.com/jekyll-algolia/) 这个网友自己搭的镜像站阅读。
- 集成到前端中还是比较繁琐的，我拜托 claude 帮我写了一下，简单用用还是足够的。
1. 继续学习 OpenC 910 中的 smart_run SoC。发现了[玄铁处理器的Linux移植](https://zhuanlan.zhihu.com/p/655723549)这个系列博客，是母校智能体系架构与开源芯片实验室的，实在是太有技术了，目前只看了第一章，后面技术细节太丰富了有机会再看吧。
2. 读了[关于财务自由若干问题的实践与思考 - 纯牛马的救赎](https://mp.weixin.qq.com/s/iM4AGQ5vLYGdf2cfNdwmiQ)，觉得作者对财务自由的理解还是很有启发性的。作者追求的财富自由并不仅仅是财富，而是建立在对自己的了解基础上的、一种自己适合和喜欢的生活状态，或者说是一种逐渐探索志趣，逐渐探索自在愉悦的生活方式。作者关于开源节流两方面的论述也挺有道理的。
3. 基于 [GitHub - allejo/jekyll-toc: A GitHub Pages compatible Table of Contents generator without a plugin or JavaScript :octocat:](https://github.com/allejo/jekyll-toc) 给博客文章加了目录。前端也是靠 Claude 写的，我爱 AI。

### 2025-7-10
1. 看完了《Rubicon》，借助 AI 学习了一点点 Buddy System 的代码。AI 用作解读代码还是不错的👍。
2. 继续看《投资第一课》，思考人生……
3. 今天是生日，白天摸鱼，晚上和大学好哥们一起去金虹桥吃了非常うまい的炸猪排（静冈胜政日式猪排）。

### 2025-7-11
1. 把要设计的加密模块的功能和流程拆分了一下，分出了几个子模块来。似乎设计整个模块也不像想象中的那么难了。
2. 继续看 Buddy System 源码，感觉内核这种项目也不是很恐怖了，毕竟也是人类维护的。网上相关的代码解读还挺多的，比如 [Memory Management \| What is the Utopian World!](https://utopianfuture.github.io/kernel/Memory-Management.html)、[3.2.4 Buddy System(伙伴系统) \| Linux核心概念详解](https://s3.shizhz.me/linux-mm/3.2-wu-li-nei-cun/3.2.4-buddy-system-huo-ban-xi-tong)，不过我感觉在了解了大致的机制以后自己结合 AI 看源码比阅读这些写好的博客要好，理解速度更快，而且可以自己发掘感兴趣的细节。
3. 搭了一个简单的 Folo Webhook to Telegram 服务，可以收集安全新闻和博客推送了。
4. 发现 [《东方幼灵梦》](https://www.bilibili.com/video/BV1r3411j7Qe)和[《东方灵灵梦》](https://www.bilibili.com/video/BV1Hm4y1d7e4)都有人做了高清重置版，看了一集就又眼泪水哒哒滴了😢

### 2025-7-12
1. 学习 Linux 音频软件栈，看到这篇博客讲得还可以（有的地方讲得很浅，在 AI 辅助之下阅读会好一些）：[Making Sense of The Audio Stack On Unix](https://venam.net/blog/unix/2021/02/07/audio-stack.html)。但是还是没有搞懂为什么我的 Thinkpad X1C gen13 Fedora 没办法正常使用耳机，我已经使用了最新的内核和 SoF 固件版本了。
2. 乐队排练，晚上在日月光吃了平成屋，算是还不错吧。

### 2025-7-13
1. 继续研究为什么笔记本 Linux 没办法用耳机，失败。一直以来俺的理想都是理解计算机这个黑盒在背后是如何工作的。现在在以 Linux 为契机学习音频系统的时候，真的有感觉到抽象层的伟大，将无数复杂的细节都隐藏了起来。物理的声卡提供了各种配置寄存器，在固件驱动下，变成 Linux 内核音频模块 ALSA 所提供的抽象的声卡接口。在用户空间，各种声音服务器（PulseAudio、PipeWure）又基于 ALSA 提供的接口，为 Linux 桌面提供了统一管理的功能。应用开发者只需要基于一些接口库，向这些音频服务器发赛音频，就可以简单地完成音频播放的功能。这其中有着一般路人难以想象的工程量，也因此我不得不佩服程序员们合作的力量。但我还是不知道我的耳机为什么不能用，感觉是固件的问题。
2. 昨天和今天一通乱搞把 PulseAudio 搞爆炸了，还好按照[reddit上的教程](https://www.reddit.com/r/pop_os/comments/n82egy/pulseaudio_failed_to_create_sink_input_sink_is/)修好了。Average Linux User...
3. 继续看《工作、消费主义和新穷人》和《中国文化通识》。

### 2025-7-14~15
1. 和溴化锂一起装了台机。
2. 推进项目：把各个模块的输入输出规划了一下。
3. 感冒了，无法干活。

### 2025-7-16
1. 调 Rubicon。
2. 去参加了 RISC-V 中国峰会的一个付费教程（200 元你敢信），了解了一下 CHERI、CHERIoT 以及 scisemi 这家公司基于 CHERIoT 搞的一套软件栈。体验了一下基于他的 [cheriot-rtos](https://github.com/CHERIoT-Platform/cheriot-rtos) 和 SDK 开发 C/C++ 嵌入式应用，其实还挺简单有趣的。希望他们以后能搞出点实际的东西（据说是即将要有实际的 CHERI 核了，支持一些常用的嵌入式接口），不要浪费了我的 200 元。

### 2025-7-17
1. 依然生病中。

### 2025-7-18
1. 在 RISC-V 中国峰会的各个场之间来回窜，把和安全相关的都听了下。目前的 RISC-V 的 TEE 还在推进生态的过程中，标准和技术都还在不断更新，比如 [smmtt](https://github.com/riscv/riscv-smmtt) 还刚刚出了一个新版（指今年二月更新了 v0.3.0）。
- 有人在把 OPTEE 迁移到 RISC-V 上以支持 GP 标准的 TA（SiFive、芯来 Nuclei），有人在基于 CoVE 标准开发 TEE 架构（玄铁），Intel 在将他们的 x86 IoT 场景 hypervisor [ACRN™](https://projectacrn.org/)迁移到 RISC-V CoVE 上（[acrn-riscv](https://github.com/intel/acrn-riscv)）。当然还有知名的 Penglai，可惜时间冲突了没去听夏老师的分享。
- 对于开发者和厂商来说，选项还挺多的；不过对于我们搞安全的来说，部署到什么系统上才是重点，毕竟攻击需要考虑攻击的收益。目前看来，RISC-V 的 TEE 并没有部署到什么现实中的应用上。但是我们可以简单估计一下它们的使用场景，其中嵌入式、健康计算、车控会比较多，其次是 AI、云计算领域。
- 尽管 RISC-V 目前主要推动的是 AI 主题，但我觉得 AI 的攻击面相比传统安全要少得多，TEE 用来保护 AI 目前来看更多还是噱头作用。而在云计算这块，或者说整个桌面和服务器领域，RISC-V 距离赶上 x86 差得不是一星半点，就不提了。下面这张图是今天超睿科技展示的“世界上第一颗桌面级 RISC-V CPU”：![](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202507182219227.png)难道真的要赶上 x86 了吗！在交大 tcloud 实验室的校友对这颗 CPU 做的[评测](https://zhuanlan.zhihu.com/p/1923399170653398232)中提到，UR-DP1000单核性能达到了SPECInt2006 10.4/GHz 和 SPECfp2006 12.0/GHz 的水平，ChatGPT 说这个成绩属于*极高的水平，远远超出大多数普通桌面处理器（即便是许多高端消费者级处理器）*。可惜，主频只有 2.23GHz 的话，乘上去之后还是离现在的 x86 桌面处理器有差距啊！
- 也有厂商在搞安全协处理器（[CryptoManager RT-6xx Root of Trust \| Security IP - Rambus](https://www.rambus.com/security/root-of-trust/rt-6xx/)）把安全攸关的任务交给协处理器完成，类似把矩阵计算交给 NPU 或者 GPU。不过这种架构也有天生的弱点，我们知道“一条链的强度取决于其最为脆弱的一环”，在安全协处理器的场景下，这一环就会变成 CPU 本身以及其与安全协处理器通信的链路。
1. 巴别塔圣歌真好玩。SHENZHEN I/O 太好玩了。

### 2025-7-19
1. 学习 OP-TEE。里面一个很重要的概念是 [Hardware Unique Key](https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html#hardware-unique-key)，OPTEE 的 [Secure storage](https://optee.readthedocs.io/en/latest/architecture/secure_storage.html#secure-storage) 子系统会基于这个硬件密钥派生加密文件用的密钥。这个 HUK 需要是一个固定的值（不然就没法解密之前加密的文件了），并且“in the best case the HUK should never ever be readable directly from software, not even from the secure side”。但和这句英文可能冲突的是，对 OPTEE 进行适配的厂商需要自己实现 `tee_otp_get_hw_unique_key` 函数，允许 OPTEE 与他的硬件交互获取 HUK；按照这句英文的说法，厂商的最佳做法应该是：只允许硬件提供一个密钥派生接口，而不允许任何方式拿到 HUK 本身。总之这是一个重要的 asset，在评估 OPTEE 安全性的时候需要重点考虑。
2. 拜访了浦东图书馆，人流量是期末季的级别。
- 看了两章周国平写的通俗书《尼采：在世纪的转折点上》。之前哲学课助教推荐的书是《导读尼采》，但这本书还是偏专业，是需要去啃的。周国平这本通俗书就很易读，但通俗的缺点就是叽里咕噜好像说了很多，信息量没那么大；但又觉得这对我来说倒是一个优点了。一个人对于哲学的追问是和他的经历与个性难以分开的，虽然我对哲学略有兴趣，但那些问题并不会给我带来痛苦和危机，而只是出于好奇，因此注定是个不入流的半吊子罢了；但总之我还是乐在其中的，所以还是会去读去啃。
- 继续看《工作、消费主义和新穷人》。中国的扶贫是真的花了很多人力物力的，另一方面底层的岗位数量也不少，还没有像书中描述的那样可怕。赢！
- 随便翻了翻《有钱，能买到快乐吗》，作者有个挺反常识的说法，说刚开始工作的年轻人应该偏重于选择高薪而稳定的职业，从年轻时开始积累财富，即使这和梦想冲突。我们通常觉得随着年龄增长，一个人的负担会越来越重，尤其是面临裁员和家庭压力的中年危机。中年危机的实质是需要用每个月的工资去填补老人和小孩的需求，总的来说就是钱的问题。但如果从工作第一年就开始存钱并同时进行长线投资，在复利的效应之下这笔钱或许可以缓解甚至解决中年危机（以及类似的问题）。另外，如果在工作了几年后更了解了自己所适合的职业和行业，也可以比较有底气地选择改变。作者的这个观点源于他自己的经历，或许对于很多情况并不适用，但作为一个比较新奇的想法还是有一些启发价值。
1. 跟随 Dr.604 学习了快速手工扒谱的技术。
2. 和室友聊天，他实习的 leader 是 [Atum](https://atum.li/)。听说 Atum 正在推进三件事：学习投资（这样就不用担心失业）、成为行业大佬（这样就不用担心失业）和强健身体（这样失业了可以回家送外卖）。我非常认同这个想法，希望我也能推进好这几件事！

### 2025-7-20~21
1. 玩 shenzhen I/O，成果见 [【Shenzhen I/O】まにまに（使用汇编语言实现）\_哔哩哔哩\_bilibili](https://www.bilibili.com/video/BV1LWgVz6E4Y)
2. 继续看《The Hardware Hacking Handbook》

### 2025-7-22
1. 又和溴化锂和 LoboQ1ng 和 M1aoo0bin 装了台机。
2. 继续复现 Rubicon（都这么多天了，疑似效率有点太低了），发现 block merge 这一部分作者根本都没在代码里实现... 哥们有点太偷懒了！
3. 读了[安全隔区 - 官方 Apple 支持 (中国)](https://support.apple.com/zh-cn/guide/security/sec59b0b31ff/web)，是《Apple 平台安全保护》的一章。发现基于完整性树的内存完整性保护在现在的苹果设备当中还是非常广泛地部署了的，于是为自己的内存加密项目感到欣慰。有空可以找一些逆向分析苹果设备安全机制的论文看看，有点感兴趣。
4. 学习了 arch 上打软件包的方法，学会把 AUR 上的仓库 clone 下来自己改改安装了。

### 2025-7-23
1. 给 Rubicon 作者发了邮件，发现 block merge 不是没有实现，错怪了 orz。大哥回邮件回得巨快，而且非常详细，弄明白了很多地方。大哥推荐我在真机上复现试试，qemu 里的环境可能差异比较多；还说之前的学生在一周内就复现成功了，鼓励我也试试，给大哥跪了！

### 2025-7-24
1. 推进内存加密课题，感到压力山大。

### 2025-7-25
1. 学习数字设计知识。以前一直看不懂 CMOS 管和逻辑门有什么关系，现在终于有点搞明白了。另外，理解了 FPGA 和 ASIC 的区别：ASIC（Application Specific Integrated Circuit）是专用于某个任务的芯片，而 FPGA 是通用的可编程集成电路。
- 我们通常接触的 CPU 等芯片都是 ASIC，这是因为这些芯片会大量地出售到消费市场中，实现 ASIC 后单个芯片的成本比 FPGA 低；另外也有性能上的考虑，ASIC 可以达到 FPGA 所无法达到的性能。
- 但是，ASIC 的流片设计需要极大的成本，而 FPGA 则不需要。因此，只有在需要大量量产（且 ASIC 量产节省的成本大于 ASIC 引入的额外单次设计成本），或者是需要 FPGA 所无法达到的性能时，才会去考虑 ASIC；否则 FPGA 是足够好的。
- 上周在浦东图书馆看到一本书叫《宇航高可靠 FPGA 设计技巧》，当时想问为什么宇航用的是 FPGA 而不是专门设计的芯片，现在懂为什么了。（因为此类芯片不会大量量产）
1. 向导师要了 Intel CPU 搭配 DDR4 内存条的设备，可以用来复现 Rubicon 和 Blacksmith。

### 2025-7-26
1. 把 [pwn.college](https://pwn.college/) 很久以前卡的一关打通了，依靠 Discord 的帮助。
2. 在 UIUCTF 2025 做了一道逆向：Damaged SoC。
- 题目基于作者自制的流水线 MIPS CPU，给出了一个基于 verilator 的 stripped 二进制文件，用来运行 CPU。所以这是一道 VM 类型的题目（大雾）。内存模块使用 `$readmemh("memory.mem", data_seg)` 加载了十六进制文件作为内存数据，题目也给出了这个文件作为附件。
- 将 `memory.mem` 转换成二进制文件后，就可以用 IDA 加载了，但需要手动选择一下 MIPS Little 指令集，并手动让 IDA 识别指令和函数。逆向文件可知基本上就是在验证一个内存中自带的密码字符串是否合法。
- 由于里面一大堆 syscall 我逆不出来到底是怎么 handle 的，我借助动调来理解程序的执行顺序和验证过程。我使用硬件断点 `rwatch` 检测哪里读取了 flag，并在这时在整个内存空间搜索此时的 PC 值。后续就可以通过 `watch *PC` 来单步调试其中的指令，或是通过 `watch *PC==0x???` 来下断点。不过由于 CPU 是流水线设计，我们能够拿到的 PC 大概率是取指阶段的 PC，其指向的指令会过几轮才发生实际的计算或访存操作。
- 很有意思的是，不管你 VM 再复杂，模拟内存也不过是一个明文大数组，因此我还可以不断检测虚拟的栈上变量。在依靠这个拿到一些常量之后解出了这题。

### 2025-7-27
1. 偷偷在导师的平板上安装了 CytusII，登陆了我已经好多年没有登陆的账号，打了几首歌玩哈哈。
2. 继续看《HHH》，学习了一些常见的低速 bus 协议（UART、SPI、IIC）。
3. 乐队排练。

### 2025-7-28
1. 复习 Cache 机制，讨论项目。
2. 拿到了 Intel 10700k 的机器，但两根内存条好像频率和 rank 都不一样！看来不能无脑跑 Blacksmith 了，得先看一看论文和工具代码。

### 2025-7-29~30
1. 台风天，在宿舍里二刷了《降世神通：最后的气宗》第一部。

### 2025-7-31
1. 终于把我的笔记本 fedora 耳机使用给修好了，原来是 pulseaudio 和 pipewrite 这两个音频服务器冲突了导致的问题，我卸载了 pulseaudio 再安装了 pipewrite-pulseaudio 这个 pipewrite 提供的 pulseaudio 兼容插件以后，一切东西都正常工作了！（Intel 我错怪你了）

## 2025-8

### 2025-8-1~2

1. 休息。
2. 乐队排练。

### 2025-8-3

1. 给博客目录添加了限制最大级数的功能。大致只要这样写：`{% assign h_max = page.toc_max_level | default: 6 %} {% include toc.html html=content h_max=h_max %}`，就可以在 page 的文件里面指定 `toc_max_level` 属性了。所以现在的目录栏位不像原来这么拥挤了（太棒了👍）

### 2025-8-4~5

接下来一长段时间要专心做项目，不得不放弃一些自由探索的时间了，要把主要的精力放在硬件设计领域。

1. 学习了 Ascon-128 算法，是一个基于海绵结构的加密认证（或者哈希）块密码算法，在硬件领域非常适合实现，而且很方便就可以支持抗侧信道的特性。[轻量级密码算法Ascon原理详解 - 知乎](https://zhuanlan.zhihu.com/p/576265874)这篇文章写得还不错。

### 2025-8-6
1. 给 VSCode 配置了 Vim 插件，而且支持自动输入法切换（[这个项目有说明如何开启这个功能](https://github.com/daipeihust/im-select)），挺好用的。

### 2025-8-7~10
1. 跟着《数字设计原理与实现》又学了一遍 verilog，比以前学得深入得多了，下面是一些笔记：
- `wire` 和 `reg` 都是 verilog 当中的 net 类型，他们的区别在于 `wire` 只能进行 continuous assignment，而 `reg` 对应 procedural assignment；换句话说 `wire` 在 `assign` 语句中被赋值，而 `reg` 在 `always` 块中被赋值。这种区分有的时候是非常不必要的，因为 `always` 除了时序逻辑之外也可以用来表示组合逻辑，而此时它就和 `wire` 的 `assign` 差不多了。所以 System Verilog 就消灭了这种区分，直接用 `logic` 代替 `wire` 和 `reg`，这也是 System Verilog 当中推荐的写法。
- Verilog 当中除了模块以外，还有 `function` 和 `task` 两种子程序。如果是一段需要重复使用的计算代码（比如提取出一串东西中的某些比特组成一个结果），就可以用 `function` 来实现，减少代码重复和可读性；如果正在编写 testbench，需要模拟一些行为但不需要返回值（比如模拟一个时钟信号、模拟一次AXI4操作），就可以用 `task` 来实现；其他时候都使用 module。
- 在编写 testbench 的时候，还可以使用 `initial` 块（对标 `always` ）来模拟一些行为，比如初始化信号、设置初始状态等。`initial` 块只会在仿真开始时执行一次，而 `always` 块则会持续执行。
- 有一些常用的内置函数和任务，比如 `$display` 类似于 `printf`、`$ffluish` 在结束前刷新缓冲区、`$random` 生成一个随机数、`$time` 返回当前仿真时间、`$stop` 停止仿真等。
- 简单地了解了一下模拟器模拟 verilog 的原理（其实我之前也读过 verilator 生成的C++代码，但在不了解高层设计的情况下读代码就是会看不到全局的设计）：模拟器需要全局维护一个事件队列和时钟，所有的事件（比如时钟上升沿、信号变化）都会被添加到这个队列中，并按照时间顺序执行。在 always block 中的 non-block assignment 中，对变量的修改不会立刻生效，因此它们会被安排到当前时刻的一个 delta delay 之后执行（这个概念非常酷！）。如果模拟器发现自己一直在处理 delta time 的赋值（比如超过1000次），我们就知道电路设计可能得有问题了。了解了模拟器的实现之后，会更加理解 verilog 语言本身中的各种设计，毕竟 verilog 语言的设计初衷就是描述电路行为而非进行电路设计。
- 然而，在使用工具对 verilog 进行综合时，确实有一些需要注意的地方：类似于 if, else 结构的电路可能会被综合成一系列线性的判断逻辑，导致延迟巨大；最好使用 `case` 语句，因为这在硬件上是并行的。loop 语句在综合时会被展开，即每一次循环都会对应一条信号通路。如果不希望循环占用面积过多，需要手动将其变成线性的。在过程块中，如果某个变量没有被完全赋值，综合工具会将其生成为一个 latch，这会影响性能因此最好避免。可以使用 `default` 语句来确保所有分支都被赋值。
2. 推进一生一芯，中间有一些思考：同步电路比异步电路实现起来更简单的原因是，在复杂的电路中往往需要涉及多个需要时间的计算或处理单元。如果简单地将它们连起来而不进行同步，那么如果上游模块在运算时产生不稳定输出，下游模块会基于这些不稳定输出做计算，从而白白增加了晶体管的状态切换、增加了电路产生意外行为的可能性。

### 2025-8-11
1. 阅读了 OpenC910 的 smart_run SoC 中的 `axi_interconnect128` 模块实现。这个模块把一个 Master 连接到四个 Slave 上：
- 对于 AW 通道，它根据地址区间选择对应的 Slave，并记录这个 Slave 的 ID 和地址 pair。
- 对于 W 通道，它根据 `wid` 查找对应的 address，再根据 address 判断属于哪一个 Slave（实现得很蠢）
- 对于 B 通道，就是简单地把 Slave 的 Response 转发给上级就行，不过对于多个 Slave 同时发送 Response 的场景简单做了一个带优先级的同步机制。
- 对于 AR 通道，就是简单地处理一下握手（ready、valid 信号），地址什么的都是直接连到 Slave 上的，都没有经过这个中转模块。
- 对于 R 通道，模块对每个 Slave 维护一个状态 read_done，用来使一个 Slave 的连续多条读响应也能够连续地返回至上级。初次以外，这里也像 B 通道一样做了简单的优先级机制。

### 2025-8-12
1. 给思源笔记配置了简单的模板标注功能，教程可以参考 [SiYuan 模板基础教程](https://ld246.com/article/1627298479208)。
- 思源笔记支持使用 Golang 的 html/template 库模板，但和标准的 `{{code}}` 不同，思源需要使用 `.action{code}`。
- 写好了模板之后需要放到思源笔记的数据目录中，由于我是使用 flatpak 安装的思源笔记，所以模板目录位于 `~/.var/app/org.b3log.siyuan/SiYuan/data/templates/`，而不是 `~/SiYuan`。
2. 终于，切实地推进了一点项目，并感到之后的部分也没有我想象得那么难了。

### 2025-8-13
1. LLM 告诉我项目可能会涉及多时钟域，所以我学习了[【高级数字电路】跨时钟域/CDC设计方法总结](https://zhuanlan.zhihu.com/p/598631863)。
- 多时钟域最头疼的问题就是，如果时钟并非是倍数关系，那么输入输出更新时，在各自时钟内的相位差是不确定的。这会导致亚稳态（在接收方处于上升沿更新数据的区间内时，发送方恰好正在更新数据，使得接受方接收不稳定的数据）、数据漏采（慢速接收者采集快信号）、同步失序（发送方的一组信号先后 available，导致接收方先后接收更新）的问题。对于亚稳态，只能通过在路径上增加几个缓冲寄存器来使数据稳定下来（处于亚稳态的寄存器会在一段时间后恢复稳定），但可惜的是这些缓冲寄存器只能使其稳定而不能确保其正确。对于数据漏采，要么采用Open-Loop方法，强行使输出的数据保持多个周期；要么采用Close-Loop方法，使用握手信号来确保数据被接收。对于同步失序，可以使用同步、异步 FIFO 等各种方法，百花齐放（具体看文章细节）。
- 如果时钟分频得到的倍数关系，那么慢速的一方在上升沿时快速的一方肯定也处于上升沿，他们之间只需要简单的握手协议以防止漏采就可以了。

### 2025-8-14
1. 在[一生一芯的AXI协议介绍](https://ysyx.oscc.cc/docs/2407/b/1.html#%E4%B8%9A%E7%95%8C%E4%B8%AD%E5%B9%BF%E6%B3%9B%E4%BD%BF%E7%94%A8%E7%9A%84%E6%80%BB%E7%BA%BF-axi%E5%8D%8F%E8%AE%AE%E5%AE%B6%E6%97%8F)中，介绍了握手的死锁和活锁问题。[ARM IHI0022 手册](https://developer.arm.com/documentation/ihi0022/latest/) 里面对握手涉及的信号进行了规范，以防止锁的出现：
- 对于死锁，在 A3.5 Dependencies between channel handshake signals 中，要求只有数据的接收方能够等待发送方置 valid 信号而置 ready，反之则不行。因此在一生一芯文档的例子中，“master 在等 slave 将 ready 置 1 后, 才将 valid 置 1” 这一行为是不允许的。
- 对于活锁，在 A3.3 中对各个 valid 信号的说明中，都有说明 "VALID must remain asserted until the rising clock edge after the Subordinate asserts the READY signal"，因此例子中 “因为上一个周期握手失败, master 在这个周期将 valid 置 0”这一行为是不允许的。
2. 知道了 git 的 `stash` 功能，可以暂存现在没有 staged 的修改，然后使用 `git stash pop` 恢复，非常适合临时 checkout 到一个以前的分支、或者在以前的 commit 上对代码做了 fix 想同步到最新 commit 的场景。

### 2025-8-15
1. 在硬件设计领域差分测试真的非常有用，在设计加密引擎的时候可以用波形图快速比对实现是否正确。
2. 之前在 RISC-V 峰会和两个哥们聊天，听他们说计算所做了一个内存监听卡，终于给我找到资里料了：[HMTT v4.3： The latest HMTT version for DDR4](https://asg.ict.ac.cn/hmtt/design/hmtt_v4/202504/t20250412_524222.html)、还有[关于HMTT的声明-包云岗](https://zhuanlan.zhihu.com/p/8760007689)。现在这张卡只能监听并记录总线上的地址信息，还没有实现数据的监听和记录，因此距离被拿来作外挂还是有点远。但是这种设备的存在就说明了也可以有监听数据的设备存在，所以内存加密真的是有场景的！
