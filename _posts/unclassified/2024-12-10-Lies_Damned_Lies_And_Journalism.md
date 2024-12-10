---
layout: post
title: "Lies, Damned lies, and Journalism"
date: "2024-12-10 23:00:00"
tags: 思考
---

![学会提问](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102135042.png)

在这个 gossip 满天飞的时代，选择相信什么、选择质疑什么好像变成了每天不得不面对的问题！最近正在读《学会提问（原书 12 版）》，是关于如何判断一个论证是否可信的一本简短的教程。这篇博客分享一下我找到书中一个 bug 的趣事。

在介绍研究成果的证明效力时，作者提到了一项研究：“结果令人信服地表明，原来的断言中有 41% 都是错误的或被极大地夸大的。”（下图的 "WTF!" 左边的内容）

![学会提问截图](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102142045.png)

41% 这个数字实在是太震撼了（WTF!），我立马拍照发给了学医的朋友，配文“医学不存在了”。然后继续读下去：

![学会提问下一页截图](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102156367.png)

发言者和写作者常常歪曲或者简化研究结论，此时我默默在上面标记了“科普者”以及“新闻作者”。

我有一个奇怪的想法，总是觉得“阅读其他领域的论文”是一个很有趣的事。这个想法可能来自 [l0tus](https://l0tus.vip/cn/5.19/)，他说：“但很巧也不幸的是，我喜欢看论文。”于是我看完了这章后就尝试在网上寻找 41% 这个研究的原文。

首先，根据书中的“Lies, Damned Lies, and Medical Science” November 2010, Atlantic Magaizne，我们可以找到书中引用的原文——一篇[杂志文章](https://dsp.domains.trincoll.edu/fake-news/fake-news/media/lies%20damned%20lies%20medical%20science.pdf)。

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102231949.png)

这篇文章并不是数据的出处，而只是介绍了 Dr. John Ioannidis 的研究成果。这个数字作为他开展的一项研究的结论出现在文章中：

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102233822.png)

根据期刊名 "Journal of the American Medical Association" 以及作者名 "Dr. John Ioannidis" 继续搜索，我们可以找到原论文《Contradicted and Initially Stronger Effects in Highly Cited Clinical Research》（[PDF链接](https://files.givewell.org/files/methods/Ioannidis%202005-Contradicted%20and%20Initially%20Stronger%20Effects%20in%20Highly%20Cited%20Clinical%20Research.pdf)），引用量高达 1830 次。

![image.png](https://blog-1308958542.cos.ap-shanghai.myqcloud.com/202412102237321.png)

可惜的是，在这篇文章中，我并没有找到 41% 这个数字。Results 部分中作者说道：在 49 篇高被引原始临床研究中，45 篇声称干预有效。其中，**7 篇( 16% )与后续研究相矛盾，7 篇( 16% )发现了比后续研究更强的效应**，20 篇( 44% )被复制，11 篇( 24% )基本没有受到挑战。

相比杂志的错误说法，我们应该重新将结果归纳为：在 45 个声称干预有效的研究中，有 14 个与后续研究矛盾或可能存在夸大，该比例达到了 **31%**。**这个数据和杂志文章《Lies, Damned Lies, and Medical Science》中的 41% 有着 10% 的巨大差距。** 

根据我的不负责任猜测，可能是杂志文章作者在计算 $14/45$ 时错误地把 $31\%$ 看成了 $41\%$，从而导致了一连串的错误，最终反映到了和医学完全无关的一本批判性思维科普书籍上。

此外，杂志中所用到的措辞 "had been convincingly shown wrong or significantly exaggerated" 也实在是过于夸张了。一个科研工作者不会动不动就“convincingly”和“significantly”，这种词会对读者产生煽动性，从而影响论证的严谨性。更何况，这篇杂志文章本来就注重于研究医学研究中的夸大现象，更不应该产生这样的不严谨描述。

有趣的是，在原版的论文中 "significant" 一次被使用了 33 次，然而，大多数的使用都位于否定句中，其余的都是对样本研究结论的引用。这就和杂志报道形成了反差。

最终，《学会提问》完成了自指——漂亮地攻击到了自己，于是就有了这篇神奇的博客。

> There are three kinds of lies: Lies, Damned Lies, and Journalism. ——鲁迅

