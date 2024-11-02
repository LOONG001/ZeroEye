# ZeroEye ⭐⭐⭐⭐⭐
## 更多关于本项目的介绍，请前往公众号获取更详细使用教程：

**[ZeroEye](https://mp.weixin.qq.com/s?__biz=MzkyNDUzNjk4MQ==&mid=2247484591&idx=1&sn=50b813e4c626aa967d6c506c4749c032&chksm=c1d51d55f6a294434e27bbcd6dc45268e64ac8a86bc1215c2df9140d350ea2f26ed6d91a2655#rd)** 用于扫描 EXE 文件的导入表，列出导入的DLL文件，并筛选出非系统DLL，符合条件的文件将被复制到特定的 **bin**  文件夹，并生成 **Infos.txt** 文件记录DLL信息。自动化找白文件，灰梭子好搭档！！！

**[灰梭子](https://mp.weixin.qq.com/s?__biz=MzkyNDUzNjk4MQ==&mid=2247483925&idx=1&sn=7424113417378915f17155260bdeef67&chksm=c1d51beff6a292f9cbb906cbaa2a55925d7ac1faeb9860b2d340b95cd33a2a0478d494daf711&scene=21#wechat_redirect)** 快速对dll进行解析函数名，并且生成对应的劫持代码，实现快速利用vs进行编译，提供了劫持模板，可前往获取。

### 存在其他问题请提交**lssues**

###  ⭐确定不来一个吗？

---

# 全版本介绍：

* 1.0 可在Release中获取
* 2.0 可在Release中获取
* 3.0 （**船新版本**）将不再在以上基础上更新，以后将完全使用c++完成所有操作！！！
* 3.1 修复bug

# 1.0版本
* 修复dll复制不全,exe路径下如不存在dll！


# 2.0版本
| 项目名          | 备注                                                         |
| --------------- | ------------------------------------------------------------ |
| x64/ZeroEye.exe | 检测x64白进程                                                |
| x86/ZeroEye.exe | 检测x86白进程                                                |
| Find_All.py     | 自动调用以上项目，实现自动遍历系统所有exe，将exe和dll自动放到当前路径的bin文件夹中。 |

* 添加对只有exe和info两个文件进行剔除，只保留文件夹下存在多个文件的情况！
* 优化代码效率

---
# 3.0版本
| 项目名             | 备注       |
| --------------- | -------- |
| x64/ZeroEye.exe | 检测x64白进程 |
| x86/ZeroEye.exe | 检测x86白进程 |

```
Usage: ZeroEye [options]
    -h     帮助
    -i    <Exe 路径>    列出Exe的导入表
    -p    <文件路径>    自动搜索文件路径下可劫持利用的白名单

example：
ZeroEye.exe -p c:\             //搜索c盘所有exe是否有劫持的可能
ZeroEye.exe -i aaa.exe         //判断指定exe是否有劫持的可能
```

    
![image](https://github.com/user-attachments/assets/12ac33d7-aacb-477f-b119-51f6fa7c0730)

![image](https://github.com/user-attachments/assets/4ae352c5-5664-4654-be1c-ad005e823f71)

---
## 3.1版本
### 存在问题

* 修复遍历导入表时,遇到空格名称输出问题。
 
* 修复目录遍历功能，可正常遍历整个盘符。

* 修复dllname触发的0xc05的内存访问冲突报错。

* 整理代码，并且对部分做出调整。
