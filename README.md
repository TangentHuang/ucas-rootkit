# ucas-rootkit
国科大软件安全原理作业

# 环境

ubuntu18.04

Linux ubuntu 4.15.0-20-generic

## 功能实现

* 通过shell 中的cd 命令控制rootkit，通过hook chdir系统调用实现

  cd  /HW/Signal/argument

  | 功能             | Singal | argument |
  | ---------------- | ------ | -------- |
  | 提权             | 1145   |          |
  | 隐藏进程         | 514    | pid      |
  | 取消隐藏进程     | 415    | pid      |
  | 隐藏端口         | 1919   | port     |
  | 取消隐藏端口     | 9191   | port     |
  | 隐藏文件         | 8100   | filename |
  | 取消隐藏文件     | 1818   | filename |
  | 隐藏自身模块     | 4399   |          |
  | 取消隐藏自身模块 | 9344   |          |
  | 进程保护         | 2333   | pid      |
  | 取消进程保护     | 2233   | pid      |

* 提权
  commit_creds(prepare_kernel_cred(0));
  ![](https://img.tangent.ink/20211021234545.png)

* 隐藏/取消隐藏进程

  维护了一个双向链表hiddenPID，把需要隐藏的pid信息添加到链表，对链表节点的增加和删除就可以达到隐藏或者取消隐藏的效果。 

  通过hook文件结构中的iterate_shared实现，iterate_shared作为回调函数，用于把一项记录（如一个目录下的文件或目录）填到返回的缓冲区里。

  只需要判断iterate_shared中pid信息是否是我们需要隐藏的，如果是就返回0，不是就正常填入

  缓冲区，这也就可以达到隐藏进程的效果。

  <img src="https://img.tangent.ink/20211021212757.png" />

  

* 隐藏/取消隐藏端口

  维护了一个双向链表hiddenPort，把需要隐藏的port信息添加到链表，对链表节点的增加和删除就可以达到隐藏或者取消隐藏的效果

  用户态程序通读取/proc/net/下的信息来读取网络端口数据。想要获取tcp4协议的端口信息，主要通过tcp4_seq_show()，也就是seq_operations中的show函数。

  通过hook掉seq_show函数，添加端口的判断，就可以实现端口的隐藏，原理同上。

  ![](https://img.tangent.ink/20211021213517.png)

  

* 隐藏/取消隐藏文件

  维护了一个双向链表fileName，把需要隐藏的文件名信息添加到链表，对链表节点的增加和删除就可以达到隐藏或者取消隐藏的效果

  对于目录的遍历主要是通过getdents或者getdents64函数实现的，在本次实验的内核版本中，ls是调用的getdents实现。

  ```c
  int getdents(unsigned int fd, struct linux_dirent *dirp,unsigned int count);
  ```

  getdents系统调用从文件描述符fd的目录中读取多个Linux_dirent结构，读取到dirp指向的缓冲区。

  可以通过hook getdents函数，添加对于文件名的判断，来实现隐藏文件的功能。
  ![](https://img.tangent.ink/20211021230826.png)

* 端口保护/取消进程保护

  维护了一个双向链表protectPID，把需要隐藏进程的pid添加到链表，对链表节点的增加和删除就可以达到保护和取消保护的效果。

  hook了kill系统调用，判断pid是否在链表中

  ![](https://img.tangent.ink/20211021214912.png)

* 隐藏自身模块

  lsmod 是通过读取/proc/modules来获取内核模块的信息，这些信息是内核利用 struct modules结构体表头去遍历链表所取得。

  只要在链表中删除自己模块的node，就可以达到隐藏rootkit模块的效果，同理，只要加上node，就能取消隐藏。

  ![](https://img.tangent.ink/20211021225126.png)

# TODO

* 实现多种网络协议端口隐藏
* 可以指定的隐藏内核模块
* 模块卸载的时候有概率会crash
