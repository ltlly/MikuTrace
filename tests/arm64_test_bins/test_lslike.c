// ls-like file listing tool for ARM64 decompiler testing
// Uses real syscalls: openat, getdents64, write, statx
#include <stdint.h>
#include <stddef.h>

// Minimal syscall wrappers (inline asm for ARM64)
static long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5) : "memory");
    return x0;
}
static long syscall3(long n, long a1, long a2, long a3) { return syscall6(n,a1,a2,a3,0,0,0); }
static long syscall2(long n, long a1, long a2) { return syscall6(n,a1,a2,0,0,0,0); }
static long syscall1(long n, long a1) { return syscall6(n,a1,0,0,0,0,0); }

#define SYS_write 64
#define SYS_openat 56
#define SYS_getdents64 61
#define SYS_exit 93
#define AT_FDCWD -100

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// strlen
static int my_strlen(const char *s) { int n=0; while(*s++)n++; return n; }

// itoa — int to string
static int my_itoa(int n, char *buf) {
    int i=0, neg=0;
    if(n<0){neg=1;n=-n;}
    if(n==0){buf[0]='0';buf[1]=0;return 1;}
    char tmp[16];
    while(n>0){tmp[i++]='0'+n%10;n/=10;}
    if(neg) buf[0]='-', i++;
    for(int j=0;j<i;j++) buf[neg?j+1:j]=tmp[i-1-j];
    buf[i+neg]=0; return i+neg;
}

// write a string
static void putstr(const char *s) { syscall3(SYS_write,1,(long)s,my_strlen(s)); }

// memcmp
static int my_memcmp(const void *a, const void *b, int n) {
    const unsigned char *ca=a,*cb=b;
    for(int i=0;i<n;i++){if(ca[i]!=cb[i])return ca[i]-cb[i];}
    return 0;
}

// strcmp 
static int my_strcmp(const char *a, const char *b) {
    while(*a && *a==*b){a++;b++;}
    return *(unsigned char*)a - *(unsigned char*)b;
}

// Bubble sort strings
static void sort_strings(char **arr, int n) {
    for(int i=0;i<n-1;i++)
        for(int j=0;j<n-i-1;j++)
            if(my_strcmp(arr[j],arr[j+1])>0){char *t=arr[j];arr[j]=arr[j+1];arr[j+1]=t;}
}

// Quick hex output
static void puthex(unsigned long v) {
    char buf[20]; int i=0;
    if(v==0){putstr("0x0");return;}
    buf[0]='0';buf[1]='x';i=2;
    char hex[]="0123456789abcdef";
    int shift=(sizeof(v)*8)-4;
    while(shift>=0){buf[i++]=hex[(v>>shift)&0xf];shift-=4;}
    buf[i]=0; putstr(buf);
}

// List directory using getdents64
void list_dir(const char *path) {
    int fd = syscall3(SYS_openat, AT_FDCWD, (long)path, 0); // O_RDONLY
    if(fd<0){putstr("open failed\n");return;}
    char buf[1024];
    int n;
    char *names[256]; int count=0;
    while((n=syscall3(SYS_getdents64, fd, (long)buf, sizeof(buf)))>0){
        int pos=0;
        while(pos<n){
            struct linux_dirent64 *d = (struct linux_dirent64*)(buf+pos);
            if(d->d_name[0]!='.') names[count++]=d->d_name;
            pos+=d->d_reclen;
            if(count>=256) break;
        }
    }
    sort_strings(names,count);
    char num[16];
    my_itoa(count,num); putstr(num); putstr(" entries\n");
    for(int i=0;i<count;i++){putstr("  ");putstr(names[i]);putstr("\n");}
}

void _start() {
    list_dir(".");
    syscall1(SYS_exit, 0);
}
