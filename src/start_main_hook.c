// #define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdarg.h>

#define SYS_CUSTOM_mmap 0x20000000
#define SYS_CUSTOM_mremap 0x20000001
#define SYS_CUSTOM_munmap 0x20000002
#define SYS_CUSTOM_mprotect 0x20000003

typedef uint8_t state_t[4][4];
struct AES_ctx
{
    uint8_t RoundKey[176];
};

void AES_ECB_encrypt(const struct AES_ctx *ctx, uint8_t *buf);
void *func = (void *)AES_ECB_encrypt;
size_t page_size;
void *page;
static volatile int daddy = -1;
static uint64_t addr = 0;
static long syscall_mprotect(unsigned long addr, unsigned long len, unsigned long prot);

// Get page size using inline assembly
static size_t get_page_size(void)
{
    long result;
    register long rax __asm__("rax") = 12; // SYS_getpagesize on x86_64

    __asm__ volatile(
        "syscall\n"
        : "=a"(result)
        : "r"(rax)
        : "rcx", "r11", "memory");

    return (size_t)result;
}

typedef int (*main_fn)(int, char **, char **);
typedef uint8_t state_t[4][4];


static int check_debugger()
{
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
    {
        return 1;
    }

    ptrace(PTRACE_DETACH, 0, 1, 0);
    return 0;
}

int __wrap_main(int argc, char **argv, char **envp)
{
    if (check_debugger())
    {
        if (argc > 1)
        {
            int i = 0;
            while (argv[1][i])
            {
                argv[1][i] ^= 0x19;
                i++;
            }
        }
        else if (original_syscall == SYS_CUSTOM_mremap)
        {
            printf("mremap returned: %ld\n", (long)regs.rax);
        }
        else if (original_syscall == SYS_CUSTOM_munmap)
        {
            printf("munmap returned: %ld\n", (long)regs.rax);
        }

        // Continue to next syscall
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
        {
            // perror("ptrace(PTRACE_SYSCALL) after syscall exit");
            break;
        }
    }

    // printf("Child process monitoring ended\n");
}

void tracee()
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
    {
        // perror("ptrace(PTRACE_TRACEME)");
        return;
    }

    raise(SIGSTOP);
}

void modify_args(int argc, char *argv[])
{
    // modify argv[1] by xoring
    if (argc > 1)
    {
        int n = strlen(argv[1]);
        for (int i = 0; i < n; i++)
        {
            argv[1][i] ^= 0xFF;
        }
    }
}

int __wrap_main(int argc, char *argv[])
{
    pid_t pid = fork();
    // pid_t pid = 0;
    extern int __real_main(int argc, char *argv[]);

    if (pid < 0)
    {
        // perror("fork failed");
        return -1;
    }
    else if (pid == 0)
    {
        daddy = 0;
        tracee();
        long ret = syscall_custom_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ret < 0)
            modify_args(argc, argv);
        int result = __real_main(argc, argv);
        return result;
    }
    else
    {
        daddy = 1;
        tracer(pid);
        return 0;
    }
}

int __wrap_printf(const char *format, ...)
{
    va_list args;
    int64_t ret;
    if (!daddy)
    {
        if (addr == 0)
        {
            ret = syscall_custom_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            addr = ret;
            if (ret > 0)
            {
                ret = 0;
            }
        }
        else
        {
            ret = syscall_custom_munmap(addr, 4096);
            addr = 0;
        }
        if (ret < 0)
        {
            // fprintf(stderr, "Error in mmap: %s\n", strerror(errno));
            return -1;
        }
    }
    va_start(args, format);
    ret = vprintf(format, args);
    va_end(args);

    return ret;
}

int __wrap_printf(const char *format, ...)
{
    va_list args;
    int ret;
    if (!daddy)
    {
        ret = syscall_custom_mremap(addr, 4096, 4436, 0, 0);
        // if (ret == -1)
        // {
        //     perror("custom_mremap syscall");
        // }
        addr = ret;
    }
    va_start(args, format);
    ret = vprintf(format, args);
    va_end(args);

    return ret;
}
