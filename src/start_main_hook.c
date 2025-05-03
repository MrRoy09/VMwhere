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
static volatile int is_parent = -1;
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

static long syscall_custom_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, int fd, unsigned long offset)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_mmap;
    register long rdi __asm__("rdi") = addr;
    register long rsi __asm__("rsi") = len;
    // Swap prot and flags as the tracer will swap them back
    register long rdx __asm__("rdx") = flags;
    register long r10 __asm__("r10") = prot;
    register long r8 __asm__("r8") = fd;
    register long r9 __asm__("r9") = offset;
    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

static long syscall_custom_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_mremap;
    register long rdi __asm__("rdi") = addr;
    // Swap old_len and new_len as the tracer will swap them back
    register long rsi __asm__("rsi") = new_len;
    register long rdx __asm__("rdx") = old_len;
    // Swap rdx and r10 as the tracer will swap them back
    register long r10 __asm__("r10") = rdx;
    rdx = flags;
    register long r8 __asm__("r8") = new_addr;
    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory");
    return ret;
}

static long syscall_custom_munmap(unsigned long addr, unsigned long len)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_munmap;
    // XOR with 0x14 and swap addr and len as the tracer will do the reverse
    register long rdi __asm__("rdi") = len ^ 0x14;
    register long rsi __asm__("rsi") = addr;
    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi)
        : "rcx", "r11", "memory");
    return ret;
}

static long syscall_mprotect(unsigned long addr, unsigned long len, unsigned long prot)
{
    long ret;
    register long rax __asm__("rax") = SYS_mprotect;
    register long rdi __asm__("rdi") = addr;
    register long rsi __asm__("rsi") = len;
    register long rdx __asm__("rdx") = prot;
    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return ret;
}

static long syscall_custom_mprotect(unsigned long addr, unsigned long len, unsigned long prot)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_mprotect;
    // In tracer: rsi ^= 0x347 and swap rdi with rdx
    register long rdi __asm__("rdi") = prot;
    register long rsi __asm__("rsi") = len ^ 0x347;
    register long rdx __asm__("rdx") = addr;
    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx)
        : "rcx", "r11", "memory");
    return ret;
}

void tracer(pid_t child_pid)
{
    int status;

    // Wait for the child to stop after TRACEME
    waitpid(child_pid, &status, 0);
    if (!WIFSTOPPED(status))
    {
        return;
    }

    // Set ptrace options
    if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1)
    {
        return;
    }

    // Resume the child
    if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
    {
        return;
    }

    struct user_regs_struct regs;
    while (1)
    {
        // Wait for syscall entry
        waitpid(child_pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            break;
        }

        // Get registers to check syscall number
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
        {
            break;
        }

        long original_syscall = regs.orig_rax;

        if (original_syscall == SYS_CUSTOM_mmap)
        {
            regs.orig_rax = SYS_mmap;
            regs.rdx ^= regs.r10;
            regs.r10 ^= regs.rdx;
            regs.rdx ^= regs.r10;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                break;
            }
        }
        else if (original_syscall == SYS_CUSTOM_mremap)
        {
            regs.orig_rax = SYS_mremap;
            unsigned long temp = regs.rsi;
            regs.rsi = regs.rdx;
            regs.rdx = temp;
            regs.rdx ^= regs.r10;
            regs.r10 ^= regs.rdx;
            regs.rdx ^= regs.r10;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                break;
            }
        }
        else if (original_syscall == SYS_CUSTOM_munmap)
        {
            regs.orig_rax = SYS_munmap;
            regs.rdi ^= 0x14;
            regs.rdi ^= regs.rsi;
            regs.rsi ^= regs.rdi;
            regs.rdi ^= regs.rsi;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                break;
            }
        }
        else if (original_syscall == SYS_CUSTOM_mprotect)
        {
            regs.orig_rax = SYS_mprotect;
            regs.rsi ^= 0x347;
            regs.rdi ^= regs.rdx;
            regs.rdx ^= regs.rdi;
            regs.rdi ^= regs.rdx;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                break;
            }
        }

        // Allow syscall to execute
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
        {
            break;
        }

        // Wait for syscall exit
        waitpid(child_pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            break;
        }

        // Continue to next syscall
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
        {
            break;
        }
    }
}

void tracee()
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
    {
        return;
    }

    raise(SIGSTOP);
}

void modify_args(int argc, char *argv[])
{
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
        return -1;
    }
    else if (pid == 0)
    {
        is_parent = 0;
        tracee();
        long ret = syscall_custom_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ret < 0)
            modify_args(argc, argv);
        int result = __real_main(argc, argv);
        return result;
    }
    else
    {
        is_parent = 1;
        tracer(pid);
        return 0;
    }
}

int __wrap_printf(const char *format, ...)
{
    va_list args;
    int64_t ret;
    if (!is_parent)
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
            return -1;
        }
    }
    va_start(args, format);
    ret = vprintf(format, args);
    va_end(args);

    return ret;
}
