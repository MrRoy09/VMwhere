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

typedef uint8_t state_t[4][4];
struct AES_ctx
{
    uint8_t RoundKey[176];
};
int daddy = 0;
long addr = -1;
#define SYS_CUSTOM_mmap 0x20000000
#define SYS_CUSTOM_mremap 0x20000001
#define SYS_CUSTOM_munmap 0x20000002

typedef int (*main_fn)(int, char **, char **);

static int check_debugger()
{
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1)
    {
        return 1;
    }

    ptrace(PTRACE_DETACH, 0, 1, 0);
    return 0;
}

// custom syscall functions with inline assembly
long syscall_custom_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, int fd, unsigned long offset)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_mmap;
    register long rdi __asm__("rdi") = addr;
    register long rsi __asm__("rsi") = len;
    register long rdx __asm__("rdx") = prot;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = fd;
    register long r9 __asm__("r9") = offset;

    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return ret;
}

long syscall_custom_mremap(unsigned long old_addr, unsigned long old_size, unsigned long new_size, unsigned long flags, unsigned long new_addr)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_mremap;
    register long rdi __asm__("rdi") = old_addr;
    register long rsi __asm__("rsi") = old_size;
    register long rdx __asm__("rdx") = new_size;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = new_addr;

    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi), "r"(rdx), "r"(r10), "r"(r8)
        : "rcx", "r11", "memory");
    return ret;
}

long syscall_custom_munmap(unsigned long addr, unsigned long len)
{
    long ret;
    register long rax __asm__("rax") = SYS_CUSTOM_munmap;
    register long rdi __asm__("rdi") = addr;
    register long rsi __asm__("rsi") = len;

    __asm__ volatile(
        "syscall\n"
        : "=a"(ret)
        : "r"(rax), "r"(rdi), "r"(rsi)
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
        printf("Incorrect state: child did not stop properly\n");
        return;
    }

    // Set ptrace options
    if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == -1)
    {
        perror("ptrace(PTRACE_SETOPTIONS)");
        return;
    }

    // Resume the child
    if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
    {
        perror("ptrace(PTRACE_SYSCALL)");
        return;
    }

    struct user_regs_struct regs;
    while (1)
    {
        // Wait for syscall entry
        waitpid(child_pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            printf("Child process terminated unexpectedly\n");
            break;
        }

        // Get registers to check syscall number
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
        {
            perror("ptrace(PTRACE_GETREGS)");
            break;
        }

        long original_syscall = regs.orig_rax;
        printf("Syscall entry: %ld\n", original_syscall);

        if (original_syscall == SYS_CUSTOM_mmap)
        {
            printf("Intercepting mmap syscall - modifying to real mmap\n");
            regs.orig_rax = SYS_mmap;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                perror("ptrace(PTRACE_SETREGS) for mmap");
                break;
            }
        }
        else if (original_syscall == SYS_CUSTOM_mremap)
        {
            printf("Intercepting mremap syscall - modifying to real mremap\n");
            regs.orig_rax = SYS_mremap;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                perror("ptrace(PTRACE_SETREGS) for mremap");
                break;
            }
        }
        else if (original_syscall == SYS_CUSTOM_munmap)
        {
            printf("Intercepting munmap syscall - modifying to real munmap\n");
            regs.orig_rax = SYS_munmap;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1)
            {
                perror("ptrace(PTRACE_SETREGS) for munmap");
                break;
            }
        }

        // Allow syscall to execute
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1)
        {
            perror("ptrace(PTRACE_SYSCALL) after syscall entry");
            break;
        }

        // Wait for syscall exit
        waitpid(child_pid, &status, 0);
        if (!WIFSTOPPED(status))
        {
            printf("Child terminated during syscall execution\n");
            break;
        }

        // Get registers to see syscall result
        if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1)
        {
            perror("ptrace(PTRACE_GETREGS) after syscall");
            break;
        }

        // Check the return value
        // Fix format specifiers in the printf statements
        if (original_syscall == SYS_CUSTOM_mmap)
        {
            printf("mmap returned: %ld\n", (long)regs.rax);
            if ((long)regs.rax == -1)
            {
                printf("mmap error: %s\n", strerror(errno));
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
            perror("ptrace(PTRACE_SYSCALL) after syscall exit");
            break;
        }
    }

    printf("Child process monitoring ended\n");
}

void tracee()
{
    // Tell the kernel we want to be traced
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
    {
        perror("ptrace(PTRACE_TRACEME)");
        exit(1);
    }

    // Stop and wait for parent to take control
    raise(SIGSTOP);
}

int __wrap_main(int argc, char *argv[])
{
    printf("In __wrap_main\n");

    pid_t pid = fork();
    extern int __real_main(int argc, char *argv[]);

    if (pid < 0)
    {
        perror("fork failed");
        return -1;
    }
    else if (pid == 0)
    {
        daddy = 0;
        tracee();
        int result = __real_main(argc, argv);
        return result;
    }
    else
    {
        // Parent process
        daddy = 1;
        tracer(pid);
        return 0;
    }
}

int __wrap___libc_start_main(
    main_fn main,
    int argc,
    char **ubp_av,
    void (*init)(void),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void *stack_end)
{
    extern int __real___libc_start_main(
        main_fn, int, char **, void (*)(void), void (*)(void), void (*)(void), void *);

    // Only attempt syscall in child process
    if (!daddy)
    {
        // printf("Attempting custom mmap syscall\n");
        long ret = syscall_custom_mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        addr = ret;
    }

    // Always proceed with regular startup
    return __real___libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

int __wrap_printf(const char *format, ...)
{
    va_list args;
    int ret;
    if (!daddy)
    {
        ret = syscall_custom_mremap(addr, 4096, 4436, 0, 0);
        if (ret == -1)
        {
            perror("custom_mremap syscall");
        }
        addr = ret;
    }
    va_start(args, format);
    ret = vprintf(format, args);
    va_end(args);

    return ret;
}
