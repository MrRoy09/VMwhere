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
