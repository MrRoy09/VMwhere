#define _GNU_SOURCE
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
    }

    extern int __real_main(int argc, char **argv, char **envp);

    int result = __real_main(argc, argv, envp);
    return result;
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
    long ret;
    extern int __real___libc_start_main(
        main_fn, int, char **, void (*)(void), void (*)(void), void (*)(void), void *);

    return __real___libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
