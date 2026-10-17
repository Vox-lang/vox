/* munmap_watch: run a program and report every munmap(2) it makes.

   Usage: munmap_watch <program> [args...]

   Prints one line per munmap on standard output, which it shares with the
   program it runs:
     munmap <length> image    the address lies in a file mapping of the
                              program itself (its code or static data)
     munmap <length> other    anything else
   and one line `mark` for every getpid(2) the program makes, so a host can
   bracket a moment (the unload test calls getpid around dlclose).
   Exits with the program's own exit status.

   Used by test.sh: a list freed in a library and freed again in the
   program must never unmap the program's own data, and a library unloaded
   by a host that keeps running must give back the buffers it made. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int in_program_image(pid_t pid, unsigned long long address, const char *program)
{
    char maps_path[64];
    snprintf(maps_path, sizeof maps_path, "/proc/%d/maps", (int) pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps)
        return 0;
    char line[PATH_MAX + 128];
    int inside = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long long start, end;
        char path[PATH_MAX] = "";
        if (sscanf(line, "%llx-%llx %*s %*s %*s %*s %4095s", &start, &end, path) < 2)
            continue;
        if (address >= start && address < end && strcmp(path, program) == 0) {
            inside = 1;
            break;
        }
    }
    fclose(maps);
    return inside;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: munmap_watch <program> [args...]\n");
        return 2;
    }
    char program[PATH_MAX];
    if (!realpath(argv[1], program)) {
        perror("munmap_watch: realpath");
        return 2;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("munmap_watch: fork");
        return 2;
    }
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execv(program, argv + 1);
        perror("munmap_watch: execv");
        _exit(127);
    }

    int status;
    waitpid(child, &status, 0); /* the stop at execv */
    ptrace(PTRACE_SETOPTIONS, child, NULL, (void *) PTRACE_O_TRACESYSGOOD);

    int entering = 1;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0)
            break;
        if (waitpid(child, &status, 0) < 0)
            break;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);
        if (!(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80)))
            continue;
        if (entering) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            if (regs.orig_rax == SYS_munmap) {
                printf("munmap %llu %s\n", regs.rsi,
                       in_program_image(child, regs.rdi, program) ? "image" : "other");
                fflush(stdout);
            } else if (regs.orig_rax == SYS_getpid) {
                printf("mark\n");
                fflush(stdout);
            }
        }
        entering = !entering;
    }
    return 2;
}
