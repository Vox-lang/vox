/* unload_host: a C host that loads a Vox library, calls one of its
   functions ten times, unloads it, and keeps running.

   Usage: unload_host <library.so> <export>

   Calls getpid(2) just before and just after dlclose, so munmap_watch can
   bracket the unload: every munmap between the two `mark` lines is the
   library giving memory back. */
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: unload_host <library.so> <export>\n");
        return 2;
    }
    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) {
        printf("dlopen: %s\n", dlerror());
        return 1;
    }
    void (*make)(void) = (void (*)(void)) dlsym(library, argv[2]);
    if (!make) {
        printf("dlsym: %s\n", dlerror());
        return 1;
    }
    for (int call = 0; call < 10; call++)
        make();
    getpid();
    dlclose(library);
    getpid();
    printf("host still running\n");
    return 0;
}
