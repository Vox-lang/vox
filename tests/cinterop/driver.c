/* C-interop boundary test driver. Linked against the .so that test.sh's
 * run_c_interop_test builds from mathkit.vox + strkit.vox. Exercises both
 * directions of the "callable from C" promise: a plain integer call (System
 * V AMD64: arg in rdi, result in rax) and a text return read as a
 * NUL-terminated char*, with no marshalling on either side. */
#include <stdio.h>
#include <string.h>

extern long math_kit_1_0_add_two(long x);
extern void *strkit_1_0_greet(void);

int main(void) {
    long n = math_kit_1_0_add_two(40);
    if (n != 42) {
        fprintf(stderr, "add_two(40) = %ld, want 42\n", n);
        return 1;
    }

    const char *s = (const char *)strkit_1_0_greet();
    if (strcmp(s, "hello from vox") != 0) {
        fprintf(stderr, "greet() = %s, want 'hello from vox'\n", s);
        return 2;
    }

    printf("%ld %s\n", n, s);
    return 0;
}
