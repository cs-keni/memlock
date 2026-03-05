/* MEDIUM: Custom wrapper functions that propagate unsafe behavior.
 * Expected: unsafe_functions (gets, strcpy via wrappers), buffer-overflow
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Wrapper that hides gets - common in legacy codebases */
static void read_line(char *buf) {
    gets(buf);   /* Still unsafe - wrapper doesn't add safety */
}

/* Wrapper that hides strcpy */
static void copy_string(char *dst, const char *src) {
    strcpy(dst, src);   /* Unbounded copy */
}

/* Allocation wrapper - no overflow check */
static char *alloc_product(size_t a, size_t b) {
    return malloc(a * b);   /* integer_overflow: unchecked multiply */
}

int main(void) {
    char buf[32];
    read_line(buf);

    char dst[8];
    copy_string(dst, "overflow");

    char *p = alloc_product(1UL << 30, 16);
    if (p) {
        p[0] = 0;
        free(p);
    }
    return 0;
}
