/* MEDIUM: Safe wrapper patterns - bounds checking, NULL checks.
 * Uses sizeof for bounds (compile-time) to avoid false positives.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

/* Safe read - uses fgets with sizeof at call site, guarded by size > 1 */
static int read_line_safe(char *buf, size_t size) {
    if (buf == NULL || size == 0) {
        return -1;
    }
    if (fgets(buf, (int)size, stdin) == NULL) {
        return -1;
    }
    if (size > 1) {
        buf[size - 1] = '\0';
    }
    return 0;
}

/* Safe copy - caller passes sizeof, guarded by dst_size > 1 check */
static void copy_string_safe(char *dst, const char *src, size_t dst_size) {
    if (dst == NULL || src == NULL || dst_size == 0) {
        return;
    }
    if (dst_size > 1) {
        strncpy(dst, src, dst_size - 1);
        dst[dst_size - 1] = '\0';
    }
}

/* Safe allocation - fixed small size, no overflow possible */
static char *alloc_small(void) {
    return malloc(256);
}

int main(void) {
    char buf[BUF_SIZE];
    if (read_line_safe(buf, sizeof(buf)) != 0) {
        return 1;
    }

    char dst[32];
    copy_string_safe(dst, buf, sizeof(dst));

    char *p = alloc_small();
    if (p == NULL) {
        return 1;
    }
    p[0] = 'x';
    free(p);
    return 0;
}
