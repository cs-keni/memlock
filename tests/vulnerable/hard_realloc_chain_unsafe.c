/* HARD: Realloc in loop - integer overflow in size calculation.
 * Expected: integer-overflow
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

char *grow_buffer(char *buf, size_t *cap, size_t extra) {
    size_t new_cap = *cap + extra;
    if (new_cap < *cap) {
        return NULL;   /* Overflow */
    }
    char *new_buf = realloc(buf, new_cap);
    if (new_buf) {
        *cap = new_cap;
    }
    return new_buf;
}

/* Vulnerable: size calculation can overflow */
char *alloc_large(size_t n, size_t m) {
    size_t total = n * m;   /* integer_overflow: unchecked */
    return malloc(total);
}

int main(void) {
    size_t cap = 64;
    char *buf = malloc(cap);
    if (!buf) {
        return 1;
    }

    buf = grow_buffer(buf, &cap, 1024);
    if (buf) {
        buf[0] = 'x';
        free(buf);
    }

    char *p = alloc_large(1UL << 31, 4);
    if (p) {
        free(p);
    }
    return 0;
}
