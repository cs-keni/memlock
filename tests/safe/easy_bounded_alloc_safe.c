/* EASY: Allocation size with bounds check before malloc.
 * Expected: all rules PASS
 */

#include <stdlib.h>
#include <stdio.h>

int main(void) {
    size_t n = 64;
    size_t m = 4;
    size_t total = n * m;

    if (total == 0 || total > 4096) {
        return 1;
    }

    char *p = malloc(total);
    if (p == NULL) {
        return 1;
    }
    p[0] = 'x';
    free(p);
    return 0;
}
