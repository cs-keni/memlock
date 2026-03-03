/* EASY: Unchecked multiplication in malloc size.
 * Expected: integer-overflow
 */

#include <stdlib.h>

int main(void) {
    size_t n = 1024 * 1024 * 1024;   /* 1GB */
    size_t m = 16;
    char *p = malloc(n * m);   /* n * m can overflow size_t */
    if (p) {
        p[0] = 0;
        free(p);
    }
    return 0;
}
