/* Expected rule results for this file (once integer_overflow is implemented):
 * - integer_overflow: PASS (sizes checked or small constants)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    size_t n = 8u;
    size_t m = 4u;
    size_t total = n * m;

    /* Bounds check before allocation */
    if (total == 0 || total > 1024) {
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
