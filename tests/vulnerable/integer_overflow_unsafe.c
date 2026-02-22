/* Expected rule results for this file (once integer_overflow is implemented):
 * - integer_overflow: FAIL (suspicious arithmetic in allocation sizes)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS (or may flag leak)
 * - hardcoded_secrets: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

void large_multiply_example(void) {
    size_t n = 1u << 30;   /* 1GB */
    size_t m = 16u;
    char *p = malloc(n * m);   /* integer_overflow: n * m can overflow */
    if (p) {
        p[0] = 0;
        free(p);
    }
}

void unchecked_arithmetic_example(size_t n, size_t m) {
    char *buf = malloc(n * m);   /* integer_overflow: unchecked multiply */
    if (buf) {
        buf[0] = 'x';
        free(buf);
    }
}

int main(void) {
    large_multiply_example();
    unchecked_arithmetic_example(1000000, 1000);
    return 0;
}
