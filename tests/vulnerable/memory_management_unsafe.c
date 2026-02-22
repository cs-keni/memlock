/* Expected rule results for this file (once memory_management is implemented):
 * - memory_management: FAIL (leak and/or double-free)
 * - unsafe_functions: PASS
 * - use_after_free: PASS (or may overlap with double-free)
 * - buffer_overflow: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

void memory_leak_example(void) {
    char *p = malloc(256);
    p[0] = 'x';
    /* Illegal memory management: p is never freed */
}

void double_free_example(void) {
    int *p = malloc(sizeof(int));
    *p = 42;
    free(p);
    free(p);   /* memory_management should flag double free */
}

int main(void) {
    memory_leak_example();
    double_free_example();
    return 0;
}
