/* Expected rule results for this file (once memory_management is implemented):
 * - memory_management: PASS (all allocations freed, no double-free)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p = malloc(sizeof(int));
    if (p == NULL) {
        return 1;
    }

    *p = 42;
    printf("%d\n", *p);
    free(p);
    p = NULL;

    return 0;
}
