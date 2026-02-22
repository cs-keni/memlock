/* Expected rule results for this file:
 * - unsafe_functions: PASS
 * - use_after_free: PASS (pointer is not used after free)
 * - buffer_overflow: PASS
 * - memory_management: PASS (once implemented; all allocations freed)
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS (simple example, but malloc result is checked)
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (p == NULL) {
        return 1;
    }

    *p = 42;
    printf("Value: %d\n", *p);

    free(p);
    p = NULL;  /* clear pointer, no further use */

    return 0;
}

