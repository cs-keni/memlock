/* Expected rule results for this file:
 * - unsafe_functions: PASS (no banned functions)
 * - use_after_free: FAIL (pointer is dereferenced and reused after free)
 * - buffer_overflow: PASS
 * - memory_management: FAIL (once implemented; potential double-free / misuse)
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS (malloc result is checked)
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *p = (int *)malloc(sizeof(int));
    if (p == NULL) {
        return 1;
    }

    *p = 7;
    free(p);

    /* Use-after-free: dereference p after it has been freed */
    *p = 42;          /* use_after_free rule should flag this line */
    printf("%d\n", *p);

    /* (For a future memory_management rule, this could also be extended to
     * demonstrate double-free by calling free(p) again.) */

    return 0;
}

