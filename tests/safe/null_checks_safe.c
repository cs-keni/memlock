/* Expected rule results for this file (once null_checks is implemented):
 * - null_checks: PASS (malloc results checked before use)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
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

    return 0;
}
