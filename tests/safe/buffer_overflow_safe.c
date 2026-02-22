/* Expected rule results for this file (once buffer_overflow is implemented):
 * - buffer_overflow: PASS (all accesses within bounds)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char buf[8];
    int arr[4];
    size_t i;

    /* Bounds-checked loop: i < sizeof(buf) */
    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = 'A';
    }
    buf[sizeof(buf) - 1] = '\0';

    /* Valid indices only: 0..3 */
    for (i = 0; i < 4; i++) {
        arr[i] = i;
    }

    return 0;
}
