/* Expected rule results for this file (once buffer_overflow is implemented):
 * - buffer_overflow: FAIL (out-of-bounds writes)
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
    int i;

    /* Out-of-bounds loop: i goes 0..8 inclusive for buf[8] */
    for (i = 0; i <= 8; i++) {   /* buffer_overflow should flag this */
        buf[i] = 'A';
    }

    /* Direct out-of-bounds write: arr has indices 0..3 */
    arr[4] = 42;                 /* buffer_overflow should flag this */

    return 0;
}
