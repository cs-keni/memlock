/* Expected rule results for this file:
 * - unsafe_functions: PASS (no findings)
 * - use_after_free: PASS (no findings)
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 *
 * This file uses only safer alternatives to unsafe C library functions.
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[64];
    char src[32] = "hello";
    char dst[32];

    /* fgets with size limit instead of gets */
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 1;
    }

    /* strncpy with explicit length */
    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\0';

    /* snprintf with explicit buffer size */
    snprintf(buf, sizeof(buf), "%s-%d", dst, 42);

    /* scanf with bounded format (width on %s) */
    char name[16];
    if (scanf("%15s", name) != 1) {
        return 1;
    }

    printf("OK %s %s\n", dst, name);
    return 0;
}

