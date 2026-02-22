/* Expected rule results for this file (once format_string is implemented):
 * - format_string: FAIL (printf/printf-family with non-literal format)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char user_input[64];

    if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
        return 1;
    }

    /* Format string vulnerability: user-controlled format */
    printf(user_input);   /* format_string should flag this */

    return 0;
}
