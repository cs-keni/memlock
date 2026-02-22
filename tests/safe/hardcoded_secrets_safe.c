/* Expected rule results for this file (once hardcoded_secrets is implemented):
 * - hardcoded_secrets: PASS (no secrets or suspicious patterns)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>

int main(void) {
    const char *msg = "Hello world";
    const char *user_prompt = "Enter your name: ";

    printf("%s%s\n", user_prompt, msg);
    return 0;
}
