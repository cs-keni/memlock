/* Expected rule results for this file (once hardcoded_secrets is implemented):
 * - hardcoded_secrets: FAIL (API key, password, token patterns)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS
 * - integer_overflow: PASS
 * - null_checks: PASS
 * - format_string: PASS
 */

#include <stdio.h>

static const char *API_KEY = "APIKEY-SECRET-1234567890";
static const char *PASSWORD = "P@ssw0rd!";
static const char *token = "sk-abc123xyz789secret";

int main(void) {
    printf("Using %s and %s\n", API_KEY, PASSWORD);
    (void)token;
    return 0;
}
