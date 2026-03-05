/* EASY: Using getenv for config - no hardcoded secrets.
 * Expected: all rules PASS (getenv returns runtime value, not literal)
 */

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *api_host = getenv("API_HOST");
    if (api_host == NULL) {
        api_host = "localhost";   /* Fallback - not a secret */
    }
    printf("Host: %s\n", api_host);   /* Literal format, runtime value as arg */
    return 0;
}
