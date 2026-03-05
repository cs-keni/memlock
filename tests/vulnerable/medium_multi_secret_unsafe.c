/* MEDIUM: Multiple secrets - direct assignment to suspicious identifiers.
 * Expected: hardcoded-secrets
 */

#include <stdio.h>

int main(void) {
    const char *db_password = "SuperSecret123!";
    const char *api_key = "sk-live-abc123xyz789";

    printf("Config loaded\n");
    (void)db_password;
    (void)api_key;
    return 0;
}
