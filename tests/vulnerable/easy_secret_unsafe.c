/* EASY: Single hardcoded password.
 * Expected: hardcoded-secrets
 */

#include <stdio.h>

int main(void) {
    const char *password = "admin123";
    printf("Login with password\n");
    (void)password;
    return 0;
}
