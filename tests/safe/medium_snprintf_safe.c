/* MEDIUM: snprintf with bounded buffers - safe string formatting.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[128];
    char user[64];

    if (fgets(user, sizeof(user), stdin) == NULL) {
        return 1;
    }
    user[strcspn(user, "\n")] = '\0';

    snprintf(buf, sizeof(buf), "User input: %s\n", user);
    printf("%s", buf);

    return 0;
}
