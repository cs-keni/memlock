/* EASY: printf with literal format string - user data as argument only.
 * Expected: all rules PASS
 */

#include <stdio.h>

int main(void) {
    char user_input[64];
    if (fgets(user_input, sizeof(user_input), stdin) == NULL) {
        return 1;
    }
    printf("You entered: %s\n", user_input);   /* Literal format, user in %s */
    return 0;
}
