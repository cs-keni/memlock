/* EASY: fgets with bounded buffer - safe alternative to gets.
 * Expected: all rules PASS
 */

#include <stdio.h>

int main(void) {
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        return 1;
    }
    printf("Read: %s\n", buf);
    return 0;
}
