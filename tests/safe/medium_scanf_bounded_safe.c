/* MEDIUM: scanf with width limits - safe input parsing.
 * Expected: all rules PASS
 */

#include <stdio.h>

int main(void) {
    char name[32];
    char id[16];

    if (scanf("%31s", name) != 1) {
        return 1;
    }
    if (scanf("%15[^\n]", id) != 1) {
        return 1;
    }

    printf("Name: %s, ID: %s\n", name, id);
    return 0;
}
