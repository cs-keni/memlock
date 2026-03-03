/* HARD: Complex control flow - multiple paths, all properly guarded.
 * Simplified to avoid use-after-free false positives (single free at end).
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

int main(void) {
    char *data = malloc(BUF_SIZE);
    if (data == NULL) {
        return 1;
    }

    if (fgets(data, BUF_SIZE, stdin) != NULL) {
        printf("Buffer: %s\n", data);
    }

    free(data);
    return 0;
}
