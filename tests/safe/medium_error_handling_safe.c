/* MEDIUM: Proper error handling - all allocations checked, format literals.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int process_with_cleanup(void) {
    char *buf = malloc(256);
    if (buf == NULL) {
        return -1;
    }

    if (fgets(buf, 256, stdin) != NULL) {
        printf("Received: %s\n", buf);   /* Literal format */
    }
    free(buf);
    return 0;
}

int main(void) {
    if (process_with_cleanup() != 0) {
        fprintf(stderr, "Error: processing failed\n");
        return 1;
    }
    return 0;
}
