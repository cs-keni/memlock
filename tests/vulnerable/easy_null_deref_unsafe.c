/* EASY: malloc result used without NULL check.
 * Expected: null-checks
 */

#include <stdlib.h>

int main(void) {
    int *p = malloc(sizeof(int));
    *p = 42;   /* No check - crash if malloc fails */
    free(p);
    return 0;
}
