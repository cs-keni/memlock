/* EASY: malloc with explicit NULL check before use.
 * Expected: all rules PASS
 */

#include <stdlib.h>
#include <stdio.h>

int main(void) {
    int *p = malloc(sizeof(int));
    if (p == NULL) {
        return 1;
    }
    *p = 42;
    printf("%d\n", *p);
    free(p);
    return 0;
}
