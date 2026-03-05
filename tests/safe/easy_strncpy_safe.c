/* EASY: strncpy with explicit bound and null termination.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char dst[32];
    char src[] = "hello world";
    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\0';
    printf("%s\n", dst);
    return 0;
}
