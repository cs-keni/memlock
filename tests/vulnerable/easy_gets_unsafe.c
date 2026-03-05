/* EASY: Single gets() call - classic buffer overflow.
 * Expected: unsafe_functions, buffer-overflow
 */

#include <stdio.h>

int main(void) {
    char buf[64];
    gets(buf);   /* Unbounded read - trivial vulnerability */
    printf("Read: %s\n", buf);
    return 0;
}
