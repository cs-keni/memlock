/* EASY: strcpy without bounds - trivial buffer overflow.
 * Expected: unsafe_functions, buffer-overflow
 */

#include <stdio.h>
#include <string.h>

int main(void) {
    char dst[8];
    char src[64] = "this string is way too long for dst";
    strcpy(dst, src);   /* No length check - overflow guaranteed */
    return 0;
}
