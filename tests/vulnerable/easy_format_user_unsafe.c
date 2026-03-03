/* EASY: printf with user-controlled format string.
 * Expected: format-string
 */

#include <stdio.h>

int main(void) {
    char fmt[128];
    if (fgets(fmt, sizeof(fmt), stdin) == NULL) {
        return 1;
    }
    printf(fmt);   /* User controls format - information leak / crash */
    return 0;
}
