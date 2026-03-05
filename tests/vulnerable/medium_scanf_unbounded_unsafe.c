/* MEDIUM: scanf with %s and %[ without width - buffer overflow.
 * Expected: unsafe-functions, buffer-overflow, format-string
 */

#include <stdio.h>

int main(void) {
    char name[32];
    char id[16];

    scanf("%s", name);      /* No width - overflow */
    scanf("%[^\n]", id);    /* %[ without width - overflow */

    printf("Name: %s, ID: %s\n", name, id);
    return 0;
}
