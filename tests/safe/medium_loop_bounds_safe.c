/* MEDIUM: Loops with correct bounds - no overflow.
 * Expected: all rules PASS
 */

#include <stdio.h>
#include <string.h>

void copy_with_correct_bound(void) {
    char src[16] = "hello";
    char dst[8];
    size_t len = strlen(src);
    size_t copy_len = len < sizeof(dst) - 1 ? len : sizeof(dst) - 1;

    for (size_t i = 0; i < copy_len; i++) {
        dst[i] = src[i];
    }
    dst[copy_len] = '\0';
}

void array_fill_safe(void) {
    int arr[4];
    for (int i = 0; i < 4; i++) {
        arr[i] = i;
    }
}

int main(void) {
    copy_with_correct_bound();
    array_fill_safe();
    return 0;
}
