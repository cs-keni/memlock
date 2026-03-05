/* MEDIUM: Loop with off-by-one or wrong bound - buffer overflow.
 * Expected: buffer-overflow
 */

#include <stdio.h>

void copy_with_wrong_bound(void) {
    char dst[8];
    /* Bug: i <= 8 means we write dst[8] which is out of bounds (valid indices 0..7) */
    for (int i = 0; i <= 8; i++) {
        dst[i] = 'A';
    }
}

void off_by_one(void) {
    int arr[4];
    /* Bug: i <= 4 means we write arr[4] which is out of bounds */
    arr[4] = 42;   /* Direct out-of-bounds write - clearly detectable */
}

int main(void) {
    copy_with_wrong_bound();
    off_by_one();
    return 0;
}
