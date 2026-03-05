/* MEDIUM: Vulnerability in one code path - error handling misses check.
 * Expected: null-checks (p used without check in success path), use-after-free
 */

#include <stdlib.h>
#include <stdio.h>

int process_data(int use_alt_path) {
    int *p = malloc(sizeof(int));
    if (use_alt_path) {
        free(p);
        return -1;
    }
    *p = 100;   /* No NULL check - p could be NULL if malloc failed */
    int result = *p;
    free(p);
    return result;
}

void use_after_free_in_branch(int flag) {
    char *buf = malloc(64);
    if (buf) {
        buf[0] = 'x';
    }
    free(buf);
    if (flag) {
        buf[0] = 'y';   /* use-after-free when flag is true */
    }
}

int main(void) {
    process_data(0);
    use_after_free_in_branch(0);
    return 0;
}
