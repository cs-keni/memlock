/* Expected rule results for this file (once null_checks is implemented):
 * - null_checks: FAIL (dereference without NULL check after malloc)
 * - unsafe_functions: PASS
 * - use_after_free: PASS
 * - buffer_overflow: PASS
 * - memory_management: PASS (or may flag leak)
 * - hardcoded_secrets: PASS
 * - integer_overflow: PASS
 * - format_string: PASS
 */

#include <stdio.h>
#include <stdlib.h>

void dereference_without_check(void) {
    int *p = malloc(sizeof(int));
    *p = 42;   /* null_checks should flag: no NULL check before dereference */
    free(p);
}

void subscript_without_check(void) {
    char *buf = malloc(64);
    buf[0] = 'x';   /* null_checks should flag: no NULL check before use */
    free(buf);
}

int main(void) {
    dereference_without_check();
    subscript_without_check();
    return 0;
}
