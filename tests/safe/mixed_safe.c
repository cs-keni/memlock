/* Mixed safe example intended to contrast with mixed_vulnerable.c.
 *
 * Expected rule results for this file (once all rules are implemented):
 * - unsafe_functions: PASS (no banned unsafe functions)
 * - use_after_free: PASS (no use-after-free)
 * - buffer_overflow: PASS (array accesses stay within bounds)
 * - memory_management: PASS (all allocations freed)
 * - hardcoded_secrets: PASS (no obvious secrets)
 * - integer_overflow: PASS (sizes are small and checked)
 * - null_checks: PASS (malloc results checked before use)
 * - format_string: PASS (printf-style functions use literals for format)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_buffer_example(void) {
    char buf[8];
    size_t i;

    for (i = 0; i < sizeof(buf); i++) {
        buf[i] = 'A';
    }
    buf[sizeof(buf) - 1] = '\0';
    printf("Buf: %s\n", buf);
}

void safe_memory_example(int user) {
    size_t n = 8u;
    size_t m = 4u;
    size_t total = n * m;

    if (total == 0 || total > 1024) {
        return;
    }

    char *p = (char *)malloc(total);
    if (p == NULL) {
        return;
    }

    p[0] = (char)user;
    printf("First byte: %d\n", (int)p[0]);

    free(p);  /* no leak, no double-free */
}

void safe_pointer_lifecycle(void) {
    int *p = (int *)malloc(sizeof(int));
    if (!p) {
        return;
    }
    *p = 5;
    printf("P = %d\n", *p);
    free(p);
    p = NULL;
}

int main(void) {
    char line[64];

    safe_buffer_example();
    safe_memory_example(42);
    safe_pointer_lifecycle();

    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 1;
    }

    /* Safe format string usage: format is a literal, user data is an argument */
    printf("Input: %s\n", line);

    return 0;
}

